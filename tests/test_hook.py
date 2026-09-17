"""Tests for the credential-guard PreToolUse hook.

The hook is enforcement, so it is tested by running it and observing the
decision -- not by inspecting its pattern lists. Both directions matter: a
hook that blocks everything passes a "did it block?" test while being just
as broken as one that blocks nothing.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

HOOK = Path(__file__).resolve().parent.parent / "agent_keychain" / "hooks" / "credential-guard.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("jq") is None or shutil.which("bash") is None,
    reason="hook requires bash and jq",
)

BLOCK_EXIT = 2


def run_hook(
    tool_name: str,
    home: str | None = None,
    hook_env: dict | None = None,
    **tool_input,
) -> int:
    """Run the hook with a tool payload; return its exit code."""
    payload = json.dumps({"tool_name": tool_name, "tool_input": tool_input})
    env = dict(os.environ)
    # Deterministic self-protection state no matter where pytest runs (a dev
    # session inside the repo would otherwise lift it via CLAUDE_PROJECT_DIR).
    env.pop("CLAUDE_PROJECT_DIR", None)
    env.pop("AGENT_KEYCHAIN_UNGUARD", None)
    if home:
        env["HOME"] = home
    if hook_env:
        env.update(hook_env)
    proc = subprocess.run(
        ["bash", str(HOOK)], input=payload, capture_output=True, text=True,
        timeout=20, env=env,
    )
    return proc.returncode


def bash(command: str, home: str | None = None, hook_env: dict | None = None) -> int:
    return run_hook("Bash", home=home, hook_env=hook_env, command=command)


# --- Layer 2: vault access -------------------------------------------------
# Moving a secret into the keychain removes it from the paths an agent
# stumbles onto, but the keychain is still reachable by anything running as
# the same user. These are the read-out paths that bypass the proxy.

@pytest.mark.parametrize(
    "command",
    [
        "security find-generic-password -s agent-keychain -a github -w",
        "security find-internet-password -s example.com",
        "security dump-keychain -d",
        'python3 -c "import keyring; print(keyring.get_password(\'agent-keychain\', \'gh\'))"',
        'python3 -c "from agent_keychain.vault.keychain_vault import KeychainVault;'
        ' print(KeychainVault().retrieve(\'gh\').value)"',
    ],
)
def test_direct_vault_reads_are_blocked(command):
    assert bash(command) == BLOCK_EXIT


def test_file_backend_store_is_blocked():
    """Our own vault file is a credential file too -- it was missed at first."""
    assert bash("cat ~/.agent-keychain/store.json") == BLOCK_EXIT


# --- Layer 2 must not block ordinary development ---------------------------
# The retrieval patterns match a call, not a mention, so reading or searching
# the source stays allowed. A guard that blocks normal work gets turned off.

@pytest.mark.parametrize(
    "command",
    [
        "grep -rn get_password agent_keychain/vault/backends.py",
        "python -m pytest tests/test_vault.py -q",
        "agent-keychain list",
        "agent-keychain audit --blocked-only",
        "git status",
    ],
)
def test_ordinary_commands_are_allowed(command):
    assert bash(command) == 0


# --- Layer 1: path blocklist (pre-existing behavior) -----------------------

def test_credential_path_is_blocked_regardless_of_verb():
    assert bash("cat ~/.aws/credentials") == BLOCK_EXIT
    assert bash("awk '{print}' ~/.ssh/id_rsa") == BLOCK_EXIT
    assert bash("python -c \"print(open('/home/u/.npmrc').read())\"") == BLOCK_EXIT


def test_non_reading_verbs_on_a_secret_file_are_allowed(tmp_path):
    """rm/mv/chmod never reveal contents, so they must not be blocked."""
    secret = tmp_path / "creds.txt"
    secret.write_text("ghp_" + "A" * 36 + "\n")
    assert bash(f"chmod 600 {secret}") == 0
    assert bash(f"mv {secret} {tmp_path / 'moved.txt'}") == 0


# --- Layer 3: content scan -------------------------------------------------

def test_reading_a_file_containing_a_secret_is_blocked(tmp_path):
    secret = tmp_path / "config.txt"
    secret.write_text("token = ghp_" + "A" * 36 + "\n")
    assert bash(f"cat {secret}") == BLOCK_EXIT
    assert run_hook("Read", file_path=str(secret)) == BLOCK_EXIT


def test_reading_a_clean_file_is_allowed(tmp_path):
    clean = tmp_path / "notes.txt"
    clean.write_text("nothing sensitive here\n")
    assert bash(f"cat {clean}") == 0
    assert run_hook("Read", file_path=str(clean)) == 0


def test_unrelated_tools_pass_through():
    assert run_hook("Glob", pattern="**/*.py") == 0


# --- The PoC recon list -----------------------------------------------------
# poc/agent_credential_exposure.py proved these exact commands leak
# credentials from an ordinary agent session. The hook must block the ones
# whose target is sensitive by PATH (deterministic on any machine); the two
# content-dependent ones (~/.gitconfig, ~/.bashrc) are covered by the
# fake-HOME tests below, because blocking them unconditionally would break
# ordinary work on machines where those files hold no secrets.

@pytest.mark.parametrize(
    "command",
    [
        "cat ~/.env",                                              # PoC #1
        "cat ~/.aws/credentials",                                  # PoC #2
        "cat ~/.npmrc",                                            # PoC #4
        "env | grep -i 'token\\|key\\|secret\\|password'",         # PoC #5
        "cat ~/.docker/config.json",                               # PoC #6
        "cat ~/.kube/config",                                      # PoC #7
        "ls -la ~/.ssh/ && head -5 ~/.ssh/id_rsa",                 # PoC #8
        "find ~/projects -name '.env' -exec cat {} \\;",           # PoC #9
    ],
)
def test_poc_recon_commands_are_blocked(command):
    assert bash(command) == BLOCK_EXIT


# --- Credential-emitting commands -------------------------------------------
# Printing a secret is these commands' documented function; a benign agent
# runs them while "checking your setup" and the secret lands in context.

@pytest.mark.parametrize(
    "command",
    [
        "gh auth token",
        "aws configure export-credentials",
        "gcloud auth print-access-token",
        "kubectl config view --raw",
        "echo $GITHUB_TOKEN",
        "printenv GITHUB_TOKEN",
    ],
)
def test_credential_emitting_commands_are_blocked(command):
    assert bash(command) == BLOCK_EXIT


@pytest.mark.parametrize(
    "command",
    [
        "gh auth status",          # masks the token itself
        "gh pr list",
        "kubectl config view",     # redacts secrets without --raw
        "gcloud auth list",
        "env",                     # bare env for debugging stays allowed
        "env | sort",
        "echo $PATH",
    ],
)
def test_nearby_legitimate_commands_stay_allowed(command):
    assert bash(command) == 0


# --- Content scan under PoC-machine conditions ------------------------------
# With HOME pointed at a directory whose dotfiles hold secrets, the
# content-dependent PoC commands must block; a clean file must not.

@pytest.fixture
def secret_home(tmp_path):
    (tmp_path / ".gitconfig").write_text(
        "[url]\n  insteadOf = https://user:ghp_" + "A" * 36 + "@github.com\n"
    )
    (tmp_path / ".bashrc").write_text("export MY_API_KEY=plainvalue123\n")
    (tmp_path / ".zshrc").write_text("alias ll='ls -la'\n")
    return str(tmp_path)


def test_gitconfig_with_secret_is_blocked(secret_home):
    assert bash("cat ~/.gitconfig", home=secret_home) == BLOCK_EXIT  # PoC #3


def test_bashrc_export_hunt_is_blocked(secret_home):
    # PoC #10 — regression for two bugs at once: the quoted pipe used to
    # break segmentation, and the exported plain value matches only the
    # name-hint pattern.
    cmd = "grep -i 'export.*token\\|export.*key\\|export.*secret' ~/.bashrc"
    assert bash(cmd, home=secret_home) == BLOCK_EXIT


def test_clean_dotfile_is_allowed(secret_home):
    assert bash("cat ~/.zshrc", home=secret_home) == 0


def test_quoted_filename_is_scanned(tmp_path):
    secret = tmp_path / "my secrets.txt"
    secret.write_text("token = ghp_" + "B" * 36 + "\n")
    assert bash(f"cat '{secret}'") == BLOCK_EXIT


# --- .env variants -----------------------------------------------------------

def test_env_example_is_allowed():
    assert bash("ls .env.example") == 0
    assert bash("cat .env.example") == 0


def test_real_env_variants_still_block():
    assert bash("cat .env") == BLOCK_EXIT
    assert bash("cat .env.local") == BLOCK_EXIT
    assert bash("cat backend/.env") == BLOCK_EXIT
    # An exempt name in the same command must not shadow the real one.
    assert bash("cat .env .env.example") == BLOCK_EXIT


# --- Self-protection ---------------------------------------------------------
# The guard must guard itself: a benign agent that hits a block will try to
# "fix" the obstacle by editing the hook, deregistering it, or uninstalling.

def test_edit_to_hook_script_is_blocked():
    assert run_hook("Edit", file_path="/home/u/.claude/hooks/credential-guard.sh") == BLOCK_EXIT


def test_write_to_settings_is_blocked():
    assert run_hook("Write", file_path="/home/u/.claude/settings.json") == BLOCK_EXIT
    assert run_hook("Write", file_path="/home/u/.claude/settings.local.json") == BLOCK_EXIT


@pytest.mark.parametrize(
    "command",
    [
        "agent-keychain uninstall",
        "rm ~/.claude/hooks/credential-guard.sh",
        "sed -i '' 's/exit 2/exit 0/' ~/.claude/hooks/credential-guard.sh",
        "echo '{}' > ~/.claude/settings.json",
        "python3 -c \"open('/home/u/.claude/settings.json','w').write('{}')\"",
    ],
)
def test_tampering_with_the_guard_is_blocked(command):
    assert bash(command) == BLOCK_EXIT


def test_reading_the_hook_stays_allowed():
    # The hook holds no secrets; inspecting it is legitimate.
    assert bash("cat ~/.claude/hooks/credential-guard.sh") == 0


def test_dev_repo_session_is_exempt():
    """Developing agent-keychain itself must not be blocked by its own guard."""
    repo_root = str(HOOK.parent.parent.parent)
    assert bash(
        "sed -i '' 's/x/y/' agent_keychain/hooks/credential-guard.sh",
        hook_env={"CLAUDE_PROJECT_DIR": repo_root},
    ) == 0


def test_operator_unguard_env_lifts_protection():
    assert bash("agent-keychain uninstall", hook_env={"AGENT_KEYCHAIN_UNGUARD": "1"}) == 0


def test_unguard_cannot_be_injected_from_the_command_line():
    """Prefixing the variable onto the command reaches the child process, not
    the hook -- the escape hatch is operator-only by construction."""
    assert bash("AGENT_KEYCHAIN_UNGUARD=1 agent-keychain uninstall") == BLOCK_EXIT
