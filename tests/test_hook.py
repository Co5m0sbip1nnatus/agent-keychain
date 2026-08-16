"""Tests for the credential-guard PreToolUse hook.

The hook is enforcement, so it is tested by running it and observing the
decision -- not by inspecting its pattern lists. Both directions matter: a
hook that blocks everything passes a "did it block?" test while being just
as broken as one that blocks nothing.
"""

import json
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


def run_hook(tool_name: str, **tool_input) -> int:
    """Run the hook with a tool payload; return its exit code."""
    payload = json.dumps({"tool_name": tool_name, "tool_input": tool_input})
    proc = subprocess.run(
        ["bash", str(HOOK)], input=payload, capture_output=True, text=True, timeout=20
    )
    return proc.returncode


def bash(command: str) -> int:
    return run_hook("Bash", command=command)


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
