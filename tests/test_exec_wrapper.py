"""Tests for the credential-injecting exec wrapper."""
import pytest
from agent_keychain.vault.command_policy import command_allowed
from agent_keychain.vault.keychain_vault import KeychainVault
from agent_keychain import exec_runner


# --- command policy (pure) --------------------------------------------------

def test_command_empty_allowlist_denies():
    assert command_allowed("aws", []) is False


def test_command_basename_match():
    assert command_allowed("/usr/local/bin/aws", ["aws"]) is True
    assert command_allowed("git", ["aws"]) is False


def test_command_glob():
    assert command_allowed("gcloud", ["gcloud", "aws"]) is True
    assert command_allowed("kubectl", ["kube*"]) is True


# --- runner (real subprocess with a harmless command) -----------------------

@pytest.fixture
def vault(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_KEYCHAIN_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    v = KeychainVault()
    yield v
    v.delete("exec-cred")


def test_blocked_when_command_not_allowed(vault):
    vault.store("exec-cred", "s3cr3t-value", "test", allowed_domains=["*"], allowed_commands=["aws"])
    result = exec_runner.run(vault, "exec-cred", [], ["git", "status"])
    assert result["ok"] is False and result["blocked"] is True


def test_env_injection_is_scrubbed_from_output(vault):
    secret = "s3cr3t-ghp_" + "A" * 30
    vault.store("exec-cred", secret, "test", allowed_domains=["*"], allowed_commands=["sh"])
    # The child echoes the injected env var; DLP must scrub it from stdout.
    result = exec_runner.run(vault, "exec-cred", ["MY_TOKEN"], ["sh", "-c", "echo $MY_TOKEN"])
    assert result["ok"] is True
    assert secret not in result["stdout"]
    assert "[REDACTED]" in result["stdout"]


def test_placeholder_substitution_is_scrubbed(vault):
    secret = "placeholder-secret-123"
    vault.store("exec-cred", secret, "test", allowed_domains=["*"], allowed_commands=["echo"])
    result = exec_runner.run(vault, "exec-cred", [], ["echo", "value={secret}"])
    assert result["ok"] is True
    assert secret not in result["stdout"]
    assert "[REDACTED]" in result["stdout"]


def test_missing_credential(vault):
    result = exec_runner.run(vault, "nope", [], ["echo", "hi"])
    assert result["ok"] is False and not result.get("blocked")
