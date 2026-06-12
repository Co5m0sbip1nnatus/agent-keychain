"""Tests for the best-effort OS sandbox (macOS sandbox-exec)."""
import subprocess
import sys
import pytest
from agent_keychain import sandbox, exec_runner
from agent_keychain.vault.keychain_vault import KeychainVault


def test_build_profile_denies_realpath():
    profile = sandbox.build_profile([("literal", "/tmp/x"), ("subpath", "~/.ssh")])
    assert "(allow default)" in profile
    assert "(deny file-read*" in profile
    # ~ is expanded; nothing is left literally "~".
    assert "~" not in profile


def test_wrap_argv_prefixes_sandbox_exec():
    wrapped = sandbox.wrap_argv(["echo", "hi"], deny_specs=[("literal", "/tmp/x")])
    assert wrapped[0] == "sandbox-exec" and wrapped[-2:] == ["echo", "hi"]


def test_exec_sandbox_fails_closed_when_unavailable(tmp_path, monkeypatch):
    """If a sandbox is requested but unavailable, the command must NOT run."""
    monkeypatch.setenv("AGENT_KEYCHAIN_AUDIT_LOG", str(tmp_path / "a.jsonl"))
    monkeypatch.setattr(sandbox, "is_available", lambda: False)
    v = KeychainVault()
    v.store("sb-cred", "s", "test", allowed_domains=["*"], allowed_commands=["echo"])
    try:
        result = exec_runner.run(v, "sb-cred", [], ["echo", "hi"], sandbox=True)
        assert result["ok"] is False and result["blocked"] is True
        assert "sandbox" in result["error"].lower()
    finally:
        v.delete("sb-cred")


@pytest.mark.skipif(not sandbox.is_available(), reason="sandbox-exec only on macOS")
def test_sandbox_actually_denies_credential_read(tmp_path):
    """Real sandbox-exec must block reading a denied file but allow others."""
    secret = tmp_path / "secret.txt"
    secret.write_text("AKIA-fake\n")
    allowed = tmp_path / "ok.txt"
    allowed.write_text("fine\n")

    deny = [("literal", str(secret))]
    blocked = subprocess.run(sandbox.wrap_argv(["cat", str(secret)], deny_specs=deny),
                             capture_output=True, text=True)
    assert blocked.returncode != 0  # read denied

    ok = subprocess.run(sandbox.wrap_argv(["cat", str(allowed)], deny_specs=deny),
                        capture_output=True, text=True)
    assert ok.returncode == 0 and "fine" in ok.stdout
