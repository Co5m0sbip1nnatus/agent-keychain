"""Tests for `agent-keychain doctor`.

Doctor exists because an installed-but-unwired security tool is worse than
none: the user believes they are protected. So the tests exercise the
failure detections, not just the happy path.
"""

import json

import pytest

from agent_keychain import cli


@pytest.fixture
def isolated_env(tmp_path, monkeypatch):
    """File backend + throwaway audit log + empty cwd, real HOME untouched."""
    monkeypatch.setenv("AGENT_KEYCHAIN_BACKEND", "file")
    monkeypatch.setenv("AGENT_KEYCHAIN_STORE", str(tmp_path / "store.json"))
    monkeypatch.setenv("AGENT_KEYCHAIN_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setattr(cli, "HOOK_INSTALL_DIR", str(tmp_path / "hooks"))
    monkeypatch.setattr(cli, "SETTINGS_PATH", str(tmp_path / "settings.json"))
    monkeypatch.chdir(tmp_path)
    return tmp_path


def run_doctor(capsys):
    """Run doctor; return (exit_code, output)."""
    code = 0
    try:
        cli.cmd_doctor(None)
    except SystemExit as exc:
        code = exc.code
    return code, capsys.readouterr().out


def test_doctor_healthy_setup_exits_zero(isolated_env, capsys):
    from agent_keychain.vault.keychain_vault import KeychainVault
    vault = KeychainVault()
    vault.store("doc-test", "fake-secret", "github", allowed_domains=["github.com"])

    code, out = run_doctor(capsys)

    assert code == 0  # warnings (no hook, no MCP reg) are not failures
    assert "storage backend 'file' reachable" in out
    assert "1 credential(s)" in out
    assert "every credential is domain-bound" in out


def test_doctor_fails_when_audit_log_unwritable(isolated_env, capsys, monkeypatch):
    # Point the audit log below a regular file so the append probe fails.
    blocker = isolated_env / "blocker"
    blocker.write_text("i am a file, not a directory")
    monkeypatch.setenv("AGENT_KEYCHAIN_AUDIT_LOG", str(blocker / "audit.jsonl"))

    code, out = run_doctor(capsys)

    assert code == 1
    assert "audit log NOT writable" in out


def test_doctor_flags_undomained_credentials(isolated_env, capsys):
    from agent_keychain.vault.keychain_vault import KeychainVault
    vault = KeychainVault()
    vault.store("no-domain", "fake-secret", "custom-service")

    code, out = run_doctor(capsys)

    assert "without allowed domains" in out
    assert "migrate" in out


def test_doctor_detects_unregistered_hook_file(isolated_env, capsys):
    # Hook file exists but settings has no registration -> fail.
    hooks_dir = isolated_env / "hooks"
    hooks_dir.mkdir()
    (hooks_dir / cli.HOOK_SCRIPT_NAME).write_text("#!/bin/bash\n")

    code, out = run_doctor(capsys)

    assert code == 1
    assert "not registered" in out


def test_doctor_detects_outdated_matcher(isolated_env, capsys):
    """An old install matched only Read|Bash, so write-capable tools never
    reach the hook and self-protection is silently off."""
    hooks_dir = isolated_env / "hooks"
    hooks_dir.mkdir()
    (hooks_dir / cli.HOOK_SCRIPT_NAME).write_text("#!/bin/bash\n")
    settings = {
        "hooks": {"PreToolUse": [{
            "matcher": "Read|Bash",
            "hooks": [{"type": "command",
                       "command": str(hooks_dir / cli.HOOK_SCRIPT_NAME)}],
        }]}
    }
    (isolated_env / "settings.json").write_text(json.dumps(settings))

    code, out = run_doctor(capsys)

    assert "outdated matcher" in out
    assert "differs from packaged version" in out  # stub != packaged source


def test_doctor_reports_mcp_registration(isolated_env, capsys):
    (isolated_env / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"agent-keychain": {"command": "python"}}})
    )

    code, out = run_doctor(capsys)

    assert "MCP server registered in this project" in out
