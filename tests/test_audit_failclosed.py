"""Fail-closed on auditability for approval-gated credentials.

Ordinary auditing is best-effort: a logging failure must not break the
request path. Approval-gated credentials invert that — they exist because
their use must be accountable, so if the use cannot be recorded it must not
happen. Both the HTTP path and the exec path enforce this.
"""

import pytest

from agent_keychain import exec_runner
from agent_keychain.mcp_server.server import vault, secure_http_request


@pytest.fixture
def unwritable_audit(tmp_path, monkeypatch):
    """Point the audit log below a regular file so every append fails."""
    blocker = tmp_path / "blocker"
    blocker.write_text("a file, not a directory")
    monkeypatch.setenv("AGENT_KEYCHAIN_AUDIT_LOG", str(blocker / "audit.jsonl"))


@pytest.fixture
def writable_audit(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_KEYCHAIN_AUDIT_LOG", str(tmp_path / "audit.jsonl"))


@pytest.fixture
def gated_credential():
    """Approval-gated credential with an open grant window and valid policy."""
    vault.store(
        "fc-gated", "fake-secret", "github",
        allowed_domains=["github.com"], require_approval=True,
    )
    vault.grant("fc-gated", 300)  # approval itself passes; audit is the gate
    yield
    vault.delete("fc-gated")


@pytest.fixture
def normal_credential():
    vault.store("fc-normal", "fake-secret", "github",
                allowed_domains=["github.com"])
    yield
    vault.delete("fc-normal")


def test_gated_credential_refused_when_unauditable(unwritable_audit, gated_credential):
    result = secure_http_request("fc-gated", "https://evil.com")
    assert "fail-closed" in result
    # Refused on auditability BEFORE any policy evaluation or secret access.
    assert "not allowed" not in result


def test_gated_credential_proceeds_when_auditable(writable_audit, gated_credential):
    # Same request with a working audit log reaches the policy gauntlet
    # (and is domain-blocked there) instead of the fail-closed gate.
    result = secure_http_request("fc-gated", "https://evil.com")
    assert "fail-closed" not in result
    assert "not allowed" in result


def test_normal_credential_tolerates_unauditable(unwritable_audit, normal_credential):
    # Best-effort auditing: an ordinary credential still reaches the
    # gauntlet when the log is broken.
    result = secure_http_request("fc-normal", "https://evil.com")
    assert "fail-closed" not in result
    assert "not allowed" in result


def test_exec_path_fails_closed_too(unwritable_audit, gated_credential):
    result = exec_runner.run(vault, "fc-gated", [], ["echo", "hi"])
    assert result["ok"] is False and result["blocked"] is True
    assert "fail-closed" in result["error"]
