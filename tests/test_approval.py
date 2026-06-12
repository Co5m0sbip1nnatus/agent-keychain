"""Tests for human-in-the-loop time-limited grants."""
import pytest
from agent_keychain.vault import approval
from agent_keychain.vault.keychain_vault import KeychainVault, CredentialEntry
from agent_keychain import exec_runner


def _entry(require_approval=False, grant_until=None):
    return CredentialEntry(name="c", service_type="aws", created_at=0.0,
                           require_approval=require_approval, grant_until=grant_until,
                           allowed_commands=["aws"])


# --- duration parsing -------------------------------------------------------

@pytest.mark.parametrize("text,expected", [("30s", 30), ("5m", 300), ("2h", 7200), ("1d", 86400), ("45", 45)])
def test_parse_duration(text, expected):
    assert approval.parse_duration(text) == expected


def test_parse_duration_invalid():
    with pytest.raises(ValueError):
        approval.parse_duration("soon")


# --- policy -----------------------------------------------------------------

def test_no_approval_required_never_blocks():
    assert approval.is_blocked_pending_approval(_entry(require_approval=False), now=100) is False


def test_blocked_without_grant():
    assert approval.is_blocked_pending_approval(_entry(require_approval=True), now=100) is True


def test_unblocked_within_window():
    e = _entry(require_approval=True, grant_until=200)
    assert approval.is_blocked_pending_approval(e, now=150) is False
    assert approval.grant_remaining(e, now=150) == 50


def test_blocked_after_window_expires():
    e = _entry(require_approval=True, grant_until=200)
    assert approval.is_blocked_pending_approval(e, now=250) is True


# --- vault grant/revoke -----------------------------------------------------

@pytest.fixture
def vault(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_KEYCHAIN_AUDIT_LOG", str(tmp_path / "a.jsonl"))
    v = KeychainVault()
    yield v
    v.delete("appr-cred")


def test_grant_then_exec_allowed_then_revoke_blocks(vault):
    vault.store("appr-cred", "s3cr3t", "test", allowed_domains=["*"],
                allowed_commands=["echo"], require_approval=True)
    # Blocked before any grant.
    r1 = exec_runner.run(vault, "appr-cred", [], ["echo", "hi"])
    assert r1["ok"] is False and r1["blocked"] is True

    # After a grant window, allowed.
    assert vault.grant("appr-cred", 60) is True
    r2 = exec_runner.run(vault, "appr-cred", [], ["echo", "hi"])
    assert r2["ok"] is True

    # After revoke, blocked again.
    assert vault.revoke("appr-cred") is True
    r3 = exec_runner.run(vault, "appr-cred", [], ["echo", "hi"])
    assert r3["ok"] is False and r3["blocked"] is True
