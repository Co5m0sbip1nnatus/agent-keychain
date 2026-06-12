"""Tests for audit-based rate limiting and anomaly summarization."""
import pytest
from agent_keychain.audit import audit_log


@pytest.fixture
def audit_file(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_KEYCHAIN_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    return tmp_path / "audit.jsonl"


def test_count_recent_counts_allowed_in_window(audit_file):
    for _ in range(3):
        audit_log.record("c", "api.github.com", "GET", audit_log.ALLOWED, "ok", status=200, success=True)
    # All just-written events are within a 60s window.
    assert audit_log.count_recent("c", 60) == 3
    # Blocked events are not counted as allowed.
    audit_log.record("c", "evil.com", "GET", audit_log.BLOCKED, "x")
    assert audit_log.count_recent("c", 60) == 3


def test_count_recent_excludes_other_credentials(audit_file):
    audit_log.record("a", "h", "GET", audit_log.ALLOWED)
    audit_log.record("b", "h", "GET", audit_log.ALLOWED)
    assert audit_log.count_recent("a", 60) == 1


def test_count_recent_respects_window(audit_file):
    audit_log.record("c", "h", "GET", audit_log.ALLOWED)
    # A window in the future relative to "now=0" excludes the just-written event.
    assert audit_log.count_recent("c", 60, now=10_000_000_000) == 0


def test_summarize_blocked_groups_and_sorts(audit_file):
    for _ in range(3):
        audit_log.record("c", "evil.com", "GET", audit_log.BLOCKED, "host not in allowed domains")
    audit_log.record("c", "x.com", "GET", audit_log.BLOCKED, "host not in allowed domains")
    audit_log.record("d", "y.com", "POST", audit_log.BLOCKED, "no allowed domains")
    groups = audit_log.summarize_blocked(min_count=2)
    # Only the (c, "host not in allowed domains") group has >= 2 hits.
    assert len(groups) == 1
    g = groups[0]
    assert g["credential"] == "c"
    assert g["count"] == 4
    assert set(g["hosts"]) == {"evil.com", "x.com"}
