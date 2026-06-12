"""Tests for the credential-usage audit log."""
import json
import os
import pytest
from agent_keychain.audit import audit_log


@pytest.fixture
def audit_file(tmp_path, monkeypatch):
    """Route the audit log to a temp file for the duration of a test."""
    path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("AGENT_KEYCHAIN_AUDIT_LOG", str(path))
    return path


def test_record_appends_jsonl(audit_file):
    audit_log.record("github-main", "api.github.com", "GET", audit_log.ALLOWED, "ok", status=200, success=True)
    audit_log.record("github-main", "evil.com", "GET", audit_log.BLOCKED, "host not in allowed domains")
    lines = audit_file.read_text().strip().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["credential"] == "github-main"
    assert first["host"] == "api.github.com"
    assert first["decision"] == "allowed"
    assert first["status"] == 200


def test_record_never_logs_secrets(audit_file):
    # The audit event must only contain the documented metadata fields.
    event = audit_log.record("c", "h", "GET", audit_log.ALLOWED)
    assert set(event.keys()) <= {"ts", "credential", "host", "method", "decision", "reason", "status", "success"}


def test_file_permissions_owner_only(audit_file):
    audit_log.record("c", "h", "GET", audit_log.BLOCKED, "x")
    mode = os.stat(audit_file).st_mode & 0o777
    assert mode == 0o600


def test_read_events_filters_by_credential(audit_file):
    audit_log.record("a", "h1", "GET", audit_log.ALLOWED)
    audit_log.record("b", "h2", "GET", audit_log.BLOCKED, "x")
    events = audit_log.read_events(credential="b")
    assert len(events) == 1
    assert events[0]["credential"] == "b"


def test_read_events_blocked_only(audit_file):
    audit_log.record("a", "h1", "GET", audit_log.ALLOWED)
    audit_log.record("a", "h2", "GET", audit_log.BLOCKED, "x")
    events = audit_log.read_events(blocked_only=True)
    assert len(events) == 1
    assert events[0]["decision"] == "blocked"


def test_read_events_limit_returns_newest(audit_file):
    for i in range(5):
        audit_log.record(f"c{i}", "h", "GET", audit_log.ALLOWED)
    events = audit_log.read_events(limit=2)
    assert [e["credential"] for e in events] == ["c3", "c4"]


def test_read_events_empty_when_no_file(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_KEYCHAIN_AUDIT_LOG", str(tmp_path / "nope.jsonl"))
    assert audit_log.read_events() == []
