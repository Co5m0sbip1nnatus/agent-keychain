"""Tests for MCP server tool functions."""
import pytest
from agent_keychain.mcp_server.server import vault, check_connection, list_available_credentials, secure_http_request


@pytest.fixture(autouse=True)
def isolate_audit_log(tmp_path, monkeypatch):
    """Keep test requests from writing to the real audit log."""
    monkeypatch.setenv("AGENT_KEYCHAIN_AUDIT_LOG", str(tmp_path / "audit.jsonl"))


@pytest.fixture
def setup_credential():
    """Store a test credential using the server's vault and clean up after."""
    vault.store("test-mcp", "fake-token-xyz", "test", "MCP test credential")
    yield
    vault.delete("test-mcp")

def test_check_connection():
    """check_connection should return a status string."""
    result = check_connection()
    assert "Agent Keychain is active" in result

def test_list_available_credentials(setup_credential):
    """list_available_credentials should show stored credentials."""
    result = list_available_credentials()
    assert "test-mcp" in result
    assert "test" in result

def test_secure_http_request_rejects_http():
    """HTTP (non-HTTPS) URLs should be rejected."""
    result = secure_http_request("any", "http://example.com")
    assert "HTTPS" in result

def test_secure_http_request_invalid_method():
    """Invalid HTTP methos should be rejected."""
    result = secure_http_request("any", "https://example.com", method="INVALID")
    assert "Error" in result

def test_secure_http_request_missing_credential():
    """Non-existent credential should return an error."""
    result = secure_http_request("nonexistent", "https://api.github.com")
    assert "not found" in result


@pytest.fixture
def github_credential():
    """A credential bound to github.com, cleaned up after the test."""
    vault.store("test-domain", "fake-token", "github", allowed_domains=["github.com"])
    yield
    vault.delete("test-domain")


def test_domain_binding_blocks_other_host(github_credential):
    """A github-bound credential must not be usable against another host.

    The request is rejected before any subprocess/network call, so this
    makes no outbound connection.
    """
    result = secure_http_request("test-domain", "https://evil.com")
    assert "not allowed" in result
    assert "github.com" in result  # error tells the user what IS allowed


def test_domain_binding_blocks_when_no_domains():
    """A credential with no allowed domains is blocked by default."""
    vault.store("test-nodomain", "fake-token", "test")  # unknown type, no domains
    try:
        result = secure_http_request("test-nodomain", "https://api.github.com")
        assert "no allowed domains" in result
    finally:
        vault.delete("test-nodomain")


def test_blocked_request_is_audited(tmp_path, monkeypatch, github_credential):
    """A blocked request must leave a 'blocked' entry in the audit log."""
    from agent_keychain.audit import audit_log
    monkeypatch.setenv("AGENT_KEYCHAIN_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    secure_http_request("test-domain", "https://evil.com")
    events = audit_log.read_events(blocked_only=True)
    assert any(e["host"] == "evil.com" and e["credential"] == "test-domain" for e in events)
