"""Tests for MCP server tool functions."""
import pytest
from src.mcp_server.server import vault, check_connection, list_available_credentials, secure_http_request

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
