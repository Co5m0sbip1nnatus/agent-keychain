"""Tests for KeychainVault credential operations."""
import pytest
from agent_keychain.vault.keychain_vault import KeychainVault
from agent_keychain.vault.secure_string import SecureString

@pytest.fixture
def vault():
    """Create a vault instance and clean up test credentials after each test."""
    v = KeychainVault()
    yield v
    # Cleanup: delete test credentials
    for name in ["test-cred", "test-empty", "test-reload"]:
        v.delete(name)
    
def test_store_and_retrieve(vault):
    """Stored credential should be retrievable as a SecureString."""
    vault.store("test-cred", "secret123", "test", "Test credential")
    result = vault.retrieve("test-cred")
    assert isinstance(result, SecureString)
    assert result.value == "secret123"

def test_list_credentials(vault):
    """Stored credential should appear in the list."""
    vault.store("test-cred", "secret123", "test")
    creds = vault.list_credentials()
    names = [c.name for c in creds]
    assert "test-cred" in names

def test_delete_credential(vault):
    """Deleted credential should no longer be retrievable."""
    vault.store("test-cred", "secret123", "test")
    vault.delete("test-cred")
    assert vault.retrieve("test-cred") is None

def test_retrieve_nonexistent(vault):
    """Retrieving a non-existent credential should return None."""
    assert vault.retrieve("does-not-exist") is None

def test_store_empty_name_raises(vault):
    """Storing with empty name should raise ValueError."""
    with pytest.raises(ValueError):
        vault.store("", "secret123", "test")

def test_store_empty_secret_raises(vault):
    """Storing with empty secret should raise ValueError."""
    with pytest.raises(ValueError):
        vault.store("test-empty", "", "test")


def test_allowed_domains_round_trip(vault):
    """allowed_domains should persist through store and reload."""
    vault.store("test-cred", "secret123", "github", allowed_domains=["github.com"])
    entry = vault.get("test-cred")
    assert entry is not None
    assert entry.allowed_domains == ["github.com"]
    # A fresh vault reading the same keychain metadata sees the domains too.
    reloaded = KeychainVault().get("test-cred")
    assert reloaded.allowed_domains == ["github.com"]


def test_store_without_domains_defaults_empty(vault):
    """Storing without domains yields an empty (deny-by-default) list."""
    vault.store("test-cred", "secret123", "test")
    assert vault.get("test-cred").allowed_domains == []


def test_reload_picks_up_external_changes(vault):
    """A second vault instance (like a long-running server) sees new
    credentials only after reload() — mirroring the CLI/server split."""
    server_view = KeychainVault()  # constructed before the store, like a running server
    vault.store("test-reload", "secret", "github", allowed_domains=["github.com"])
    assert server_view.get("test-reload") is None      # stale cache
    server_view.reload()
    assert server_view.get("test-reload") is not None   # fresh after reload


def test_set_allowed_domains(vault):
    """set_allowed_domains updates an existing credential's domains."""
    vault.store("test-cred", "secret123", "test")
    assert vault.set_allowed_domains("test-cred", ["api.example.com"]) is True
    assert vault.get("test-cred").allowed_domains == ["api.example.com"]
    assert vault.set_allowed_domains("does-not-exist", ["x.com"]) is False