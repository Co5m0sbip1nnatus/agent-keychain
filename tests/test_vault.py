"""Tests for KeychainVault credential operations."""
import pytest
from src.vault.keychain_vault import KeychainVault

@pytest.fixture
def vault():
    """Create a vault instance and clean up test credentials after each test."""
    v = KeychainVault()
    yield v
    # Cleanup: delete test credentials
    for name in ["test-cred", "test-empty"]:
        v.delete(name)
    
def test_store_and_retrieve(vault):
    """Stored credential should be retrievable."""
    vault.store("test-cred", "secret123", "test", "Test credential")
    assert vault.retrieve("test-cred") == "secret123"

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