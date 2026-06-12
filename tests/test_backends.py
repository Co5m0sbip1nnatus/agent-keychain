"""Tests for pluggable secret backends and the file backend (headless/CI)."""
import os
import pytest
from agent_keychain.vault.backends import FileBackend, KeyringBackend, get_backend
from agent_keychain.vault.keychain_vault import KeychainVault


def test_file_backend_round_trip(tmp_path):
    b = FileBackend(str(tmp_path / "store.json"))
    assert b.get("k") is None
    b.set("k", "v")
    assert b.get("k") == "v"
    b.delete("k")
    assert b.get("k") is None


def test_file_backend_is_owner_only(tmp_path):
    path = tmp_path / "store.json"
    b = FileBackend(str(path))
    b.set("k", "v")
    assert (os.stat(path).st_mode & 0o777) == 0o600


def test_get_backend_selection(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_KEYCHAIN_BACKEND", "file")
    monkeypatch.setenv("AGENT_KEYCHAIN_STORE", str(tmp_path / "s.json"))
    assert isinstance(get_backend(), FileBackend)
    monkeypatch.setenv("AGENT_KEYCHAIN_BACKEND", "keyring")
    assert isinstance(get_backend(), KeyringBackend)


def test_vault_on_file_backend_full_flow(tmp_path):
    """The whole vault (secret + policy metadata) works headless on a file."""
    store = str(tmp_path / "store.json")
    v = KeychainVault(backend=FileBackend(store))
    v.store("ci-cred", "s3cr3t", "github", allowed_domains=["github.com"],
            allowed_methods=["GET"], rate_limit_per_min=10)

    with v.retrieve("ci-cred") as secret:
        assert secret.value == "s3cr3t"

    # A fresh vault on the same file recovers the credential and its policy.
    v2 = KeychainVault(backend=FileBackend(store))
    entry = v2.get("ci-cred")
    assert entry is not None
    assert entry.allowed_domains == ["github.com"]
    assert entry.allowed_methods == ["GET"]
    assert entry.rate_limit_per_min == 10

    assert v2.delete("ci-cred") is True
    assert KeychainVault(backend=FileBackend(store)).get("ci-cred") is None
