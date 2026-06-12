"""Tests for credential rotation tracking and policy."""
import pytest
from agent_keychain.vault.keychain_vault import KeychainVault, CredentialEntry
from agent_keychain.vault import rotation

DAY = rotation.SECONDS_PER_DAY


def _entry(created_at=0.0, last_rotated_at=None, rotate_after_days=None):
    return CredentialEntry(
        name="c",
        service_type="github",
        created_at=created_at,
        last_rotated_at=last_rotated_at,
        rotate_after_days=rotate_after_days,
    )


def test_days_since_rotation_uses_last_rotated():
    e = _entry(created_at=0.0, last_rotated_at=10 * DAY)
    assert rotation.days_since_rotation(e, now=15 * DAY) == 5


def test_days_since_rotation_falls_back_to_created():
    e = _entry(created_at=3 * DAY, last_rotated_at=None)
    assert rotation.days_since_rotation(e, now=8 * DAY) == 5


def test_rotation_not_due_without_policy():
    e = _entry(created_at=0.0, last_rotated_at=0.0, rotate_after_days=None)
    assert rotation.is_rotation_due(e, now=999 * DAY) is False


def test_rotation_due_when_overdue():
    e = _entry(created_at=0.0, last_rotated_at=0.0, rotate_after_days=30)
    assert rotation.is_rotation_due(e, now=31 * DAY) is True
    assert rotation.is_rotation_due(e, now=29 * DAY) is False


@pytest.fixture
def vault():
    v = KeychainVault()
    yield v
    v.delete("test-rot")


def test_store_sets_rotation_fields(vault):
    vault.store("test-rot", "s1", "github", allowed_domains=["github.com"], rotate_after_days=30)
    e = vault.get("test-rot")
    assert e.rotate_after_days == 30
    assert e.rotation_count == 0
    assert e.last_rotated_at is not None


def test_rotate_replaces_secret_and_tracks(vault):
    vault.store("test-rot", "s1", "github", allowed_domains=["github.com"])
    first_rotated = vault.get("test-rot").last_rotated_at
    assert vault.rotate("test-rot", "s2") is True
    e = vault.get("test-rot")
    assert e.rotation_count == 1
    assert e.last_rotated_at >= first_rotated
    with vault.retrieve("test-rot") as secret:
        assert secret.value == "s2"
    # Metadata (domains) is preserved across rotation.
    assert KeychainVault().get("test-rot").allowed_domains == ["github.com"]


def test_rotate_missing_returns_false(vault):
    assert vault.rotate("does-not-exist", "x") is False


def test_rotate_empty_secret_raises(vault):
    vault.store("test-rot", "s1", "github", allowed_domains=["github.com"])
    with pytest.raises(ValueError):
        vault.rotate("test-rot", "")
