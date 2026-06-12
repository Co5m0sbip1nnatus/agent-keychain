"""
Pluggable secret-storage backends.

The vault's *policy* (domain binding, scoping, DLP, audit, approval) is valuable
everywhere, but its default storage — the OS keychain via ``keyring`` — isn't
available in headless/CI environments. This module abstracts storage behind a
tiny key/value interface so the same policy engine can run on a desktop keychain
or a CI-friendly file.

Backends:
  - KeyringBackend (default): OS keychain / SecretService / Credential Manager.
  - FileBackend: a single 0600 JSON file — for headless/CI where no keychain
    exists. Less protected than a keychain (plaintext on disk), so use it where
    the host filesystem is already the trust boundary (ephemeral CI runners).

Selection: AGENT_KEYCHAIN_BACKEND=keyring|file (default keyring); the file path
comes from AGENT_KEYCHAIN_STORE (default ~/.agent-keychain/store.json).

Extension point: a HashiCorp Vault / AWS Secrets Manager / 1Password backend is
just a class with get/set/delete against that service — drop it in and select it
here. Those integrations are intentionally not bundled (extra dependencies and
credentials), but the interface is stable.
"""

import json
import os
from typing import Optional


class BackendError(Exception):
    """Raised when a backend fails to persist a secret."""


class KeyringBackend:
    """OS-native keychain storage (default). Wraps the ``keyring`` library."""

    SERVICE = "agent-keychain"

    def __init__(self):
        import keyring  # imported lazily so the file backend works without it
        self._keyring = keyring

    def get(self, key: str) -> Optional[str]:
        return self._keyring.get_password(self.SERVICE, key)

    def set(self, key: str, value: str) -> None:
        import keyring.errors
        try:
            self._keyring.set_password(self.SERVICE, key, value)
        except keyring.errors.PasswordSetError as exc:
            raise BackendError(str(exc)) from exc

    def delete(self, key: str) -> None:
        import keyring.errors
        try:
            self._keyring.delete_password(self.SERVICE, key)
        except keyring.errors.PasswordDeleteError:
            pass  # already absent


class FileBackend:
    """Single-file JSON storage for headless/CI use. The file is mode 0600."""

    def __init__(self, path: str):
        self.path = os.path.abspath(os.path.expanduser(path))

    def _load(self) -> dict:
        if not os.path.isfile(self.path):
            return {}
        try:
            with open(self.path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}

    def _save(self, data: dict) -> None:
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)

    def get(self, key: str) -> Optional[str]:
        return self._load().get(key)

    def set(self, key: str, value: str) -> None:
        try:
            data = self._load()
            data[key] = value
            self._save(data)
        except OSError as exc:
            raise BackendError(str(exc)) from exc

    def delete(self, key: str) -> None:
        data = self._load()
        if key in data:
            del data[key]
            self._save(data)


def default_store_path() -> str:
    return os.environ.get(
        "AGENT_KEYCHAIN_STORE",
        os.path.expanduser("~/.agent-keychain/store.json"),
    )


def get_backend():
    """Return the backend selected by AGENT_KEYCHAIN_BACKEND (default keyring)."""
    kind = os.environ.get("AGENT_KEYCHAIN_BACKEND", "keyring").lower()
    if kind == "file":
        return FileBackend(default_store_path())
    return KeyringBackend()
