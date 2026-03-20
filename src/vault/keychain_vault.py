"""
Agent Keychain Vault
Credential storage backed by the OS-native keychain (macOS Keychain / Linux SecretService).
"""

import keyring
import json
import time
from dataclasses import dataclass
from typing import Optional

import keyring.errors

VALID_AUTH_TYPES = {"bearer", "basic", "api-key"}

@dataclass
class CredentialEntry:
    """Represents metadata for a stored credential. Secret values are never held here."""
    name: str
    service_type: str
    created_at: float
    description: str = ""
    auth_type: str = "bearer"  # bearer, basic, api-key

class KeychainVault:
    """
    OS-native keychain-backed credential store.

    Secret values are encrypted at rest by the OS keychain.
    Only non-sensitive metadata (name, type, timestamp) is kept in memory.
    """

    SERVICE_NAME = "agent-keychain"
    METADATA_KEY = "_metadata"

    def __init__(self):
        self._metadata: dict[str, CredentialEntry] = {}
        self._load_metadata()
    
    def _save_metadata(self):
        """Serialize credential metadata to the keychain."""
        data = {}
        for name, entry in self._metadata.items():
            data[name] = {
                "service_type": entry.service_type,
                "created_at": entry.created_at,
                "description": entry.description,
                "auth_type": entry.auth_type,
            }
        keyring.set_password(
            self.SERVICE_NAME,
            self.METADATA_KEY,
            json.dumps(data)
        )
    
    def _load_metadata(self):
        """Load credential metadata from the keychain."""
        raw = keyring.get_password(self.SERVICE_NAME, self.METADATA_KEY)
        if raw is None:
            return
        try:
            data = json.loads(raw)
            for name, info in data.items():
                self._metadata[name] = CredentialEntry(
                    name=name,
                    service_type=info["service_type"],
                    created_at=info["created_at"],
                    description=info.get("description", ""),
                    auth_type=info.get("auth_type", "bearer"),
                )
        except (json.JSONDecodeError, KeyError):
            pass
    
    def store(self, name: str, secret: str, service_type: str, description: str = "", auth_type: str = "bearer") -> None:
        """Store a credential. The secret is encrypted by the OS keychain."""
        if not name or not secret:
            raise ValueError("Credential name and secret must not be empty")
        if auth_type not in VALID_AUTH_TYPES:
            raise ValueError(f"auth_type must be one of {', '.join(sorted(VALID_AUTH_TYPES))}")

        try:
            keyring.set_password(self.SERVICE_NAME, name, secret)
        except keyring.errors.PasswordSetError as e:
            raise RuntimeError(f"Failed to store credential '{name}' in keychain") from e

        self._metadata[name] = CredentialEntry(
            name=name,
            service_type=service_type,
            created_at=time.time(),
            description=description,
            auth_type=auth_type,
        )
        self._save_metadata()

    def retrieve(self, name: str) -> Optional[str]:
        """Retrieve a secret value from the keychain. Returns None if not found."""
        if name not in self._metadata:
            return None
        return keyring.get_password(self.SERVICE_NAME, name)
    
    def delete(self, name: str) -> bool:
        """Remove a credential from the keychain. Returns True if deleted."""
        if name not in self._metadata:
            return False
        try:
            keyring.delete_password(self.SERVICE_NAME, name)
        except keyring.errors.PasswordDeleteError:
            pass
        del self._metadata[name]
        self._save_metadata()
        return True
    
    def list_credentials(self) -> list[CredentialEntry]:
        """Return metadata for all stored credentials. No secrets are included."""
        return list(self._metadata.values())
    
    def has(self, name: str) -> bool:
        """Check whether a credential exists."""
        return name in self._metadata