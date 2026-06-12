"""
Agent Keychain Vault
Credential storage backed by the OS-native keychain (macOS Keychain / Linux SecretService).
"""

import keyring
import json
import time
from dataclasses import dataclass, field
from typing import Optional

import keyring.errors
from agent_keychain.logging.logger import get_logger
from agent_keychain.vault.secure_string import SecureString

log = get_logger("vault")

VALID_AUTH_TYPES = {"bearer", "basic", "api-key"}

@dataclass
class CredentialEntry:
    """Represents metadata for a stored credential. Secret values are never held here."""
    name: str
    service_type: str
    created_at: float
    description: str = ""
    auth_type: str = "bearer"  # bearer, basic, api-key
    expires_at: Optional[float] = None  # Unix timestamp; None means no expiry
    # Domains this credential may be used against (suffix match). Empty means
    # the credential is blocked from all outbound requests (deny-by-default).
    # The special value ["*"] marks the credential as explicitly unrestricted.
    allowed_domains: list[str] = field(default_factory=list)
    # Rotation tracking. last_rotated_at defaults to created_at on first store.
    # rotate_after_days is an optional policy used to flag overdue credentials.
    last_rotated_at: Optional[float] = None
    rotate_after_days: Optional[int] = None
    rotation_count: int = 0
    # Least-privilege request scope. Empty lists mean "unrestricted" for that
    # dimension. allowed_methods is a set of HTTP verbs; allowed_paths is a list
    # of URL path globs (e.g. "/repos/*"). Enforced at request time.
    allowed_methods: list[str] = field(default_factory=list)
    allowed_paths: list[str] = field(default_factory=list)

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
                "expires_at": entry.expires_at,
                "allowed_domains": entry.allowed_domains,
                "last_rotated_at": entry.last_rotated_at,
                "rotate_after_days": entry.rotate_after_days,
                "rotation_count": entry.rotation_count,
                "allowed_methods": entry.allowed_methods,
                "allowed_paths": entry.allowed_paths,
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
                    expires_at=info.get("expires_at"),
                    allowed_domains=info.get("allowed_domains", []),
                    last_rotated_at=info.get("last_rotated_at"),
                    rotate_after_days=info.get("rotate_after_days"),
                    rotation_count=info.get("rotation_count", 0),
                    allowed_methods=info.get("allowed_methods", []),
                    allowed_paths=info.get("allowed_paths", []),
                )
        except (json.JSONDecodeError, KeyError):
            pass
    
    def store(self, name: str, secret: str, service_type: str, description: str = "", auth_type: str = "bearer", ttl: Optional[int] = None, allowed_domains: Optional[list[str]] = None, rotate_after_days: Optional[int] = None, allowed_methods: Optional[list[str]] = None, allowed_paths: Optional[list[str]] = None) -> None:
        """Store a credential. The secret is encrypted by the OS keychain.

        Args:
            ttl: Optional time-to-live in seconds. If provided, the credential
                 will automatically expire after this duration.
            allowed_domains: Optional list of domains the credential may be used
                 against (suffix match). Empty/None means the credential is
                 blocked from outbound requests until domains are set; the
                 special value ["*"] marks it as explicitly unrestricted.
                 Enforcement happens at request time, not here.
            rotate_after_days: Optional rotation policy. If set, the credential
                 is flagged as overdue once this many days pass since it was
                 last rotated (or created).
        """
        if not name or not secret:
            raise ValueError("Credential name and secret must not be empty")
        if auth_type not in VALID_AUTH_TYPES:
            raise ValueError(f"auth_type must be one of {', '.join(sorted(VALID_AUTH_TYPES))}")

        now = time.time()
        expires_at = now + ttl if ttl is not None else None

        try:
            keyring.set_password(self.SERVICE_NAME, name, secret)
        except keyring.errors.PasswordSetError as e:
            log.error("Failed to store credential '%s' in keychain", name)
            raise RuntimeError(f"Failed to store credential '{name}' in keychain") from e

        if expires_at is not None:
            log.info("Stored credential '%s' (type: %s, auth: %s, expires in %ds)", name, service_type, auth_type, ttl)
        else:
            log.info("Stored credential '%s' (type: %s, auth: %s, no expiry)", name, service_type, auth_type)

        self._metadata[name] = CredentialEntry(
            name=name,
            service_type=service_type,
            created_at=now,
            description=description,
            auth_type=auth_type,
            expires_at=expires_at,
            allowed_domains=list(allowed_domains) if allowed_domains else [],
            last_rotated_at=now,
            rotate_after_days=rotate_after_days,
            rotation_count=0,
            allowed_methods=[m.upper() for m in allowed_methods] if allowed_methods else [],
            allowed_paths=list(allowed_paths) if allowed_paths else [],
        )
        self._save_metadata()

    def rotate(self, name: str, new_secret: str) -> bool:
        """Replace the secret for an existing credential, keeping its metadata.

        Updates the keychain entry and records the rotation (last_rotated_at,
        rotation_count). Returns False if the credential does not exist.
        Raises ValueError on an empty secret.
        """
        if not new_secret:
            raise ValueError("New secret must not be empty")
        entry = self._metadata.get(name)
        if entry is None:
            return False

        try:
            keyring.set_password(self.SERVICE_NAME, name, new_secret)
        except keyring.errors.PasswordSetError as e:
            log.error("Failed to rotate credential '%s' in keychain", name)
            raise RuntimeError(f"Failed to rotate credential '{name}' in keychain") from e

        entry.last_rotated_at = time.time()
        entry.rotation_count += 1
        self._save_metadata()
        log.info("Rotated credential '%s' (rotation #%d)", name, entry.rotation_count)
        return True

    def retrieve(self, name: str) -> Optional[SecureString]:
        """Retrieve a secret value from the keychain wrapped in a SecureString.

        Returns None if the credential is not found or has expired.
        The returned SecureString should be used as a context manager
        so the secret is automatically scrubbed from memory after use::

            with vault.retrieve("my-cred") as secret:
                do_something(secret.value)
            # secret is now zeroed in memory
        """
        if name not in self._metadata:
            return None

        entry = self._metadata[name]
        if entry.expires_at is not None and time.time() > entry.expires_at:
            log.warning("Credential '%s' has expired — auto-deleting", name)
            self.delete(name)
            return None

        raw = keyring.get_password(self.SERVICE_NAME, name)
        if raw is None:
            return None
        return SecureString(raw)
    
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
        log.info("Deleted credential '%s'", name)
        return True
    
    def list_credentials(self) -> list[CredentialEntry]:
        """Return metadata for all stored credentials. No secrets are included."""
        return list(self._metadata.values())

    def get(self, name: str) -> Optional[CredentialEntry]:
        """Return the metadata entry for a credential, or None if not found."""
        return self._metadata.get(name)

    def set_allowed_domains(self, name: str, allowed_domains: list[str]) -> bool:
        """Replace the allowed-domain list for an existing credential.

        Returns True if the credential exists and was updated. The secret
        itself is untouched -- only metadata is rewritten.
        """
        entry = self._metadata.get(name)
        if entry is None:
            return False
        entry.allowed_domains = list(allowed_domains)
        self._save_metadata()
        log.info("Updated allowed domains for '%s': %s", name, ", ".join(allowed_domains) or "(none)")
        return True

    def set_scope(self, name: str, allowed_methods: Optional[list[str]] = None, allowed_paths: Optional[list[str]] = None) -> bool:
        """Set the request scope (methods/paths) for an existing credential.

        Only the dimensions passed (non-None) are replaced. Returns False if
        the credential does not exist.
        """
        entry = self._metadata.get(name)
        if entry is None:
            return False
        if allowed_methods is not None:
            entry.allowed_methods = [m.upper() for m in allowed_methods]
        if allowed_paths is not None:
            entry.allowed_paths = list(allowed_paths)
        self._save_metadata()
        log.info("Updated request scope for '%s' (methods: %s, paths: %s)", name,
                 ", ".join(entry.allowed_methods) or "any", ", ".join(entry.allowed_paths) or "any")
        return True

    def has(self, name: str) -> bool:
        """Check whether a credential exists."""
        return name in self._metadata