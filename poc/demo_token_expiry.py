"""
PoC: Token Expiry — Before vs After
Shows how credentials persist indefinitely without TTL
vs auto-deleting after expiration.
"""

import time
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.vault.keychain_vault import KeychainVault

CRED_NAME = "poc-expiry-test"


def cleanup(vault):
    vault.delete(CRED_NAME)


def without_expiry():
    """Credential stays forever — stolen token remains valid."""
    print("=" * 60)
    print("  WITHOUT Token Expiry")
    print("=" * 60)

    vault = KeychainVault()
    cleanup(vault)

    vault.store(CRED_NAME, "stolen-token-abc123", "test", "No expiry demo")
    print(f"\n  Stored credential '{CRED_NAME}' with no expiry")

    print(f"  Waiting 3 seconds (simulating time passing)...")
    time.sleep(3)

    result = vault.retrieve(CRED_NAME)
    if result is not None:
        print(f"  After 3s: credential still accessible")
        print(f"\n  ⚠ If this token was stolen, it remains valid forever.")
        print(f"  ⚠ Attacker has unlimited time to use it.\n")

    cleanup(vault)


def with_expiry():
    """Credential auto-deletes after TTL — limits attack window."""
    print("=" * 60)
    print("  WITH Token Expiry (TTL=2 seconds)")
    print("=" * 60)

    vault = KeychainVault()
    cleanup(vault)

    vault.store(CRED_NAME, "short-lived-token-xyz", "test", "Expiry demo", ttl=2)
    print(f"\n  Stored credential '{CRED_NAME}' with TTL=2s")

    result = vault.retrieve(CRED_NAME)
    if result is not None:
        print(f"  Immediately: credential accessible")

    print(f"  Waiting 3 seconds...")
    time.sleep(3)

    result = vault.retrieve(CRED_NAME)
    if result is None:
        print(f"  After 3s: credential auto-deleted (expired)")
        print(f"\n  ✓ Even if token was stolen, it's no longer valid.")
        print(f"  ✓ Attack window is limited to the TTL duration.\n")

    cleanup(vault)


if __name__ == "__main__":
    without_expiry()
    print()
    with_expiry()
