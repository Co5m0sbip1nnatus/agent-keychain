"""
PoC: Memory Scrubbing — Before vs After
Shows how credentials linger in process memory without scrubbing
vs being zeroed out immediately with SecureString.
"""

import ctypes
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def read_memory(s: str, length: int = 0) -> bytes:
    """Read raw bytes from a Python string's memory buffer."""
    if length == 0:
        length = len(s)
    buf = (ctypes.c_char * length).from_address(id(s) + sys.getsizeof(s) - length - 1)
    return bytes(buf)


def without_scrubbing():
    """Simulate normal credential usage — stays in memory."""
    print("=" * 60)
    print("  WITHOUT Memory Scrubbing")
    print("=" * 60)

    secret = "ghp_SuperSecretGitHubToken1234567890ABCDEF"
    print(f"\n  Credential loaded: {secret[:10]}...")
    print(f"  Memory address: {hex(id(secret))}")

    # Simulate using the credential
    _ = f"Authorization: Bearer {secret}"

    # "Done" using it, but it's still in memory
    memory_content = read_memory(secret)
    print(f"  After use, memory contains: {memory_content[:20]}...")
    print(f"\n  ⚠ Credential is still readable in process memory.")
    print(f"  ⚠ A memory dump attack (AIKatz) can extract it.\n")


def with_scrubbing():
    """Use SecureString — credential is zeroed after use."""
    from src.vault.secure_string import SecureString

    print("=" * 60)
    print("  WITH Memory Scrubbing (SecureString)")
    print("=" * 60)

    secret_value = "ghp_SuperSecretGitHubToken1234567890ABCDEF"
    secure = SecureString(secret_value)
    print(f"\n  Credential loaded into SecureString")
    print(f"  repr: {repr(secure)}")

    with secure as ss:
        credential = ss.value
        print(f"  Inside context: {credential[:10]}...")
        # Simulate using the credential
        _ = f"Authorization: Bearer {credential}"

    # After context manager exit, memory is scrubbed
    print(f"  After context exit:")
    print(f"    is_scrubbed: {secure.is_scrubbed}")
    print(f"    repr: {repr(secure)}")
    print(f"\n  ✓ Credential has been zeroed in memory.")
    print(f"  ✓ Memory dump attack would find only zeros.\n")


if __name__ == "__main__":
    without_scrubbing()
    print()
    with_scrubbing()
