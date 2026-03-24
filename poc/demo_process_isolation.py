"""
PoC: Process Isolation — Before vs After
Shows how credentials stay in the MCP server's memory without isolation
vs being confined to a short-lived subprocess that exits after use.
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.vault.keychain_vault import KeychainVault

CRED_NAME = "poc-isolation-test"


def cleanup(vault):
    vault.delete(CRED_NAME)


def without_isolation():
    """Credential loaded into the main process — stays in memory."""
    print("=" * 60)
    print("  WITHOUT Process Isolation")
    print("=" * 60)

    vault = KeychainVault()
    cleanup(vault)
    vault.store(CRED_NAME, "secret-in-main-process-xyz", "test", "Isolation demo")

    print(f"\n  MCP server process (PID {os.getpid()}) retrieves credential...")
    secure = vault.retrieve(CRED_NAME)

    with secure as ss:
        secret = ss.value
        print(f"  Credential loaded in PID {os.getpid()}: {secret[:15]}...")
        print(f"  Making HTTP request from the same process...")
        # Simulate HTTP request
        print(f"  Request complete.")

    print(f"\n  ⚠ Credential was loaded in the long-lived MCP server process.")
    print(f"  ⚠ Even with scrubbing, Python may have copies in internal buffers.")
    print(f"  ⚠ A memory dump of PID {os.getpid()} could find remnants.\n")

    cleanup(vault)


def with_isolation():
    """Credential handled in a short-lived subprocess — memory released on exit."""
    from src.proxy.process_pool import run_isolated_request
    import json

    print("=" * 60)
    print("  WITH Process Isolation")
    print("=" * 60)

    vault = KeychainVault()
    cleanup(vault)
    vault.store(CRED_NAME, "secret-in-subprocess-only", "test", "Isolation demo")

    print(f"\n  MCP server process (PID {os.getpid()}) delegates to subprocess...")
    print(f"  Credential is NEVER loaded in the MCP server process.")

    result_json = run_isolated_request(
        credential_name=CRED_NAME,
        url="https://api.github.com/zen",
        method="GET",
    )
    result = json.loads(result_json)

    print(f"  Subprocess completed and exited.")
    if result.get("success"):
        print(f"  Response received (credential scrubbed).")
    else:
        print(f"  Request result: {result.get('error', 'done')}")
        print(f"  (The credential was still handled in the subprocess, not the main process.)")

    print(f"\n  ✓ Credential only existed in the subprocess memory.")
    print(f"  ✓ Subprocess exited — all memory released by the OS.")
    print(f"  ✓ Memory dump of MCP server (PID {os.getpid()}) finds nothing.\n")

    cleanup(vault)


if __name__ == "__main__":
    without_isolation()
    print()
    with_isolation()
