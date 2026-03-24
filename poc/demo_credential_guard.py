"""
PoC: Credential Guard — Before vs After
Shows how file contents are exposed without guard vs redacted with guard.
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DEMO_FILE = os.path.join(os.path.dirname(__file__), "fake_credentials", ".env")

def without_guard():
    """Simulate a normal file read — credentials fully exposed."""
    print("=" * 60)
    print("  WITHOUT Credential Guard")
    print("=" * 60)
    with open(DEMO_FILE) as f:
        content = f.read()
    print(f"\n  Agent reads {DEMO_FILE}:\n")
    for line in content.strip().split("\n"):
        print(f"    {line}")
    print(f"\n  ⚠ All credentials are visible to the AI agent.")
    print(f"  ⚠ These values are now in the LLM context window.\n")


def with_guard():
    """Read through Credential Guard — credentials automatically redacted."""
    from src.guard.credential_guard import redact

    print("=" * 60)
    print("  WITH Credential Guard")
    print("=" * 60)
    with open(DEMO_FILE) as f:
        content = f.read()

    redacted, findings = redact(content)

    print(f"\n  Agent reads {DEMO_FILE} via safe_read_file:\n")
    for line in redacted.strip().split("\n"):
        print(f"    {line}")

    print(f"\n  Detected and redacted:")
    for f in findings:
        print(f"    - {f['type']}: {f['count']} occurrence(s)")
    print(f"\n  ✓ Credentials are hidden from the AI agent.\n")


if __name__ == "__main__":
    without_guard()
    print()
    with_guard()
