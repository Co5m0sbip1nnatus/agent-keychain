"""Measure the broker's isolation overhead.

Every proxied call pays for a fresh subprocess: fork + interpreter start +
imports + vault (keyring) metadata load + the re-run policy checks. This
script measures that cost WITHOUT network noise, by timing requests that the
subprocess itself rejects (domain not allowed) — the full isolation pipeline
runs, no bytes leave the machine.

For contrast it also times the in-process rejection path (the server's own
policy gauntlet, no subprocess), which is what a request costs when it never
reaches the spawn.

Run:
    python poc/measure_overhead.py
"""

import logging
import os
import statistics
import sys
import tempfile
import time

logging.disable(logging.CRITICAL)

# Route audit writes to a throwaway file before importing anything that uses it.
_FD, _AUDIT = tempfile.mkstemp(prefix="akc-perf-", suffix=".jsonl")
os.close(_FD)
os.environ["AGENT_KEYCHAIN_AUDIT_LOG"] = _AUDIT

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent_keychain.mcp_server.server import vault, secure_http_request
from agent_keychain.proxy.process_pool import run_isolated_request

CRED = "perf-probe"
FAKE = "ghp_" + "P" * 36
RUNS = 15


def timed(fn, runs=RUNS):
    samples = []
    for _ in range(runs):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000.0)
    return samples


def main():
    vault.store(CRED, FAKE, "github", allowed_domains=["github.com"])
    try:
        # Warm-up (first spawn pays filesystem cache misses).
        run_isolated_request(CRED, "https://blocked.example/x")

        # Full isolation pipeline: spawn + imports + vault load + policy
        # checks inside the subprocess. Rejected there; no network.
        iso = timed(lambda: run_isolated_request(CRED, "https://blocked.example/x"))

        # In-process rejection: the server's own gauntlet, no subprocess.
        inproc = timed(lambda: secure_http_request(CRED, "https://blocked.example/x"))

        print("\n  Isolation overhead (per brokered call, no network)")
        print("  " + "-" * 56)
        print(f"  subprocess pipeline   median {statistics.median(iso):7.1f} ms   "
              f"p90 {statistics.quantiles(iso, n=10)[8]:7.1f} ms   ({RUNS} runs)")
        print(f"  in-process gauntlet   median {statistics.median(inproc):7.3f} ms   "
              f"p90 {statistics.quantiles(inproc, n=10)[8]:7.3f} ms")
        print()
        print("  The difference is the price of the memory-isolation guarantee:")
        print("  the secret only ever exists in a process that exits. It is paid")
        print("  once per authenticated call, alongside a network round trip that")
        print("  typically costs the same order of magnitude or more.")
        print()
    finally:
        vault.delete(CRED)
        if os.path.exists(_AUDIT):
            os.remove(_AUDIT)


if __name__ == "__main__":
    main()
