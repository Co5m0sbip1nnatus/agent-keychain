"""
Audit log for credential usage.

Every attempt to use a stored credential through the proxy is recorded as a
single JSON line so that a user can later answer "which credential was sent
where, when, and was it allowed?". This makes credential misuse — for example
a prompt-injected agent probing a blocked host — visible after the fact.

What is recorded: timestamp, credential name, destination host, HTTP method,
the allow/block decision and reason, and (for completed requests) the response
status. What is NEVER recorded: the secret value, the full URL, query strings,
request bodies, or response bodies — so the audit log itself can't leak a
credential.

The log lives at ~/.agent-keychain/audit.jsonl with owner-only permissions.
The path can be overridden with the AGENT_KEYCHAIN_AUDIT_LOG env var (used by
tests and for routing to a central location).
"""

import calendar
import json
import os
import time
from collections import Counter
from typing import Optional

AUDIT_DIR = os.path.expanduser("~/.agent-keychain")
DEFAULT_AUDIT_PATH = os.path.join(AUDIT_DIR, "audit.jsonl")

# Decision constants.
ALLOWED = "allowed"
BLOCKED = "blocked"


def audit_path() -> str:
    """Return the active audit log path (env override or default)."""
    return os.environ.get("AGENT_KEYCHAIN_AUDIT_LOG", DEFAULT_AUDIT_PATH)


def record(
    credential: str,
    host: str,
    method: str,
    decision: str,
    reason: str = "",
    status: Optional[int] = None,
    success: Optional[bool] = None,
) -> dict:
    """Append one audit event and return it.

    Never raises on I/O problems — auditing must not break the request path.
    """
    event = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "credential": credential,
        "host": host,
        "method": method,
        "decision": decision,
        "reason": reason,
    }
    if status is not None:
        event["status"] = status
    if success is not None:
        event["success"] = success

    try:
        path = audit_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # Open with owner-only perms; O_APPEND keeps concurrent writers safe.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(json.dumps(event) + "\n")
    except OSError:
        # Auditing is best-effort; a logging failure must not block the request.
        pass

    return event


def read_events(
    limit: int = 20,
    credential: Optional[str] = None,
    blocked_only: bool = False,
) -> list[dict]:
    """Return the most recent audit events, newest last, after filtering."""
    path = audit_path()
    if not os.path.isfile(path):
        return []

    events: list[dict] = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if credential is not None and event.get("credential") != credential:
                continue
            if blocked_only and event.get("decision") != BLOCKED:
                continue
            events.append(event)

    return events[-limit:] if limit and limit > 0 else events


def _parse_ts(ts: str) -> Optional[float]:
    """Parse an audit event's ISO-UTC timestamp into epoch seconds."""
    try:
        return calendar.timegm(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))
    except (ValueError, TypeError):
        return None


def count_recent(credential: str, window_seconds: int, decision: str = ALLOWED, now: Optional[float] = None) -> int:
    """Count this credential's events with the given decision in the last window.

    Used by the rate limiter. Best-effort: events with unparseable timestamps
    are skipped.
    """
    if now is None:
        now = time.time()
    cutoff = now - window_seconds
    count = 0
    for event in read_events(limit=0, credential=credential):
        if event.get("decision") != decision:
            continue
        ts = _parse_ts(event.get("ts", ""))
        if ts is not None and ts >= cutoff:
            count += 1
    return count


def summarize_blocked(min_count: int = 1) -> list[dict]:
    """Group blocked events by (credential, reason) for anomaly review.

    Returns a list of {"credential", "reason", "count", "hosts"} sorted by
    count (descending), filtered to groups with at least ``min_count`` hits.
    Repeated blocks are a signal of probing or misuse.
    """
    counts: Counter = Counter()
    hosts: dict = {}
    for event in read_events(limit=0, blocked_only=True):
        key = (event.get("credential", ""), event.get("reason", ""))
        counts[key] += 1
        hosts.setdefault(key, set()).add(event.get("host", ""))

    summary = [
        {"credential": cred, "reason": reason, "count": n, "hosts": sorted(h for h in hosts[(cred, reason)] if h)}
        for (cred, reason), n in counts.items()
        if n >= min_count
    ]
    summary.sort(key=lambda r: r["count"], reverse=True)
    return summary
