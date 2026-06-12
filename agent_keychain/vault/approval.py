"""
Human-in-the-loop approval via time-limited grants.

Some credentials are sensitive enough that an agent should not be able to use
them on its own. Marking a credential ``require_approval`` blocks it by default;
a human then opens a short, explicit window with ``agent-keychain grant`` during
which the agent may use it. Outside that window every request is denied.

This is synchronous-enough HITL without the proxy having to block on an
interactive prompt: the human authorizes a bounded window out of band, and the
grant simply expires.
"""

import re
from typing import Optional

_DURATION_RE = re.compile(r"^\s*(\d+)\s*([smhd]?)\s*$", re.IGNORECASE)
_UNIT_SECONDS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(text: str) -> int:
    """Parse a duration like '30s', '5m', '2h', '1d', or a bare number of seconds."""
    m = _DURATION_RE.match(str(text))
    if not m:
        raise ValueError(f"invalid duration: {text!r} (use e.g. 30s, 5m, 2h, 1d)")
    value, unit = int(m.group(1)), m.group(2).lower()
    return value * _UNIT_SECONDS[unit]


def requires_approval(entry) -> bool:
    return bool(getattr(entry, "require_approval", False))


def grant_active(entry, now: float) -> bool:
    """True if an unexpired approval window is currently open."""
    until = getattr(entry, "grant_until", None)
    return until is not None and now <= until


def is_blocked_pending_approval(entry, now: float) -> bool:
    """True if the credential needs approval and no window is currently open."""
    return requires_approval(entry) and not grant_active(entry, now)


def grant_remaining(entry, now: float) -> float:
    """Seconds left in the current grant window (0 if none/expired)."""
    until = getattr(entry, "grant_until", None)
    if until is None:
        return 0.0
    return max(0.0, until - now)
