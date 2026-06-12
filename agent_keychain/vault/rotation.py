"""
Credential rotation policy helpers.

Long-lived secrets are a liability: the longer a token stays valid, the longer
a leaked copy is useful to an attacker. Rotation tracking lets a user replace a
secret periodically and surfaces credentials that are overdue for rotation.

These are pure functions so they can be unit-tested without a keychain. The
"age" of a credential is measured from ``last_rotated_at`` (which falls back to
``created_at`` for credentials stored before rotation tracking existed).
"""

from typing import Optional

SECONDS_PER_DAY = 86400


def _reference_time(entry) -> Optional[float]:
    """The timestamp rotation age is measured from."""
    return entry.last_rotated_at if entry.last_rotated_at is not None else entry.created_at


def days_since_rotation(entry, now: float) -> Optional[float]:
    """Days since the credential was last rotated (or created). None if unknown."""
    ref = _reference_time(entry)
    if ref is None:
        return None
    return max(0.0, (now - ref) / SECONDS_PER_DAY)


def is_rotation_due(entry, now: float) -> bool:
    """True if a rotation policy is set and the credential is past due."""
    if not entry.rotate_after_days:
        return False
    age = days_since_rotation(entry, now)
    if age is None:
        return False
    return age >= entry.rotate_after_days
