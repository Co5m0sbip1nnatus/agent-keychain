"""
Least-privilege request scoping for stored credentials.

Domain binding limits *where* a credential can be sent; request scoping limits
*what* it can do once there. A credential can be restricted to specific HTTP
methods (e.g. read-only GET) and URL path globs (e.g. "/repos/*"), shrinking
the blast radius if an agent is tricked into making a request.

Empty restriction lists mean "unrestricted" for that dimension, so scoping is
an opt-in tightening that never breaks existing credentials. Pure functions so
they can be unit-tested without a keychain.
"""

from fnmatch import fnmatch
from urllib.parse import urlparse


def extract_path(url: str) -> str:
    """Return the URL path (without query), defaulting to '/'."""
    try:
        path = urlparse(url).path
    except ValueError:
        return "/"
    return path or "/"


def method_allowed(method: str, allowed_methods: list[str]) -> bool:
    """True if the method is permitted. Empty list = any method allowed."""
    if not allowed_methods:
        return True
    return method.upper() in {m.upper() for m in allowed_methods}


def path_allowed(path: str, allowed_paths: list[str]) -> bool:
    """True if the path matches an allowed glob. Empty list = any path allowed.

    Matching uses shell-style globs (fnmatch), so "/repos/*" permits
    "/repos/owner/name" and "*" permits everything.
    """
    if not allowed_paths:
        return True
    return any(fnmatch(path, pattern) for pattern in allowed_paths)
