"""
Command allowlist policy for the `exec` wrapper.

`exec` injects a secret into a subprocess the agent chose, which is inherently
more powerful than the HTTP proxy (the agent controls the command). To keep it
least-privilege, a credential can only be injected into commands on its
allowlist — and the list is empty by default, so a credential cannot be used
with `exec` at all until explicitly permitted.
"""

import os
from fnmatch import fnmatch


def command_allowed(program: str, allowed_commands: list[str]) -> bool:
    """True if the program (a path or bare name) is on the allowlist.

    Matching is on the basename with shell globs, so "aws" permits
    "/usr/local/bin/aws". An empty allowlist permits nothing (deny-by-default).
    """
    if not allowed_commands:
        return False
    base = os.path.basename(program)
    return any(fnmatch(base, pattern) or fnmatch(program, pattern) for pattern in allowed_commands)
