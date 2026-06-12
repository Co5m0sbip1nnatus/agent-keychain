"""
Best-effort OS sandbox for the `exec` wrapper (macOS).

`exec` injects a secret into a command the agent chose. With `--sandbox`, that
command runs under `sandbox-exec` with reads of known credential files denied,
so even a coerced command can't pull *other* secrets off disk to exfiltrate
alongside the one it was given.

Honest scope:
  - macOS only (uses the deprecated-but-present `sandbox-exec`). On other
    platforms `--sandbox` fails closed rather than running unprotected.
  - It denies a fixed list of sensitive paths; it is not a general containment
    boundary and does not restrict network egress. Pair with the command
    allowlist and, for hard isolation, a real container/VM.

Deny paths must be realpath-resolved — macOS aliases like /tmp -> /private/tmp
mean an unresolved literal silently fails to match.
"""

import os
import shutil
import sys

# (kind, path) — "literal" for files, "subpath" for directory trees.
DEFAULT_DENY = [
    ("literal", "~/.aws/credentials"),
    ("subpath", "~/.ssh"),
    ("literal", "~/.npmrc"),
    ("literal", "~/.git-credentials"),
    ("literal", "~/.docker/config.json"),
    ("subpath", "~/.config/gh"),
    ("literal", "~/.kube/config"),
]


def is_available() -> bool:
    """True if OS sandboxing is usable on this platform."""
    return sys.platform == "darwin" and shutil.which("sandbox-exec") is not None


def _resolve(path: str) -> str:
    return os.path.realpath(os.path.expanduser(path))


def default_deny_specs() -> list[tuple[str, str]]:
    """The default deny list plus a .env in the current directory."""
    specs = list(DEFAULT_DENY)
    specs.append(("literal", os.path.join(os.getcwd(), ".env")))
    return specs


def build_profile(deny_specs: list[tuple[str, str]]) -> str:
    """Build an SBPL profile that allows everything except reads of deny paths."""
    lines = ["(version 1)", "(allow default)"]
    rules = []
    for kind, path in deny_specs:
        resolved = _resolve(path).replace("\\", "\\\\").replace('"', '\\"')
        rules.append(f'({kind} "{resolved}")')
    if rules:
        lines.append("(deny file-read* " + " ".join(rules) + ")")
    return "\n".join(lines)


def wrap_argv(argv: list[str], deny_specs: list[tuple[str, str]] | None = None) -> list[str]:
    """Return argv wrapped to run under sandbox-exec with the deny profile."""
    profile = build_profile(deny_specs if deny_specs is not None else default_deny_specs())
    return ["sandbox-exec", "-p", profile, *argv]
