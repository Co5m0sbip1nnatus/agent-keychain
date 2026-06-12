"""
Discovery scanner for credentials living *outside* the vault.

Agent Keychain only protects secrets you actually put in it. Most leaks start
with credentials that are already sitting in environment variables and dotfiles
where any agent with shell access can read them. This scanner finds those so a
user can move them into the vault.

It reports only *where* a secret is and *what kind* it looks like — never the
secret value itself — so running it (or sharing its output) cannot leak
anything.
"""

import os

from agent_keychain.guard.credential_guard import scan as scan_content

# Environment variables whose name strongly suggests a secret value.
_SECRET_NAME_HINTS = ("TOKEN", "SECRET", "PASSWORD", "PASSWD", "API_KEY", "APIKEY", "ACCESS_KEY", "PRIVATE_KEY")

# Common credential file locations (relative to home unless absolute).
_COMMON_FILES = [
    "~/.aws/credentials",
    "~/.aws/config",
    "~/.npmrc",
    "~/.git-credentials",
    "~/.docker/config.json",
    "~/.kube/config",
    "~/.config/gh/hosts.yml",
    "~/.env",
]


def _name_looks_secret(name: str) -> bool:
    upper = name.upper()
    return any(hint in upper for hint in _SECRET_NAME_HINTS)


def scan_environment(extra_files: list[str] | None = None, include_cwd_env: bool = True) -> list[dict]:
    """Scan env vars and common credential files for secrets outside the vault.

    Returns a list of {"source", "type", "count"} findings. Secret values are
    never included.
    """
    findings: list[dict] = []

    # --- Environment variables ---
    for name, value in os.environ.items():
        if not value:
            continue
        matched = scan_content(value)
        if matched:
            for f in matched:
                findings.append({"source": f"env:{name}", "type": f["type"], "count": f["count"]})
        elif _name_looks_secret(name):
            findings.append({"source": f"env:{name}", "type": "Possible secret (by variable name)", "count": 1})

    # --- Files ---
    paths = list(_COMMON_FILES)
    if include_cwd_env:
        paths.append(os.path.join(os.getcwd(), ".env"))
    if extra_files:
        paths.extend(extra_files)

    seen = set()
    for raw_path in paths:
        path = os.path.abspath(os.path.expanduser(raw_path))
        if path in seen or not os.path.isfile(path):
            continue
        seen.add(path)
        try:
            with open(path, "r", errors="replace") as fh:
                content = fh.read()
        except OSError:
            continue
        for f in scan_content(content):
            findings.append({"source": path, "type": f["type"], "count": f["count"]})

    return findings
