"""
Onboarding helpers: move secrets that live in files into the vault.

`scan` only *reports* secrets sitting in dotfiles; this module actually imports
them and (optionally) scrubs the original, so the proxy's protections become
real instead of advisory. It handles `KEY=value` / `KEY: value` style files
(dotenv, ~/.aws/credentials, ~/.npmrc, …) — the common case — parsing only the
lines whose value looks like a secret or whose key is named like one.
"""

import os
import re
import shutil

from agent_keychain.guard.credential_guard import scan
from agent_keychain.guard.env_scanner import _name_looks_secret

_LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*[=:]\s*(.+?)\s*$")
_SCRUB_MARKER = "<scrubbed-by-agent-keychain>"

# Map a key name to a likely service type, for domain inference at import time.
_SERVICE_HINTS = {
    "github": "github", "gh": "github", "gitlab": "gitlab",
    "aws": "aws", "stripe": "stripe", "openai": "openai",
    "anthropic": "anthropic", "slack": "slack", "npm": "npm", "sendgrid": "sendgrid",
}


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
        return value[1:-1]
    return value


def _guess_service(key: str) -> str:
    lower = key.lower()
    for hint, service in _SERVICE_HINTS.items():
        if hint in lower:
            return service
    return ""


def parse_secret_lines(content: str) -> list[dict]:
    """Return [{key, value, service}] for KEY=value lines that hold a secret."""
    found = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";", "[")):
            continue
        m = _LINE_RE.match(line)
        if not m:
            continue
        key, raw_value = m.group(1), _strip_quotes(m.group(2))
        if not raw_value:
            continue
        is_secret = bool(scan(raw_value)) or _name_looks_secret(key)
        if is_secret:
            found.append({"key": key, "value": raw_value, "service": _guess_service(key)})
    return found


def scrub_file(path: str, values: list[str]) -> str:
    """Replace each secret value in the file with a marker, keeping a .bak.

    Returns the backup path. Only exact value occurrences are replaced, so
    non-secret content is untouched.
    """
    backup = path + ".bak"
    shutil.copy2(path, backup)
    with open(path, "r", errors="replace") as f:
        content = f.read()
    for value in values:
        if value:
            content = content.replace(value, _SCRUB_MARKER)
    with open(path, "w") as f:
        f.write(content)
    return backup
