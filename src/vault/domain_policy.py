"""
Domain binding policy for stored credentials.

Each credential is bound to a set of allowed domains so that a credential can
only ever be used against the endpoints it belongs to. This prevents a
compromised or prompt-injected agent from exfiltrating a token by pointing
``secure_http_request`` at an attacker-controlled host -- the token is never
sent anywhere outside its allowed domains.

Domains are matched by suffix, so a single entry like ``github.com`` covers
``api.github.com``, ``uploads.github.com``, etc. The special value ``"*"``
marks a credential as unrestricted (an explicit, loud opt-out).
"""

from urllib.parse import urlparse

# Default allowed domains inferred from a credential's service type.
# Values are treated as domain suffixes (subdomains are covered automatically).
SERVICE_DOMAIN_MAP: dict[str, list[str]] = {
    "github": ["github.com", "githubusercontent.com"],
    "gitlab": ["gitlab.com"],
    "aws": ["amazonaws.com"],
    "stripe": ["api.stripe.com"],
    "openai": ["api.openai.com"],
    "anthropic": ["api.anthropic.com"],
    "slack": ["slack.com"],
    "npm": ["registry.npmjs.org"],
    "sendgrid": ["api.sendgrid.com"],
}

# Marker for an explicitly unrestricted credential.
WILDCARD = "*"


def infer_domains(service_type: str) -> list[str]:
    """Return the default allowed domains for a service type, or [] if unknown."""
    if not service_type:
        return []
    return list(SERVICE_DOMAIN_MAP.get(service_type.lower(), []))


def _host_matches(host: str, domain: str) -> bool:
    """True if ``host`` equals ``domain`` or is a subdomain of it.

    Supports an optional leading ``*.`` on ``domain`` (e.g. ``*.github.com``),
    which is treated the same as the bare suffix ``github.com``.
    """
    domain = domain.lower().strip()
    if domain.startswith("*."):
        domain = domain[2:]
    if not domain:
        return False
    host = host.lower().strip()
    return host == domain or host.endswith("." + domain)


def host_allowed(host: str, allowed_domains: list[str]) -> bool:
    """Return True if ``host`` is permitted by ``allowed_domains``.

    - An empty ``allowed_domains`` denies everything (deny-by-default).
    - ``"*"`` anywhere in the list permits any host (explicit opt-out).
    - Otherwise the host must match at least one domain by suffix.
    """
    if not host:
        return False
    if not allowed_domains:
        return False
    if WILDCARD in allowed_domains:
        return True
    return any(_host_matches(host, d) for d in allowed_domains)


def extract_host(url: str) -> str:
    """Return the lowercase hostname from a URL, or "" if it cannot be parsed."""
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""
