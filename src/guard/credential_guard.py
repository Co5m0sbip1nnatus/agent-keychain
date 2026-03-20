"""
Credential Guard
Scans file contents and redacts detected credentials before they reach the AI agent.
"""

import re

# Regex patterns for known credential formats
CREDENTIAL_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Key", re.compile(r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*[A-Za-z0-9/+=]{40}")),
    ("GitHub Token (classic)", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("GitHub Token (fine-grained)", re.compile(r"github_pat_[A-Za-z0-9_]{82}")),
    ("GitLab Token", re.compile(r"glpat-[A-Za-z0-9\-]{20}")),
    ("NPM Token", re.compile(r"npm_[A-Za-z0-9]{36}")),
    ("OpenAI API Key", re.compile(r"sk-[A-Za-z0-9]{48}")),
    ("Anthropic API Key", re.compile(r"sk-ant-[A-Za-z0-9\-]{36,}")),
    ("Stripe Secret Key", re.compile(r"sk_(?:test|live)_[A-Za-z0-9]{24,}")),
    ("Slack Bot Token", re.compile(r"xoxb-[A-Za-z0-9\-]+")),
    ("Slack User Token", re.compile(r"xoxp-[A-Za-z0-9\-]+")),
    ("SendGrid API Key", re.compile(r"SG\.[A-Za-z0-9\-_.]{22}\.[A-Za-z0-9\-_.]{43}")),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |OPENSSH )?PRIVATE KEY-----")),
    ("Database URL with Password", re.compile(r"(?:postgres|mysql|mongodb)(?:ql)?://[^:]+:[^@\s]+@[^\s]+")),
    ("Bearer Token", re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*")),
    ("JWT", re.compile(r"eyJhbGciOi[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*")),
]


def redact(content: str) -> tuple[str, list[dict]]:
    """
    Scan content and replace detected credentials with [REDACTED].

    Returns:
        (redacted_content, findings) where findings is a list of
        {"type": str, "count": int} for each detected credential type.
    """
    findings = []
    redacted = content

    for name, pattern in CREDENTIAL_PATTERNS:
        matches = pattern.findall(redacted)
        if matches:
            findings.append({"type": name, "count": len(matches)})
            redacted = pattern.sub(f"[REDACTED:{name}]", redacted)

    return redacted, findings


def scan(content: str) -> list[dict]:
    """
    Scan content for credentials without modifying it.

    Returns:
        List of {"type": str, "count": int} for each detected credential type.
    """
    _, findings = redact(content)
    return findings
