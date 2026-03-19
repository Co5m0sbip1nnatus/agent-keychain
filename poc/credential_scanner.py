"""
Agent Keychain PoC #1: Credential Exposure Scanner
===================================================
This script demonstrates how an AI coding agent with standard shell access
can discover and extract ALL credentials from a developer's local environment.

This simulates what happens when an agent executes commands like:
  - cat ~/.aws/credentials
  - echo $GITHUB_TOKEN
  - cat ~/.npmrc

Every credential found here would be sent to the LLM provider's API server
as part of the agent's context window.

WARNING: This script uses FAKE credentials in a Docker container.
         Never run credential scanners against real environments.
"""

import os
import re
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

# ─── Configuration ───────────────────────────────────────────────

HOME = os.environ.get("HOME", os.path.expanduser("~"))

# Known credential file locations
CREDENTIAL_FILES = [
    ("AWS Credentials", ".aws/credentials"),
    ("AWS Config", ".aws/config"),
    ("SSH Private Key", ".ssh/id_rsa"),
    ("SSH Private Key (Ed25519)", ".ssh/id_ed25519"),
    ("Git Config", ".gitconfig"),
    ("Git Credentials", ".git-credentials"),
    ("NPM Token", ".npmrc"),
    ("Docker Config", ".docker/config.json"),
    ("Kubernetes Config", ".kube/config"),
    ("Home .env", ".env"),
    ("Bash RC", ".bashrc"),
    ("Bash Profile", ".bash_profile"),
    ("Zsh RC", ".zshrc"),
]

# Regex patterns to detect secrets in file contents and env vars
SECRET_PATTERNS = [
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret Key", r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*([A-Za-z0-9/+=]{40})"),
    ("GitHub Token (classic)", r"ghp_[A-Za-z0-9]{36}"),
    ("GitHub Token (fine-grained)", r"github_pat_[A-Za-z0-9_]{82}"),
    ("GitLab Token", r"glpat-[A-Za-z0-9\-]{20}"),
    ("NPM Token", r"npm_[A-Za-z0-9]{36}"),
    ("OpenAI API Key", r"sk-[A-Za-z0-9]{48}"),
    ("Anthropic API Key", r"sk-ant-[A-Za-z0-9\-]{36,}"),
    ("Stripe Secret Key", r"sk_(test|live)_[A-Za-z0-9]{24,}"),
    ("Slack Bot Token", r"xoxb-[A-Za-z0-9\-]+"),
    ("Slack User Token", r"xoxp-[A-Za-z0-9\-]+"),
    ("SendGrid API Key", r"SG\.[A-Za-z0-9\-_.]{22}\.[A-Za-z0-9\-_.]{43}"),
    ("Private Key Block", r"-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----"),
    ("Database URL with Password", r"(?:postgres|mysql|mongodb)(?:ql)?://[^:]+:[^@]+@[^\s]+"),
    ("JWT Secret", r"(?:JWT_SECRET|jwt_secret)\s*[=:]\s*\S+"),
    ("Generic Password in URL", r"://[^:]+:([^@\s]{8,})@"),
    ("Bearer Token", r"Bearer\s+[A-Za-z0-9\-._~+/]+=*"),
    ("Base64 Auth", r'"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"'),
    ("K8s Service Account Token", r"eyJhbGciOi[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"),
]

# Environment variable names commonly containing secrets
SECRET_ENV_VARS = [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITLAB_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "STRIPE_SECRET_KEY",
    "DATABASE_URL",
    "REDIS_URL",
    "SLACK_BOT_TOKEN",
    "SLACK_TOKEN",
    "SENDGRID_API_KEY",
    "JWT_SECRET",
    "SECRET_KEY",
    "API_KEY",
    "PRIVATE_KEY",
]


# ─── Data Structures ────────────────────────────────────────────

@dataclass
class FoundCredential:
    source: str           # Where it was found (file path, env var, etc.)
    cred_type: str        # Type of credential
    value: str            # The actual secret value
    method: str           # How an agent would access it
    risk_level: str       # "CRITICAL", "HIGH", "MEDIUM"


# ─── Scanner Functions ───────────────────────────────────────────

def scan_credential_files() -> list[FoundCredential]:
    """Scan known credential file locations."""
    findings = []

    for name, rel_path in CREDENTIAL_FILES:
        full_path = os.path.join(HOME, rel_path)

        if not os.path.exists(full_path):
            continue

        try:
            with open(full_path, "r", errors="replace") as f:
                content = f.read()
        except PermissionError:
            continue

        # Search for secret patterns in the file
        for pattern_name, pattern in SECRET_PATTERNS:
            matches = re.findall(pattern, content)
            if matches:
                for match in matches:
                    # For patterns with groups, match might be a string from the group
                    value = match if isinstance(match, str) else match[0]
                    findings.append(FoundCredential(
                        source=full_path,
                        cred_type=pattern_name,
                        value=_mask_middle(value),
                        method=f'cat {full_path}',
                        risk_level=_assess_risk(pattern_name),
                    ))

    return findings


def scan_environment_variables() -> list[FoundCredential]:
    """Scan environment variables for secrets."""
    findings = []

    for var_name in SECRET_ENV_VARS:
        value = os.environ.get(var_name)
        if value:
            findings.append(FoundCredential(
                source=f"ENV:{var_name}",
                cred_type=f"Environment Variable ({var_name})",
                value=_mask_middle(value),
                method=f'echo ${var_name}',
                risk_level="CRITICAL",
            ))

    # Also check for secrets exported in shell config
    for shell_file in [".bashrc", ".bash_profile", ".zshrc"]:
        full_path = os.path.join(HOME, shell_file)
        if os.path.exists(full_path):
            try:
                with open(full_path, "r") as f:
                    for line in f:
                        if line.strip().startswith("export "):
                            for var_name in SECRET_ENV_VARS:
                                if var_name in line:
                                    # Extract the value
                                    match = re.search(
                                        rf'export\s+{var_name}\s*=\s*["\']?([^"\'\s]+)',
                                        line
                                    )
                                    if match:
                                        findings.append(FoundCredential(
                                            source=full_path,
                                            cred_type=f"Exported Secret ({var_name})",
                                            value=_mask_middle(match.group(1)),
                                            method=f'grep {var_name} {full_path}',
                                            risk_level="CRITICAL",
                                        ))
            except (PermissionError, UnicodeDecodeError):
                continue

    return findings


def scan_project_env_files() -> list[FoundCredential]:
    """Recursively scan for .env files in project directories."""
    findings = []
    projects_dir = os.path.join(HOME, "projects")

    if not os.path.exists(projects_dir):
        return findings

    for env_file in Path(projects_dir).rglob(".env*"):
        if env_file.is_file() and not env_file.name.endswith(".example"):
            try:
                content = env_file.read_text(errors="replace")
                for pattern_name, pattern in SECRET_PATTERNS:
                    matches = re.findall(pattern, content)
                    for match in matches:
                        value = match if isinstance(match, str) else match[0]
                        findings.append(FoundCredential(
                            source=str(env_file),
                            cred_type=pattern_name,
                            value=_mask_middle(value),
                            method=f'cat {env_file}',
                            risk_level=_assess_risk(pattern_name),
                        ))
            except (PermissionError, UnicodeDecodeError):
                continue

    return findings


# ─── Helpers ─────────────────────────────────────────────────────

def _mask_middle(value: str, show_chars: int = 6) -> str:
    """Mask the middle of a secret value for safe display."""
    if len(value) <= show_chars * 2:
        return value[:3] + "***" + value[-3:]
    return value[:show_chars] + "..." + value[-show_chars:]

def _assess_risk(cred_type: str) -> str:
    """Assess the risk level of a credential type."""
    critical = ["AWS Access Key", "AWS Secret Key", "Private Key Block",
                "Database URL with Password", "GitHub Token", "K8s Service Account Token"]
    high = ["OpenAI API Key", "Anthropic API Key", "Stripe Secret Key",
            "Slack Bot Token", "SendGrid API Key"]

    for c in critical:
        if c in cred_type:
            return "CRITICAL"
    for h in high:
        if h in cred_type:
            return "HIGH"
    return "MEDIUM"


# ─── Report ──────────────────────────────────────────────────────

def print_report(findings: list[FoundCredential]):
    """Print a formatted report of all found credentials."""

    risk_colors = {
        "CRITICAL": "\033[91m",  # Red
        "HIGH": "\033[93m",      # Yellow
        "MEDIUM": "\033[96m",    # Cyan
    }
    reset = "\033[0m"
    bold = "\033[1m"

    print(f"\n{'='*70}")
    print(f"{bold}  AGENT KEYCHAIN PoC #1: Credential Exposure Report{reset}")
    print(f"{'='*70}")
    print(f"\n  Scanned environment: {HOME}")
    print(f"  Total credentials found: {bold}{len(findings)}{reset}")

    # Count by risk level
    risk_counts = {}
    for f in findings:
        risk_counts[f.risk_level] = risk_counts.get(f.risk_level, 0) + 1

    print(f"\n  Risk breakdown:")
    for level in ["CRITICAL", "HIGH", "MEDIUM"]:
        count = risk_counts.get(level, 0)
        color = risk_colors.get(level, "")
        if count > 0:
            print(f"    {color}{level}: {count}{reset}")

    print(f"\n{'-'*70}")
    print(f"  {bold}FINDINGS{reset}")
    print(f"{'-'*70}\n")

    for i, f in enumerate(findings, 1):
        color = risk_colors.get(f.risk_level, "")
        print(f"  [{color}{f.risk_level}{reset}] #{i}: {f.cred_type}")
        print(f"    Source:  {f.source}")
        print(f"    Value:   {f.value}")
        print(f"    Method:  {bold}{f.method}{reset}")
        print()

    print(f"{'='*70}")
    print(f"  {bold}WHAT THIS MEANS{reset}")
    print(f"{'='*70}")
    print(f"""
  An AI coding agent with shell access can execute any of the commands
  listed above. Each command's output becomes part of the LLM's context
  window and is sent to the API provider's servers.

  Even without malicious intent, an agent might:
    - Read .env files to "understand the project configuration"
    - Cat ~/.aws/credentials to "check AWS setup"
    - Read ~/.ssh/id_rsa to "debug SSH connection issues"

  With prompt injection, an attacker can deliberately instruct the
  agent to exfiltrate these credentials to an external server.

  {bold}Agent Keychain aims to make this impossible.{reset}
""")


# ─── Main ────────────────────────────────────────────────────────

def main():
    all_findings = []

    print("\n[*] Scanning credential files...")
    all_findings.extend(scan_credential_files())

    print("[*] Scanning environment variables...")
    all_findings.extend(scan_environment_variables())

    print("[*] Scanning project .env files...")
    all_findings.extend(scan_project_env_files())

    # Deduplicate by (source, value)
    seen = set()
    unique_findings = []
    for f in all_findings:
        key = (f.source, f.value)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    # Sort by risk level
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    unique_findings.sort(key=lambda f: risk_order.get(f.risk_level, 3))

    print_report(unique_findings)

    # Also save as JSON for further analysis
    report_data = {
        "scan_target": HOME,
        "total_findings": len(unique_findings),
        "findings": [
            {
                "source": f.source,
                "type": f.cred_type,
                "value": f.value,
                "method": f.method,
                "risk_level": f.risk_level,
            }
            for f in unique_findings
        ]
    }

    report_path = os.path.join(HOME, "poc", "scan_report.json")
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w") as f:
        json.dump(report_data, f, indent=2)

    print(f"  Report saved to: {report_path}\n")


if __name__ == "__main__":
    main()
