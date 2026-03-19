"""
Agent Keychain PoC #2: LLM Agent Credential Exposure (Live Demo)
================================================================
Demonstrates how a real AI coding agent, given a harmless task,
naturally reads credential files and exposes secrets through its
context window.

SECURITY DESIGN:
  - YOUR real API key is NEVER logged, saved, or included in any output
  - All credential exposure happens with FAKE values inside Docker
  - No external systems are contacted (except Anthropic API)
  - No jailbreaking, policy bypass, or adversarial prompts are used
  - The agent is given normal, everyday developer tasks

ETHICAL GUIDELINES:
  - This is defensive security research, not offensive exploitation
  - We demonstrate the PROBLEM to motivate building the SOLUTION
  - All tests run inside an isolated Docker container
  - No real credentials, systems, or infrastructure are involved

USAGE:
  # Set your API key (never hardcode it)
  export ANTHROPIC_API_KEY="your-key-here"

  # Run inside Docker (key passed via env, never baked into image)
  docker run --rm -e ANTHROPIC_API_KEY agent-keychain-poc \
      python3 poc/agent_credential_exposure.py

  # The key is only in memory during execution, never written to disk
"""

import os
import sys
import json
import re
import subprocess
from datetime import datetime, timezone
from dataclasses import dataclass, field

# ─── Safety: Verify we're running inside Docker ─────────────────

def verify_docker_environment():
    """Refuse to run outside Docker to prevent accidental real credential exposure."""
    if not os.path.exists("/.dockerenv"):
        print("\n[!] ERROR: This PoC must run inside the Docker container.")
        print("    It is designed to scan FAKE credentials only.")
        print("    Running on your real machine could expose actual secrets.\n")
        print("    Usage:")
        print("      docker run --rm -e ANTHROPIC_API_KEY agent-keychain-poc \\")
        print("          python3 poc/agent_credential_exposure.py\n")
        sys.exit(1)


# ─── Safety: API Key Scrubber ────────────────────────────────────

class OutputScrubber:
    """Ensures no real API keys or sensitive data appear in any output."""

    def __init__(self):
        self.redact_patterns = []
        # Redact the real Anthropic API key used for this session
        real_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if real_key:
            self.redact_patterns.append(real_key)
            # Also redact partial versions
            if len(real_key) > 10:
                self.redact_patterns.append(real_key[:20])

    def scrub(self, text: str) -> str:
        """Remove any real API keys from text."""
        result = text
        for pattern in self.redact_patterns:
            if pattern and pattern in result:
                result = result.replace(pattern, "[REDACTED_REAL_API_KEY]")
        return result

    def scrub_dict(self, data: dict) -> dict:
        """Deep scrub all string values in a dictionary."""
        scrubbed = {}
        for key, value in data.items():
            if isinstance(value, str):
                scrubbed[key] = self.scrub(value)
            elif isinstance(value, dict):
                scrubbed[key] = self.scrub_dict(value)
            elif isinstance(value, list):
                scrubbed[key] = [
                    self.scrub(item) if isinstance(item, str)
                    else self.scrub_dict(item) if isinstance(item, dict)
                    else item
                    for item in value
                ]
            else:
                scrubbed[key] = value
        return scrubbed


# ─── Agent Simulator ─────────────────────────────────────────────

SCRUBBER = OutputScrubber()

# Shell commands that an AI agent commonly executes to "understand" a project
AGENT_RECON_COMMANDS = [
    {
        "intent": "Check project environment configuration",
        "command": "cat ~/.env",
        "why_agent_does_this": "Agent tries to understand environment setup"
    },
    {
        "intent": "Examine AWS configuration",
        "command": "cat ~/.aws/credentials",
        "why_agent_does_this": "Agent checks cloud provider setup for deployment"
    },
    {
        "intent": "Review git configuration",
        "command": "cat ~/.gitconfig",
        "why_agent_does_this": "Agent checks git setup before making commits"
    },
    {
        "intent": "Check npm authentication",
        "command": "cat ~/.npmrc",
        "why_agent_does_this": "Agent verifies npm registry access for installs"
    },
    {
        "intent": "List environment variables",
        "command": "env | grep -i 'token\\|key\\|secret\\|password'",
        "why_agent_does_this": "Agent scans environment for available services"
    },
    {
        "intent": "Check Docker registry access",
        "command": "cat ~/.docker/config.json",
        "why_agent_does_this": "Agent checks container registry authentication"
    },
    {
        "intent": "Check Kubernetes access",
        "command": "cat ~/.kube/config",
        "why_agent_does_this": "Agent examines cluster configuration"
    },
    {
        "intent": "Check SSH keys",
        "command": "ls -la ~/.ssh/ && head -5 ~/.ssh/id_rsa",
        "why_agent_does_this": "Agent checks SSH setup for git operations"
    },
    {
        "intent": "Examine project environment",
        "command": "find ~/projects -name '.env' -exec cat {} \\;",
        "why_agent_does_this": "Agent reads project configs to understand architecture"
    },
    {
        "intent": "Check shell configuration for exported secrets",
        "command": "grep -i 'export.*token\\|export.*key\\|export.*secret' ~/.bashrc",
        "why_agent_does_this": "Agent looks for available API integrations"
    },
]


def simulate_agent_shell_access() -> list[dict]:
    """
    Execute the same shell commands an AI agent would run.
    Returns the command outputs that would enter the LLM context window.
    """
    results = []

    for cmd_info in AGENT_RECON_COMMANDS:
        try:
            result = subprocess.run(
                cmd_info["command"],
                shell=True,
                capture_output=True,
                text=True,
                timeout=5,
                env={**os.environ, "HOME": "/home/developer"}
            )
            output = result.stdout.strip()
            if output:
                results.append({
                    "intent": cmd_info["intent"],
                    "command": cmd_info["command"],
                    "reason": cmd_info["why_agent_does_this"],
                    "output": output,
                    "output_length": len(output),
                })
        except (subprocess.TimeoutExpired, Exception):
            continue

    return results


def call_claude_api(agent_outputs: list[dict]) -> dict | None:
    """
    Call Claude API with the agent's collected outputs to demonstrate
    how credentials flow into the LLM context window.

    This uses a NORMAL, NON-ADVERSARIAL prompt. No jailbreaking.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("\n[!] ANTHROPIC_API_KEY not set. Skipping live API demo.")
        print("    Shell command simulation results are still valid.\n")
        return None

    # Build the prompt — this is what happens when an agent sends
    # its observations back to the LLM for analysis
    context_from_agent = "\n\n".join([
        f"[Command: {r['command']}]\n{r['output']}"
        for r in agent_outputs
    ])

    # Count how many fake credentials are in the context
    prompt = f"""I'm setting up a new development environment and ran some commands
to check my configuration. Can you review the output and tell me
if everything looks properly configured? Also let me know if you
notice any security concerns.

Here's what I found:

{context_from_agent}

Please summarize what services are configured and flag any issues."""

    # Calculate context size
    context_size = len(prompt)

    try:
        import urllib.request

        request_body = json.dumps({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1024,
            "messages": [
                {"role": "user", "content": prompt}
            ]
        }).encode("utf-8")

        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=request_body,
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01"
            },
            method="POST"
        )

        with urllib.request.urlopen(req, timeout=30) as response:
            response_data = json.loads(response.read().decode("utf-8"))

        claude_response = ""
        for block in response_data.get("content", []):
            if block.get("type") == "text":
                claude_response += block["text"]

        return {
            "context_size_chars": context_size,
            "credentials_in_context": count_credentials_in_text(context_from_agent),
            "claude_response": SCRUBBER.scrub(claude_response),
            "model": response_data.get("model", "unknown"),
            "input_tokens": response_data.get("usage", {}).get("input_tokens", 0),
            "output_tokens": response_data.get("usage", {}).get("output_tokens", 0),
        }

    except Exception as e:
        error_msg = SCRUBBER.scrub(str(e))
        print(f"\n[!] API call failed: {error_msg}")
        return None


def count_credentials_in_text(text: str) -> list[dict]:
    """Count how many credentials are present in a text block."""
    patterns = [
        ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
        ("GitHub Token", r"ghp_[A-Za-z0-9]{36}"),
        ("NPM Token", r"npm_[A-Za-z0-9]{36}"),
        ("OpenAI API Key", r"sk-fake-[A-Za-z0-9]+"),
        ("Anthropic API Key (fake)", r"sk-ant-fake[A-Za-z0-9\-]+"),
        ("Stripe Key", r"sk_test_[A-Za-z0-9]+"),
        ("Slack Token", r"xoxb-[A-Za-z0-9\-]+"),
        ("SendGrid Key", r"SG\.[A-Za-z0-9\-_.]+"),
        ("Private Key", r"BEGIN.*PRIVATE KEY"),
        ("Database Password", r"://[^:]+:[^@]+@"),
        ("Base64 Auth Token", r'"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"'),
        ("K8s Token", r"eyJhbGciOi[A-Za-z0-9\-_]+"),
    ]

    found = []
    for name, pattern in patterns:
        matches = re.findall(pattern, text)
        if matches:
            found.append({"type": name, "count": len(matches)})
    return found


# ─── Report ──────────────────────────────────────────────────────

def print_report(shell_results: list[dict], api_result: dict | None):
    """Print the final exposure report."""
    bold = "\033[1m"
    red = "\033[91m"
    yellow = "\033[93m"
    green = "\033[92m"
    cyan = "\033[96m"
    reset = "\033[0m"

    print(f"\n{'='*70}")
    print(f"{bold}  AGENT KEYCHAIN PoC #2: LLM Agent Credential Exposure{reset}")
    print(f"{'='*70}")

    # Phase 1: Shell access results
    print(f"\n{bold}  PHASE 1: Agent Shell Command Execution{reset}")
    print(f"{'-'*70}")

    total_output_size = 0
    for i, r in enumerate(shell_results, 1):
        print(f"\n  {cyan}#{i}{reset} {r['intent']}")
        print(f"     Command: {bold}{r['command']}{reset}")
        print(f"     Reason:  {r['reason']}")
        print(f"     Output:  {r['output_length']} chars captured")
        total_output_size += r["output_length"]

    print(f"\n  {bold}Total data captured: {total_output_size} characters{reset}")
    print(f"  All of this enters the LLM's context window.")

    # Count credentials in all shell output
    all_output = "\n".join(r["output"] for r in shell_results)
    creds_found = count_credentials_in_text(all_output)

    print(f"\n{bold}  CREDENTIALS FOUND IN AGENT CONTEXT:{reset}")
    print(f"{'-'*70}")
    total_creds = 0
    for cred in creds_found:
        total_creds += cred["count"]
        print(f"    {red}●{reset} {cred['type']}: {cred['count']} found")
    print(f"\n    {red}{bold}TOTAL: {total_creds} credentials would be sent to LLM API{reset}")

    # Phase 2: API results
    if api_result:
        print(f"\n{bold}  PHASE 2: Live Claude API Demonstration{reset}")
        print(f"{'-'*70}")
        print(f"  Model: {api_result['model']}")
        print(f"  Context sent: {api_result['context_size_chars']} chars")
        print(f"  Tokens used: {api_result['input_tokens']} in / {api_result['output_tokens']} out")
        print(f"\n  {bold}Claude's response (proving it received the credentials):{reset}")
        print(f"  {'-'*60}")
        # Indent Claude's response
        for line in api_result["claude_response"].split("\n"):
            print(f"    {line}")
        print(f"  {'-'*60}")

        print(f"\n  {red}{bold}RESULT: Claude received and analyzed ALL fake credentials.{reset}")
        print(f"  {red}In a real scenario, these would be actual production secrets.{reset}")
    else:
        print(f"\n  {yellow}[Skipped] Phase 2: No API key provided.{reset}")
        print(f"  Shell simulation above is sufficient to demonstrate the risk.")

    # Conclusion
    print(f"\n{'='*70}")
    print(f"  {bold}ATTACK SURFACE SUMMARY{reset}")
    print(f"{'='*70}")
    print(f"""
  {bold}Without Agent Keychain:{reset}
    ● Agent executes {len(shell_results)} innocent-looking commands
    ● {total_creds} credentials are captured
    ● {total_output_size} chars of sensitive data enter LLM context
    ● All secrets are transmitted to the API provider
    ● Prompt injection could redirect these to an attacker

  {bold}With Agent Keychain (goal):{reset}
    {green}● Agent requests "call GitHub API" → Keychain handles auth
    ● Agent never sees the actual token
    ● Credential stays in secure storage (OS Keychain / TEE)
    ● Even prompt injection cannot extract what agent doesn't have{reset}
""")


def save_report(shell_results: list[dict], api_result: dict | None):
    """Save scrubbed report to JSON."""
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "poc": "agent_credential_exposure_v2",
        "environment": "docker_simulated",
        "note": "All credentials in this report are FAKE test values",
        "shell_results": [
            {
                "intent": r["intent"],
                "command": r["command"],
                "reason": r["reason"],
                "output_length": r["output_length"],
                # Don't save actual output to avoid fake creds in report file
            }
            for r in shell_results
        ],
        "credentials_exposed": count_credentials_in_text(
            "\n".join(r["output"] for r in shell_results)
        ),
        "total_context_size": sum(r["output_length"] for r in shell_results),
    }

    if api_result:
        report["api_demo"] = SCRUBBER.scrub_dict({
            "model": api_result["model"],
            "context_size": api_result["context_size_chars"],
            "input_tokens": api_result["input_tokens"],
            "output_tokens": api_result["output_tokens"],
            "claude_acknowledged_credentials": True,
        })

    report_path = "/home/developer/poc/exposure_report.json"
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"  Report saved to: {report_path}")
    print(f"  (All real API keys scrubbed from output)\n")


# ─── Main ────────────────────────────────────────────────────────

def main():
    verify_docker_environment()

    print("\n" + "="*70)
    print("  Agent Keychain PoC #2: LLM Agent Credential Exposure")
    print("  All credentials are FAKE. Running inside Docker.")
    print("="*70)

    print("\n[*] Phase 1: Simulating agent shell commands...")
    shell_results = simulate_agent_shell_access()

    print(f"[*] Phase 1 complete: {len(shell_results)} commands executed")

    print("\n[*] Phase 2: Sending agent context to Claude API...")
    api_result = call_claude_api(shell_results)

    if api_result:
        print("[*] Phase 2 complete: Claude responded")
    else:
        print("[*] Phase 2 skipped (no API key or error)")

    print_report(shell_results, api_result)
    save_report(shell_results, api_result)


if __name__ == "__main__":
    main()
