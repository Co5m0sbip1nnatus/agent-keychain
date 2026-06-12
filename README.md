# Agent Keychain

[![Tests](https://github.com/Co5m0sbip1nnatus/agent-keychain/actions/workflows/test.yml/badge.svg)](https://github.com/Co5m0sbip1nnatus/agent-keychain/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A credential isolation framework for AI coding agents.

Like Apple Keychain protects your passwords from apps, Agent Keychain protects your credentials from AI coding agents (Claude Code, Cursor, etc.).

## The Problem

AI coding agents run with your user privileges. They can read `~/.aws/credentials`, `~/.ssh/id_rsa`, environment variables, and `.env` files. Every secret they access is sent to the LLM provider's API as part of the context window.

## Architecture

```
Agent                    Agent Keychain                  External API
  │                           │                               │
  ├── "Call GitHub API" ────► │                               │
  │                           ├── Inject credential ────────► │
  │                           │◄── Response ──────────────────┤
  │◄── Scrubbed response ─────┤                               │
  │                           │                               │
  (never sees the token)      (secret stays here)
```

## Components

- **Vault** (`agent_keychain/vault/`) — credential store behind a pluggable backend: the OS keychain (macOS Keychain / Linux SecretService / Windows Credential Manager) by default, or a file backend for headless/CI (`backends.py`). Includes `SecureString` for automatic memory scrubbing after use, and **domain binding** (`domain_policy.py`) so each credential can only be used against its allowed domains.
- **MCP Server** (`agent_keychain/mcp_server/`) — Exposes credential-proxied tools to AI agents via the [Model Context Protocol](https://modelcontextprotocol.io/). Agents can make authenticated API calls without ever seeing raw secrets.
- **Credential Guard** (`agent_keychain/guard/`) — Scans file contents and automatically redacts detected credentials (API keys, tokens, private keys, database URLs) before they reach the AI agent's context window.
- **Process Isolation** (`agent_keychain/proxy/`) — Credential-bearing HTTP requests run in short-lived subprocesses that exit after completion, ensuring credentials never reside in the long-lived MCP server process memory.

## Quick Start

### 1. Install

From source:

```bash
git clone https://github.com/Co5m0sbip1nnatus/agent-keychain.git
cd agent-keychain
pip install -e .
```

(A PyPI release is planned but not yet published.)

### 2. Enable credential guard (Claude Code)

```bash
agent-keychain install
```

This registers a hook in Claude Code that automatically blocks file reads containing credentials and directs the agent to use `safe_read_file` instead. To remove:

```bash
agent-keychain uninstall
```

### 3. Store a credential

```bash
agent-keychain store github-personal --type github --description "Personal access token"
```

The secret is prompted interactively and stored in your OS keychain, never written to a file.

**Domain binding (deny-by-default).** Every credential is bound to the domains it is allowed to be used against. A credential can only ever be sent to those hosts — so a prompt-injected agent cannot exfiltrate a token by pointing a request at an attacker-controlled URL. For known service types (`github`, `aws`, `stripe`, `openai`, `anthropic`, …) the domain is inferred automatically, so the common case needs no extra flags. For an unknown type you'll be asked once for the allowed domain(s).

Options:

```bash
--auth-type bearer|basic|api-key   # Authentication method (default: bearer)
--ttl 3600                         # Auto-expire after N seconds
--allowed-domain api.github.com    # Bind to a domain (repeatable; suffix match covers subdomains)
--allow-any                        # Store unrestricted — sendable to any host (use with care)
--rotate-after 90                  # Rotation policy in days; flagged overdue once exceeded
--allowed-method GET               # Restrict to HTTP method(s) (repeatable; default: any)
--allowed-path /repos/*            # Restrict to URL path glob(s) (repeatable; default: any)
--rate-limit 60                    # Max requests per minute for this credential (default: unlimited)
--allowed-command aws              # Permit a command for `exec` (repeatable; default: none)
```

**Least-privilege request scope.** Domain binding limits *where* a credential goes; scoping limits *what* it can do there. Restrict a credential to specific HTTP methods and URL paths so a tricked agent can't do more than intended — e.g. a read-only GitHub token:

```bash
agent-keychain store gh-readonly --type github --allowed-method GET --allowed-path '/repos/*'
agent-keychain scope my-token --allowed-method GET   # tighten an existing credential
```

Requests are also scanned before they leave: if the URL or body contains what looks like *another* credential, the proxy blocks the request so a secret can't be smuggled out through an otherwise-allowed host.

Other credential commands:

```bash
agent-keychain list                                    # List credentials, bound domains, and rotation status
agent-keychain rotate my-token                         # Replace a credential's secret (keeps its metadata)
agent-keychain scope my-token --allowed-method GET     # Restrict an existing credential's methods/paths
agent-keychain grant my-token --for 5m                 # Open a human-approved window for a gated credential
agent-keychain revoke my-token                         # Close the approval window now
agent-keychain allow-domain my-token --allowed-domain api.example.com  # Add a domain to an existing credential
agent-keychain migrate                                 # Backfill domains for credentials that have none
agent-keychain audit                                   # Show recent credential-usage events
agent-keychain scan                                    # Find secrets living outside the vault
agent-keychain allow-command aws-prod --command aws    # Permit a command for exec
agent-keychain delete my-token                         # Delete a credential
```

**Beyond HTTP: the `exec` wrapper.** Most real workflows authenticate with non-HTTP tools — `git`, `aws`, `gcloud`, `psql`, `docker`. `agent-keychain exec` injects a stored secret into a subprocess's environment (or a `{secret}` argument placeholder) so those tools authenticate without the secret ever entering the agent's context. The command's output is run through response DLP before it's shown.

```bash
agent-keychain store aws-prod --type aws --allow-any --allowed-command aws
agent-keychain exec --credential aws-prod --env AWS_SECRET_ACCESS_KEY -- aws s3 ls
```

A credential can only be injected into commands on its allowlist (empty by default — deny-by-default), so a credential can't be used with `exec` until you permit a specific binary. **Honest limitation:** the agent still chooses the command, so an allowlisted binary could in principle be coerced into leaking. The allowlist bounds *which* tools a credential can touch; it is not a full sandbox (see SECURITY.md).

**Onboarding scan + import.** Agent Keychain only protects what's in its vault — but most leaks start with secrets already sitting in environment variables and dotfiles. `agent-keychain scan` checks your environment and common credential files and reports what it finds — only the location and credential type, never the secret value. Then `agent-keychain import` moves them in and (with `--scrub`) removes them from the source, keeping a `.bak`:

```bash
agent-keychain scan                                    # what's exposed?
agent-keychain import --from-file app-config --scrub   # move secrets into the vault, scrub the file
```

**MCP registration.** `agent-keychain register-mcp` writes the project `.mcp.json` (or `.cursor/mcp.json` with `--cursor`) so the client picks up the server without hand-editing config.

**Audit actor.** Set `AGENT_KEYCHAIN_ACTOR` on the server/CLI process to label which agent or deployment a request came from; it's recorded with each audit event.

**Rotation.** Long-lived secrets are a liability — the longer a token stays valid, the longer a leaked copy is useful. Set a rotation policy with `--rotate-after <days>` when storing; `agent-keychain list` then shows each credential's age and flags any that are overdue (`ROTATION DUE ⚠`). When it's time, `agent-keychain rotate <name>` prompts for the new secret and swaps it in place, preserving the credential's domains, auth type, and other metadata.

**Audit log.** Every request made through `secure_http_request` is recorded to `~/.agent-keychain/audit.jsonl` (owner-only) — credential name, destination host, method, the allow/block decision, and response status. Secret values, full URLs, and request/response bodies are never written, so the log itself cannot leak a credential. Review it with:

```bash
agent-keychain audit                       # last 20 events
agent-keychain audit --blocked-only        # only denied requests (spot probing / misuse)
agent-keychain audit --credential my-token # filter by credential
agent-keychain audit --suspicious          # group repeated blocks — a probing/misuse signal
```

**Rate limiting.** Cap how often a credential can be used with `store --rate-limit <n>` (requests per minute). Once the limit is hit, further requests are blocked (and audited) until the window clears — bounding how fast a compromised agent can use a token.

**Human-in-the-loop approval.** Mark a sensitive credential `store --require-approval` and it's blocked by default — the agent cannot use it on its own. A human opens a short, explicit window with `agent-keychain grant <name> --for 5m`; outside that window every request (HTTP or `exec`) is denied and audited. `agent-keychain revoke <name>` closes it immediately. This is a time-boxed grant rather than a synchronous prompt, so it works even with a headless MCP server.

### Headless / CI

The OS keychain isn't available on CI runners or in containers. Select the file
backend so the same policy engine (domain binding, scoping, DLP, audit,
approval) runs anywhere:

```bash
export AGENT_KEYCHAIN_BACKEND=file
export AGENT_KEYCHAIN_STORE=/run/secrets/agent-keychain.json   # 0600 JSON file
agent-keychain store ci-token --type github
```

The file backend stores secrets in a single owner-only JSON file — less
protected than a keychain (plaintext on disk), so use it where the runner's
filesystem is already the trust boundary (ephemeral CI). For production secret
managers (HashiCorp Vault, AWS Secrets Manager, 1Password), implement the small
`get`/`set`/`delete` backend interface in `agent_keychain/vault/backends.py` and
select it the same way — those integrations are intentionally not bundled.

### 4. Use as MCP Server (with Claude Code)

Create a `.mcp.json` in the project root:

```json
{
  "mcpServers": {
    "agent-keychain": {
      "command": "./venv/bin/python",
      "args": ["-m", "agent_keychain.mcp_server.server"]
    }
  }
}
```

Then start Claude Code in this directory:

```bash
claude
```

Then use the exposed tools:
- `check_connection` — Verify the keychain is active
- `list_available_credentials` — See stored credential names (no secrets)
- `secure_http_request` — Make authenticated API calls through the proxy
- `safe_read_file` — Read files with automatic credential redaction
- `scan_file_for_secrets` — Check if a file contains credentials before reading

### 5. Run the PoC demos

Before/after comparison demos (run locally):

```bash
python poc/demo_credential_guard.py     # File read: exposed vs redacted
python poc/demo_memory_scrubbing.py     # Memory: lingering vs zeroed
python poc/demo_token_expiry.py         # Token: permanent vs auto-expired
python poc/demo_process_isolation.py    # Process: shared vs isolated
python poc/demo_end_to_end.py           # Full lifecycle: all protections together
python poc/benchmark_attacks.py         # Adversarial scorecard: naive proxy vs Agent Keychain
```

The end-to-end demo walks a single credential through discovery, storage with a
least-privilege policy, blocked misuse (exfil / out-of-scope / smuggling / rate
limit), a legitimate request passing every guard, the audit trail, and rotation
— all locally with fake secrets and no network calls.

The benchmark runs a battery of prompt-injection / exfiltration attacks
(exfil to an attacker host, domain lookalikes, method/path escalation, secret
smuggling in body and URL, HTTP downgrade, response-side token leak) and prints
a quantified before/after scorecard — a naive inject-and-forward proxy leaks
every one; Agent Keychain blocks them all. The same scenarios are asserted in
`tests/test_adversarial.py`.

Attack simulation demos (run in Docker):

```bash
# Build the simulated developer environment
docker build -t agent-keychain-poc .

# PoC #1: Credential scanner — shows how easily agents find secrets
docker run --rm agent-keychain-poc python3 poc/credential_scanner.py

# PoC #2: Live LLM exposure demo (requires API key, passed via env)
docker run --rm -e ANTHROPIC_API_KEY agent-keychain-poc \
    python3 poc/agent_credential_exposure.py
```

## Project Structure

```
agent-keychain/
├── agent_keychain/
│   ├── vault/                 # OS keychain-backed credential store
│   │   ├── keychain_vault.py  # Store/retrieve/rotate + metadata
│   │   ├── secure_string.py   # Memory scrubbing via ctypes
│   │   ├── domain_policy.py   # Per-credential allowed-domain matching
│   │   ├── request_scope.py   # HTTP method + path allowlists
│   │   ├── command_policy.py  # exec command allowlist matching
│   │   ├── approval.py        # Human-in-the-loop grant windows
│   │   ├── backends.py        # Pluggable storage (keychain / file / CI)
│   │   └── rotation.py        # Rotation age / overdue policy
│   ├── mcp_server/            # MCP server for AI agent integration
│   │   └── server.py          # Enforces domain/scope/smuggling/rate-limit
│   ├── guard/                 # Credential detection and redaction engine
│   │   ├── credential_guard.py
│   │   └── env_scanner.py     # Find secrets living outside the vault
│   ├── proxy/                 # Process-isolated credential handling
│   │   ├── isolated_request.py  # Short-lived subprocess for HTTP
│   │   └── process_pool.py      # Subprocess spawner
│   ├── hooks/                 # Credential guard hook for Claude Code
│   │   └── credential-guard.sh
│   ├── audit/                 # Append-only audit log of credential usage
│   │   └── audit_log.py       # record / rate-limit counts / anomaly summary
│   ├── logging/               # Structured logging (secrets never logged)
│   │   └── logger.py
│   ├── exec_runner.py        # exec wrapper: inject secret into a subprocess
│   └── cli.py                # Unified CLI entry point
├── tests/                     # Unit and integration tests
├── poc/                       # Proof of Concept demos
│   ├── credential_scanner.py  # PoC #1: Credential exposure scanner
│   ├── agent_credential_exposure.py  # PoC #2: Live LLM exposure demo
│   ├── demo_credential_guard.py     # Before/after: file redaction
│   ├── demo_memory_scrubbing.py     # Before/after: memory zeroing
│   ├── demo_token_expiry.py         # Before/after: TTL auto-deletion
│   ├── demo_process_isolation.py    # Before/after: subprocess isolation
│   ├── demo_end_to_end.py           # Full lifecycle: all protections together
│   └── fake_credentials/            # Simulated developer credential files
├── .github/workflows/         # CI (test.yml) + manual PyPI release (release.yml)
├── pyproject.toml             # Package configuration
├── Dockerfile                 # Simulated developer environment for PoCs
└── requirements.txt
```

## Security Design

Agent Keychain implements defense-in-depth against credential exposure in AI agent environments:

| Layer | Defense | Threat Mitigated |
|-------|---------|-----------------|
| **Vault** | OS keychain encryption | Credentials stored in plaintext files |
| **Domain Binding** | Per-credential allowed-domain enforcement | Token exfiltration to attacker-controlled endpoints |
| **Request Scoping** | Per-credential HTTP method + path allowlist | Over-broad use of a credential (least privilege) |
| **Smuggling Guard** | Scan of outbound URL/body for credentials | Exfiltrating a second secret via an allowed host |
| **Response DLP** | Redaction of secrets in API responses | Secrets (e.g. freshly issued tokens) leaking back to the agent |
| **Credential Guard** | Pattern-based redaction | Secrets leaking into LLM context window |
| **Hook Enforcement** | Path-blocklist + content scan on reads | Agent reading credential files directly |
| **Memory Scrubbing** | ctypes-based zeroing after use | Credentials lingering in process memory |
| **Process Isolation** | Short-lived subprocess for HTTP | Long-lived process accumulating secrets |
| **Token Expiry** | TTL-based auto-deletion | Stolen credentials remaining valid indefinitely |
| **Rotation Policy** | Age tracking + overdue flagging + in-place rotation | Long-lived secrets accumulating exposure |
| **Audit Log** | Append-only record of every credential use | Undetected misuse / exfiltration attempts |
| **Rate Limiting** | Per-credential requests-per-minute cap | Rapid bulk use by a compromised agent |
| **Command Allowlist** | `exec` deny-by-default command binding | A non-HTTP credential being injected into arbitrary commands |
| **Approval Grants** | Human-opened time-limited use windows | Autonomous use of a sensitive credential without sign-off |

### Threat Model & Limitations

Agent Keychain protects against credential exposure through the **LLM context window** and **process memory** of AI coding agents. It does **not** protect against:

- **Browser session token theft** — Session cookies for web-based AI apps (ChatGPT, Claude) are managed by the browser. Protecting these requires vendor-side changes such as storing tokens in a secure enclave. See [AIKatz — Attacking AI Desktop Apps for Fun & Profit (RSA Conference 2026)](https://www.lumia.security/blog/aikatz) for research on this attack vector.
- **Kernel-level attacks** — An attacker with root/kernel access can bypass all userspace protections.
- **Prompt injection via external content** — If an agent processes malicious input that instructs it to exfiltrate data through side channels.

## References

- [AIKatz — Attacking AI Desktop Apps for Fun & Profit](https://www.lumia.security/blog/aikatz) (RSA Conference 2026) — Research on extracting authentication tokens from AI desktop app process memory. Agent Keychain's memory scrubbing and process isolation features are designed to mitigate this class of attacks.
- [MITRE ATLAS — AML.CS0036](https://atlas.mitre.org/studies/AML.CS0036) — MITRE case study on AI application credential theft.
- [Model Context Protocol](https://modelcontextprotocol.io/) — The protocol used by Agent Keychain to expose secure tools to AI agents.

## License

MIT
