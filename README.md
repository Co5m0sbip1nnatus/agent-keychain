# Agent Keychain

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

- **Vault** (`src/vault/`) — OS-native keychain-backed credential store (macOS Keychain / Linux SecretService). Secrets are encrypted at rest by the OS.
- **MCP Server** (`src/mcp_server/`) — Exposes credential-proxied tools to AI agents via the [Model Context Protocol](https://modelcontextprotocol.io/). Agents can make authenticated API calls without ever seeing raw secrets.
- **Credential Guard** (`src/guard/`) — Scans file contents and automatically redacts detected credentials (API keys, tokens, private keys, database URLs) before they reach the AI agent's context window.
- **Intent Proxy** (`src/proxy/`) — Local Unix Domain Socket proxy that handles credential-bearing HTTP requests on behalf of agents.

## Quick Start

### 1. Install

```bash
pip install agent-keychain
```

Or from source:

```bash
git clone https://github.com/Co5m0sbip1nnatus/agent-keychain.git
cd agent-keychain
pip install -e .
```

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

Other credential commands:

```bash
agent-keychain list              # List all stored credentials
agent-keychain delete my-token   # Delete a credential
```

### 4. Use as MCP Server (with Claude Code)

Create a `.mcp.json` in the project root:

```json
{
  "mcpServers": {
    "agent-keychain": {
      "command": "./venv/bin/python",
      "args": ["-m", "src.mcp_server.server"]
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

### 5. Run the PoC demos (Docker)

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
├── src/
│   ├── vault/                  # OS keychain-backed credential store
│   │   └── keychain_vault.py
│   ├── mcp_server/             # MCP server for AI agent integration
│   │   └── server.py
│   ├── guard/                  # Credential detection and redaction engine
│   │   └── credential_guard.py
│   └── proxy/                  # Unix socket intent proxy
│       └── intent_proxy.py
│   └── cli.py                 # Unified CLI entry point
├── tests/                       # Unit and integration tests
├── poc/                         # Proof of Concept demos
│   ├── credential_scanner.py    # PoC #1: Credential exposure scanner
│   ├── agent_credential_exposure.py  # PoC #2: Live LLM exposure demo
│   └── fake_credentials/        # Simulated developer credential files
├── .claude/hooks/               # Credential guard hook for Claude Code
├── Dockerfile                   # Simulated developer environment for PoCs
├── pyproject.toml               # Package configuration
└── requirements.txt
```

## License

MIT
