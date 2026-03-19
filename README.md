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
- **Intent Proxy** (`src/proxy/`) — Local Unix Domain Socket proxy that handles credential-bearing HTTP requests on behalf of agents.

## Quick Start

### 1. Install dependencies

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Store a credential

```bash
python store_credential.py <name> --type <service_type> [--description "..."]
```

Example:

```bash
python store_credential.py github-personal --type github --description "Personal access token"
```

The secret is prompted interactively and stored in your OS keychain (macOS Keychain / Linux SecretService), never written to a file. Run `python store_credential.py -h` for more examples.

### 3. Use as MCP Server (with Claude Code)

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

### 4. Run the PoC demos (Docker)

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
│   └── proxy/                  # Unix socket intent proxy
│       └── intent_proxy.py
├── poc/                        # Proof of Concept demos
│   ├── credential_scanner.py   # PoC #1: Credential exposure scanner
│   ├── agent_credential_exposure.py  # PoC #2: Live LLM exposure demo
│   └── fake_credentials/       # Simulated developer credential files
├── Dockerfile                  # Simulated developer environment for PoCs
├── store_credential.py          # CLI to store credentials in OS keychain
└── requirements.txt
```

## License

MIT
