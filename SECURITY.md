# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Agent Keychain, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: jeehoohwang@gmail.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact

You will receive a response within 48 hours.

## Scope

The following are in scope:
- Credential leakage through MCP tools
- Bypass of Credential Guard redaction patterns
- Hook enforcement bypass
- Secret exposure in logs or error messages
- Response DLP / smuggling-guard bypass

## Known limitations

- **`exec` is not a sandbox.** The `exec` wrapper injects a secret into a
  subprocess the agent chose. A credential's command allowlist bounds *which*
  binaries it can be injected into (deny-by-default), but an allowlisted binary
  can in principle still be coerced into leaking the secret (e.g. piping an
  injected env var to an attacker). Treat the allowlist as least-privilege
  scoping, not containment; pair it with OS-level sandboxing for hard isolation.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.12.x  | Yes       |
| < 1.12  | No        |
