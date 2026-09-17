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

## What is and isn't guaranteed

Agent Keychain provides guarantees of three different strengths. They are listed
separately on purpose, because stating them as one blanket claim would overstate
the weakest of them.

- **Structural — the agent does not receive the secret.** When a credential is
  used through the proxy, it is retrieved inside a short-lived subprocess and
  never enters the agent's context or the long-lived server's memory. No MCP
  tool returns a secret and no CLI command prints one; the code path does not
  exist. This holds without anything having to behave correctly.
- **Best-effort — accidental exposure is removed.** `scan` / `import --scrub`
  move secrets out of the files an agent reads while doing ordinary work, and
  the hook blocks the read paths that remain. This substantially reduces
  accidental discovery. It is not a boundary.
- **Not guaranteed — a hostile agent that can run arbitrary code.** The agent
  runs with your user's privileges, so it can reach anything you can, including
  the vault itself. The hook raises the cost of that; it cannot prevent it. For
  containment, run the agent in a container or VM.

## Known limitations

- **The vault is reachable by anything running as your user.** Storing a secret
  in the OS keychain removes it from the well-known file paths an agent reads
  during ordinary reconnaissance — it does not put it behind a privilege
  boundary. The hook blocks the direct read-out paths it knows about (keychain
  query commands, `keyring` / vault retrieval calls, the file backend's store),
  but it matches on command text and can be evaded by an agent that is
  deliberately trying to. Treat this as friction, not containment.
- **The guard guards itself, best-effort.** A benign agent that hits a block
  will often try to "fix" the obstacle — by editing the hook script, removing
  its registration from `.claude/settings.json`, or running `agent-keychain
  uninstall`. The hook blocks all three (edits via Write/Edit tools and via
  shell write verbs; reads of the hook stay allowed). Two deliberate escape
  hatches, both read from the hook's own environment so they cannot be
  injected from a command line: `AGENT_KEYCHAIN_UNGUARD=1` set by the
  operator, and sessions developing agent-keychain itself. Like the rest of
  the hook this is string matching — friction against accidents, not
  containment against intent.
- **Hook coverage is enumerated, not complete.** The hook now also blocks
  credential-emitting commands (`gh auth token`, `aws configure
  export-credentials`, `gcloud auth print-access-token`, `kubectl config view
  --raw`) and targeted environment-variable hunting (`env | grep -i token`,
  `echo $GITHUB_TOKEN`). Known residuals, accepted deliberately: a bare `env`
  dump stays allowed (blocking it breaks ordinary debugging — run
  `agent-keychain scan` / `import --scrub` and restart the agent session so
  there is nothing in the environment to dump), secrets in formats none of the
  patterns recognize pass the content scan, and output of arbitrary commands
  that happen to print a secret (`docker inspect`, `ps`, shell history) is not
  scanned — output-side DLP exists only on the proxy and `exec` paths.

- **`exec` is not a sandbox.** The `exec` wrapper injects a secret into a
  subprocess the agent chose. A credential's command allowlist bounds *which*
  binaries it can be injected into (deny-by-default), but an allowlisted binary
  can in principle still be coerced into leaking the secret (e.g. piping an
  injected env var to an attacker). Treat the allowlist as least-privilege
  scoping, not containment. `exec --sandbox` (macOS) adds `sandbox-exec` denial
  of credential-file reads and fails closed when unavailable, but it denies a
  fixed path list and does not restrict network egress — for hard isolation,
  run the agent in a container or VM.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.15.x  | Yes       |
| < 1.15  | No        |
