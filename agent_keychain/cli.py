"""
Agent Keychain CLI
Unified entry point for all agent-keychain commands.
"""
import argparse
import getpass
import json
import os
import re
import shutil
import sys

CLAUDE_DIR = os.path.expanduser("~/.claude")
SETTINGS_PATH = os.path.join(CLAUDE_DIR, "settings.json")
HOOK_INSTALL_DIR = os.path.join(CLAUDE_DIR, "hooks")
HOOK_SCRIPT_NAME = "credential-guard.sh"
HOOK_SOURCE = os.path.join(os.path.dirname(__file__), "hooks", HOOK_SCRIPT_NAME)

HOOK_CONFIG = {
    "matcher": "Read|Bash",
    "hooks": [
        {
            "type": "command",
            "command": os.path.join(HOOK_INSTALL_DIR, HOOK_SCRIPT_NAME),
            "timeout": 10
        }
    ]
}


def load_settings():
    if os.path.exists(SETTINGS_PATH):
        with open(SETTINGS_PATH, "r") as f:
            return json.load(f)
    return {}


def save_settings(settings):
    os.makedirs(CLAUDE_DIR, exist_ok=True)
    with open(SETTINGS_PATH, "w") as f:
        json.dump(settings, f, indent=2)


def cmd_install(args):
    """Install credential guard hook into Claude Code."""
    os.makedirs(HOOK_INSTALL_DIR, exist_ok=True)
    dest = os.path.join(HOOK_INSTALL_DIR, HOOK_SCRIPT_NAME)

    # Resolve the hook source path
    source = os.path.normpath(HOOK_SOURCE)
    if not os.path.exists(source):
        print(f"Error: Hook script not found at {source}", file=sys.stderr)
        sys.exit(1)

    shutil.copy2(source, dest)
    os.chmod(dest, 0o755)

    settings = load_settings()
    if "hooks" not in settings:
        settings["hooks"] = {}
    if "PreToolUse" not in settings["hooks"]:
        settings["hooks"]["PreToolUse"] = []

    for entry in settings["hooks"]["PreToolUse"]:
        for hook in entry.get("hooks", []):
            if HOOK_SCRIPT_NAME in hook.get("command", ""):
                print("Agent Keychain is already installed.")
                return

    settings["hooks"]["PreToolUse"].append(HOOK_CONFIG)
    save_settings(settings)
    print("Agent Keychain installed successfully.")
    print(f"  Hook: {dest}")
    print(f"  Settings: {SETTINGS_PATH}")
    print("\nAll projects are now protected. Restart Claude Code to apply.")


def cmd_uninstall(args):
    """Remove credential guard hook from Claude Code."""
    settings = load_settings()
    pre_tool = settings.get("hooks", {}).get("PreToolUse", [])
    settings.setdefault("hooks", {})["PreToolUse"] = [
        entry for entry in pre_tool
        if not any(HOOK_SCRIPT_NAME in h.get("command", "") for h in entry.get("hooks", []))
    ]

    if not settings["hooks"]["PreToolUse"]:
        del settings["hooks"]["PreToolUse"]
    if not settings["hooks"]:
        del settings["hooks"]

    save_settings(settings)

    dest = os.path.join(HOOK_INSTALL_DIR, HOOK_SCRIPT_NAME)
    if os.path.exists(dest):
        os.remove(dest)

    print("Agent Keychain uninstalled. Restart Claude Code to apply.")


def _resolve_store_domains(args):
    """Determine the allowed domains for a credential being stored.

    Resolution order (deny-by-default with friction absorbed at setup time):
      1. Explicit --allowed-domain flags win.
      2. --allow-any marks the credential unrestricted (loud opt-out).
      3. Otherwise infer from the service type's built-in map.
      4. If the type is unknown, prompt once for domains rather than
         silently storing a credential that can never be used.

    Returns the resolved domain list (may be ["*"] for unrestricted).
    """
    from agent_keychain.vault.domain_policy import infer_domains, WILDCARD

    if args.allowed_domain:
        return list(args.allowed_domain)

    if args.allow_any:
        print("⚠  Storing as UNRESTRICTED — this credential may be sent to any host.")
        return [WILDCARD]

    inferred = infer_domains(args.service_type)
    if inferred:
        print(f"Bound to: {', '.join(inferred)}")
        return inferred

    # Unknown service type and no domains given — prompt instead of storing dead.
    print(f"No default domain is known for type '{args.service_type}'.")
    entered = input("Enter allowed domain(s), comma-separated (or leave blank to abort): ").strip()
    if not entered:
        print("Aborted: a credential needs at least one allowed domain "
              "(or use --allow-any to store it unrestricted).", file=sys.stderr)
        sys.exit(1)
    return [d.strip() for d in entered.split(",") if d.strip()]


def cmd_store(args):
    """Store a credential in the OS keychain."""
    from agent_keychain.vault.keychain_vault import KeychainVault
    domains = _resolve_store_domains(args)
    vault = KeychainVault()
    secret = getpass.getpass("Secret: ")
    vault.store(args.name, secret, args.service_type, args.description, args.auth_type,
                ttl=args.ttl, allowed_domains=domains, rotate_after_days=args.rotate_after,
                allowed_methods=args.allowed_method, allowed_paths=args.allowed_path,
                rate_limit_per_min=args.rate_limit, allowed_commands=args.allowed_command)
    ttl_info = f", ttl: {args.ttl}s" if args.ttl else ""
    rot_info = f", rotate every {args.rotate_after}d" if args.rotate_after else ""
    print(f"Stored '{args.name}' ({args.service_type}, auth: {args.auth_type}{ttl_info}{rot_info})")


def cmd_scope(args):
    """Set the request scope (methods/paths) for an existing credential."""
    from agent_keychain.vault.keychain_vault import KeychainVault
    vault = KeychainVault()
    entry = vault.get(args.name)
    if entry is None:
        print(f"Credential '{args.name}' not found.", file=sys.stderr)
        sys.exit(1)
    methods = args.allowed_method if args.allowed_method else None
    paths = args.allowed_path if args.allowed_path else None
    if methods is None and paths is None:
        print("Specify at least one --allowed-method or --allowed-path.", file=sys.stderr)
        sys.exit(1)
    vault.set_scope(args.name, allowed_methods=methods, allowed_paths=paths)
    e = vault.get(args.name)
    print(f"Updated scope for '{args.name}': "
          f"methods={', '.join(e.allowed_methods) or 'any'}, paths={', '.join(e.allowed_paths) or 'any'}")


def cmd_rotate(args):
    """Replace the secret for an existing credential."""
    from agent_keychain.vault.keychain_vault import KeychainVault
    vault = KeychainVault()
    if not vault.has(args.name):
        print(f"Credential '{args.name}' not found.", file=sys.stderr)
        sys.exit(1)
    new_secret = getpass.getpass("New secret: ")
    vault.rotate(args.name, new_secret)
    entry = vault.get(args.name)
    print(f"Rotated '{args.name}' (rotation #{entry.rotation_count})")


def _format_domains(allowed_domains):
    """Human-readable domain status for display in `list`."""
    if not allowed_domains:
        return "NO DOMAINS (blocked) ⚠"
    if "*" in allowed_domains:
        return "UNRESTRICTED ⚠"
    return ", ".join(allowed_domains)


def _format_rotation(entry, now):
    """Human-readable rotation/age status for display in `list`."""
    from agent_keychain.vault.rotation import days_since_rotation, is_rotation_due
    age = days_since_rotation(entry, now)
    if age is None:
        return None
    age_str = f"{int(age)}d old"
    if entry.rotate_after_days:
        if is_rotation_due(entry, now):
            return f"{age_str} — ROTATION DUE (policy: {entry.rotate_after_days}d) ⚠"
        return f"{age_str} (rotate every {entry.rotate_after_days}d)"
    return age_str


def cmd_list(args):
    """List all stored credentials."""
    import time
    from agent_keychain.vault.keychain_vault import KeychainVault
    vault = KeychainVault()
    creds = vault.list_credentials()
    if not creds:
        print("No credentials stored.")
        return
    now = time.time()
    for c in creds:
        desc = f" — {c.description}" if c.description else ""
        print(f"  {c.name} ({c.service_type}, auth: {c.auth_type}){desc}")
        print(f"      domains: {_format_domains(c.allowed_domains)}")
        if c.allowed_methods or c.allowed_paths:
            methods = ", ".join(c.allowed_methods) if c.allowed_methods else "any"
            paths = ", ".join(c.allowed_paths) if c.allowed_paths else "any"
            print(f"      scope: methods={methods}, paths={paths}")
        if c.rate_limit_per_min:
            print(f"      rate limit: {c.rate_limit_per_min}/min")
        if c.allowed_commands:
            print(f"      exec: {', '.join(c.allowed_commands)}")
        rotation = _format_rotation(c, now)
        if rotation:
            print(f"      rotation: {rotation}")


def cmd_allow_domain(args):
    """Add one or more allowed domains to an existing credential."""
    from agent_keychain.vault.keychain_vault import KeychainVault
    vault = KeychainVault()
    entry = vault.get(args.name)
    if entry is None:
        print(f"Credential '{args.name}' not found.", file=sys.stderr)
        sys.exit(1)
    existing = list(entry.allowed_domains)
    for d in args.allowed_domain:
        if d not in existing:
            existing.append(d)
    vault.set_allowed_domains(args.name, existing)
    print(f"Updated '{args.name}' domains: {_format_domains(existing)}")


def cmd_migrate(args):
    """Backfill allowed domains for credentials that have none, using their type."""
    from agent_keychain.vault.keychain_vault import KeychainVault
    from agent_keychain.vault.domain_policy import infer_domains
    vault = KeychainVault()
    backfilled, unmapped = [], []
    for c in vault.list_credentials():
        if c.allowed_domains:
            continue
        inferred = infer_domains(c.service_type)
        if inferred:
            vault.set_allowed_domains(c.name, inferred)
            backfilled.append((c.name, inferred))
        else:
            unmapped.append(c.name)

    if backfilled:
        print("Backfilled domains:")
        for name, domains in backfilled:
            print(f"  {name} -> {', '.join(domains)}")
    if unmapped:
        print("\nNo default domain known for these (set manually with "
              "`agent-keychain allow-domain <name> --allowed-domain <host>`):")
        for name in unmapped:
            print(f"  {name}")
    if not backfilled and not unmapped:
        print("Nothing to migrate — all credentials already have domains.")


def cmd_audit(args):
    """Show recent credential-usage audit events."""
    from agent_keychain.audit import audit_log

    if args.suspicious:
        groups = audit_log.summarize_blocked(min_count=2)
        if not groups:
            print("No repeated blocked requests detected.")
            return
        print("Repeated blocked requests (possible probing / misuse):")
        for g in groups:
            hosts = f" — hosts: {', '.join(g['hosts'])}" if g["hosts"] else ""
            print(f"  {g['count']:>4}x  {g['credential']}  [{g['reason']}]{hosts}")
        return

    events = audit_log.read_events(
        limit=args.limit,
        credential=args.credential,
        blocked_only=args.blocked_only,
    )
    if not events:
        print("No audit events recorded.")
        return
    for e in events:
        mark = "BLOCKED" if e.get("decision") == audit_log.BLOCKED else "allowed"
        status = e.get("status")
        status_str = f" [{status}]" if status is not None else ""
        reason = e.get("reason", "")
        reason_str = f" — {reason}" if reason else ""
        actor = e.get("actor", "")
        actor_str = f" <{actor}>" if actor else ""
        print(f"  {e.get('ts','')}  {mark:7}  {e.get('credential','')}{actor_str} "
              f"{e.get('method','')} {e.get('host','')}{status_str}{reason_str}")


def cmd_exec(args):
    """Run a command with a stored secret injected, without exposing it."""
    from agent_keychain.vault.keychain_vault import KeychainVault
    from agent_keychain.audit import audit_log
    from agent_keychain import exec_runner

    vault = KeychainVault()
    command = args.exec_command
    # argparse REMAINDER includes a leading "--" when present; drop it.
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("Usage: agent-keychain exec --credential <name> --env VAR -- <command...>", file=sys.stderr)
        sys.exit(2)

    program = os.path.basename(command[0])
    result = exec_runner.run(vault, args.credential, args.env, command)

    if not result["ok"]:
        decision = audit_log.BLOCKED if result.get("blocked") else audit_log.ALLOWED
        audit_log.record(args.credential, f"exec:{program}", "EXEC", decision, result["error"])
        print(f"Error: {result['error']}", file=sys.stderr)
        sys.exit(1)

    audit_log.record(args.credential, f"exec:{program}", "EXEC", audit_log.ALLOWED, "ok",
                     status=result["returncode"], success=(result["returncode"] == 0))
    if result["redacted"]:
        print(f"[Response DLP: redacted {', '.join(result['redacted'])} from command output]", file=sys.stderr)
    if result["stdout"]:
        sys.stdout.write(result["stdout"])
    if result["stderr"]:
        sys.stderr.write(result["stderr"])
    sys.exit(result["returncode"])


def cmd_allow_command(args):
    """Add allowed exec command(s) to an existing credential."""
    from agent_keychain.vault.keychain_vault import KeychainVault
    vault = KeychainVault()
    entry = vault.get(args.name)
    if entry is None:
        print(f"Credential '{args.name}' not found.", file=sys.stderr)
        sys.exit(1)
    existing = list(entry.allowed_commands)
    for c in args.command:
        if c not in existing:
            existing.append(c)
    vault.set_allowed_commands(args.name, existing)
    print(f"Updated '{args.name}' allowed commands: {', '.join(existing) or '(none)'}")


def _sanitize_name(key: str, prefix: str = "") -> str:
    name = re.sub(r"[^A-Za-z0-9]+", "-", key.strip().lower()).strip("-")
    return f"{prefix}{name}" if prefix else name


def cmd_import(args):
    """Import secrets from a KEY=value file into the vault (and optionally scrub it)."""
    from agent_keychain.vault.keychain_vault import KeychainVault
    from agent_keychain.vault.domain_policy import infer_domains, WILDCARD
    from agent_keychain.onboarding import parse_secret_lines, scrub_file

    path = os.path.abspath(os.path.expanduser(args.from_file))
    if not os.path.isfile(path):
        print(f"Error: file '{args.from_file}' not found.", file=sys.stderr)
        sys.exit(1)

    with open(path, "r", errors="replace") as f:
        found = parse_secret_lines(f.read())
    if not found:
        print(f"No KEY=value secrets found in {path}.")
        return

    vault = KeychainVault()
    imported, values = [], []
    for item in found:
        name = _sanitize_name(item["key"], args.prefix)
        service = args.type or item["service"] or "imported"
        if args.allowed_domain:
            domains = list(args.allowed_domain)
        elif args.allow_any:
            domains = [WILDCARD]
        else:
            domains = infer_domains(service)
        vault.store(name, item["value"], service, allowed_domains=domains)
        imported.append((name, service, domains))
        values.append(item["value"])

    print(f"Imported {len(imported)} secret(s) into the vault:")
    for name, service, domains in imported:
        dom = ", ".join(domains) if domains else "NO DOMAINS (blocked) ⚠ — set with allow-domain"
        print(f"  {name} ({service}) -> {dom}")

    if args.scrub:
        backup = scrub_file(path, values)
        print(f"\nScrubbed the secrets from {path} (backup: {backup}).")
    else:
        print("\nThe original file still contains the secrets. Re-run with --scrub to remove them.")


def cmd_register_mcp(args):
    """Register the Agent Keychain MCP server for Claude Code or Cursor."""
    server_cmd = sys.executable
    server_args = ["-m", "agent_keychain.mcp_server.server"]
    entry = {"command": server_cmd, "args": server_args}

    if args.cursor:
        target = os.path.join(os.getcwd(), ".cursor", "mcp.json")
    else:
        target = os.path.join(os.getcwd(), ".mcp.json")

    os.makedirs(os.path.dirname(target), exist_ok=True) if os.path.dirname(target) else None
    config = {}
    if os.path.isfile(target):
        try:
            with open(target) as f:
                config = json.load(f)
        except (json.JSONDecodeError, OSError):
            config = {}
    config.setdefault("mcpServers", {})["agent-keychain"] = entry
    with open(target, "w") as f:
        json.dump(config, f, indent=2)
    client = "Cursor" if args.cursor else "Claude Code"
    print(f"Registered Agent Keychain MCP server for {client} in {target}.")
    print("Restart the client to load it.")


def cmd_scan(args):
    """Find credentials living outside the vault (env vars + common files)."""
    from agent_keychain.guard.env_scanner import scan_environment
    findings = scan_environment(extra_files=args.path or None)
    if not findings:
        print("No credentials found outside the vault. ✓")
        return

    # Group by source for a readable report (values are never shown).
    by_source: dict[str, list[dict]] = {}
    for f in findings:
        by_source.setdefault(f["source"], []).append(f)

    print(f"Found credentials outside the vault in {len(by_source)} location(s):\n")
    for source, items in by_source.items():
        kinds = ", ".join(f"{i['count']}x {i['type']}" for i in items)
        print(f"  {source}\n      {kinds}")
    print("\nThese are readable by any agent with shell access. Move them into the")
    print("vault so requests go through the proxy instead:")
    print("  agent-keychain store <name> --type <service> --allowed-domain <host>")


def cmd_delete(args):
    """Delete a credential from the OS keychain."""
    from agent_keychain.vault.keychain_vault import KeychainVault
    vault = KeychainVault()
    if vault.delete(args.name):
        print(f"Deleted '{args.name}'")
    else:
        print(f"Credential '{args.name}' not found.")


def main():
    parser = argparse.ArgumentParser(
        prog="agent-keychain",
        description="Credential isolation framework for AI coding agents",
    )
    sub = parser.add_subparsers(dest="command")

    # install
    sub.add_parser("install", help="Install credential guard hook for Claude Code")

    # uninstall
    sub.add_parser("uninstall", help="Remove credential guard hook")

    # store
    p_store = sub.add_parser("store", help="Store a credential in the OS keychain")
    p_store.add_argument("name", help="Credential name (e.g. github-personal)")
    p_store.add_argument("--type", required=True, dest="service_type", help="Service type (e.g. github, aws)")
    p_store.add_argument("--description", default="", help="Optional description")
    p_store.add_argument("--auth-type", default="bearer", dest="auth_type",
                         choices=["bearer", "basic", "api-key"],
                         help="Authentication type (default: bearer)")
    p_store.add_argument("--ttl", type=int, default=None,
                         help="Time-to-live in seconds (credential expires after this duration)")
    p_store.add_argument("--allowed-domain", dest="allowed_domain", action="append", default=[],
                         help="Domain this credential may be used against (repeatable, suffix match)")
    p_store.add_argument("--allow-any", dest="allow_any", action="store_true",
                         help="Store the credential unrestricted (sendable to any host) — use with care")
    p_store.add_argument("--rotate-after", dest="rotate_after", type=int, default=None,
                         help="Rotation policy in days; the credential is flagged overdue after this long")
    p_store.add_argument("--allowed-method", dest="allowed_method", action="append", default=[],
                         help="Restrict to an HTTP method (repeatable, e.g. GET). Default: any")
    p_store.add_argument("--allowed-path", dest="allowed_path", action="append", default=[],
                         help="Restrict to a URL path glob (repeatable, e.g. /repos/*). Default: any")
    p_store.add_argument("--rate-limit", dest="rate_limit", type=int, default=None,
                         help="Max requests per minute for this credential (default: unlimited)")
    p_store.add_argument("--allowed-command", dest="allowed_command", action="append", default=[],
                         help="Command this credential may be injected into via exec (repeatable, e.g. aws)")

    # list
    sub.add_parser("list", help="List stored credentials")

    # rotate
    p_rotate = sub.add_parser("rotate", help="Replace the secret for an existing credential")
    p_rotate.add_argument("name", help="Credential name to rotate")

    # scope
    p_scope = sub.add_parser("scope", help="Set request scope (methods/paths) for an existing credential")
    p_scope.add_argument("name", help="Credential name")
    p_scope.add_argument("--allowed-method", dest="allowed_method", action="append", default=[],
                         help="HTTP method to allow (repeatable)")
    p_scope.add_argument("--allowed-path", dest="allowed_path", action="append", default=[],
                         help="URL path glob to allow (repeatable)")

    # allow-domain
    p_allow = sub.add_parser("allow-domain", help="Add allowed domain(s) to an existing credential")
    p_allow.add_argument("name", help="Credential name")
    p_allow.add_argument("--allowed-domain", dest="allowed_domain", action="append", required=True,
                         help="Domain to allow (repeatable, suffix match)")

    # migrate
    sub.add_parser("migrate", help="Backfill allowed domains for credentials that have none")

    # audit
    p_audit = sub.add_parser("audit", help="Show recent credential-usage audit events")
    p_audit.add_argument("--limit", type=int, default=20, help="Max events to show (default: 20)")
    p_audit.add_argument("--credential", default=None, help="Filter by credential name")
    p_audit.add_argument("--blocked-only", dest="blocked_only", action="store_true",
                         help="Show only blocked (denied) requests")
    p_audit.add_argument("--suspicious", action="store_true",
                         help="Summarize repeated blocked requests (probing / misuse signal)")

    # exec
    p_exec = sub.add_parser("exec", help="Run a command with a stored secret injected (never exposed)")
    p_exec.add_argument("--credential", required=True, help="Credential to inject")
    p_exec.add_argument("--env", action="append", default=[],
                        help="Env var to set to the secret in the child (repeatable)")
    p_exec.add_argument("exec_command", nargs=argparse.REMAINDER, metavar="-- command ...",
                        help="-- followed by the command to run (use {secret} as an arg placeholder)")

    # allow-command
    p_allow_cmd = sub.add_parser("allow-command", help="Add allowed exec command(s) to a credential")
    p_allow_cmd.add_argument("name", help="Credential name")
    p_allow_cmd.add_argument("--command", action="append", required=True,
                             help="Command basename to allow (repeatable)")

    # import
    p_import = sub.add_parser("import", help="Import secrets from a KEY=value file into the vault")
    p_import.add_argument("--from-file", dest="from_file", required=True, help="File to import from (.env, credentials, ...)")
    p_import.add_argument("--type", default="", dest="type", help="Service type override for imported secrets")
    p_import.add_argument("--allowed-domain", dest="allowed_domain", action="append", default=[],
                          help="Bind imported secrets to a domain (repeatable)")
    p_import.add_argument("--allow-any", dest="allow_any", action="store_true", help="Import unrestricted")
    p_import.add_argument("--prefix", default="", help="Name prefix for imported credentials")
    p_import.add_argument("--scrub", action="store_true", help="Remove the secrets from the source file (keeps a .bak)")

    # register-mcp
    p_reg = sub.add_parser("register-mcp", help="Register the MCP server for Claude Code (or Cursor)")
    p_reg.add_argument("--cursor", action="store_true", help="Write Cursor config (.cursor/mcp.json) instead of .mcp.json")

    # scan
    p_scan = sub.add_parser("scan", help="Find credentials living outside the vault (env vars + common files)")
    p_scan.add_argument("--path", action="append", default=[],
                        help="Additional file to scan (repeatable)")

    # delete
    p_delete = sub.add_parser("delete", help="Delete a credential")
    p_delete.add_argument("name", help="Credential name to delete")

    args = parser.parse_args()

    commands = {
        "install": cmd_install,
        "uninstall": cmd_uninstall,
        "store": cmd_store,
        "list": cmd_list,
        "rotate": cmd_rotate,
        "scope": cmd_scope,
        "allow-domain": cmd_allow_domain,
        "migrate": cmd_migrate,
        "audit": cmd_audit,
        "exec": cmd_exec,
        "allow-command": cmd_allow_command,
        "import": cmd_import,
        "register-mcp": cmd_register_mcp,
        "scan": cmd_scan,
        "delete": cmd_delete,
    }

    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
