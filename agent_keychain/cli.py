"""
Agent Keychain CLI
Unified entry point for all agent-keychain commands.
"""
import argparse
import getpass
import json
import os
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
                allowed_methods=args.allowed_method, allowed_paths=args.allowed_path)
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
        print(f"  {e.get('ts','')}  {mark:7}  {e.get('credential','')} "
              f"{e.get('method','')} {e.get('host','')}{status_str}{reason_str}")


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
        "delete": cmd_delete,
    }

    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
