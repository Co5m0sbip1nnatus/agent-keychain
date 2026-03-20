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


def cmd_store(args):
    """Store a credential in the OS keychain."""
    from src.vault.keychain_vault import KeychainVault
    vault = KeychainVault()
    secret = getpass.getpass("Secret: ")
    vault.store(args.name, secret, args.service_type, args.description)
    print(f"Stored '{args.name}' ({args.service_type})")


def cmd_list(args):
    """List all stored credentials."""
    from src.vault.keychain_vault import KeychainVault
    vault = KeychainVault()
    creds = vault.list_credentials()
    if not creds:
        print("No credentials stored.")
        return
    for c in creds:
        desc = f" — {c.description}" if c.description else ""
        print(f"  {c.name} ({c.service_type}){desc}")


def cmd_delete(args):
    """Delete a credential from the OS keychain."""
    from src.vault.keychain_vault import KeychainVault
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

    # list
    sub.add_parser("list", help="List stored credentials")

    # delete
    p_delete = sub.add_parser("delete", help="Delete a credential")
    p_delete.add_argument("name", help="Credential name to delete")

    args = parser.parse_args()

    commands = {
        "install": cmd_install,
        "uninstall": cmd_uninstall,
        "store": cmd_store,
        "list": cmd_list,
        "delete": cmd_delete,
    }

    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
