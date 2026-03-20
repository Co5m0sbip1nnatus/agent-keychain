"""
Agent Keychain Installer
Registers the credential guard hook in Claude Code's global settings
so that all projects are protected automatically.
"""
import argparse
import json
import os
import shutil
import sys

CLAUDE_DIR = os.path.expanduser("~/.claude")
SETTINGS_PATH = os.path.join(CLAUDE_DIR, "settings.json")
HOOK_INSTALL_DIR = os.path.join(CLAUDE_DIR, "hooks")
HOOK_SCRIPT_NAME = "credential-guard.sh"
HOOK_SOURCE = os.path.join(os.path.dirname(__file__), "src", "hooks", HOOK_SCRIPT_NAME)

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


def install():
    # Copy hook script to ~/.claude/hooks/
    os.makedirs(HOOK_INSTALL_DIR, exist_ok=True)
    dest = os.path.join(HOOK_INSTALL_DIR, HOOK_SCRIPT_NAME)
    shutil.copy2(HOOK_SOURCE, dest)
    os.chmod(dest, 0o755)

    # Update settings.json
    settings = load_settings()

    if "hooks" not in settings:
        settings["hooks"] = {}
    if "PreToolUse" not in settings["hooks"]:
        settings["hooks"]["PreToolUse"] = []

    # Check if already installed
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


def uninstall():
    # Remove from settings.json
    settings = load_settings()
    pre_tool = settings.get("hooks", {}).get("PreToolUse", [])
    settings["hooks"]["PreToolUse"] = [
        entry for entry in pre_tool
        if not any(HOOK_SCRIPT_NAME in h.get("command", "") for h in entry.get("hooks", []))
    ]

    # Clean up empty structures
    if not settings["hooks"]["PreToolUse"]:
        del settings["hooks"]["PreToolUse"]
    if not settings["hooks"]:
        del settings["hooks"]

    save_settings(settings)

    # Remove hook script
    dest = os.path.join(HOOK_INSTALL_DIR, HOOK_SCRIPT_NAME)
    if os.path.exists(dest):
        os.remove(dest)

    print("Agent Keychain uninstalled.")
    print("Restart Claude Code to apply.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Install or uninstall Agent Keychain credential guard")
    parser.add_argument("action", choices=["install", "uninstall"], help="install or uninstall the credential guard hook")
    args = parser.parse_args()

    if args.action == "install":
        install()
    else:
        uninstall()
