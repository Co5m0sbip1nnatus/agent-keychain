"""Utility script to store a credential in the vault."""
import argparse
import getpass
from src.vault.keychain_vault import KeychainVault

EXAMPLES = """
examples:
  # Store a GitHub personal access token
  python store_credential.py github-personal --type github --description "Personal access token"

  # Store an AWS key
  python store_credential.py aws-prod --type aws --description "Production AWS account"

  # Store a Slack bot token
  python store_credential.py slack-bot --type slack

  # View this help message
  python store_credential.py -h
"""

parser = argparse.ArgumentParser(
    description="Store a credential in Agent Keychain. "
                "The secret is saved to your OS keychain (macOS Keychain / Linux SecretService) "
                "and never written to a file. AI agents access it via the MCP server without seeing the raw value.",
    epilog=EXAMPLES,
    formatter_class=argparse.RawDescriptionHelpFormatter,
)
parser.add_argument("name", help="Credential name used to reference it later (e.g. github-personal)")
parser.add_argument("--type", required=True, dest="service_type",
                    help="Service type (e.g. github, aws, slack, openai)")
parser.add_argument("--description", default="", help="Optional human-readable description")
args = parser.parse_args()

vault = KeychainVault()
secret = getpass.getpass("Secret: ")
vault.store(args.name, secret, args.service_type, args.description)
print(f"Stored '{args.name}' ({args.service_type})")
