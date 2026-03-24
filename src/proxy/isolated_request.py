"""
Isolated credential-bearing HTTP request subprocess.

This script is designed to be spawned as a short-lived subprocess by the MCP
server (via process_pool.run_isolated_request). It:

  1. Reads request parameters from stdin (JSON)
  2. Retrieves the credential from the OS keychain
  3. Makes the HTTP request with the proper auth header
  4. Scrubs the credential from the response
  5. Prints the result as JSON to stdout
  6. Exits -- releasing all memory that held the credential

By running in a separate process, the credential never resides in the
long-lived MCP server's address space.
"""

import json
import sys
import os
import base64
import urllib.request
import urllib.error

# Allow imports from project root regardless of working directory
_project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, _project_root)

from src.vault.keychain_vault import KeychainVault


def _build_auth_header(auth_type: str, secret: str) -> tuple[str, str]:
    """Return (header_name, header_value) for the given auth type."""
    if auth_type == "basic":
        encoded = base64.b64encode(secret.encode("utf-8")).decode("utf-8")
        return ("Authorization", f"Basic {encoded}")
    elif auth_type == "api-key":
        return ("X-API-Key", secret)
    else:
        # Default: bearer token
        return ("Authorization", f"Bearer {secret}")


def _resolve_auth_type(vault: KeychainVault, credential_name: str, requested_auth_type: str | None) -> str:
    """
    Determine the auth type to use. If the caller specified one, use it;
    otherwise look up the credential's stored auth_type metadata.
    """
    if requested_auth_type:
        return requested_auth_type

    for entry in vault.list_credentials():
        if entry.name == credential_name:
            return entry.auth_type
    return "bearer"


def main() -> None:
    """Entry point -- read stdin, make request, write stdout, exit."""
    result: dict

    try:
        raw_input = sys.stdin.read()
        params = json.loads(raw_input)
    except (json.JSONDecodeError, ValueError) as exc:
        result = {"success": False, "error": f"Invalid JSON input: {exc}"}
        sys.stdout.write(json.dumps(result))
        sys.exit(1)

    credential_name: str = params.get("credential_name", "")
    url: str = params.get("url", "")
    method: str = params.get("method", "GET").upper()
    body: str = params.get("body", "")
    auth_type: str | None = params.get("auth_type")  # None means "use stored default"

    # --- Validate inputs ---
    if not credential_name:
        result = {"success": False, "error": "Missing 'credential_name'"}
        sys.stdout.write(json.dumps(result))
        sys.exit(1)

    if not url:
        result = {"success": False, "error": "Missing 'url'"}
        sys.stdout.write(json.dumps(result))
        sys.exit(1)

    if not url.startswith("https://"):
        result = {"success": False, "error": "Only HTTPS URLs are allowed for security."}
        sys.stdout.write(json.dumps(result))
        sys.exit(1)

    allowed_methods = {"GET", "POST", "PUT", "DELETE", "PATCH"}
    if method not in allowed_methods:
        result = {"success": False, "error": f"Method must be one of {', '.join(sorted(allowed_methods))}"}
        sys.stdout.write(json.dumps(result))
        sys.exit(1)

    # --- Retrieve credential ---
    vault = KeychainVault()
    secret = vault.retrieve(credential_name)

    if secret is None:
        result = {
            "success": False,
            "error": f"Credential '{credential_name}' not found. "
                     "Use list_available_credentials to see available options.",
        }
        sys.stdout.write(json.dumps(result))
        sys.exit(1)

    resolved_auth_type = _resolve_auth_type(vault, credential_name, auth_type)

    # --- Make the HTTP request ---
    try:
        data = body.encode("utf-8") if body else None
        req = urllib.request.Request(url, data=data, method=method)

        header_name, header_value = _build_auth_header(resolved_auth_type, secret)
        req.add_header(header_name, header_value)
        req.add_header("User-Agent", "agent-keychain-mcp/0.1")
        if data:
            req.add_header("Content-Type", "application/json")

        with urllib.request.urlopen(req, timeout=15) as resp:
            resp_body = resp.read().decode("utf-8", errors="replace")

            # Scrub the credential from the response to prevent echo-back leakage
            safe_body = resp_body.replace(secret, "[REDACTED]")

            result = {
                "success": True,
                "status": resp.status,
                "body": safe_body,
            }

    except urllib.error.HTTPError as exc:
        result = {"success": False, "error": f"HTTP Error: {exc.code}", "status": exc.code}
    except urllib.error.URLError as exc:
        result = {"success": False, "error": f"Could not connect to {url} — {exc.reason}"}
    except TimeoutError:
        result = {"success": False, "error": f"Request to {url} timed out after 15 seconds."}
    except Exception as exc:
        result = {"success": False, "error": f"Request failed — {type(exc).__name__}"}

    # --- Write result and exit ---
    # Explicitly clear the secret from local scope before writing output
    secret = None  # noqa: F841

    sys.stdout.write(json.dumps(result))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
