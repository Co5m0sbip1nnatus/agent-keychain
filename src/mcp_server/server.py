"""
Agent Keychain MCP Server
Exposes credential-proxied tools to AI agents via the Model Context Protocol.
Agents can make authenticated API calls without ever seeing the raw secrets.
"""

import urllib.request
import urllib.error

from mcp.server.fastmcp import FastMCP
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from src.vault.keychain_vault import KeychainVault
from src.guard.credential_guard import redact, scan
from src.logging.logger import get_logger

log = get_logger("mcp")
vault = KeychainVault()
mcp = FastMCP("agent-keychain")

@mcp.tool()
def check_connection() -> str:
    """Check if the Agent Keychain proxy is running and accessible."""
    count = len(vault.list_credentials())
    return f"Agent Keychain is active. {count} credential(s) available."

@mcp.tool()
def list_available_credentials() -> str:
    """
    List all stored credential names and their service types.
    No secret values are ever returned -- only names and types.
    Use this to discover which credentials are available before making requests.
    """
    creds = vault.list_credentials()
    if not creds:
        return "No credentials stored. Use the CLI to add credentials first."
    
    result = []
    for c in creds:
        result.append(f"- {c.name} (type: {c.service_type})")
    return "Available credentials:\n" + "\n".join(result)

@mcp.tool()
def secure_http_request(credential_name: str, url: str, method: str = "GET", body: str = "") -> str:
    """
    Make an authenticated HTTP request using a stored credential.
    The credential is injected into the Authorization header by the proxy --
    it never appears in the request or response visible to the agent.

    Use this tool whenever you need to call an external API that requires
    authentication, instead of reading tokens or API keys directly.

    Args:
        credential_name: Name of the stored credential to use (see list_available_credentials)
        url: The HTTPS URL to request
        method: HTTP method (GET, POST, PUT, DELETE, PATCH)
        body: Optional JSON request body for POST/PUT/PATCH requests
    """
    # Validate URL scheme to prevent SSRF
    if not url.startswith("https://"):
        return "Error: Only HTTPS URLs are allowed for security."
    
    # Validate HTTP method
    allowed_methods = {"GET", "POST", "PUT", "DELETE", "PATCH"}
    method = method.upper()
    if method not in allowed_methods:
        return f"Error: Method must be one of {', '.join(sorted(allowed_methods))}"
    
    # Retrieve credential from the vault (never exposed to the agent)
    secret = vault.retrieve(credential_name)
    if secret is None:
        return f"Error: Credential '{credential_name}' not found. Use list_available_credentials to see available options."

    # Get auth type from credential metadata
    creds = vault.list_credentials()
    auth_type = "bearer"
    for c in creds:
        if c.name == credential_name:
            auth_type = c.auth_type
            break

    try:
        data = body.encode("utf-8") if body else None
        req = urllib.request.Request(url, data=data, method=method)

        # Apply authentication based on auth_type
        if auth_type == "bearer":
            req.add_header("Authorization", f"Bearer {secret}")
        elif auth_type == "basic":
            import base64
            encoded = base64.b64encode(secret.encode("utf-8")).decode("utf-8")
            req.add_header("Authorization", f"Basic {encoded}")
        elif auth_type == "api-key":
            req.add_header("X-API-Key", secret)

        req.add_header("User-Agent", "agent-keychain-mcp/0.1")
        if data:
            req.add_header("Content-Type", "application/json")

        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            # Scrub credential from response to prevent echo-back leakage
            safe_body = body.replace(secret, "[REDACTED]")
            return f"Status: {resp.status}\n\n{safe_body}"
    
    except urllib.error.HTTPError as e:
        log.warning("HTTP %d for %s %s (credential: %s)", e.code, method, url, credential_name)
        return f"HTTP Error: {e.code}"
    except urllib.error.URLError as e:
        log.error("Connection failed for %s: %s", url, e.reason)
        return f"Error: Could not connect to {url} — {e.reason}"
    except TimeoutError:
        log.error("Request timed out for %s %s", method, url)
        return f"Error: Request to {url} timed out after 15 seconds."
    except Exception as e:
        log.error("Unexpected error for %s %s: %s", method, url, type(e).__name__)
        return f"Error: Request failed — {type(e).__name__}"

@mcp.tool()
def safe_read_file(file_path: str) -> str:
    """
    Read a file with automatic credential redaction.
    Any detected credentials (API keys, tokens, passwords, private keys)
    are replaced with [REDACTED] before the content reaches the agent.

    Use this instead of reading files directly when the file might contain secrets.

    Args:
        file_path: Absolute or relative path to the file to read
    """
    import os
    if not os.path.isfile(file_path):
        return f"Error: File '{file_path}' not found."

    try:
        with open(file_path, "r", errors="replace") as f:
            content = f.read()
    except PermissionError:
        return f"Error: Permission denied for '{file_path}'."

    redacted_content, findings = redact(content)

    if findings:
        summary = ", ".join(f"{f['count']} {f['type']}" for f in findings)
        log.info("Redacted credentials in '%s': %s", file_path, summary)
        header = f"[Credential Guard: redacted {summary}]\n\n"
        return header + redacted_content

    log.debug("No credentials found in '%s'", file_path)
    return redacted_content


@mcp.tool()
def scan_file_for_secrets(file_path: str) -> str:
    """
    Scan a file for credential patterns without returning its contents.
    Returns a report of what types of credentials were detected.

    Use this to check if a file contains secrets before reading it.

    Args:
        file_path: Absolute or relative path to the file to scan
    """
    import os
    if not os.path.isfile(file_path):
        return f"Error: File '{file_path}' not found."

    try:
        with open(file_path, "r", errors="replace") as f:
            content = f.read()
    except PermissionError:
        return f"Error: Permission denied for '{file_path}'."

    findings = scan(content)

    if not findings:
        return f"No credentials detected in '{file_path}'."

    result = f"Credentials detected in '{file_path}':\n"
    for f in findings:
        result += f"- {f['type']}: {f['count']} occurrence(s)\n"
    return result


if __name__ == "__main__":
    mcp.run(transport="stdio")