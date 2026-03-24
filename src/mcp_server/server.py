"""
Agent Keychain MCP Server
Exposes credential-proxied tools to AI agents via the Model Context Protocol.
Agents can make authenticated API calls without ever seeing the raw secrets.
"""

from mcp.server.fastmcp import FastMCP
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from src.vault.keychain_vault import KeychainVault
from src.guard.credential_guard import redact, scan
from src.proxy.process_pool import run_isolated_request
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
    
    # Check credential exists before spawning subprocess
    if not vault.has(credential_name):
        return f"Error: Credential '{credential_name}' not found. Use list_available_credentials to see available options."

    # Get auth type from credential metadata
    creds = vault.list_credentials()
    auth_type = "bearer"
    for c in creds:
        if c.name == credential_name:
            auth_type = c.auth_type
            break

    # Run the HTTP request in an isolated subprocess.
    # The credential is retrieved, used, and scrubbed entirely within
    # the subprocess — it never enters the MCP server's memory.
    import json
    raw = run_isolated_request(
        credential_name=credential_name,
        url=url,
        method=method,
        body=body,
        auth_type=auth_type,
    )
    result = json.loads(raw)

    if result.get("success"):
        return f"Status: {result['status']}\n\n{result['body']}"
    else:
        log.warning("Request failed for %s %s: %s", method, url, result.get("error", "unknown"))
        return f"Error: {result.get('error', 'Request failed')}"

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