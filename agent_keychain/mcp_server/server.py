"""
Agent Keychain MCP Server
Exposes credential-proxied tools to AI agents via the Model Context Protocol.
Agents can make authenticated API calls without ever seeing the raw secrets.
"""

from mcp.server.fastmcp import FastMCP
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from agent_keychain.vault.keychain_vault import KeychainVault
from agent_keychain.vault.domain_policy import host_allowed, extract_host
from agent_keychain.vault.request_scope import method_allowed, path_allowed, extract_path
from agent_keychain.guard.credential_guard import redact, scan
from agent_keychain.proxy.process_pool import run_isolated_request
from agent_keychain.audit import audit_log
from agent_keychain.logging.logger import get_logger

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

    # Parse the destination host up front so it can be audited even on rejection.
    host = extract_host(url)

    # Check credential exists before spawning subprocess
    entry = vault.get(credential_name)
    if entry is None:
        audit_log.record(credential_name, host, method, audit_log.BLOCKED, "credential not found")
        return f"Error: Credential '{credential_name}' not found. Use list_available_credentials to see available options."

    if not host:
        audit_log.record(credential_name, host, method, audit_log.BLOCKED, "unparseable url")
        return f"Error: Could not parse a hostname from '{url}'."

    # Enforce domain binding: a credential may only be used against the
    # domains it is bound to. This prevents a prompt-injected agent from
    # exfiltrating the token by pointing the request at an arbitrary host.
    if not host_allowed(host, entry.allowed_domains):
        if not entry.allowed_domains:
            audit_log.record(credential_name, host, method, audit_log.BLOCKED, "no allowed domains")
            log.warning("Blocked request: credential '%s' has no allowed domains (host: %s)", credential_name, host)
            return (
                f"Error: credential '{credential_name}' has no allowed domains, "
                f"so it is blocked from all requests (deny-by-default). "
                f"Run: agent-keychain migrate  (to backfill from service type)  or  "
                f"agent-keychain allow-domain {credential_name} --allowed-domain {host}"
            )
        audit_log.record(credential_name, host, method, audit_log.BLOCKED, "host not in allowed domains")
        log.warning("Blocked request: credential '%s' not allowed to call '%s' (allowed: %s)", credential_name, host, ", ".join(entry.allowed_domains))
        return (
            f"Error: credential '{credential_name}' is not allowed to call '{host}'. "
            f"Allowed: {', '.join(entry.allowed_domains)}. "
            f"To permit: agent-keychain allow-domain {credential_name} --allowed-domain {host}"
        )

    # Enforce least-privilege request scope (method + path), if set.
    if not method_allowed(method, entry.allowed_methods):
        audit_log.record(credential_name, host, method, audit_log.BLOCKED, "method not in scope")
        return (
            f"Error: credential '{credential_name}' is not allowed to use method '{method}'. "
            f"Allowed: {', '.join(entry.allowed_methods)}."
        )
    path = extract_path(url)
    if not path_allowed(path, entry.allowed_paths):
        audit_log.record(credential_name, host, method, audit_log.BLOCKED, "path not in scope")
        return (
            f"Error: credential '{credential_name}' is not allowed to access path '{path}'. "
            f"Allowed: {', '.join(entry.allowed_paths)}."
        )

    # Outbound secret-smuggling guard: block if the URL or body carries OTHER
    # credentials. This stops a prompt-injected agent from exfiltrating a
    # second secret by hiding it in a request to an otherwise-allowed host.
    smuggled = scan(url + "\n" + body)
    if smuggled:
        kinds = ", ".join(f["type"] for f in smuggled)
        audit_log.record(credential_name, host, method, audit_log.BLOCKED, f"secret in request ({kinds})")
        log.warning("Blocked request: credential material detected in outbound request (%s)", kinds)
        return (
            f"Error: request blocked — it contains what looks like credential material "
            f"({kinds}) in the URL or body. Secrets must not be sent through this proxy."
        )

    auth_type = entry.auth_type

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
        audit_log.record(credential_name, host, method, audit_log.ALLOWED, "ok",
                         status=result.get("status"), success=True)
        return f"Status: {result['status']}\n\n{result['body']}"
    else:
        audit_log.record(credential_name, host, method, audit_log.ALLOWED, result.get("error", "request failed"),
                         status=result.get("status"), success=False)
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