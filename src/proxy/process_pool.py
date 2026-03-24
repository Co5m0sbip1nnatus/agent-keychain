"""
Process-isolated credential request runner.

Spawns src/proxy/isolated_request.py as a short-lived subprocess so that
credentials are never held in the long-lived MCP server process. The
subprocess retrieves the credential from the OS keychain, makes the HTTP
request, scrubs the credential from the response, prints JSON to stdout,
and exits -- releasing all memory.

Usage from the MCP server:

    from src.proxy.process_pool import run_isolated_request

    result = run_isolated_request(
        credential_name="github-token",
        url="https://api.github.com/user",
        method="GET",
    )
"""

import json
import os
import subprocess
import sys
from typing import Optional

from src.logging.logger import get_logger

log = get_logger("process_pool")

# Path to the isolated request script
_ISOLATED_SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "isolated_request.py",
)

# Use the same Python interpreter that is running the current process.
# This ensures the subprocess has access to the same packages / venv.
_PYTHON = sys.executable

# Maximum time (seconds) the subprocess is allowed to run before being killed.
DEFAULT_TIMEOUT = 15


def run_isolated_request(
    credential_name: str,
    url: str,
    method: str = "GET",
    body: str = "",
    auth_type: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> str:
    """
    Spawn a short-lived subprocess to make a credential-bearing HTTP request.

    The subprocess:
      1. Receives request params via stdin (JSON).
      2. Retrieves the credential from the OS keychain.
      3. Makes the HTTP request with the proper auth header.
      4. Scrubs the credential from the response.
      5. Returns the result as JSON on stdout.
      6. Exits, releasing all memory that held the credential.

    Args:
        credential_name: Name of the credential stored in the keychain.
        url: The HTTPS URL to request.
        method: HTTP method (GET, POST, PUT, DELETE, PATCH).
        body: Optional request body (JSON string) for POST/PUT/PATCH.
        auth_type: Auth header style ("bearer", "basic", "api-key").
                   If None, the credential's stored auth_type is used.
        timeout: Maximum seconds to wait for the subprocess (default 15).

    Returns:
        A JSON string with the subprocess result.  The caller should
        json.loads() it to inspect ``success``, ``status``, ``body``, or
        ``error`` fields.
    """
    payload = {
        "credential_name": credential_name,
        "url": url,
        "method": method,
        "body": body,
    }
    if auth_type is not None:
        payload["auth_type"] = auth_type

    stdin_data = json.dumps(payload)

    log.info(
        "Spawning isolated request: %s %s (credential: %s)",
        method,
        url,
        credential_name,
    )

    try:
        proc = subprocess.run(
            [_PYTHON, _ISOLATED_SCRIPT],
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=timeout,
            # Inherit the current environment so keyring backend detection
            # and any venv paths work correctly.
            env=os.environ.copy(),
        )
    except subprocess.TimeoutExpired:
        log.error(
            "Isolated request timed out after %ds: %s %s",
            timeout,
            method,
            url,
        )
        return json.dumps({
            "success": False,
            "error": f"Isolated request timed out after {timeout} seconds.",
        })
    except OSError as exc:
        log.error("Failed to spawn isolated request subprocess: %s", exc)
        return json.dumps({
            "success": False,
            "error": f"Failed to spawn subprocess: {exc}",
        })

    stdout = proc.stdout.strip()
    stderr = proc.stderr.strip()

    if proc.returncode != 0 and not stdout:
        # The subprocess crashed without producing JSON output.
        log.error(
            "Isolated request exited with code %d; stderr: %s",
            proc.returncode,
            stderr[:500],
        )
        return json.dumps({
            "success": False,
            "error": f"Subprocess exited with code {proc.returncode}",
        })

    if stderr:
        # Log stderr for diagnostics but don't expose to the caller --
        # it may contain tracebacks that leak internal paths.
        log.warning("Isolated request stderr: %s", stderr[:500])

    # Validate that the subprocess produced valid JSON.
    try:
        json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        log.error("Isolated request returned invalid JSON: %s", stdout[:200])
        return json.dumps({
            "success": False,
            "error": "Subprocess returned invalid output.",
        })

    log.info("Isolated request completed: %s %s", method, url)
    return stdout
