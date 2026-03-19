"""
Agent Keychain Intent Proxy
A local proxy server that handles credential-bearing API calls
on behalf of AI agents, ensuring secrets never enter the agent's context.
"""

import json
import os
import socket
import threading
import urllib.request
import urllib.error
from typing import Optional

from src.vault.keychain_vault import KeychainVault

class IntentProxy:
    """
    Local proxy server communicating over a Unix Domain Socket.

    Agents send intents (e.g. "call GitHub API") and receive responses without
    ever seeing the underlying credentials.
    The socket file is created with restricted permissions (owner-only).
    """

    DEFAULT_SOCKET_PATH = "/tmp/agent-keychain.sock"

    def __init__(self, vault: KeychainVault, socket_path: Optional[str] = None):
        self._vault = vault
        self._socket_path = socket_path or self.DEFAULT_SOCKET_PATH
        self._server: Optional[socket.socket] = None
        self._running = False

    def start(self):
        """Start listening for agent requests on the Unix Domain Socket."""
        # Remove stale socket file if it exists
        if os.path.exists(self._socket_path):
            os.unlink(self._socket_path)
        
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(self._socket_path)

        # Restrict socket permissions to owner only (rw-------)
        os.chmod(self._socket_path, 0o600)

        self._server.listen(5)
        self._running = True

        print(f"[proxy] Listening on {self._socket_path}")

        while self._running:
            try:
                self._server.settimeout(1.0)
                conn, _ = self._server.accept()
                thread = threading.Thread(
                    target=self._handle_connection,
                    args=(conn,),
                    daemon=True
                )
                thread.start()
            except socket.timeout:
                continue
            except OSError:
                break
    
    def stop(self):
        """Shut down the proxy server and clean up the socket file."""
        self._running = False
        if self._server:
            self._server.close()
        if os.path.exists(self._socket_path):
            os.unlink(self._socket_path)
        print("[proxy] Stopped")
    
    def _handle_connection(self, conn: socket.socket):
        """Handle a single agent connection. Read intent, execute, return result."""
        try:
            data = self._recv_all(conn)
            if not data:
                return
            
            request = json.loads(data)
            response = self._execute_intent(request)

            conn.sendall(json.dumps(response).encode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            error_resp = {"success": False, "error": "Invalid request format"}
            conn.sendall(json.dumps(error_resp).encode("utf-8"))
        except Exception:
            error_resp = {"success": False, "error": "Internal proxy error"}
            conn.sendall(json.dumps(error_resp).encode("utf-8"))
        finally:
            conn.close()

    def _recv_all(self, conn: socket.socket, buffer_size: int = 65536) -> str:
        """Read all data from the socket connection."""
        conn.settimeout(5.0)
        chunks = []
        while True:
            try:
                chunk = conn.recv(buffer_size)
                if not chunk:
                    break
                chunks.append(chunk)
                if len(chunk) < buffer_size:
                    break
            except socket.timeout:
                break
        return b"".join(chunks).decode("utf-8")
    
    def _execute_intent(self, request: dict) -> dict:
        """
        Execute an agent's intent using stored credentials.
        The credential value is used internally but never returned to the agent.

        Supported intents:
            - http_request: Make an HTTP request with credential injected in headers
            - list_credentials: List available credential names (no secret values)
            - ping: Health check
        """
        intent = request.get("intent")

        if intent == "ping":
            return {"success": True, "message": "proxy is running"}
        
        if intent == "list_credentials":
            creds = self._vault.list_credentials()
            return {
                "success": True,
                "credentials": [
                    {"name": c.name, "service_type": c.service_type}
                    for c in creds
                ],
            }
        
        if intent == "http_request":
            return self._handle_http_request(request)
        
        return {"success": False, "error": f"Unknown intent: {intent}"}
    
    def _handle_http_request(self, request: dict) -> dict:
        """
        Execute an HTTP request with the credential injected into the
        Authorization header. The agent never sees the raw credential.
        """
        credential_name = request.get("credential")
        url = request.get("url")
        method = request.get("method", "GET").upper()

        if not credential_name or not url:
            return {"success": False, "error": "Missing 'credential' or 'url'"}
        
        # Validate URL scheme to prevent SSRF
        if not url.startswith("https://"):
            return {"success": False, "error": "Only HTTPS URLs are allowed"}
        
        # Retrieve the secret from the vault (stays in proxy memory only)
        secret = self._vault.retrieve(credential_name)
        if secret is None:
            return {"success": False, "error": f"Credential '{credential_name}' not found"}
        
        try:
            req = urllib.request.Request(url, method=method)
            req.add_header("Authorization", f"Bearer {secret}")
            req.add_header("User-Agent", "agent-keychain-proxy/0.1")

            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                # Scrub the credential from the response in case of echo-back
                safe_body = body.replace(secret, "[REDACTED]")

                return {
                    "success": True,
                    "status": resp.status,
                    "body": safe_body,
                }
        except urllib.error.HTTPError as e:
            return {
                "success": False,
                "status": e.code,
                "error": f"HTTP {e.code}",
            }
        except urllib.error.URLError:
            return {"success": False, "error": "Connection failed"}
        except Exception:
            return {"success": False, "error": "Request failed"}