"""
Credential-injecting exec wrapper.

Runs a subprocess with a stored secret injected into its environment (and/or a
`{secret}` placeholder in its arguments), so tools that don't speak HTTP — git,
aws, gcloud, psql, docker — can authenticate without the secret ever entering
the agent's context.

Guarantees:
  - The command must be on the credential's allowlist (deny-by-default).
  - The secret is retrieved, used, and scrubbed within this short-lived process.
  - The child's stdout/stderr are run through response DLP before being shown,
    so the secret (and any other credential) can't echo back to the agent.

Honest limitation: the agent chooses the command, so even an allowlisted binary
could in principle be coerced into leaking. The allowlist bounds *which* tools a
credential can touch; it is not a full sandbox. See SECURITY.md.
"""

import os
import subprocess

from agent_keychain.vault.command_policy import command_allowed
from agent_keychain.guard.credential_guard import scrub_response

PLACEHOLDER = "{secret}"


def run(vault, credential_name: str, env_names: list[str], command: list[str]) -> dict:
    """Run ``command`` with the credential injected. Returns a result dict.

    Result keys:
      ok (bool); on success: returncode, stdout, stderr, redacted (list[str]);
      on failure: error (str), blocked (bool, True for a policy denial).
    Output is already DLP-scrubbed. Never returns the raw secret.
    """
    if not command:
        return {"ok": False, "error": "no command given", "blocked": False}

    entry = vault.get(credential_name)
    if entry is None:
        return {"ok": False, "error": f"credential '{credential_name}' not found", "blocked": False}

    program = command[0]
    if not command_allowed(program, entry.allowed_commands):
        allowed = ", ".join(entry.allowed_commands) or "(none)"
        return {
            "ok": False,
            "blocked": True,
            "error": (f"credential '{credential_name}' is not allowed to run '{os.path.basename(program)}'. "
                      f"Allowed commands: {allowed}. "
                      f"To permit: agent-keychain allow-command {credential_name} --command {os.path.basename(program)}"),
        }

    secure = vault.retrieve(credential_name)
    if secure is None:
        return {"ok": False, "error": f"credential '{credential_name}' not found or expired", "blocked": False}

    with secure as ss:
        secret = ss.value
        child_env = dict(os.environ)
        for name in env_names:
            child_env[name] = secret
        argv = [arg.replace(PLACEHOLDER, secret) for arg in command]
        try:
            proc = subprocess.run(argv, env=child_env, capture_output=True, text=True)
        except FileNotFoundError:
            return {"ok": False, "error": f"command not found: {program}", "blocked": False}
        except OSError as exc:
            return {"ok": False, "error": f"failed to run command: {exc}", "blocked": False}

        out, red_out = scrub_response(proc.stdout, secret)
        err, red_err = scrub_response(proc.stderr, secret)

    return {
        "ok": True,
        "returncode": proc.returncode,
        "stdout": out,
        "stderr": err,
        "redacted": sorted(set(red_out + red_err)),
    }
