"""Tests for outbound response DLP (credential_guard.scrub_response)."""
from agent_keychain.guard.credential_guard import scrub_response


def test_scrubs_injected_secret():
    secret = "super-secret-token-value"
    body, redacted = scrub_response(f'{{"echo": "{secret}"}}', injected_secret=secret)
    assert secret not in body
    assert "[REDACTED]" in body


def test_redacts_other_secret_in_response():
    # An API that returns a *new* token must not leak it back to the agent.
    new_token = "ghp_" + "A" * 36
    body, redacted = scrub_response(f'{{"new_token": "{new_token}"}}', injected_secret="unrelated")
    assert new_token not in body
    assert any("GitHub" in r for r in redacted)


def test_clean_response_untouched():
    body, redacted = scrub_response('{"ok": true}', injected_secret="x")
    assert body == '{"ok": true}'
    assert redacted == []


def test_handles_empty_injected_secret():
    aws = "AKIA" + "B" * 16
    body, redacted = scrub_response(f"key={aws}")
    assert aws not in body
    assert redacted  # AWS key still caught by general DLP
