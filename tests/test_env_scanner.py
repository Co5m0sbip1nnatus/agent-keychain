"""Tests for the out-of-vault credential discovery scanner."""
import pytest
from agent_keychain.guard import env_scanner


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    # Start from a minimal environment so host secrets don't leak into asserts.
    for var in list(env_scanner.os.environ):
        monkeypatch.delenv(var, raising=False)


def test_detects_secret_pattern_in_env(monkeypatch):
    monkeypatch.setenv("SOME_VAR", "ghp_" + "A" * 36)
    findings = env_scanner.scan_environment(include_cwd_env=False)
    assert any(f["source"] == "env:SOME_VAR" and "GitHub" in f["type"] for f in findings)


def test_detects_secret_by_var_name(monkeypatch):
    monkeypatch.setenv("MY_API_TOKEN", "not-a-known-pattern-but-named-like-a-secret")
    findings = env_scanner.scan_environment(include_cwd_env=False)
    assert any(f["source"] == "env:MY_API_TOKEN" for f in findings)


def test_ignores_empty_and_innocuous(monkeypatch):
    monkeypatch.setenv("PATH_LIKE", "/usr/bin:/bin")
    monkeypatch.setenv("EMPTY_TOKEN", "")
    findings = env_scanner.scan_environment(include_cwd_env=False)
    assert findings == []


def test_scans_extra_file_without_exposing_value(tmp_path, monkeypatch):
    secret_file = tmp_path / "creds.txt"
    secret_file.write_text("aws_key = AKIA" + "A" * 16 + "\n")
    findings = env_scanner.scan_environment(extra_files=[str(secret_file)], include_cwd_env=False)
    matched = [f for f in findings if f["source"] == str(secret_file)]
    assert matched
    # Findings carry only type/count/source — never the secret value.
    for f in matched:
        assert set(f.keys()) == {"source", "type", "count"}
