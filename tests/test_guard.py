"""Tests for Credential Guard redaction and scanning."""
import pytest
from src.guard.credential_guard import redact, scan


def test_redact_github_token():
    """GitHub classic token should be redacted."""
    content = "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
    redacted, findings = redact(content)
    assert "ghp_" not in redacted
    assert "[REDACTED:GitHub Token (classic)]" in redacted
    assert findings[0]["type"] == "GitHub Token (classic)"


def test_redact_aws_access_key():
    """AWS access key should be redacted."""
    content = "aws_key=AKIAIOSFODNN7EXAMPLE"
    redacted, findings = redact(content)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "[REDACTED:AWS Access Key]" in redacted


def test_redact_private_key():
    """Private key block should be redacted."""
    content = "-----BEGIN RSA PRIVATE KEY-----\nMIIBog...\n-----END RSA PRIVATE KEY-----"
    redacted, findings = redact(content)
    assert "MIIBog" not in redacted
    assert "[REDACTED:Private Key Block]" in redacted


def test_redact_database_url():
    """Database URL with password should be redacted."""
    content = "DATABASE_URL=postgresql://admin:SuperSecret@db.example.com:5432/prod"
    redacted, findings = redact(content)
    assert "SuperSecret" not in redacted
    assert "[REDACTED:Database URL with Password]" in redacted


def test_redact_multiple_credentials():
    """Multiple credentials in same content should all be redacted."""
    content = (
        "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n"
        "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
    )
    redacted, findings = redact(content)
    assert len(findings) == 2


def test_no_credentials():
    """Content without credentials should pass through unchanged."""
    content = "hello world\nno secrets here\n"
    redacted, findings = redact(content)
    assert redacted == content
    assert findings == []


def test_scan_returns_findings_only():
    """scan() should return findings without modifying content."""
    content = "key=AKIAIOSFODNN7EXAMPLE"
    findings = scan(content)
    assert len(findings) == 1
    assert findings[0]["type"] == "AWS Access Key"
    assert findings[0]["count"] == 1
