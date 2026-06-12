"""Tests for least-privilege request scoping (methods/paths)."""
from agent_keychain.vault.request_scope import (
    extract_path,
    method_allowed,
    path_allowed,
)


def test_extract_path():
    assert extract_path("https://api.github.com/repos/o/n?x=1") == "/repos/o/n"
    assert extract_path("https://api.github.com") == "/"


def test_method_allowed_empty_is_any():
    assert method_allowed("POST", []) is True


def test_method_allowed_membership_case_insensitive():
    assert method_allowed("get", ["GET"]) is True
    assert method_allowed("DELETE", ["GET", "POST"]) is False


def test_path_allowed_empty_is_any():
    assert path_allowed("/anything", []) is True


def test_path_allowed_glob():
    assert path_allowed("/repos/owner/name", ["/repos/*"]) is True
    assert path_allowed("/users/me", ["/repos/*"]) is False
    assert path_allowed("/anything", ["*"]) is True
