"""Tests for the domain binding policy."""
from agent_keychain.vault.domain_policy import (
    infer_domains,
    host_allowed,
    extract_host,
    WILDCARD,
)


def test_infer_known_service():
    assert "github.com" in infer_domains("github")
    assert infer_domains("GitHub") == infer_domains("github")  # case-insensitive


def test_infer_unknown_service_is_empty():
    assert infer_domains("some-internal-thing") == []
    assert infer_domains("") == []


def test_empty_domains_denies_everything():
    # deny-by-default: no domains means nothing is allowed
    assert host_allowed("api.github.com", []) is False


def test_exact_match():
    assert host_allowed("github.com", ["github.com"]) is True


def test_subdomain_suffix_match():
    assert host_allowed("api.github.com", ["github.com"]) is True
    assert host_allowed("uploads.github.com", ["github.com"]) is True


def test_non_match_is_denied():
    assert host_allowed("evil.com", ["github.com"]) is False
    # must not be fooled by a suffix that isn't a domain boundary
    assert host_allowed("notgithub.com", ["github.com"]) is False
    assert host_allowed("github.com.evil.com", ["github.com"]) is False


def test_wildcard_allows_any():
    assert host_allowed("anything.example.com", [WILDCARD]) is True
    assert host_allowed("evil.com", ["*"]) is True


def test_star_dot_domain():
    assert host_allowed("api.github.com", ["*.github.com"]) is True
    assert host_allowed("github.com", ["*.github.com"]) is True


def test_extract_host():
    assert extract_host("https://api.github.com/user") == "api.github.com"
    assert extract_host("https://API.GitHub.com/x") == "api.github.com"
    assert extract_host("not a url") == ""


def test_empty_host_denied():
    assert host_allowed("", ["github.com"]) is False
