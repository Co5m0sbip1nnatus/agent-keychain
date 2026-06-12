"""Tests for file-based secret import and scrubbing."""
from agent_keychain.guard.credential_guard import find_secrets
from agent_keychain.onboarding import parse_secret_lines, scrub_file


def test_find_secrets_returns_values():
    token = "ghp_" + "A" * 36
    results = find_secrets(f"x = {token}")
    assert any(val == token and "GitHub" in typ for typ, val in results)


def test_parse_secret_lines_dotenv():
    content = "\n".join([
        "# comment",
        "PORT=8080",                       # not a secret
        "GITHUB_TOKEN=ghp_" + "A" * 36,    # secret by pattern + name
        "API_PASSWORD=hunter2hunter2",     # secret by name
        'QUOTED="ghp_' + "B" * 36 + '"',   # quoted secret
    ])
    found = parse_secret_lines(content)
    keys = {f["key"] for f in found}
    assert "GITHUB_TOKEN" in keys
    assert "API_PASSWORD" in keys
    assert "QUOTED" in keys
    assert "PORT" not in keys
    # service inferred from key name
    gh = next(f for f in found if f["key"] == "GITHUB_TOKEN")
    assert gh["service"] == "github"
    # quotes stripped
    q = next(f for f in found if f["key"] == "QUOTED")
    assert q["value"] == "ghp_" + "B" * 36


def test_scrub_file_replaces_values_and_backs_up(tmp_path):
    secret = "ghp_" + "C" * 36
    f = tmp_path / "app.env"
    f.write_text(f"TOKEN={secret}\nPORT=80\n")
    backup = scrub_file(str(f), [secret])
    after = f.read_text()
    assert secret not in after
    assert "PORT=80" in after            # non-secret content untouched
    assert "<scrubbed-by-agent-keychain>" in after
    # backup preserves the original
    import os
    assert os.path.isfile(backup)
    assert secret in open(backup).read()
