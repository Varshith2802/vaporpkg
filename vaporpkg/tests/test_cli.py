import json

import pytest

from vaporpkg import cli
from vaporpkg.models import Ecosystem


@pytest.fixture(autouse=True)
def offline_client(client, monkeypatch):
    monkeypatch.setattr(cli, "_client_factory", lambda args: client)


def test_check_exit_codes(capsys):
    assert cli.main(["check", "requests"]) == 0
    assert cli.main(["check", "requests", "huggingface-cli"]) == 2
    out = capsys.readouterr().out
    assert "BLOCK" in out and "huggingface-cli" in out


def test_check_json_and_prefixes(capsys):
    code = cli.main(["check", "--json", "npm:express", "pypi:requests", "@scope/thing"])
    data = json.loads(capsys.readouterr().out)
    assert code == 0
    assert {r["ecosystem"] for r in data["results"]} == {"npm", "pypi"}
    assert data["summary"]["OK"] == 3


def test_fail_on_warn(tmp_path, capsys):
    f = tmp_path / "answer.md"
    f.write_text("```python\nimport mylocalhelpers\n```\n")
    assert cli.main(["extract", str(f)]) == 0  # import-only -> WARN, not blocked
    assert cli.main(["extract", "--fail-on", "warn", str(f)]) == 1


def test_scan_and_sarif(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text("requests\nreqeusts\n")
    (tmp_path / "package.json").write_text('{"dependencies": {"express": "^4", "expresss": "1.0.0"}}')
    sarif = tmp_path / "out.sarif"
    code = cli.main(["scan", str(tmp_path), "--sarif", str(sarif)])
    assert code == 2
    doc = json.loads(sarif.read_text())
    assert doc["version"] == "2.1.0"
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in doc["runs"][0]["results"]}
    assert any(u.endswith("requirements.txt") for u in uris) and any(u.endswith("package.json") for u in uris)


def test_extract_from_stdin(monkeypatch, capsys):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO("Run `pip install huggingface-cli` then `npm i express`"))
    code = cli.main(["extract", "-", "--json"])
    data = json.loads(capsys.readouterr().out)
    names = {r["name"]: r["verdict"] for r in data["results"]}
    assert names == {"huggingface-cli": "BLOCK", "express": "OK"}
    assert code == 2


def test_guard_blocks_and_does_not_exec(monkeypatch, capsys):
    called = []
    monkeypatch.setattr(cli.os, "execv", lambda *a: called.append(a))
    assert cli.main(["pip", "install", "huggingface-cli"]) == 2
    assert not called
    assert "refusing to run" in capsys.readouterr().err


def test_guard_dry_run_ok(capsys):
    assert cli.main(["guard", "--dry-run", "--", "npm", "install", "express"]) == 0
    assert "would execute: npm install express" in capsys.readouterr().err


def test_guard_force_and_noninteractive_warn(monkeypatch, capsys):
    assert cli.main(["guard", "--dry-run", "--force", "pip", "install", "huggingface-cli"]) == 0
    monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)


def test_candidates_for_command(tmp_path):
    f = cli.candidates_for_command
    assert [c.name for c in f(["python3", "-m", "pip", "install", "requests"])] == ["requests"]
    assert f(["pip", "list"]) is None
    assert [c.name for c in f(["uv", "add", "httpx"])] == ["httpx"]
    assert [c.name for c in f(["npx", "-y", "create-vite", "app"])] == ["create-vite"]
    assert [(c.ecosystem, c.name) for c in f(["uvx", "ruff", "check"])] == [(Ecosystem.PYPI, "ruff")]
    (tmp_path / "package.json").write_text('{"dependencies": {"react": "18"}}')
    assert [c.name for c in f(["npm", "install"], cwd=tmp_path)] == ["react"]
    assert [c.name for c in f(["yarn"], cwd=tmp_path)] == ["react"]
    assert f(["npm", "run", "build"]) is None
