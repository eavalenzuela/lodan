from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from lodan.cli import app
from lodan.paths import workspace_db


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("LODAN_HOME", str(tmp_path))
    runner = CliRunner()
    result = runner.invoke(app, ["init", "w", "--cidrs", "10.0.0.0/24"])
    assert result.exit_code == 0
    conn = sqlite3.connect(workspace_db("w"))
    conn.execute(
        "INSERT INTO scans (id, started_at, cidrs, workspace, status) "
        "VALUES (1, '2026-04-24T00:00:00', '[]', 'w', 'completed')"
    )
    conn.executemany(
        "INSERT INTO services (scan_id, ip, port, proto, service, banner, tech) "
        "VALUES (?, ?, ?, 'tcp', ?, ?, ?)",
        [
            (1, "10.0.0.5", 22, "ssh", "SSH-2.0-OpenSSH_9.3p1", None),
            (1, "10.0.0.5", 443, "tls", "nginx/1.25.3", '["nginx"]'),
        ],
    )
    conn.commit()
    conn.close()
    return "w"


def test_query_table_output(workspace: str) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["query", workspace, "tech:nginx"])
    assert result.exit_code == 0, result.output
    assert "10.0.0.5" in result.output
    assert "443" in result.output
    assert "1 match" in result.output


def test_query_json_output(workspace: str) -> None:
    import json

    runner = CliRunner()
    result = runner.invoke(
        app, ["query", workspace, "banner:OpenSSH*", "--json"]
    )
    assert result.exit_code == 0
    line = result.output.strip().splitlines()[0]
    row = json.loads(line)
    assert row["ip"] == "10.0.0.5"
    assert row["port"] == 22


def test_query_no_matches(workspace: str) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["query", workspace, "tech:drupal"])
    assert result.exit_code == 0
    assert "no matches" in result.output


def test_query_syntax_error(workspace: str) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["query", workspace, "port:abc"])
    assert result.exit_code == 1
    assert "query error" in result.output


def test_query_unknown_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LODAN_HOME", str(tmp_path))
    runner = CliRunner()
    result = runner.invoke(app, ["query", "ghost", "port:22"])
    assert result.exit_code == 1
