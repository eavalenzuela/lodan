from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from lodan.cli import app as cli_app
from lodan.paths import workspace_db


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("LODAN_HOME", str(tmp_path))
    runner = CliRunner()
    result = runner.invoke(cli_app, ["init", "w", "--cidrs", "10.0.0.0/24"])
    assert result.exit_code == 0
    conn = sqlite3.connect(workspace_db("w"))
    conn.execute(
        "INSERT INTO scans (id, started_at, cidrs, workspace, status) "
        "VALUES (1, '2026-04-24T00:00:00', '[]', 'w', 'completed')"
    )
    conn.executemany(
        "INSERT INTO services (scan_id, ip, port, proto, service, banner, tech, cert_sans) "
        "VALUES (?, ?, ?, 'tcp', ?, ?, ?, ?)",
        [
            (1, "10.0.0.5", 22, "ssh", "SSH-2.0-OpenSSH_9.3p1", None, None),
            (1, "10.0.0.5", 443, "tls", "nginx/1.25.3", '["nginx"]',
             '["*.corp.example.com"]'),
            (1, "10.0.0.9", 80, "http", "Apache/2.4.54", '["apache"]', None),
        ],
    )
    conn.commit()
    conn.close()
    return "w"


def _client(workspace: str) -> TestClient:
    from lodan.ui.app import create_app
    return TestClient(create_app(workspace))


def test_query_page_empty(workspace: str) -> None:
    body = _client(workspace).get("/query").text
    assert "DSL:" in body
    # No results section before a query runs.
    assert "match(es)" not in body


def test_query_page_returns_rows(workspace: str) -> None:
    body = _client(workspace).get("/query", params={"q": "tech:nginx"}).text
    assert "1 match" in body
    assert "10.0.0.5" in body
    assert "443" in body


def test_query_page_wildcard_san(workspace: str) -> None:
    body = _client(workspace).get(
        "/query", params={"q": "sans:*.corp.example.com"}
    ).text
    assert "10.0.0.5" in body


def test_query_page_syntax_error(workspace: str) -> None:
    r = _client(workspace).get("/query", params={"q": "port:abc"})
    assert r.status_code == 200
    assert "query error" in r.text
