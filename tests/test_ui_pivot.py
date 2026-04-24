from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from lodan.cli import app as cli_app
from lodan.paths import workspace_db, workspace_dir
from lodan.probes import dispatch as probe_dispatch


@pytest.fixture(autouse=True)
def _quiet(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(probe_dispatch, "register_defaults", probe_dispatch.clear_registry)
    probe_dispatch.clear_registry()

    async def _noop(*args, **kwargs):
        return 0

    monkeypatch.setattr("lodan.scan.enrich_hosts", _noop)


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("LODAN_HOME", str(tmp_path))
    runner = CliRunner()
    result = runner.invoke(cli_app, ["init", "w", "--cidrs", "10.0.0.0/24"])
    assert result.exit_code == 0
    cfg = workspace_dir("w") / "config.toml"
    cfg.write_text(cfg.read_text().replace('backend = "auto"', 'backend = "fake"'))
    # Seed two scans directly via SQL so we don't need discovery.
    conn = sqlite3.connect(workspace_db("w"))
    conn.execute(
        "INSERT INTO scans (id, started_at, cidrs, workspace, status) VALUES "
        "(1, '2026-04-10T00:00:00', '[]', 'w', 'completed')"
    )
    conn.execute(
        "INSERT INTO scans (id, started_at, cidrs, workspace, status) VALUES "
        "(2, '2026-04-20T00:00:00', '[]', 'w', 'completed')"
    )
    conn.executemany(
        "INSERT INTO services (scan_id, ip, port, proto, service, banner, "
        "cert_fingerprint, cert_sans, favicon_mmh3, ja3s) "
        "VALUES (?, ?, ?, 'tcp', ?, ?, ?, ?, ?, ?)",
        [
            (1, "10.0.0.5", 443, "tls", "Apache", "aa" * 32, '["example.corp","*.corp.example.com"]', 12345, "ja3s-1"),
            (1, "10.0.0.9", 443, "tls", "nginx",  "bb" * 32, '["other.example"]', 99999, "ja3s-2"),
            (2, "10.0.0.5", 443, "tls", "Apache", "aa" * 32, '["example.corp","*.corp.example.com"]', 12345, "ja3s-1"),
            (2, "10.0.0.11", 443, "tls", "caddy", "cc" * 32, '["*.corp.example.com"]', 12345, "ja3s-1"),
        ],
    )
    conn.commit()
    conn.close()
    return "w"


def _client(workspace: str) -> TestClient:
    from lodan.ui.app import create_app
    return TestClient(create_app(workspace))


def test_pivot_cert_finds_all_occurrences(workspace: str) -> None:
    client = _client(workspace)
    body = client.get("/pivot/cert/" + "aa" * 32).text
    # 10.0.0.5 appears in both scans with this cert.
    assert body.count("10.0.0.5") >= 2
    assert "10.0.0.9" not in body  # different cert


def test_pivot_favicon(workspace: str) -> None:
    client = _client(workspace)
    body = client.get("/pivot/favicon/12345").text
    assert "10.0.0.5" in body
    assert "10.0.0.11" in body
    assert "10.0.0.9" not in body


def test_pivot_favicon_rejects_non_int(workspace: str) -> None:
    client = _client(workspace)
    r = client.get("/pivot/favicon/notanumber")
    assert r.status_code == 400


def test_pivot_ja3s(workspace: str) -> None:
    client = _client(workspace)
    body = client.get("/pivot/ja3s/ja3s-1").text
    assert "10.0.0.5" in body
    assert "10.0.0.11" in body
    assert "10.0.0.9" not in body


def test_pivot_san_wildcard(workspace: str) -> None:
    client = _client(workspace)
    body = client.get("/pivot/san", params={"q": "*.corp.example.com"}).text
    assert "10.0.0.5" in body
    assert "10.0.0.11" in body
    assert "10.0.0.9" not in body


def test_pivot_san_substring(workspace: str) -> None:
    client = _client(workspace)
    body = client.get("/pivot/san", params={"q": "other.example"}).text
    assert "10.0.0.9" in body
    assert "10.0.0.11" not in body


def test_pivot_san_empty(workspace: str) -> None:
    client = _client(workspace)
    body = client.get("/pivot/san").text
    assert "no matches" in body
