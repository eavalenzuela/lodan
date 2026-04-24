"""Hosts / services / host-detail routes + HTMX partial responses."""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from lodan.cli import app as cli_app
from lodan.discovery.base import DiscoveryResult
from lodan.discovery.fake import FakeBackend
from lodan.paths import workspace_db, workspace_dir
from lodan.probes import dispatch as probe_dispatch
from lodan.scan import run_scan_sync


@pytest.fixture(autouse=True)
def _quiet_scan(monkeypatch: pytest.MonkeyPatch) -> None:
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
    return "w"


def _register_fake(results: list[DiscoveryResult]) -> None:
    from lodan.discovery import dispatch

    class _F(FakeBackend):
        def __init__(self) -> None:
            super().__init__(results)

    dispatch.register("fake", _F)


def _populate(workspace: str) -> None:
    _register_fake([
        DiscoveryResult("10.0.0.5", 22, "tcp"),
        DiscoveryResult("10.0.0.5", 443, "tcp"),
        DiscoveryResult("10.0.0.9", 80, "tcp"),
    ])
    run_scan_sync(workspace)
    # Decorate services with banner / cert / tech so table renders have content.
    import sqlite3

    conn = sqlite3.connect(workspace_db(workspace))
    conn.execute(
        "UPDATE services SET banner=?, tech=?, cert_fingerprint=? WHERE ip=? AND port=?",
        ("nginx/1.25.3", '["nginx"]', "deadbeef" * 8, "10.0.0.5", 443),
    )
    conn.execute(
        "UPDATE services SET banner=?, service=? WHERE ip=? AND port=?",
        ("SSH-2.0-OpenSSH_9.3", "ssh", "10.0.0.5", 22),
    )
    conn.commit()
    conn.close()


def _client(workspace: str) -> TestClient:
    from lodan.ui.app import create_app
    return TestClient(create_app(workspace))


def test_hosts_page_lists_unique_ips(workspace: str) -> None:
    _populate(workspace)
    client = _client(workspace)
    body = client.get("/hosts").text
    assert "10.0.0.5" in body
    assert "10.0.0.9" in body
    assert "2 svc" in body  # 10.0.0.5 has two services
    assert "1 svc" in body


def test_hosts_filter_partial(workspace: str) -> None:
    _populate(workspace)
    client = _client(workspace)
    r = client.get("/hosts/rows", params={"scan": 1, "q": "0.0.9"})
    assert r.status_code == 200
    assert "10.0.0.9" in r.text
    assert "10.0.0.5" not in r.text
    # Partial should not contain the base template scaffolding.
    assert "<html" not in r.text


def test_services_page_renders_banner_cert_tech(workspace: str) -> None:
    _populate(workspace)
    client = _client(workspace)
    body = client.get("/services").text
    assert "nginx/1.25.3" in body
    assert "deadbeefdead…" in body  # short_fp truncates the sha256 hex at 12 chars
    assert "nginx" in body


def test_services_filter_by_banner(workspace: str) -> None:
    _populate(workspace)
    client = _client(workspace)
    r = client.get("/services/rows", params={"scan": 1, "q": "OpenSSH"})
    assert "SSH-2.0-OpenSSH_9.3" in r.text
    assert "nginx/1.25.3" not in r.text


def test_host_detail_shows_services(workspace: str) -> None:
    _populate(workspace)
    client = _client(workspace)
    r = client.get("/host/10.0.0.5")
    assert r.status_code == 200
    assert "22" in r.text
    assert "443" in r.text
    assert "SSH-2.0-OpenSSH_9.3" in r.text


def test_host_detail_unknown_ip(workspace: str) -> None:
    _populate(workspace)
    client = _client(workspace)
    r = client.get("/host/192.168.99.99")
    assert r.status_code == 404


def test_hosts_empty_workspace(workspace: str) -> None:
    client = _client(workspace)
    r = client.get("/hosts")
    assert r.status_code == 200
    assert "no hosts match" in r.text
