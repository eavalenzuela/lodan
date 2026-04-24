from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from lodan.cli import app as cli_app
from lodan.discovery.base import DiscoveryResult
from lodan.discovery.fake import FakeBackend
from lodan.paths import workspace_dir
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
    assert result.exit_code == 0, result.output
    cfg = workspace_dir("w") / "config.toml"
    cfg.write_text(cfg.read_text().replace('backend = "auto"', 'backend = "fake"'))
    return "w"


def _register_fake(results: list[DiscoveryResult]) -> None:
    from lodan.discovery import dispatch

    class _F(FakeBackend):
        def __init__(self) -> None:
            super().__init__(results)

    dispatch.register("fake", _F)


def _client(workspace: str) -> TestClient:
    from lodan.ui.app import create_app
    return TestClient(create_app(workspace))


def test_dashboard_renders_when_empty(workspace: str) -> None:
    client = _client(workspace)
    r = client.get("/")
    assert r.status_code == 200
    assert "No scans yet" in r.text
    assert workspace in r.text


def test_dashboard_shows_latest_and_diff(workspace: str) -> None:
    _register_fake([DiscoveryResult("10.0.0.5", 22, "tcp")])
    run_scan_sync(workspace)
    _register_fake([
        DiscoveryResult("10.0.0.5", 22, "tcp"),
        DiscoveryResult("10.0.0.9", 80, "tcp"),
    ])
    run_scan_sync(workspace)

    client = _client(workspace)
    body = client.get("/").text
    assert "Latest scan" in body
    assert "Diff 1 → 2" in body
    assert "new_service" in body
    assert "new_host" in body


def test_healthz(workspace: str) -> None:
    client = _client(workspace)
    assert client.get("/healthz").text == "ok"


def test_create_app_unknown_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LODAN_HOME", str(tmp_path))
    from lodan.ui.app import create_app
    with pytest.raises(FileNotFoundError):
        create_app("ghost")


def test_serve_refuses_nonloopback_without_token(
    workspace: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = CliRunner()
    result = runner.invoke(cli_app, ["serve", workspace, "--addr", "0.0.0.0:8080"])
    assert result.exit_code == 1
    assert "non-loopback" in result.output


def test_serve_rejects_invalid_addr(workspace: str) -> None:
    runner = CliRunner()
    result = runner.invoke(cli_app, ["serve", workspace, "--addr", "nonsense"])
    assert result.exit_code == 1
