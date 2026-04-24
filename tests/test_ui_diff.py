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


def test_diffs_empty_workspace(workspace: str) -> None:
    client = _client(workspace)
    body = client.get("/diffs").text
    assert "No diffs yet" in body


def test_diffs_timeline_and_detail(workspace: str) -> None:
    _register_fake([DiscoveryResult("10.0.0.5", 22, "tcp")])
    run_scan_sync(workspace)
    _register_fake([
        DiscoveryResult("10.0.0.5", 22, "tcp"),
        DiscoveryResult("10.0.0.9", 443, "tcp"),
    ])
    run_scan_sync(workspace)

    client = _client(workspace)

    listing = client.get("/diffs").text
    assert "1 → 2" not in listing  # rendered as two <td>s, not joined
    assert "#1" in listing and "#2" in listing
    assert "2 →" in listing  # total link (1 new_service + 1 new_host)

    detail = client.get("/diff/1/2").text
    assert "new_service" in detail
    assert "new_host" in detail
    assert "10.0.0.9" in detail


def test_diff_detail_identical_scans(workspace: str) -> None:
    _register_fake([DiscoveryResult("10.0.0.5", 22, "tcp")])
    run_scan_sync(workspace)
    _register_fake([DiscoveryResult("10.0.0.5", 22, "tcp")])
    run_scan_sync(workspace)

    client = _client(workspace)
    detail = client.get("/diff/1/2").text
    assert "No findings" in detail


def test_diff_unknown_pair_renders_empty(workspace: str) -> None:
    _register_fake([DiscoveryResult("10.0.0.5", 22, "tcp")])
    run_scan_sync(workspace)
    client = _client(workspace)
    # There's no scan_diffs rows for (999, 1000) — should 200 with "No findings".
    detail = client.get("/diff/999/1000").text
    assert "No findings" in detail
