"""End-to-end test of `lodan diff` + auto-diff after scan."""
from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from lodan.cli import app
from lodan.discovery.base import DiscoveryResult
from lodan.discovery.fake import FakeBackend
from lodan.paths import workspace_dir
from lodan.probes import dispatch as probe_dispatch
from lodan.scan import run_scan_sync


@pytest.fixture(autouse=True)
def _no_probes_no_enrich(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(probe_dispatch, "register_defaults", probe_dispatch.clear_registry)
    probe_dispatch.clear_registry()

    async def _noop_enrich(*args, **kwargs):
        return 0

    monkeypatch.setattr("lodan.scan.enrich_hosts", _noop_enrich)


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("LODAN_HOME", str(tmp_path))
    runner = CliRunner()
    result = runner.invoke(app, ["init", "w", "--cidrs", "10.0.0.0/24"])
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


def test_auto_diff_after_second_scan(workspace: str) -> None:
    # Scan 1: ssh + http
    _register_fake([
        DiscoveryResult("10.0.0.5", 22, "tcp"),
        DiscoveryResult("10.0.0.5", 80, "tcp"),
    ])
    first = run_scan_sync(workspace)
    assert first.diff_from is None  # nothing to diff against

    # Scan 2: http + https (ssh gone, https new)
    _register_fake([
        DiscoveryResult("10.0.0.5", 80, "tcp"),
        DiscoveryResult("10.0.0.5", 443, "tcp"),
    ])
    second = run_scan_sync(workspace)
    assert second.diff_from == first.scan_id
    assert second.diff_total == 2  # one new, one gone


def test_lodan_diff_cli_prev_to_latest(workspace: str) -> None:
    _register_fake([DiscoveryResult("10.0.0.5", 22, "tcp")])
    run_scan_sync(workspace)
    _register_fake([
        DiscoveryResult("10.0.0.5", 22, "tcp"),
        DiscoveryResult("10.0.0.9", 22, "tcp"),
    ])
    run_scan_sync(workspace)

    runner = CliRunner()
    result = runner.invoke(app, ["diff", workspace])
    assert result.exit_code == 0, result.output
    assert "1 new" in result.output
    assert "1 new hosts" in result.output


def test_lodan_diff_cli_explicit_ids(workspace: str) -> None:
    _register_fake([DiscoveryResult("10.0.0.5", 22, "tcp")])
    run_scan_sync(workspace)
    _register_fake([DiscoveryResult("10.0.0.5", 443, "tcp")])
    run_scan_sync(workspace)

    runner = CliRunner()
    result = runner.invoke(app, ["diff", workspace, "--from", "1", "--to", "2"])
    assert result.exit_code == 0
    assert "1 -> 2" in result.output


def test_lodan_diff_same_scan_rejected(workspace: str) -> None:
    _register_fake([DiscoveryResult("10.0.0.5", 22, "tcp")])
    run_scan_sync(workspace)

    runner = CliRunner()
    result = runner.invoke(app, ["diff", workspace, "--from", "1", "--to", "1"])
    assert result.exit_code == 1
    assert "same scan" in result.output


def test_lodan_diff_unknown_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LODAN_HOME", str(tmp_path))
    runner = CliRunner()
    result = runner.invoke(app, ["diff", "ghost"])
    assert result.exit_code == 1
