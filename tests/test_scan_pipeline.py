"""End-to-end scan pipeline test using the fake backend.

No sockets, no subprocess. Covers the happy path, off-range rejection,
and the CLI integration.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from lodan.cli import app
from lodan.discovery.base import DiscoveryResult, DiscoverySpec
from lodan.discovery.fake import FakeBackend
from lodan.paths import workspace_db, workspace_dir
from lodan.scan import run_scan_sync


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("LODAN_HOME", str(tmp_path))
    runner = CliRunner()
    result = runner.invoke(app, ["init", "w", "--cidrs", "10.0.0.0/24"])
    assert result.exit_code == 0, result.output
    # Force backend=fake so the scan loop doesn't try to pick a real backend.
    cfg = workspace_dir("w") / "config.toml"
    cfg.write_text(cfg.read_text().replace('backend = "auto"', 'backend = "fake"'))
    return "w"


def _register_fake(results: list[DiscoveryResult]) -> None:
    from lodan.discovery import dispatch

    class _F(FakeBackend):
        def __init__(self) -> None:
            super().__init__(results)

    dispatch.register("fake", _F)


def test_scan_writes_services(workspace: str) -> None:
    _register_fake([
        DiscoveryResult("10.0.0.5", 22, "tcp"),
        DiscoveryResult("10.0.0.5", 443, "tcp"),
        DiscoveryResult("10.0.0.7", 53, "udp"),
    ])
    summary = run_scan_sync(workspace)
    assert summary.services_discovered == 3
    assert summary.authz_rejections == 0

    conn = sqlite3.connect(workspace_db(workspace))
    rows = sorted(conn.execute("SELECT ip, port, proto FROM services").fetchall())
    assert rows == [("10.0.0.5", 22, "tcp"), ("10.0.0.5", 443, "tcp"), ("10.0.0.7", 53, "udp")]
    (status,) = conn.execute("SELECT status FROM scans WHERE id = ?", (summary.scan_id,)).fetchone()
    assert status == "completed"
    conn.close()


def test_scan_rejects_off_range_targets(workspace: str) -> None:
    _register_fake([
        DiscoveryResult("10.0.0.5", 22, "tcp"),
        DiscoveryResult("8.8.8.8", 53, "udp"),  # outside authorized_ranges
    ])
    summary = run_scan_sync(workspace)
    assert summary.services_discovered == 1
    assert summary.authz_rejections == 1

    conn = sqlite3.connect(workspace_db(workspace))
    err = conn.execute(
        "SELECT ip, stage FROM scan_errors WHERE scan_id = ?", (summary.scan_id,)
    ).fetchone()
    assert err == ("8.8.8.8", "discovery")
    conn.close()


def test_scan_via_cli(workspace: str) -> None:
    _register_fake([DiscoveryResult("10.0.0.5", 22, "tcp")])
    runner = CliRunner()
    result = runner.invoke(app, ["scan", workspace])
    assert result.exit_code == 0, result.output
    assert "1 services" in result.output


def test_scan_unknown_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LODAN_HOME", str(tmp_path))
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "ghost"])
    assert result.exit_code == 1


def test_discovery_spec_is_built_from_config(workspace: str) -> None:
    captured: list[DiscoverySpec] = []

    class Capturing(FakeBackend):
        name = "fake"

        def __init__(self) -> None:
            super().__init__([])

        async def run(self, spec):
            captured.append(spec)
            async for r in super().run(spec):
                yield r

    from lodan.discovery import dispatch

    dispatch.register("fake", Capturing)
    run_scan_sync(workspace)
    assert len(captured) == 1
    assert captured[0].tcp is True
    assert captured[0].udp is True
    assert 22 in captured[0].ports
