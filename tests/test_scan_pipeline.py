"""End-to-end scan pipeline test using the fake backend.

No sockets, no subprocess. Covers the happy path, off-range rejection,
and the CLI integration.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from lodan.cli import app
from lodan.discovery.base import DiscoveryResult, DiscoverySpec
from lodan.discovery.fake import FakeBackend
from lodan.paths import workspace_db, workspace_dir, workspace_scan_log
from lodan.probes import dispatch as probe_dispatch
from lodan.scan import run_scan_sync


@pytest.fixture(autouse=True)
def _no_probes_no_enrich(monkeypatch: pytest.MonkeyPatch) -> None:
    """Scan-pipeline tests exercise discovery; suppress the probe and
    enrichment phases so we don't try to open real sockets or hit the
    system resolver for 10.0.0.5."""
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


def test_scan_writes_audit_log(workspace: str) -> None:
    _register_fake([
        DiscoveryResult("10.0.0.5", 22, "tcp"),
        DiscoveryResult("8.8.8.8", 53, "udp"),  # out of scope
    ])
    summary = run_scan_sync(workspace)

    events = [
        json.loads(ln)
        for ln in workspace_scan_log(workspace).read_text().splitlines()
        if ln.strip()
    ]
    by_name = {e["event"]: e for e in events}
    # Every event carries the scan_id + an operator for reconstructability.
    assert all(e["scan_id"] == summary.scan_id for e in events)
    assert all(e.get("operator") for e in events)

    assert by_name["scan_started"]["cidrs"] == ["10.0.0.0/24"]
    assert by_name["scan_started"]["backend"] == "fake"

    rejected = [e for e in events if e["event"] == "authz_rejected"]
    assert len(rejected) == 1
    assert rejected[0]["ip"] == "8.8.8.8"

    assert by_name["scan_finished"]["status"] == "completed"
    assert by_name["scan_finished"]["services_discovered"] == 1
    assert by_name["scan_finished"]["authz_rejections"] == 1


def test_scan_populates_authz_ledger(workspace: str) -> None:
    _register_fake([
        DiscoveryResult("10.0.0.5", 22, "tcp"),
        DiscoveryResult("8.8.8.8", 53, "udp"),  # out of scope
    ])
    summary = run_scan_sync(workspace)

    from lodan.store import writer
    from lodan.store.db import connect

    conn = connect(workspace_db(workspace))
    try:
        rows = writer.iter_authz_ledger(conn, scan_id=summary.scan_id)
    finally:
        conn.close()

    authorized = [r for r in rows if r["decision"] == "authorized"]
    refused = [r for r in rows if r["decision"] == "refused"]
    assert [r["target"] for r in authorized] == ["10.0.0.0/24"]
    assert len(refused) == 1
    assert refused[0]["target"] == "8.8.8.8"
    assert refused[0]["port"] == 53
    assert all(r["operator"] for r in rows)


def test_authz_ledger_cli(workspace: str) -> None:
    _register_fake([
        DiscoveryResult("10.0.0.5", 22, "tcp"),
        DiscoveryResult("8.8.8.8", 53, "udp"),
    ])
    run_scan_sync(workspace)
    runner = CliRunner()
    result = runner.invoke(app, ["authz-ledger", workspace, "--decision", "refused"])
    assert result.exit_code == 0, result.output
    assert "8.8.8.8" in result.output
    assert "refused" in result.output
    # An unknown decision filter is rejected.
    bad = runner.invoke(app, ["authz-ledger", workspace, "--decision", "maybe"])
    assert bad.exit_code == 1


def test_notification_fires_only_on_change(
    workspace: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict] = []

    async def _fake_send(cfg, summary, **kwargs):
        calls.append(summary)
        from lodan.notify import SinkResult
        return [SinkResult("webhook", True, "HTTP 200")]

    monkeypatch.setattr("lodan.notify.send", _fake_send)
    cfgp = workspace_dir(workspace) / "config.toml"
    cfgp.write_text(cfgp.read_text() + '\n[notify]\nwebhook_url = "https://hooks.example.com/x"\n')

    # First scan: no previous scan to diff against -> no notification.
    _register_fake([DiscoveryResult("10.0.0.5", 22, "tcp")])
    run_scan_sync(workspace)
    assert calls == []

    # Identical rescan: diff total is 0 -> stays quiet.
    _register_fake([DiscoveryResult("10.0.0.5", 22, "tcp")])
    run_scan_sync(workspace)
    assert calls == []

    # A new service appears: diff > 0 -> notification fires exactly once.
    _register_fake([
        DiscoveryResult("10.0.0.5", 22, "tcp"),
        DiscoveryResult("10.0.0.6", 443, "tcp"),
    ])
    run_scan_sync(workspace)
    assert len(calls) == 1
    assert calls[0]["workspace"] == workspace
    assert calls[0]["counts"]["total"] >= 1


def test_batched_discovery_preserves_partial_results_on_failure(
    workspace: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failure partway through discovery still commits the rows written
    before it — the batched transaction flushes in `finally`."""
    good = [DiscoveryResult(f"10.0.0.{i}", 22, "tcp") for i in range(5)]

    class _Exploding(FakeBackend):
        def __init__(self) -> None:
            super().__init__(good)

        async def run(self, spec):
            for r in good:
                yield r
            raise RuntimeError("backend died mid-stream")

    from lodan.discovery import dispatch

    dispatch.register("fake", _Exploding)
    with pytest.raises(RuntimeError):
        run_scan_sync(workspace)

    conn = sqlite3.connect(workspace_db(workspace))
    try:
        (n,) = conn.execute("SELECT COUNT(*) FROM services").fetchone()
        (status,) = conn.execute(
            "SELECT status FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    assert n == 5              # partial results survived the crash
    assert status == "failed"  # and the scan is marked failed


def test_scan_audit_log_records_failure(workspace: str, monkeypatch: pytest.MonkeyPatch) -> None:
    _register_fake([DiscoveryResult("10.0.0.5", 22, "tcp")])

    def _boom(*args, **kwargs):
        raise RuntimeError("discovery exploded")

    monkeypatch.setattr("lodan.scan.writer.upsert_discovered_service", _boom)
    with pytest.raises(RuntimeError):
        run_scan_sync(workspace)

    events = [
        json.loads(ln)
        for ln in workspace_scan_log(workspace).read_text().splitlines()
        if ln.strip()
    ]
    failed = [e for e in events if e["event"] == "scan_failed"]
    assert len(failed) == 1
    assert failed[0]["status"] == "failed"
    assert "discovery exploded" in failed[0]["error"]


def test_scan_via_cli(workspace: str) -> None:
    _register_fake([DiscoveryResult("10.0.0.5", 22, "tcp")])
    runner = CliRunner()
    result = runner.invoke(app, ["scan", workspace])
    assert result.exit_code == 0, result.output
    assert "1 services" in result.output
    assert "0 probed" in result.output


def test_scan_unknown_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LODAN_HOME", str(tmp_path))
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "ghost"])
    assert result.exit_code == 1


def test_ipv6_scan_stores_canonical_and_rejects_off_range(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LODAN_HOME", str(tmp_path))
    runner = CliRunner()
    assert runner.invoke(app, ["init", "w6", "--cidrs", "2001:db8::/32"]).exit_code == 0
    cfg = workspace_dir("w6") / "config.toml"
    cfg.write_text(cfg.read_text().replace('backend = "auto"', 'backend = "fake"'))

    _register_fake([
        DiscoveryResult("2001:DB8:0:0:0:0:0:5", 443, "tcp"),  # in range, non-canonical form
        DiscoveryResult("2001:dead::1", 80, "tcp"),           # out of range
    ])
    summary = run_scan_sync("w6")
    assert summary.services_discovered == 1
    assert summary.authz_rejections == 1

    conn = sqlite3.connect(workspace_db("w6"))
    rows = conn.execute("SELECT ip, port FROM services").fetchall()
    # Stored in canonical compressed form, not the padded input.
    assert rows == [("2001:db8::5", 443)]
    (rej,) = conn.execute(
        "SELECT ip FROM scan_errors WHERE scan_id = ?", (summary.scan_id,)
    ).fetchone()
    assert rej == "2001:dead::1"
    conn.close()


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
