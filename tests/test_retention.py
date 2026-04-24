from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from lodan.cli import app
from lodan.paths import workspace_config, workspace_db
from lodan.retention import ScanRecord, apply, compute_keep_set
from lodan.store.db import bootstrap, connect


def _scan(id: int, ts: str, status: str = "completed") -> ScanRecord:
    return ScanRecord(id=id, started_at=ts, status=status)


def test_keep_last_n() -> None:
    scans = [
        _scan(1, "2026-01-01T00:00:00"),
        _scan(2, "2026-02-01T00:00:00"),
        _scan(3, "2026-03-01T00:00:00"),
        _scan(4, "2026-04-01T00:00:00"),
    ]
    keep = compute_keep_set(scans, keep_last_n=2, keep_monthly=None)
    assert keep == {3, 4}


def test_keep_monthly_picks_earliest_per_month() -> None:
    scans = [
        _scan(1, "2026-04-01T00:00:00"),
        _scan(2, "2026-04-15T00:00:00"),   # same month; earliest (1) wins
        _scan(3, "2026-05-01T00:00:00"),
        _scan(4, "2026-06-01T00:00:00"),
    ]
    keep = compute_keep_set(scans, keep_last_n=None, keep_monthly=2)
    # Two most recent months are 2026-06 and 2026-05 -> ids 4 and 3.
    assert keep == {3, 4}


def test_keep_last_and_monthly_are_union() -> None:
    scans = [
        _scan(1, "2026-01-15T00:00:00"),
        _scan(2, "2026-02-15T00:00:00"),
        _scan(3, "2026-03-15T00:00:00"),
        _scan(4, "2026-04-15T00:00:00"),
    ]
    # keep_last_n=1 -> {4}, keep_monthly=2 -> earliest in the 2 most recent
    # months with any completed scan = 2026-04 and 2026-03 -> {3, 4}.
    keep = compute_keep_set(scans, keep_last_n=1, keep_monthly=2)
    assert keep == {3, 4}


def test_non_completed_always_kept() -> None:
    scans = [
        _scan(1, "2026-01-15T00:00:00", status="completed"),
        _scan(2, "2026-02-15T00:00:00", status="running"),
        _scan(3, "2026-03-15T00:00:00", status="failed"),
    ]
    keep = compute_keep_set(scans, keep_last_n=1, keep_monthly=None)
    assert 2 in keep  # running scan — never deleted
    assert 3 in keep  # failed scan — never deleted
    assert 1 in keep  # newest completed


def test_apply_deletes_and_cascades(tmp_path: Path) -> None:
    dbp = tmp_path / "l.db"
    bootstrap(dbp)
    conn = connect(dbp)

    for i, ts in [(1, "2026-01-01T00:00:00"), (2, "2026-02-01T00:00:00"),
                  (3, "2026-03-01T00:00:00")]:
        conn.execute(
            "INSERT INTO scans (id, started_at, cidrs, workspace, status) "
            "VALUES (?, ?, '[]', 'w', 'completed')",
            (i, ts),
        )
        conn.execute(
            "INSERT INTO services (scan_id, ip, port, proto) VALUES (?, ?, ?, 'tcp')",
            (i, f"10.0.0.{i}", 22),
        )

    stats = apply(conn, keep_last_n=1, keep_monthly=None)
    assert stats.total_scans == 3
    assert stats.kept == 1
    assert stats.deleted == 2

    remaining_scans = {r[0] for r in conn.execute("SELECT id FROM scans")}
    assert remaining_scans == {3}
    remaining_services = {r[0] for r in conn.execute("SELECT scan_id FROM services")}
    assert remaining_services == {3}  # FK cascade wiped services for scans 1 and 2


def test_apply_dry_run_does_not_delete(tmp_path: Path) -> None:
    dbp = tmp_path / "l.db"
    bootstrap(dbp)
    conn = connect(dbp)
    conn.execute(
        "INSERT INTO scans (id, started_at, cidrs, workspace, status) "
        "VALUES (1, '2026-01-01T00:00:00', '[]', 'w', 'completed')"
    )
    conn.execute(
        "INSERT INTO scans (id, started_at, cidrs, workspace, status) "
        "VALUES (2, '2026-02-01T00:00:00', '[]', 'w', 'completed')"
    )

    stats = apply(conn, keep_last_n=1, keep_monthly=None, dry_run=True)
    assert stats.deleted == 1
    (count,) = conn.execute("SELECT COUNT(*) FROM scans").fetchone()
    assert count == 2


# --- CLI ---


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("LODAN_HOME", str(tmp_path))
    runner = CliRunner()
    result = runner.invoke(app, ["init", "w", "--cidrs", "10.0.0.0/24"])
    assert result.exit_code == 0
    return "w"


def _seed_scans(workspace: str) -> None:
    conn = sqlite3.connect(workspace_db(workspace))
    for i, ts in [(1, "2026-01-01T00:00:00"), (2, "2026-02-01T00:00:00"),
                  (3, "2026-03-01T00:00:00")]:
        conn.execute(
            "INSERT INTO scans (id, started_at, cidrs, workspace, status) "
            "VALUES (?, ?, '[]', 'w', 'completed')",
            (i, ts),
        )
    conn.commit()
    conn.close()


def test_cli_no_policy_exits_ok(workspace: str) -> None:
    _seed_scans(workspace)
    runner = CliRunner()
    result = runner.invoke(app, ["prune", workspace])
    assert result.exit_code == 0
    assert "not configured" in result.output


def test_cli_applies_policy(workspace: str) -> None:
    _seed_scans(workspace)
    cfg = workspace_config(workspace)
    cfg.write_text(
        cfg.read_text()
        + "\n[retention]\nkeep_last_n = 1\n"
    )
    runner = CliRunner()
    result = runner.invoke(app, ["prune", workspace])
    assert result.exit_code == 0
    assert "deleted=2" in result.output

    conn = sqlite3.connect(workspace_db(workspace))
    remaining = {r[0] for r in conn.execute("SELECT id FROM scans")}
    conn.close()
    assert remaining == {3}


def test_cli_dry_run(workspace: str) -> None:
    _seed_scans(workspace)
    cfg = workspace_config(workspace)
    cfg.write_text(cfg.read_text() + "\n[retention]\nkeep_last_n = 1\n")
    runner = CliRunner()
    result = runner.invoke(app, ["prune", workspace, "--dry-run"])
    assert result.exit_code == 0
    assert "would delete=2" in result.output

    conn = sqlite3.connect(workspace_db(workspace))
    (count,) = conn.execute("SELECT COUNT(*) FROM scans").fetchone()
    conn.close()
    assert count == 3
