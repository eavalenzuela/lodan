from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from lodan.cli import app


@pytest.fixture
def lodan_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("LODAN_HOME", str(tmp_path))
    return tmp_path


def test_init_creates_workspace(lodan_home: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["init", "home-lab", "--cidrs", "10.0.0.0/24,192.168.1.0/24"])
    assert result.exit_code == 0, result.output

    wdir = lodan_home / "workspaces" / "home-lab"
    assert (wdir / "config.toml").exists()
    assert (wdir / "lodan.db").exists()

    cfg = (wdir / "config.toml").read_text()
    assert '"10.0.0.0/24"' in cfg
    assert '"192.168.1.0/24"' in cfg

    conn = sqlite3.connect(wdir / "lodan.db")
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()
    for expected in ("scans", "hosts", "services", "vulns", "scan_errors", "cve_cpe", "scan_diffs"):
        assert expected in tables


def test_init_rejects_existing_workspace(lodan_home: Path) -> None:
    runner = CliRunner()
    runner.invoke(app, ["init", "dup", "--cidrs", "10.0.0.0/24"])
    result = runner.invoke(app, ["init", "dup", "--cidrs", "10.0.0.0/24"])
    assert result.exit_code != 0


def test_init_rejects_bad_cidr(lodan_home: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["init", "bad", "--cidrs", "not-a-cidr"])
    assert result.exit_code != 0


def test_scan_not_implemented(lodan_home: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "whatever"])
    assert result.exit_code == 2
