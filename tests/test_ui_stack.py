"""Web-UI coverage for the passive stack fingerprint.

Seeds services/hosts rows directly so nothing here needs discovery or a
raw socket.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from lodan.cli import app as cli_app
from lodan.paths import workspace_db
from lodan.probes import dispatch as probe_dispatch

_LINUX = "64:64240:1460:7:M,S,T,N,W:DF"
_WINDOWS = "128:65535:1460:8:M,N,W,N,N,S:DF"


@pytest.fixture(autouse=True)
def _quiet(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(probe_dispatch, "register_defaults", probe_dispatch.clear_registry)
    probe_dispatch.clear_registry()


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("LODAN_HOME", str(tmp_path))
    runner = CliRunner()
    assert runner.invoke(cli_app, ["init", "w", "--cidrs", "10.0.0.0/24"]).exit_code == 0
    conn = sqlite3.connect(workspace_db("w"))
    conn.execute(
        "INSERT INTO scans (id, started_at, cidrs, workspace, status) VALUES "
        "(1, '2026-04-10T00:00:00', '[]', 'w', 'completed')"
    )
    conn.executemany(
        "INSERT INTO services (scan_id, ip, port, proto, service, stack_sig, "
        "os_family, hop_count, clock_key) VALUES (1, ?, ?, 'tcp', ?, ?, ?, ?, ?)",
        [
            # Two IPs, same stack and same boot bucket — one machine, two addresses.
            ("10.0.0.5", 22, "ssh", _LINUX, "linux", 2, "1000:1700000000"),
            ("10.0.0.6", 22, "ssh", _LINUX, "linux", 2, "1000:1700000000"),
            # A genuinely different box.
            ("10.0.0.9", 3389, "rdp", _WINDOWS, "windows", 5, "1000:1700009999"),
        ],
    )
    conn.executemany(
        "INSERT INTO hosts (scan_id, ip, stack_sig, os_family, os_confidence, hop_count) "
        "VALUES (1, ?, ?, ?, ?, ?)",
        [
            ("10.0.0.5", _LINUX, "linux", 0.9, 2),
            ("10.0.0.6", _LINUX, "linux", 0.9, 2),
            ("10.0.0.9", _WINDOWS, "windows", 0.9, 5),
        ],
    )
    conn.commit()
    conn.close()
    return "w"


def _client(workspace: str) -> TestClient:
    from lodan.ui.app import create_app
    return TestClient(create_app(workspace))


def test_pivot_stack_groups_matching_signatures(workspace: str) -> None:
    body = _client(workspace).get(f"/pivot/stack/{_LINUX}").text
    assert "10.0.0.5" in body
    assert "10.0.0.6" in body
    assert "10.0.0.9" not in body


def test_pivot_clock_clusters_addresses_on_one_machine(workspace: str) -> None:
    body = _client(workspace).get("/pivot/clock/1000:1700000000").text
    assert "10.0.0.5" in body
    assert "10.0.0.6" in body
    assert "10.0.0.9" not in body


def test_pivot_clock_unknown_bucket_is_empty_not_an_error(workspace: str) -> None:
    r = _client(workspace).get("/pivot/clock/1000:1")
    assert r.status_code == 200
    assert "10.0.0." not in r.text


def test_hosts_table_shows_os_and_hops(workspace: str) -> None:
    body = _client(workspace).get("/hosts?scan=1").text
    assert "linux" in body
    assert "windows" in body


def test_hosts_filter_matches_os_family(workspace: str) -> None:
    body = _client(workspace).get("/hosts/rows?scan=1&q=windows").text
    assert "10.0.0.9" in body
    assert "10.0.0.5" not in body


def test_host_detail_shows_stack_and_links_to_pivot(workspace: str) -> None:
    body = _client(workspace).get("/host/10.0.0.5?scan=1").text
    assert "linux" in body
    assert f"/pivot/stack/{_LINUX}" in body
    assert "/pivot/clock/1000:1700000000" in body


def test_host_detail_without_stack_data_still_renders(workspace: str) -> None:
    """A masscan/naabu scan populates none of these columns."""
    conn = sqlite3.connect(workspace_db(workspace))
    conn.execute(
        "INSERT INTO services (scan_id, ip, port, proto, service) "
        "VALUES (1, '10.0.0.77', 80, 'tcp', 'http')"
    )
    conn.commit()
    conn.close()
    r = _client(workspace).get("/host/10.0.0.77?scan=1")
    assert r.status_code == 200
    assert "/pivot/stack/" not in r.text
