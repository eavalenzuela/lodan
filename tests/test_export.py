from __future__ import annotations

import io
import json
import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from lodan.cli import app
from lodan.export import iter_rows, write_json_array, write_jsonl
from lodan.paths import workspace_db
from lodan.store.db import bootstrap, connect


@pytest.fixture
def db(tmp_path: Path):
    dbp = tmp_path / "l.db"
    bootstrap(dbp)
    conn = connect(dbp)
    conn.execute(
        "INSERT INTO scans (id, started_at, cidrs, workspace, status) "
        "VALUES (1, '2026-04-24T00:00:00', '[\"10.0.0.0/24\"]', 'w', 'completed')"
    )
    conn.execute(
        "INSERT INTO scans (id, started_at, cidrs, workspace, status) "
        "VALUES (2, '2026-04-25T00:00:00', '[\"10.0.0.0/24\"]', 'w', 'completed')"
    )
    conn.execute(
        "INSERT INTO hosts (scan_id, ip, rdns, asn, asn_org, country) "
        "VALUES (1, '10.0.0.5', 'host5.corp', 64500, 'Lab', 'US')"
    )
    conn.execute(
        "INSERT INTO services (scan_id, ip, port, proto, service, banner, "
        "cert_sans, tech) VALUES "
        "(1, '10.0.0.5', 443, 'tcp', 'tls', 'nginx/1.25.3', "
        "'[\"example.corp\"]', '[\"nginx\"]')"
    )
    conn.execute(
        "INSERT INTO services (scan_id, ip, port, proto, service) "
        "VALUES (2, '10.0.0.7', 22, 'tcp', 'ssh')"
    )
    conn.execute(
        "INSERT INTO vulns (scan_id, ip, port, cve, cpe, confidence, source) "
        "VALUES (1, '10.0.0.5', 443, 'CVE-2023-0001', 'cpe:x', 0.7, 'banner')"
    )
    yield conn
    conn.close()


def test_iter_rows_all_tables(db) -> None:
    rows = list(iter_rows(db, scan_id=None, tables=("scans", "services", "vulns")))
    tables_seen = {r["_table"] for r in rows}
    assert tables_seen == {"scans", "services", "vulns"}


def test_scan_filter_excludes_other_scans(db) -> None:
    rows = list(iter_rows(db, scan_id=1, tables=("services",)))
    assert len(rows) == 1
    assert rows[0]["ip"] == "10.0.0.5"


def test_scans_filter_uses_id_not_scan_id(db) -> None:
    # scans.id is the scan identifier, not scan_id. scan=2 should match row id=2.
    rows = list(iter_rows(db, scan_id=2, tables=("scans",)))
    assert len(rows) == 1
    assert rows[0]["id"] == 2


def test_json_columns_are_rehydrated(db) -> None:
    (row,) = list(iter_rows(db, scan_id=1, tables=("services",)))
    assert row["tech"] == ["nginx"]
    assert row["cert_sans"] == ["example.corp"]


def test_write_jsonl_and_json(db) -> None:
    rows = list(iter_rows(db, scan_id=1, tables=("hosts",)))
    buf = io.StringIO()
    count = write_jsonl(rows, buf)
    assert count == 1
    assert buf.getvalue().endswith("\n")
    parsed = json.loads(buf.getvalue().splitlines()[0])
    assert parsed["ip"] == "10.0.0.5"

    buf2 = io.StringIO()
    count = write_json_array(rows, buf2)
    arr = json.loads(buf2.getvalue())
    assert count == 1
    assert arr[0]["asn_org"] == "Lab"


def test_unknown_table_raises(db) -> None:
    with pytest.raises(ValueError):
        list(iter_rows(db, scan_id=None, tables=("wat",)))


# --- CLI ---

@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("LODAN_HOME", str(tmp_path))
    runner = CliRunner()
    result = runner.invoke(app, ["init", "w", "--cidrs", "10.0.0.0/24"])
    assert result.exit_code == 0
    conn = sqlite3.connect(workspace_db("w"))
    conn.execute(
        "INSERT INTO scans (id, started_at, cidrs, workspace, status) "
        "VALUES (1, '2026-04-24T00:00:00', '[]', 'w', 'completed')"
    )
    conn.execute(
        "INSERT INTO services (scan_id, ip, port, proto, service, banner) "
        "VALUES (1, '10.0.0.5', 443, 'tcp', 'tls', 'nginx/1.25.3')"
    )
    conn.commit()
    conn.close()
    return "w"


def test_cli_export_jsonl_to_stdout(workspace: str) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["export", workspace, "--include", "services"])
    assert result.exit_code == 0, result.output
    first = result.output.strip().splitlines()[0]
    parsed = json.loads(first)
    assert parsed["_table"] == "services"
    assert parsed["banner"] == "nginx/1.25.3"


def test_cli_export_json_to_file(
    workspace: str, tmp_path: Path
) -> None:
    out = tmp_path / "dump.json"
    runner = CliRunner()
    result = runner.invoke(
        app, ["export", workspace, "--format", "json", "--output", str(out)]
    )
    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text())
    # scan + service rows for scan_id 1.
    assert any(r["_table"] == "scans" for r in data)
    assert any(r["_table"] == "services" for r in data)


def test_cli_export_bad_format(workspace: str) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["export", workspace, "--format", "xml"])
    assert result.exit_code == 1
    assert "unknown --format" in result.output


def test_cli_export_unknown_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LODAN_HOME", str(tmp_path))
    runner = CliRunner()
    result = runner.invoke(app, ["export", "ghost"])
    assert result.exit_code == 1
