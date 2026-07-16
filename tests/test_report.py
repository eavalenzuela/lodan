"""Shareable report bundle: content, escaping, SARIF, manifest integrity."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from lodan import report
from lodan.store import writer
from lodan.store.db import bootstrap, connect


@pytest.fixture
def conn(tmp_path: Path):
    dbp = tmp_path / "l.db"
    bootstrap(dbp)
    c = connect(dbp)
    yield c
    c.close()


def _scan_with_data(conn, *, banner="OpenSSH_9.6", with_vuln=True) -> int:
    h = writer.open_scan(conn, "w", ["10.0.0.0/24"])
    conn.execute(
        "INSERT INTO services (scan_id, ip, port, proto, service, banner, tech, cert_sans) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (h.scan_id, "10.0.0.5", 22, "tcp", "ssh", banner,
         json.dumps(["nginx"]), json.dumps(["a.example.com", "b.example.com"])),
    )
    conn.execute(
        "INSERT INTO hosts (scan_id, ip, rdns, asn, asn_org, country) VALUES (?,?,?,?,?,?)",
        (h.scan_id, "10.0.0.5", "host.example.com", 64500, "Example ISP", "US"),
    )
    if with_vuln:
        conn.execute(
            "INSERT INTO vulns (scan_id, ip, port, cve, cpe, confidence, source) "
            "VALUES (?,?,?,?,?,?,?)",
            (h.scan_id, "10.0.0.5", 22, "CVE-2024-6387", "cpe:/a:openbsd:openssh", 0.8, "nvd"),
        )
    writer.finish_scan(conn, h, status="completed")
    return h.scan_id


def test_generate_writes_all_bundle_files(conn, tmp_path: Path) -> None:
    sid = _scan_with_data(conn)
    out_dir, files = report.generate(conn, sid, tmp_path / "bundle", "9.9.9")
    assert set(files) == {
        "report.html", "services.csv", "hosts.csv", "vulns.csv",
        "findings.csv", "findings.sarif", "manifest.json",
    }
    for name in files:
        assert (out_dir / name).exists()


def test_manifest_checksums_match_files(conn, tmp_path: Path) -> None:
    sid = _scan_with_data(conn)
    out_dir, _ = report.generate(conn, sid, tmp_path / "b", "1.0.0", generated_at="2026-07-15T00:00:00+00:00")
    manifest = json.loads((out_dir / "manifest.json").read_text())
    assert manifest["scan_id"] == sid
    assert manifest["tool"] == "lodan"
    assert manifest["files"]  # non-empty
    for entry in manifest["files"]:
        data = (out_dir / entry["name"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == entry["sha256"]
        assert entry["bytes"] == len(data)
    # manifest never lists itself
    assert "manifest.json" not in {e["name"] for e in manifest["files"]}


def test_html_escapes_hostile_banner(conn, tmp_path: Path) -> None:
    sid = _scan_with_data(conn, banner="<script>alert(1)</script>")
    out_dir, _ = report.generate(conn, sid, tmp_path / "b", "1.0.0")
    htmltext = (out_dir / "report.html").read_text()
    assert "<script>alert(1)</script>" not in htmltext
    assert "&lt;script&gt;" in htmltext


def test_sarif_maps_cve_to_result(conn, tmp_path: Path) -> None:
    sid = _scan_with_data(conn)
    out_dir, _ = report.generate(conn, sid, tmp_path / "b", "1.0.0")
    sarif = json.loads((out_dir / "findings.sarif").read_text())
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "lodan"
    assert [r["ruleId"] for r in run["results"]] == ["CVE-2024-6387"]
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "10.0.0.5:22"


def test_sarif_valid_with_no_vulns(conn, tmp_path: Path) -> None:
    sid = _scan_with_data(conn, with_vuln=False)
    out_dir, _ = report.generate(conn, sid, tmp_path / "b", "1.0.0")
    sarif = json.loads((out_dir / "findings.sarif").read_text())
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


def test_services_csv_flattens_json_arrays(conn, tmp_path: Path) -> None:
    sid = _scan_with_data(conn)
    out_dir, _ = report.generate(conn, sid, tmp_path / "b", "1.0.0")
    csv_text = (out_dir / "services.csv").read_text()
    assert "a.example.com; b.example.com" in csv_text
    assert "nginx" in csv_text


def test_unknown_scan_raises(conn) -> None:
    with pytest.raises(report.ReportError):
        report.build_content(conn, 999, "1.0.0", "2026-07-15T00:00:00+00:00")


def test_report_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from typer.testing import CliRunner

    from lodan.cli import app
    from lodan.paths import workspace_db

    monkeypatch.setenv("LODAN_HOME", str(tmp_path))
    runner = CliRunner()
    assert runner.invoke(app, ["init", "w", "--cidrs", "10.0.0.0/24"]).exit_code == 0

    # No completed scan yet -> error.
    empty = runner.invoke(app, ["report", "w"])
    assert empty.exit_code == 1
    assert "no completed scan" in empty.output

    c = connect(workspace_db("w"))
    sid = _scan_with_data(c)
    c.close()

    out = tmp_path / "bundle"
    result = runner.invoke(app, ["report", "w", "--output", str(out)])
    assert result.exit_code == 0, result.output
    assert (out / "manifest.json").exists()
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["scan_id"] == sid


def test_diff_section_present_when_prior_scan_diffed(conn, tmp_path: Path) -> None:
    from lodan.diff.scanner import compute_and_store

    s1 = _scan_with_data(conn, with_vuln=False)
    s2 = _scan_with_data(conn, with_vuln=False)
    # Add a new service in s2 so the diff is non-empty, then compute+store it.
    conn.execute(
        "INSERT INTO services (scan_id, ip, port, proto, service) VALUES (?,?,?,?,?)",
        (s2, "10.0.0.9", 443, "tcp", "https"),
    )
    compute_and_store(conn, s1, s2)
    out_dir, _ = report.generate(conn, s2, tmp_path / "b", "1.0.0")
    htmltext = (out_dir / "report.html").read_text()
    assert f"Changes since scan #{s1}" in htmltext
    assert "10.0.0.9" in htmltext
