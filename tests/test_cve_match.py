from __future__ import annotations

from pathlib import Path

import pytest

from lodan.enrich.cve import banner_to_cpes, enrich_cves, match_cpes
from lodan.enrich.cve_data import CVERecord, upsert
from lodan.enrich.cve_data import connect as cve_connect
from lodan.store import writer
from lodan.store.db import bootstrap, connect


@pytest.mark.parametrize(
    "banner,expected",
    [
        ("Apache/2.4.54 (Ubuntu)", ("apache", "http_server", "2.4.54")),
        ("Server: nginx/1.25.3\r\n", ("nginx", "nginx", "1.25.3")),
        ("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", ("openbsd", "openssh", "8.2p1")),
        ("Microsoft-IIS/10.0", ("microsoft", "internet_information_services", "10.0")),
        ("lighttpd/1.4.65", ("lighttpd", "lighttpd", "1.4.65")),
        ("Caddy v2.7.6", ("caddy", "caddy", "2.7.6")),
    ],
)
def test_banner_recognizers(banner: str, expected: tuple[str, str, str]) -> None:
    guesses = banner_to_cpes(banner)
    assert guesses, f"no guess for {banner!r}"
    g = guesses[0]
    assert (g.vendor, g.product, g.version) == expected
    assert g.confidence == 0.7


def test_banner_no_match() -> None:
    assert banner_to_cpes("random banner") == []
    assert banner_to_cpes(None) == []
    assert banner_to_cpes("") == []


def test_match_cpes_finds_hits_by_prefix(tmp_path: Path) -> None:
    cve = cve_connect(tmp_path / "c.db")
    upsert(
        cve,
        [
            CVERecord(
                "cpe:2.3:a:apache:http_server:2.4.54:*:*:*:*:*:*:*",
                "CVE-2023-1",
                7.5,
                None,
                None,
            ),
            CVERecord(
                "cpe:2.3:a:apache:http_server:2.4.54:update1:*:*:*:*:*:*",
                "CVE-2023-2",
                5.3,
                None,
                None,
            ),
            CVERecord(
                "cpe:2.3:a:apache:http_server:2.4.55:*:*:*:*:*:*:*",
                "CVE-2023-3",
                None,
                None,
                None,
            ),
        ],
    )
    guesses = banner_to_cpes("Apache/2.4.54 (Ubuntu)")
    matches = match_cpes(cve, guesses)
    assert {m.cve for m in matches} == {"CVE-2023-1", "CVE-2023-2"}


def test_enrich_cves_writes_vulns(tmp_path: Path) -> None:
    workspace = tmp_path / "w.db"
    bootstrap(workspace)
    ws = connect(workspace)
    handle = writer.open_scan(ws, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(ws, handle, "10.0.0.5", 80, "tcp")
    ws.execute(
        "UPDATE services SET banner = ? WHERE ip = ? AND port = ?",
        ("Apache/2.4.54 (Ubuntu)", "10.0.0.5", 80),
    )

    cve = cve_connect(tmp_path / "c.db")
    upsert(
        cve,
        [
            CVERecord(
                "cpe:2.3:a:apache:http_server:2.4.54:*:*:*:*:*:*:*",
                "CVE-2023-1",
                7.5,
                None,
                None,
            ),
        ],
    )

    n = enrich_cves(ws, cve, handle.scan_id)
    assert n == 1
    row = ws.execute(
        "SELECT ip, port, cve, confidence, source FROM vulns WHERE scan_id = ?",
        (handle.scan_id,),
    ).fetchone()
    assert row == ("10.0.0.5", 80, "CVE-2023-1", 0.7, "banner-regex")


def test_enrich_cves_is_idempotent(tmp_path: Path) -> None:
    workspace = tmp_path / "w.db"
    bootstrap(workspace)
    ws = connect(workspace)
    handle = writer.open_scan(ws, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(ws, handle, "10.0.0.5", 80, "tcp")
    ws.execute(
        "UPDATE services SET banner = ? WHERE ip = ? AND port = ?",
        ("nginx/1.25.3", "10.0.0.5", 80),
    )
    cve = cve_connect(tmp_path / "c.db")
    upsert(
        cve,
        [
            CVERecord(
                "cpe:2.3:a:nginx:nginx:1.25.3:*:*:*:*:*:*:*",
                "CVE-2024-1",
                5.0,
                None,
                None,
            )
        ],
    )
    enrich_cves(ws, cve, handle.scan_id)
    enrich_cves(ws, cve, handle.scan_id)
    (count,) = ws.execute(
        "SELECT COUNT(*) FROM vulns WHERE scan_id = ?", (handle.scan_id,)
    ).fetchone()
    assert count == 1


def test_enrich_cves_uses_raw_json_for_ssh(tmp_path: Path) -> None:
    workspace = tmp_path / "w.db"
    bootstrap(workspace)
    ws = connect(workspace)
    handle = writer.open_scan(ws, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(ws, handle, "10.0.0.5", 22, "tcp")
    # SSH probe stashes the rich banner inside raw, not the top-level banner.
    import json

    raw = json.dumps(
        {
            "banner": "SSH-2.0-OpenSSH_9.3p1 Debian",
            "parsed": {"software": "OpenSSH_9.3p1"},
        }
    )
    ws.execute(
        "UPDATE services SET service='ssh', raw=? WHERE ip=? AND port=?",
        (raw, "10.0.0.5", 22),
    )

    cve = cve_connect(tmp_path / "c.db")
    upsert(
        cve,
        [
            CVERecord(
                "cpe:2.3:a:openbsd:openssh:9.3p1:*:*:*:*:*:*:*",
                "CVE-2024-SSH",
                7.0,
                None,
                None,
            )
        ],
    )
    n = enrich_cves(ws, cve, handle.scan_id)
    assert n == 1


def test_enrich_cves_no_cves_returns_zero(tmp_path: Path) -> None:
    workspace = tmp_path / "w.db"
    bootstrap(workspace)
    ws = connect(workspace)
    handle = writer.open_scan(ws, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(ws, handle, "10.0.0.5", 80, "tcp")
    ws.execute(
        "UPDATE services SET banner = ? WHERE ip = ? AND port = ?",
        ("Apache/2.4.54", "10.0.0.5", 80),
    )
    cve = cve_connect(tmp_path / "c.db")  # empty
    assert enrich_cves(ws, cve, handle.scan_id) == 0
