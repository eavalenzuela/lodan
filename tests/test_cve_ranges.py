"""Range-aware CVE matching and structured-version CPEs.

The two precision fixes: advisories expressed as ranges against a wildcard CPE
(which could never match a prefix ending in a concrete version), and CPEs built
from the version fields probes actually parse rather than from banner prose.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from lodan.enrich.cve import CPEGuess, enrich_cves, match_cpes, raw_to_cpes
from lodan.enrich.cve_data import CVERecord, parse_record, upsert
from lodan.enrich.cve_data import connect as cve_connect
from lodan.store import writer
from lodan.store.db import bootstrap, connect


@pytest.fixture
def cve_db(tmp_path: Path):
    conn = cve_connect(tmp_path / "cve.db")
    yield conn
    conn.close()


@pytest.fixture
def db(tmp_path: Path):
    dbp = tmp_path / "l.db"
    bootstrap(dbp)
    conn = connect(dbp)
    yield conn
    conn.close()


def _record(cpe: str, cve: str, **bounds) -> CVERecord:
    return CVERecord(
        cpe=cpe, cve=cve, cvss=7.5, published=None, last_modified=None, **bounds
    )


def _guess(vendor: str, product: str, version: str) -> CPEGuess:
    return CPEGuess(vendor=vendor, product=product, version=version,
                    confidence=0.9, source="test")


# --- NVD record parsing ------------------------------------------------------

def _nvd(cpe_match: dict) -> dict:
    return {
        "cve": {
            "id": "CVE-2023-0001",
            "metrics": {},
            "configurations": [{"nodes": [{"cpeMatch": [cpe_match]}]}],
        }
    }


def test_parse_record_captures_end_excluding() -> None:
    rows = parse_record(_nvd({
        "vulnerable": True,
        "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
        "versionEndExcluding": "2.4.55",
    }))
    assert len(rows) == 1
    assert rows[0].version_end == "2.4.55"
    assert rows[0].version_end_inclusive is False
    assert rows[0].version_start is None


def test_parse_record_captures_start_including() -> None:
    rows = parse_record(_nvd({
        "vulnerable": True,
        "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
        "versionStartIncluding": "2.4.0",
        "versionEndIncluding": "2.4.54",
    }))
    assert rows[0].version_start == "2.4.0"
    assert rows[0].version_start_inclusive is True
    assert rows[0].version_end_inclusive is True


def test_parse_record_without_bounds_leaves_them_null() -> None:
    rows = parse_record(_nvd({
        "vulnerable": True,
        "criteria": "cpe:2.3:a:apache:http_server:2.4.54:*:*:*:*:*:*:*",
    }))
    assert rows[0].version_start is None and rows[0].version_end is None


def test_bounds_round_trip_through_the_database(cve_db) -> None:
    upsert(cve_db, [_record(
        "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "CVE-2023-0001",
        version_end="2.4.55", version_end_inclusive=False,
    )])
    row = cve_db.execute(
        "SELECT version_end, version_end_inclusive FROM cve_cpe"
    ).fetchone()
    assert row == ("2.4.55", 0)


# --- range matching ----------------------------------------------------------

def test_range_advisory_matches_an_affected_version(cve_db) -> None:
    """The headline fix: this row could never match under exact-prefix LIKE."""
    upsert(cve_db, [_record(
        "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "CVE-2023-0001",
        version_end="2.4.55", version_end_inclusive=False,
    )])
    hits = match_cpes(cve_db, [_guess("apache", "http_server", "2.4.54")])
    assert [h.cve for h in hits] == ["CVE-2023-0001"]


def test_range_advisory_suppresses_a_patched_version(cve_db) -> None:
    """Range evaluation removes false positives as well as adding matches."""
    upsert(cve_db, [_record(
        "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "CVE-2023-0001",
        version_end="2.4.55", version_end_inclusive=False,
    )])
    assert match_cpes(cve_db, [_guess("apache", "http_server", "2.4.55")]) == []
    assert match_cpes(cve_db, [_guess("apache", "http_server", "2.4.58")]) == []


def test_closed_range_bounds_both_sides(cve_db) -> None:
    upsert(cve_db, [_record(
        "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", "CVE-2023-0002",
        version_start="1.20.0", version_start_inclusive=True,
        version_end="1.24.0", version_end_inclusive=False,
    )])
    assert match_cpes(cve_db, [_guess("nginx", "nginx", "1.22.1")]) != []
    assert match_cpes(cve_db, [_guess("nginx", "nginx", "1.19.9")]) == []
    assert match_cpes(cve_db, [_guess("nginx", "nginx", "1.24.0")]) == []


def test_concrete_version_still_matches_exactly(cve_db) -> None:
    upsert(cve_db, [_record(
        "cpe:2.3:a:apache:http_server:2.4.54:*:*:*:*:*:*:*", "CVE-2023-0003"
    )])
    assert match_cpes(cve_db, [_guess("apache", "http_server", "2.4.54")]) != []
    assert match_cpes(cve_db, [_guess("apache", "http_server", "2.4.55")]) == []


def test_concrete_version_is_not_prefix_matched(cve_db) -> None:
    """2.4.5 must not match a CVE that names 2.4.54."""
    upsert(cve_db, [_record(
        "cpe:2.3:a:apache:http_server:2.4.54:*:*:*:*:*:*:*", "CVE-2023-0003"
    )])
    assert match_cpes(cve_db, [_guess("apache", "http_server", "2.4.5")]) == []


def test_unbounded_wildcard_matches_at_reduced_confidence(cve_db) -> None:
    """"All versions" is a real NVD encoding but the broadest possible match."""
    upsert(cve_db, [_record(
        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", "CVE-2023-0004"
    )])
    hits = match_cpes(cve_db, [_guess("vendor", "product", "1.2.3")])
    assert len(hits) == 1
    assert hits[0].confidence < 0.9


def test_a_different_product_never_matches(cve_db) -> None:
    upsert(cve_db, [_record(
        "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", "CVE-2023-0001",
        version_end="9.9", version_end_inclusive=True,
    )])
    assert match_cpes(cve_db, [_guess("nginx", "nginx", "1.0")]) == []


def test_openssh_portable_version_in_a_range(cve_db) -> None:
    upsert(cve_db, [_record(
        "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "CVE-2023-38408",
        version_start="5.5", version_start_inclusive=True,
        version_end="9.3p2", version_end_inclusive=False,
    )])
    assert match_cpes(cve_db, [_guess("openbsd", "openssh", "8.2p1")]) != []
    assert match_cpes(cve_db, [_guess("openbsd", "openssh", "9.3p2")]) == []


def test_unparseable_version_does_not_match_every_range(cve_db) -> None:
    upsert(cve_db, [_record(
        "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*", "CVE-2023-0005",
        version_end="7.0.0", version_end_inclusive=False,
    )])
    assert match_cpes(cve_db, [_guess("redis", "redis", "unknown")]) == []


# --- structured-version CPEs -------------------------------------------------

@pytest.mark.parametrize(
    ("service", "raw", "vendor", "product", "expected"),
    [
        ("redis", {"fields": {"redis_version": "6.2.6"}}, "redis", "redis", "6.2.6"),
        ("docker", {"payload": {"Version": "24.0.7"}}, "docker", "docker", "24.0.7"),
        ("kubernetes", {"payload": {"gitVersion": "v1.28.2"}},
         "kubernetes", "kubernetes", "1.28.2"),
        ("elasticsearch", {"version": "8.11.1"}, "elastic", "elasticsearch", "8.11.1"),
        ("mongo", {"version": "6.0.11"}, "mongodb", "mongodb", "6.0.11"),
        ("mysql", {"server_version": "8.0.35"}, "oracle", "mysql", "8.0.35"),
    ],
)
def test_raw_recognizers_read_structured_fields(
    service: str, raw: dict, vendor: str, product: str, expected: str
) -> None:
    guesses = raw_to_cpes(service, raw)
    assert len(guesses) == 1
    assert (guesses[0].vendor, guesses[0].product) == (vendor, product)
    assert guesses[0].version == expected
    assert guesses[0].confidence == 0.9
    assert guesses[0].source == "raw-field"


def test_distro_packaging_suffix_is_trimmed() -> None:
    """Debian/Ubuntu append their own revision; NVD indexes upstream."""
    guesses = raw_to_cpes("mysql", {"server_version": "8.0.35-0ubuntu0.22.04.1"})
    assert guesses[0].version == "8.0.35"


def test_k3s_style_build_suffix_is_trimmed() -> None:
    guesses = raw_to_cpes("kubernetes", {"payload": {"gitVersion": "v1.28.2+k3s1"}})
    assert guesses[0].version == "1.28.2"


def test_openssh_version_from_the_parsed_field() -> None:
    guesses = raw_to_cpes("ssh", {"parsed": {"software": "OpenSSH_8.2p1"}})
    assert (guesses[0].vendor, guesses[0].product) == ("openbsd", "openssh")
    assert guesses[0].version == "8.2p1"


def test_php_from_x_powered_by() -> None:
    guesses = raw_to_cpes("http", {"headers": {"x-powered-by": "PHP/8.1.2"}})
    assert (guesses[0].vendor, guesses[0].product) == ("php", "php")
    assert guesses[0].version == "8.1.2"


def test_recognizer_only_fires_for_its_own_service() -> None:
    assert raw_to_cpes("http", {"fields": {"redis_version": "6.2.6"}}) == []


@pytest.mark.parametrize(
    "raw", [None, {}, {"fields": {}}, {"fields": {"redis_version": "unknown"}}, "a string"]
)
def test_raw_recognizers_tolerate_missing_or_junk(raw) -> None:
    assert raw_to_cpes("redis", raw) == []


# --- end to end --------------------------------------------------------------

def test_redis_gets_cve_coverage_it_never_had(db, cve_db) -> None:
    """Redis matched nothing before: the banner recognizers only ever caught
    web-server and SSH strings."""
    upsert(cve_db, [_record(
        "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*", "CVE-2022-0543",
        version_end="6.2.7", version_end_inclusive=False,
    )])
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(db, h, "10.0.0.5", 6379, "tcp")
    db.execute(
        "UPDATE services SET service = 'redis', banner = 'redis 6.2.6', raw = ? "
        "WHERE scan_id = ?",
        (json.dumps({"fields": {"redis_version": "6.2.6"}}), h.scan_id),
    )
    assert enrich_cves(db, cve_db, h.scan_id) == 1
    row = db.execute(
        "SELECT cve, confidence, source FROM vulns WHERE scan_id = ?", (h.scan_id,)
    ).fetchone()
    assert row[0] == "CVE-2022-0543"
    assert row[1] == 0.9
    assert row[2] == "raw-field"


def test_patched_redis_is_not_reported(db, cve_db) -> None:
    upsert(cve_db, [_record(
        "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*", "CVE-2022-0543",
        version_end="6.2.7", version_end_inclusive=False,
    )])
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(db, h, "10.0.0.5", 6379, "tcp")
    db.execute(
        "UPDATE services SET service = 'redis', raw = ? WHERE scan_id = ?",
        (json.dumps({"fields": {"redis_version": "7.2.3"}}), h.scan_id),
    )
    assert enrich_cves(db, cve_db, h.scan_id) == 0


def test_enrich_preserves_keyposture_vulns(db, cve_db) -> None:
    """ROCA rows are written by a different pass and must survive a re-run."""
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(db, h, "10.0.0.5", 22, "tcp")
    db.execute(
        "UPDATE services SET service = 'ssh', banner = 'x' WHERE scan_id = ?",
        (h.scan_id,),
    )
    db.execute(
        "INSERT INTO vulns (scan_id, ip, port, cve, confidence, source) "
        "VALUES (?, '10.0.0.5', 22, 'CVE-2017-15361', 0.9, 'keyposture')",
        (h.scan_id,),
    )
    enrich_cves(db, cve_db, h.scan_id)
    remaining = db.execute(
        "SELECT cve FROM vulns WHERE scan_id = ? AND source = 'keyposture'", (h.scan_id,)
    ).fetchall()
    assert remaining == [("CVE-2017-15361",)]


def test_migration_adds_bounds_to_an_existing_database(tmp_path: Path) -> None:
    """An existing ~/.lodan/data/nvd/cve.db must gain the columns without a
    full re-download."""
    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.execute(
        "CREATE TABLE cve_cpe (cpe TEXT NOT NULL, cve TEXT NOT NULL, cvss REAL, "
        "published TEXT, last_modified TEXT, PRIMARY KEY (cpe, cve))"
    )
    old.execute(
        "INSERT INTO cve_cpe (cpe, cve, cvss) VALUES "
        "('cpe:2.3:a:apache:http_server:2.4.54:*:*:*:*:*:*:*', 'CVE-2000-0001', 5.0)"
    )
    old.commit()
    old.close()

    conn = cve_connect(path)
    try:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(cve_cpe)")}
        assert {"version_start", "version_end", "version_start_inclusive",
                "version_end_inclusive"} <= columns
        # Existing rows survive and still match.
        assert match_cpes(conn, [_guess("apache", "http_server", "2.4.54")]) != []
    finally:
        conn.close()
