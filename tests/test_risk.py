"""Rising-risk analysis: EPSS / KEV / EOL ingestion, scoring, and the
`risk_increased` diff.

Every dataset is fed in as already-fetched text, so nothing here needs a
network.
"""
from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from lodan.diff.scanner import compute_and_store
from lodan.enrich.cve_data import connect as cve_connect
from lodan.enrich.risk import cycle_for, enrich_risk, eol_lookup, priority_for
from lodan.enrich.risk_data import (
    ensure_schema,
    parse_eol,
    parse_epss_csv,
    parse_kev,
    upsert_eol,
    upsert_epss,
    upsert_kev,
)
from lodan.store import writer
from lodan.store.db import bootstrap, connect
from lodan.store.query import QueryError, compile, run_query

_TODAY = date(2026, 7, 30)


@pytest.fixture
def risk_db(tmp_path: Path):
    conn = cve_connect(tmp_path / "cve.db")
    ensure_schema(conn)
    yield conn
    conn.close()


@pytest.fixture
def db(tmp_path: Path):
    dbp = tmp_path / "l.db"
    bootstrap(dbp)
    conn = connect(dbp)
    yield conn
    conn.close()


# --- EPSS ingestion ----------------------------------------------------------

_EPSS_CSV = """#model_version:v2023.03.01,score_date:2026-07-29T00:00:00+0000
cve,epss,percentile
CVE-2021-44228,0.97540,0.99990
CVE-2023-0001,0.00042,0.10000
"""


def test_parse_epss_skips_the_comment_header() -> None:
    rows = parse_epss_csv(_EPSS_CSV)
    assert len(rows) == 2
    assert rows[0][0] == "CVE-2021-44228"
    assert rows[0][1] == pytest.approx(0.9754)
    assert rows[0][3] == "2026-07-29T00:00:00+0000"   # score_date from the comment


def test_parse_epss_ignores_junk_rows() -> None:
    rows = parse_epss_csv("cve,epss,percentile\nnot-a-cve,0.5,0.5\nCVE-1,bad,0.5\n")
    assert rows == []


def test_parse_epss_on_empty_input() -> None:
    assert parse_epss_csv("") == []


def test_epss_round_trips(risk_db) -> None:
    assert upsert_epss(risk_db, parse_epss_csv(_EPSS_CSV)) == 2
    row = risk_db.execute(
        "SELECT score, percentile FROM epss WHERE cve = 'CVE-2021-44228'"
    ).fetchone()
    assert row[0] == pytest.approx(0.9754)


# --- KEV ingestion -----------------------------------------------------------

_KEV_JSON = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 RCE",
            "dateAdded": "2021-12-10",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
            "shortDescription": "…",
        },
        {"cveID": "CVE-2023-0002", "knownRansomwareCampaignUse": "Unknown"},
        {"cveID": "not-a-cve"},
    ]
}


def test_parse_kev_reads_entries_and_ransomware_flag() -> None:
    rows = parse_kev(_KEV_JSON)
    assert len(rows) == 2                       # the junk id is dropped
    assert rows[0][0] == "CVE-2021-44228"
    assert rows[0][6] == 1                      # ransomware known
    assert rows[1][6] == 0


def test_parse_kev_accepts_a_json_string() -> None:
    assert len(parse_kev(json.dumps(_KEV_JSON))) == 2


def test_parse_kev_on_junk() -> None:
    assert parse_kev("not json") == []
    assert parse_kev({}) == []


# --- EOL ingestion -----------------------------------------------------------

_EOL_JSON = [
    {"cycle": "20.04", "eol": "2025-05-29", "support": "2025-04-02", "latest": "20.04.6"},
    {"cycle": "22.04", "eol": "2027-06-01", "latest": "22.04.3"},
    {"cycle": "18.04", "eol": True, "latest": "18.04.6"},
    {"cycle": "24.04", "eol": False, "latest": "24.04.1"},
]


def test_parse_eol_handles_polymorphic_eol_field() -> None:
    """endoflife.date uses a date, `true`, or `false` in the same field."""
    rows = {r[1]: r[2] for r in parse_eol("ubuntu", _EOL_JSON)}
    assert rows["20.04"] == "2025-05-29"
    assert rows["18.04"] == "1970-01-01"        # already EOL, date unknown
    assert rows["24.04"] is None                # still supported


def test_parse_eol_on_junk() -> None:
    assert parse_eol("ubuntu", "not json") == []
    assert parse_eol("ubuntu", {}) == []


# --- cycle derivation --------------------------------------------------------

@pytest.mark.parametrize(
    ("product", "version", "expected"),
    [
        ("ubuntu", "20.04", "20.04"),
        ("ubuntu", "20.04.6", "20.04"),
        ("apache", "2.4.54", "2.4"),
        ("kubernetes", "1.28.2", "1.28"),
        ("debian", "11.7", "11"),
        ("postgresql", "15.4", "15"),
        ("openssh", "8.2p1", "8.2p1"),   # no dot beyond depth; kept whole
    ],
)
def test_cycle_for(product: str, version: str, expected: str) -> None:
    assert cycle_for(product, version) == expected


def test_cycle_for_rejects_non_versions() -> None:
    assert cycle_for("ubuntu", "unknown") is None
    assert cycle_for("ubuntu", None) is None


# --- EOL lookup --------------------------------------------------------------

def test_eol_lookup_flags_a_past_date(risk_db) -> None:
    upsert_eol(risk_db, parse_eol("ubuntu", _EOL_JSON))
    verdict = eol_lookup(risk_db, "ubuntu", "20.04.6", today=_TODAY)
    assert verdict is not None
    assert verdict.cycle == "20.04"
    assert verdict.days_past > 400


def test_eol_lookup_is_silent_for_supported_releases(risk_db) -> None:
    upsert_eol(risk_db, parse_eol("ubuntu", _EOL_JSON))
    assert eol_lookup(risk_db, "ubuntu", "22.04.3", today=_TODAY) is None
    assert eol_lookup(risk_db, "ubuntu", "24.04.1", today=_TODAY) is None


def test_eol_lookup_on_an_unknown_cycle(risk_db) -> None:
    upsert_eol(risk_db, parse_eol("ubuntu", _EOL_JSON))
    assert eol_lookup(risk_db, "ubuntu", "19.10", today=_TODAY) is None


# --- priority ----------------------------------------------------------------

def test_kev_outranks_every_score() -> None:
    """"Someone is actually exploiting this" is a different kind of fact."""
    assert priority_for(cvss=0.0, epss=0.0, on_kev=True) == "critical"
    assert priority_for(cvss=None, epss=None, on_kev=True) == "critical"


def test_high_epss_or_high_cvss_is_high() -> None:
    assert priority_for(cvss=None, epss=0.5, on_kev=False) == "high"
    assert priority_for(cvss=9.8, epss=None, on_kev=False) == "high"


def test_moderate_signals_are_medium() -> None:
    assert priority_for(cvss=None, epss=0.02, on_kev=False) == "medium"
    assert priority_for(cvss=7.5, epss=None, on_kev=False) == "medium"


def test_everything_else_is_low() -> None:
    assert priority_for(cvss=3.0, epss=0.0001, on_kev=False) == "low"
    assert priority_for(cvss=None, epss=None, on_kev=False) == "low"


# --- enrichment --------------------------------------------------------------

def _vuln(conn, handle, ip, port, cve, **cols):
    conn.execute(
        "INSERT INTO vulns (scan_id, ip, port, cve, confidence, source) "
        "VALUES (?, ?, ?, ?, 0.9, 'test')",
        (handle.scan_id, ip, port, cve),
    )
    if cols:
        sets = ", ".join(f"{k} = ?" for k in cols)
        conn.execute(
            f"UPDATE vulns SET {sets} WHERE scan_id = ? AND cve = ?",
            (*cols.values(), handle.scan_id, cve),
        )


def test_enrich_risk_scores_vulns(db, risk_db) -> None:
    upsert_epss(risk_db, parse_epss_csv(_EPSS_CSV))
    upsert_kev(risk_db, parse_kev(_KEV_JSON))
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(db, h, "10.0.0.5", 8080, "tcp")
    _vuln(db, h, "10.0.0.5", 8080, "CVE-2021-44228")
    _vuln(db, h, "10.0.0.5", 8080, "CVE-2023-0001")

    prioritized, _eol = enrich_risk(db, risk_db, h.scan_id, today=_TODAY)
    assert prioritized == 2
    rows = {
        cve: (epss, kev, ransomware, priority)
        for cve, epss, kev, ransomware, priority in db.execute(
            "SELECT cve, epss, kev, ransomware, priority FROM vulns WHERE scan_id = ?",
            (h.scan_id,),
        )
    }
    assert rows["CVE-2021-44228"][1] == 1          # on KEV
    assert rows["CVE-2021-44228"][2] == 1          # ransomware
    assert rows["CVE-2021-44228"][3] == "critical"
    assert rows["CVE-2023-0001"][1] == 0
    assert rows["CVE-2023-0001"][3] == "low"


def test_enrich_risk_flags_eol_from_os_guess(db, risk_db) -> None:
    upsert_eol(risk_db, parse_eol("ubuntu", _EOL_JSON))
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(db, h, "10.0.0.5", 22, "tcp")
    db.execute(
        "UPDATE services SET service = 'ssh', os_guess = 'Ubuntu 20.04' WHERE scan_id = ?",
        (h.scan_id,),
    )
    _prioritized, eol_count = enrich_risk(db, risk_db, h.scan_id, today=_TODAY)
    assert eol_count == 1
    row = db.execute(
        "SELECT category, severity, title FROM findings WHERE scan_id = ?", (h.scan_id,)
    ).fetchone()
    assert row[0] == "eol"
    assert row[1] == "high"                        # more than a year past
    assert "end of support" in row[2]


def test_supported_release_produces_no_eol_finding(db, risk_db) -> None:
    upsert_eol(risk_db, parse_eol("ubuntu", _EOL_JSON))
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(db, h, "10.0.0.5", 22, "tcp")
    db.execute(
        "UPDATE services SET os_guess = 'Ubuntu 22.04' WHERE scan_id = ?", (h.scan_id,)
    )
    assert enrich_risk(db, risk_db, h.scan_id, today=_TODAY)[1] == 0


def test_enrich_risk_is_idempotent(db, risk_db) -> None:
    upsert_eol(risk_db, parse_eol("ubuntu", _EOL_JSON))
    upsert_kev(risk_db, parse_kev(_KEV_JSON))
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(db, h, "10.0.0.5", 22, "tcp")
    db.execute(
        "UPDATE services SET os_guess = 'Ubuntu 20.04' WHERE scan_id = ?", (h.scan_id,)
    )
    _vuln(db, h, "10.0.0.5", 22, "CVE-2021-44228")
    first = enrich_risk(db, risk_db, h.scan_id, today=_TODAY)
    second = enrich_risk(db, risk_db, h.scan_id, today=_TODAY)
    assert first == second
    assert db.execute(
        "SELECT COUNT(*) FROM findings WHERE category = 'eol'"
    ).fetchone()[0] == 1


def test_enrich_risk_on_an_empty_scan(db, risk_db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    assert enrich_risk(db, risk_db, h.scan_id, today=_TODAY) == (0, 0)


# --- query DSL ---------------------------------------------------------------

def test_dsl_kev_priority_and_epss(db, risk_db) -> None:
    upsert_epss(risk_db, parse_epss_csv(_EPSS_CSV))
    upsert_kev(risk_db, parse_kev(_KEV_JSON))
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    for ip, cve in (("10.0.0.5", "CVE-2021-44228"), ("10.0.0.6", "CVE-2023-0001")):
        writer.upsert_discovered_service(db, h, ip, 8080, "tcp")
        _vuln(db, h, ip, 8080, cve)
    enrich_risk(db, risk_db, h.scan_id, today=_TODAY)

    assert {r["ip"] for r in run_query(db, "kev:true", scan_id=h.scan_id)} == {"10.0.0.5"}
    assert {r["ip"] for r in run_query(db, "kev:false", scan_id=h.scan_id)} == {"10.0.0.6"}
    assert {r["ip"] for r in run_query(db, "priority:critical", scan_id=h.scan_id)} == {
        "10.0.0.5"
    }
    assert {r["ip"] for r in run_query(db, "epss:0.5", scan_id=h.scan_id)} == {"10.0.0.5"}


def test_dsl_eol_filter(db, risk_db) -> None:
    upsert_eol(risk_db, parse_eol("ubuntu", _EOL_JSON))
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    for ip, release in (("10.0.0.5", "Ubuntu 20.04"), ("10.0.0.6", "Ubuntu 22.04")):
        writer.upsert_discovered_service(db, h, ip, 22, "tcp")
        db.execute(
            "UPDATE services SET os_guess = ? WHERE scan_id = ? AND ip = ?",
            (release, h.scan_id, ip),
        )
    enrich_risk(db, risk_db, h.scan_id, today=_TODAY)
    assert {r["ip"] for r in run_query(db, "eol:true", scan_id=h.scan_id)} == {"10.0.0.5"}


def test_dsl_rejects_bad_risk_values() -> None:
    for expr in ("kev:sometimes", "eol:maybe", "epss:high"):
        with pytest.raises(QueryError):
            compile(expr)


# --- risk_increased diff -----------------------------------------------------

def _two_scans(conn):
    a = writer.open_scan(conn, "w", ["10.0.0.0/24"])
    writer.finish_scan(conn, a)
    b = writer.open_scan(conn, "w", ["10.0.0.0/24"])
    writer.finish_scan(conn, b)
    return a, b


def test_newly_kev_fires_risk_increased(db) -> None:
    """Nothing moved on the wire; the CVE became known-exploited."""
    a, b = _two_scans(db)
    for handle, kev, priority in ((a, 0, "medium"), (b, 1, "critical")):
        writer.upsert_discovered_service(db, handle, "10.0.0.5", 8080, "tcp")
        _vuln(db, handle, "10.0.0.5", 8080, "CVE-2021-44228",
              kev=kev, priority=priority)
    counts = compute_and_store(db, a.scan_id, b.scan_id)
    assert counts.risk_increased == 1
    (raw,) = db.execute(
        "SELECT detail FROM scan_diffs WHERE kind = 'risk_increased'"
    ).fetchone()
    detail = json.loads(raw)
    assert "newly-kev" in detail["reasons"]


def test_priority_rising_fires_risk_increased(db) -> None:
    a, b = _two_scans(db)
    for handle, priority in ((a, "low"), (b, "high")):
        writer.upsert_discovered_service(db, handle, "10.0.0.5", 8080, "tcp")
        _vuln(db, handle, "10.0.0.5", 8080, "CVE-2023-0001", kev=0, priority=priority)
    assert compute_and_store(db, a.scan_id, b.scan_id).risk_increased == 1


def test_priority_falling_is_not_a_risk_increase(db) -> None:
    """Good news is not a finding."""
    a, b = _two_scans(db)
    for handle, priority in ((a, "critical"), (b, "low")):
        writer.upsert_discovered_service(db, handle, "10.0.0.5", 8080, "tcp")
        _vuln(db, handle, "10.0.0.5", 8080, "CVE-2023-0001", kev=0, priority=priority)
    assert compute_and_store(db, a.scan_id, b.scan_id).risk_increased == 0


def test_unchanged_risk_is_silent(db) -> None:
    a, b = _two_scans(db)
    for handle in (a, b):
        writer.upsert_discovered_service(db, handle, "10.0.0.5", 8080, "tcp")
        _vuln(db, handle, "10.0.0.5", 8080, "CVE-2023-0001", kev=0, priority="medium")
    assert compute_and_store(db, a.scan_id, b.scan_id).risk_increased == 0


def test_newly_eol_fires_risk_increased(db) -> None:
    a, b = _two_scans(db)
    for handle in (a, b):
        writer.upsert_discovered_service(db, handle, "10.0.0.5", 22, "tcp")
    db.execute(
        "INSERT INTO findings (scan_id, ip, port, category, severity, title) "
        "VALUES (?, '10.0.0.5', 22, 'eol', 'high', 'ubuntu 20.04 reached EOL')",
        (b.scan_id,),
    )
    counts = compute_and_store(db, a.scan_id, b.scan_id)
    assert counts.risk_increased == 1
    (raw,) = db.execute(
        "SELECT detail FROM scan_diffs WHERE kind = 'risk_increased'"
    ).fetchone()
    assert "newly-eol" in json.loads(raw)["reasons"]


def test_a_brand_new_service_is_not_double_counted(db) -> None:
    """It's already reported as new_service."""
    a, b = _two_scans(db)
    writer.upsert_discovered_service(db, b, "10.0.0.9", 8080, "tcp")
    _vuln(db, b, "10.0.0.9", 8080, "CVE-2021-44228", kev=1, priority="critical")
    counts = compute_and_store(db, a.scan_id, b.scan_id)
    assert counts.new_service == 1
    assert counts.risk_increased == 0


def test_several_rising_cves_collapse_to_one_row(db) -> None:
    """scan_diffs is keyed on (kind, ip, port)."""
    a, b = _two_scans(db)
    for handle, priority in ((a, "low"), (b, "critical")):
        writer.upsert_discovered_service(db, handle, "10.0.0.5", 8080, "tcp")
        for cve in ("CVE-2023-0001", "CVE-2023-0002"):
            _vuln(db, handle, "10.0.0.5", 8080, cve, kev=0, priority=priority)
    counts = compute_and_store(db, a.scan_id, b.scan_id)
    assert counts.risk_increased == 1
    (raw,) = db.execute(
        "SELECT detail FROM scan_diffs WHERE kind = 'risk_increased'"
    ).fetchone()
    assert len(json.loads(raw)["items"]) == 2
