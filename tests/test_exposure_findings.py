"""Exposure findings: HTTP headers/pages, amplification, and the
new_exposure / gone_exposure diff.

All pure post-hoc analysis of `raw` the probes already collected.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from lodan.diff.scanner import compute_and_store
from lodan.findings import ServiceRow, detect
from lodan.store import writer
from lodan.store.db import bootstrap, connect
from lodan.store.query import run_query

_NOW = datetime(2026, 7, 30, tzinfo=UTC)

_ALL_HEADERS = {
    "strict-transport-security": "max-age=63072000",
    "content-security-policy": "default-src 'self'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
}


@pytest.fixture
def db(tmp_path: Path):
    dbp = tmp_path / "l.db"
    bootstrap(dbp)
    conn = connect(dbp)
    yield conn
    conn.close()


def _http(**raw) -> ServiceRow:
    return ServiceRow(ip="10.0.0.5", port=80, service="http", banner="x", raw=raw)


def _categories(findings) -> set[str]:
    return {f.category for f in findings}


# --- security headers --------------------------------------------------------

def test_fully_hardened_site_gets_grade_a_and_no_finding() -> None:
    findings = detect(_http(headers=dict(_ALL_HEADERS)), _NOW)
    assert "http-headers" not in _categories(findings)


def test_missing_headers_are_graded_not_enumerated() -> None:
    """Five separate rows for one unhardened site is noise."""
    findings = [f for f in detect(_http(headers={}), _NOW) if f.category == "http-headers"]
    assert len(findings) == 1
    assert findings[0].detail["grade"] == "F"
    assert len(findings[0].detail["missing"]) == 5


def test_partial_hardening_grades_between() -> None:
    headers = {"strict-transport-security": "max-age=1", "x-frame-options": "DENY"}
    findings = [f for f in detect(_http(headers=headers), _NOW) if f.category == "http-headers"]
    assert findings[0].detail["grade"] == "D"


def test_wildcard_cors_is_low_alone() -> None:
    headers = dict(_ALL_HEADERS, **{"access-control-allow-origin": "*"})
    findings = [f for f in detect(_http(headers=headers), _NOW) if "CORS" in f.title]
    assert [f.severity for f in findings] == ["low"]


def test_wildcard_cors_with_credentials_is_high() -> None:
    """The combination browsers refuse — a server sending both is misconfigured."""
    headers = dict(_ALL_HEADERS, **{
        "access-control-allow-origin": "*",
        "access-control-allow-credentials": "true",
    })
    findings = [f for f in detect(_http(headers=headers), _NOW) if "CORS" in f.title]
    assert [f.severity for f in findings] == ["high"]


def test_specific_cors_origin_is_not_flagged() -> None:
    headers = dict(_ALL_HEADERS, **{"access-control-allow-origin": "https://app.example.com"})
    assert not [f for f in detect(_http(headers=headers), _NOW) if "CORS" in f.title]


def test_cookie_missing_attributes_is_flagged() -> None:
    headers = dict(_ALL_HEADERS, **{"set-cookie": "session=abc123; Path=/"})
    findings = [f for f in detect(_http(headers=headers), _NOW) if "Cookie" in f.title]
    assert len(findings) == 1
    for flag in ("Secure", "HttpOnly", "SameSite"):
        assert flag in findings[0].title


def test_fully_attributed_cookie_is_clean() -> None:
    headers = dict(_ALL_HEADERS, **{
        "set-cookie": "session=abc; Path=/; Secure; HttpOnly; SameSite=Strict",
    })
    assert not [f for f in detect(_http(headers=headers), _NOW) if "Cookie" in f.title]


def test_no_headers_at_all_produces_nothing() -> None:
    assert detect(_http(), _NOW) == []


# --- pages -------------------------------------------------------------------

def test_directory_listing_is_high() -> None:
    findings = detect(_http(headers=dict(_ALL_HEADERS),
                            body="<html><title>Index of /backup</title>"), _NOW)
    listing = [f for f in findings if f.category == "directory-listing"]
    assert [f.severity for f in listing] == ["high"]


def test_default_nginx_page_is_low() -> None:
    findings = detect(_http(headers=dict(_ALL_HEADERS), body="<h1>Welcome to nginx!</h1>"), _NOW)
    assert [f.severity for f in findings if f.category == "default-page"] == ["low"]


@pytest.mark.parametrize(
    "body",
    ["Werkzeug Debugger", "Traceback (most recent call last)", "<title>phpinfo()"],
)
def test_debug_pages_are_high(body: str) -> None:
    findings = detect(_http(headers=dict(_ALL_HEADERS), body=body), _NOW)
    assert [f.severity for f in findings if f.category == "debug-page"] == ["high"]


def test_only_one_page_category_fires() -> None:
    """A page can only be one kind of page."""
    body = "<title>Index of /</title> Welcome to nginx!"
    findings = detect(_http(headers=dict(_ALL_HEADERS), body=body), _NOW)
    page_findings = [
        f for f in findings
        if f.category in ("directory-listing", "default-page", "debug-page")
    ]
    assert len(page_findings) == 1


def test_open_admin_panel_is_flagged() -> None:
    findings = detect(
        _http(headers=dict(_ALL_HEADERS), title="Grafana", status=200), _NOW
    )
    admin = [f for f in findings if f.category == "admin-open"]
    assert len(admin) == 1
    assert admin[0].detail["product"] == "Grafana"


@pytest.mark.parametrize("status", [401, 403])
def test_admin_panel_behind_auth_is_not_flagged(status: int) -> None:
    """A 401 means the gate is doing its job."""
    findings = detect(
        _http(headers=dict(_ALL_HEADERS), title="Grafana", status=status), _NOW
    )
    assert "admin-open" not in _categories(findings)


def test_page_detectors_ignore_non_http_services() -> None:
    row = ServiceRow(ip="10.0.0.5", port=22, service="ssh", banner="x",
                     raw={"body": "Welcome to nginx!"})
    assert "default-page" not in _categories(detect(row, _NOW))


# --- amplification / UDP services --------------------------------------------

def test_amplification_is_reported_by_factor() -> None:
    row = ServiceRow(ip="10.0.0.5", port=123, service="ntp", banner="x",
                     raw={"amplification": 40.0})
    findings = [f for f in detect(row, _NOW) if f.category == "amplification"]
    assert [f.severity for f in findings] == ["high"]
    row = ServiceRow(ip="10.0.0.5", port=123, service="ntp", banner="x",
                     raw={"amplification": 8.0})
    assert [f.severity for f in detect(row, _NOW) if f.category == "amplification"] == [
        "medium"
    ]


def test_small_amplification_is_not_reported() -> None:
    row = ServiceRow(ip="10.0.0.5", port=123, service="ntp", banner="x",
                     raw={"amplification": 1.5})
    assert "amplification" not in _categories(detect(row, _NOW))


def test_default_community_snmp_is_high() -> None:
    row = ServiceRow(ip="10.0.0.5", port=161, service="snmp", banner="x",
                     raw={"community_accepted": "public", "sys_descr": "Cisco IOS"})
    findings = [f for f in detect(row, _NOW) if f.category == "unauth-service"]
    assert [f.severity for f in findings] == ["high"]


def test_weak_ike_transform_is_flagged() -> None:
    row = ServiceRow(ip="10.0.0.5", port=500, service="ike", banner="x",
                     raw={"weak_transform": ["DES", "MD5"],
                          "selected_transform": {"encryption": "DES"}})
    assert "weak-crypto" in _categories(detect(row, _NOW))


def test_anonymous_ldap_rootdse_is_flagged() -> None:
    row = ServiceRow(ip="10.0.0.5", port=389, service="ldap", banner="x",
                     raw={"rootdse": {"namingContexts": ["dc=x"]},
                          "naming_contexts": ["dc=x"]})
    assert "unauth-service" in _categories(detect(row, _NOW))


def test_refused_ldap_is_not_flagged() -> None:
    row = ServiceRow(ip="10.0.0.5", port=389, service="ldap", banner="x",
                     raw={"result_code": 50})
    assert detect(row, _NOW) == []


# --- DSL ---------------------------------------------------------------------

def _finding(conn, handle, ip, port, category, severity="high"):
    conn.execute(
        "INSERT INTO findings (scan_id, ip, port, category, severity, title) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (handle.scan_id, ip, port, category, severity, f"{category} on {ip}"),
    )


def test_dsl_finding_and_severity_facets(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    for ip, category, severity in (
        ("10.0.0.5", "directory-listing", "high"),
        ("10.0.0.6", "http-headers", "low"),
    ):
        writer.upsert_discovered_service(db, h, ip, 80, "tcp")
        _finding(db, h, ip, 80, category, severity)

    assert {r["ip"] for r in run_query(db, "finding:directory-listing", scan_id=h.scan_id)} == {
        "10.0.0.5"
    }
    assert {r["ip"] for r in run_query(db, "severity:high", scan_id=h.scan_id)} == {"10.0.0.5"}
    assert {r["ip"] for r in run_query(db, "finding:http-*", scan_id=h.scan_id)} == {"10.0.0.6"}


# --- new_exposure / gone_exposure --------------------------------------------

def _two_scans(conn):
    a = writer.open_scan(conn, "w", ["10.0.0.0/24"])
    writer.finish_scan(conn, a)
    b = writer.open_scan(conn, "w", ["10.0.0.0/24"])
    writer.finish_scan(conn, b)
    return a, b


def test_new_exposure_fires_when_a_category_appears(db) -> None:
    a, b = _two_scans(db)
    for handle in (a, b):
        writer.upsert_discovered_service(db, handle, "10.0.0.5", 80, "tcp")
    _finding(db, b, "10.0.0.5", 80, "directory-listing")
    counts = compute_and_store(db, a.scan_id, b.scan_id)
    assert counts.new_exposure == 1
    assert counts.gone_exposure == 0
    (raw,) = db.execute(
        "SELECT detail FROM scan_diffs WHERE kind = 'new_exposure'"
    ).fetchone()
    assert json.loads(raw)["categories"] == ["directory-listing"]


def test_gone_exposure_reports_remediation(db) -> None:
    """An operator needs to see a fix land, not only a break appear."""
    a, b = _two_scans(db)
    for handle in (a, b):
        writer.upsert_discovered_service(db, handle, "10.0.0.5", 80, "tcp")
    _finding(db, a, "10.0.0.5", 80, "directory-listing")
    counts = compute_and_store(db, a.scan_id, b.scan_id)
    assert counts.gone_exposure == 1
    assert counts.new_exposure == 0


def test_an_ageing_certificate_does_not_fire_every_scan(db) -> None:
    """Titles embed day counts; matching on them would report a change forever."""
    a, b = _two_scans(db)
    for handle, title in (
        (a, "TLS certificate expires within 30 days (12 days)."),
        (b, "TLS certificate expires within 30 days (11 days)."),
    ):
        writer.upsert_discovered_service(db, handle, "10.0.0.5", 443, "tcp")
        db.execute(
            "INSERT INTO findings (scan_id, ip, port, category, severity, title) "
            "VALUES (?, '10.0.0.5', 443, 'tls-cert', 'low', ?)",
            (handle.scan_id, title),
        )
    counts = compute_and_store(db, a.scan_id, b.scan_id)
    assert counts.new_exposure == 0
    assert counts.gone_exposure == 0


def test_several_categories_on_one_service_collapse(db) -> None:
    a, b = _two_scans(db)
    for handle in (a, b):
        writer.upsert_discovered_service(db, handle, "10.0.0.5", 80, "tcp")
    for category in ("directory-listing", "debug-page", "http-headers"):
        _finding(db, b, "10.0.0.5", 80, category)
    counts = compute_and_store(db, a.scan_id, b.scan_id)
    assert counts.new_exposure == 1
    (raw,) = db.execute(
        "SELECT detail FROM scan_diffs WHERE kind = 'new_exposure'"
    ).fetchone()
    assert len(json.loads(raw)["categories"]) == 3


def test_unchanged_exposures_are_silent(db) -> None:
    a, b = _two_scans(db)
    for handle in (a, b):
        writer.upsert_discovered_service(db, handle, "10.0.0.5", 80, "tcp")
        _finding(db, handle, "10.0.0.5", 80, "http-headers", "low")
    counts = compute_and_store(db, a.scan_id, b.scan_id)
    assert counts.new_exposure == counts.gone_exposure == 0
