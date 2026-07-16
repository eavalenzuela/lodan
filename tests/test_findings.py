"""Exposure/misconfiguration detectors + storage."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from lodan import findings
from lodan.findings import ServiceRow
from lodan.store import writer
from lodan.store.db import bootstrap, connect

_NOW = datetime(2026, 7, 15, tzinfo=UTC)


def _row(service, port=0, banner="", **raw) -> ServiceRow:
    return ServiceRow(ip="10.0.0.5", port=port, service=service, banner=banner, raw=raw)


def test_telnet_is_cleartext_admin() -> None:
    fs = findings.detect(_row("telnet", 23), _NOW)
    assert [f.category for f in fs] == ["cleartext-admin"]
    assert fs[0].severity == "high"


@pytest.mark.parametrize("service,key", [
    ("smtp", "starttls"), ("imap", "starttls"), ("pop3", "stls"),
    ("ftp", "auth_tls"), ("mysql", "ssl"), ("postgresql", "ssl"),
])
def test_no_tls_when_signal_false(service: str, key: str) -> None:
    fs = findings.detect(_row(service, **{key: False}), _NOW)
    assert any(f.category == "no-tls" and f.severity == "medium" for f in fs)
    # When the upgrade IS offered, no finding.
    assert findings.detect(_row(service, **{key: True}), _NOW) == []


def test_vnc_no_auth_is_high() -> None:
    fs = findings.detect(_row("vnc", 5900, no_auth=True), _NOW)
    assert fs[0].category == "unauth-service" and fs[0].severity == "high"
    assert findings.detect(_row("vnc", 5900, no_auth=False), _NOW) == []


def test_unauth_elasticsearch_and_redis() -> None:
    assert findings.detect(_row("elasticsearch", 9200, unauthenticated=True), _NOW)
    assert findings.detect(_row("redis", 6379, fields={"redis_version": "7"}), _NOW)
    # Redis requiring auth (only auth_line, no fields) is not a finding.
    assert findings.detect(_row("redis", 6379, auth_line="-NOAUTH"), _NOW) == []


def test_tls_expired_and_expiring_and_self_signed() -> None:
    expired = findings.detect(
        _row("tls", 443, cert_not_valid_after=(_NOW - timedelta(days=1)).isoformat()), _NOW)
    assert any(f.category == "tls-cert" and f.severity == "high" for f in expired)

    soon = findings.detect(
        _row("tls", 443, cert_not_valid_after=(_NOW + timedelta(days=10)).isoformat()), _NOW)
    assert any(f.severity == "low" for f in soon)

    ss = findings.detect(_row("tls", 443, cert_subject="CN=x", cert_issuer="CN=x"), _NOW)
    assert any("self-signed" in f.title for f in ss)


def test_weak_tls_version() -> None:
    fs = findings.detect(_row("tls", 443, tls_version=0x0301, tls_version_label="TLS 1.0"), _NOW)
    assert any(f.category == "tls-version" for f in fs)
    # TLS 1.2 is fine.
    assert not any(f.category == "tls-version"
                   for f in findings.detect(_row("tls", 443, tls_version=0x0303), _NOW))


def test_clean_service_has_no_findings() -> None:
    assert findings.detect(_row("http", 80, banner="nginx"), _NOW) == []


def test_run_and_iter_findings_ordered_by_severity(tmp_path: Path) -> None:
    dbp = tmp_path / "l.db"
    bootstrap(dbp)
    conn = connect(dbp)
    try:
        h = writer.open_scan(conn, "w", ["10.0.0.0/24"])
        # telnet (high), smtp no-tls (medium), tls self-signed (low).
        conn.execute(
            "INSERT INTO services (scan_id, ip, port, proto, service, raw) VALUES (?,?,?,?,?,?)",
            (h.scan_id, "10.0.0.5", 23, "tcp", "telnet", None))
        conn.execute(
            "INSERT INTO services (scan_id, ip, port, proto, service, raw) VALUES (?,?,?,?,?,?)",
            (h.scan_id, "10.0.0.6", 25, "tcp", "smtp", json.dumps({"starttls": False})))
        conn.execute(
            "INSERT INTO services (scan_id, ip, port, proto, service, raw) VALUES (?,?,?,?,?,?)",
            (h.scan_id, "10.0.0.7", 443, "tcp", "tls",
             json.dumps({"cert_subject": "CN=x", "cert_issuer": "CN=x"})))

        n = findings.run_findings(conn, h.scan_id, now=_NOW)
        assert n == 3
        rows = findings.iter_findings(conn, scan_id=h.scan_id)
        assert [r["severity"] for r in rows] == ["high", "medium", "low"]
        assert rows[0]["category"] == "cleartext-admin"
        # severity filter
        assert len(findings.iter_findings(conn, scan_id=h.scan_id, severity="high")) == 1
    finally:
        conn.close()
