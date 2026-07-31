"""Persistence + findings + query coverage for the TLS posture work.

Covers the glue: chain certs reaching `chain_certs` with their DER intact, the
CA-reuse pivot seeing intermediates the leaf-only column cannot, and the
hygiene/matrix detectors turning stored `raw` into findings.
"""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from lodan.findings import ServiceRow, detect, iter_findings, run_findings
from lodan.probes.base import ProbeResult
from lodan.store import writer
from lodan.store.db import bootstrap, connect
from lodan.store.query import compile, run_query

_NOW = datetime(2026, 7, 30, tzinfo=UTC)


@pytest.fixture
def db(tmp_path: Path):
    dbp = tmp_path / "l.db"
    bootstrap(dbp)
    conn = connect(dbp)
    yield conn
    conn.close()


def _tls_result(*, chain_meta, chain_der, jarm=None, matrix=None, hygiene=None):
    raw = {"tls_version": 0x0303, "chain": chain_meta}
    if hygiene is not None:
        raw["chain_hygiene"] = hygiene
    if matrix is not None:
        raw["tls_matrix"] = matrix
    if jarm:
        raw["jarm"] = jarm
    return ProbeResult(
        service="tls", banner="TLS 1.2", cert_fingerprint="aa" * 32,
        jarm=jarm, raw=raw, chain_der=chain_der,
    )


def _meta(position, sha256, subject, issuer, **kw):
    base = {
        "position": position, "sha256": sha256, "subject": subject, "issuer": issuer,
        "serial": "01", "key_type": "rsa", "key_bits": 2048, "curve": None,
        "sig_algo": "sha256", "not_before": "2026-01-01T00:00:00+00:00",
        "not_after": "2027-01-01T00:00:00+00:00", "is_ca": False,
        "self_signed": False, "sans": [], "parse_error": None,
    }
    base.update(kw)
    return base


# --- chain persistence -------------------------------------------------------

def test_chain_certs_persisted_with_der(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(db, h, "10.0.0.5", 443, "tcp")
    result = _tls_result(
        chain_meta=[
            _meta(0, "aa" * 32, "CN=leaf.example.com", "CN=Corp CA"),
            _meta(1, "bb" * 32, "CN=Corp CA", "CN=Corp Root", is_ca=True),
        ],
        chain_der=[b"leaf-der-bytes", b"ca-der-bytes"],
    )
    writer.update_service_from_probe(db, h, "10.0.0.5", 443, "tcp", result)

    rows = db.execute(
        "SELECT position, sha256, subject, is_ca, der FROM chain_certs "
        "WHERE scan_id = ? ORDER BY position", (h.scan_id,)
    ).fetchall()
    assert len(rows) == 2
    assert rows[0][0] == 0 and rows[0][2] == "CN=leaf.example.com"
    assert rows[0][4] == b"leaf-der-bytes"      # DER kept for offline key analysis
    assert rows[1][3] == 1                      # is_ca stored as int


def test_chain_certs_reprobe_is_idempotent(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(db, h, "10.0.0.5", 443, "tcp")
    result = _tls_result(
        chain_meta=[_meta(0, "aa" * 32, "CN=leaf", "CN=ca")],
        chain_der=[b"der"],
    )
    for _ in range(2):
        writer.update_service_from_probe(db, h, "10.0.0.5", 443, "tcp", result)
    assert db.execute("SELECT COUNT(*) FROM chain_certs").fetchone()[0] == 1


def test_no_chain_means_no_chain_rows(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(db, h, "10.0.0.5", 22, "tcp")
    writer.update_service_from_probe(
        db, h, "10.0.0.5", 22, "tcp", ProbeResult(service="ssh", banner="SSH-2.0-x")
    )
    assert db.execute("SELECT COUNT(*) FROM chain_certs").fetchone()[0] == 0


def test_chain_rows_survive_missing_parsed_metadata(db) -> None:
    """DER with no matching `raw['chain']` entry still gets a fingerprint."""
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(db, h, "10.0.0.5", 443, "tcp")
    result = ProbeResult(service="tls", raw={}, chain_der=[b"orphan-der"])
    writer.update_service_from_probe(db, h, "10.0.0.5", 443, "tcp", result)
    (sha256, der) = db.execute("SELECT sha256, der FROM chain_certs").fetchone()
    assert len(sha256) == 64
    assert der == b"orphan-der"


def test_chain_certs_cascade_delete_with_the_scan(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(db, h, "10.0.0.5", 443, "tcp")
    writer.update_service_from_probe(
        db, h, "10.0.0.5", 443, "tcp",
        _tls_result(chain_meta=[_meta(0, "aa" * 32, "CN=l", "CN=c")], chain_der=[b"d"]),
    )
    db.execute("DELETE FROM scans WHERE id = ?", (h.scan_id,))
    assert db.execute("SELECT COUNT(*) FROM chain_certs").fetchone()[0] == 0


# --- pivots ------------------------------------------------------------------

def test_chain_issuer_pivot_reaches_intermediates(db) -> None:
    """The point of the whole table: cluster by a CA that signs many leaves,
    which the leaf-only services.cert_fingerprint column cannot express."""
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    for ip, leaf_fp in (("10.0.0.5", "aa" * 32), ("10.0.0.6", "cc" * 32)):
        writer.upsert_discovered_service(db, h, ip, 443, "tcp")
        writer.update_service_from_probe(
            db, h, ip, 443, "tcp",
            _tls_result(
                chain_meta=[
                    _meta(0, leaf_fp, f"CN={ip}", "CN=Corp CA"),
                    _meta(1, "bb" * 32, "CN=Corp CA", "CN=Corp Root", is_ca=True),
                ],
                chain_der=[b"leaf", b"ca"],
            ),
        )
    shared_ca = {r["ip"] for r in run_query(db, f'chain_cert:{"bb" * 32}', scan_id=h.scan_id)}
    assert shared_ca == {"10.0.0.5", "10.0.0.6"}
    by_issuer = {r["ip"] for r in run_query(db, 'chain_issuer:"CN=Corp Root"', scan_id=h.scan_id)}
    assert by_issuer == {"10.0.0.5", "10.0.0.6"}


def test_chain_issuer_pivot_accepts_wildcards(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(db, h, "10.0.0.5", 443, "tcp")
    writer.update_service_from_probe(
        db, h, "10.0.0.5", 443, "tcp",
        _tls_result(chain_meta=[_meta(0, "aa" * 32, "CN=l", "CN=Corp CA")],
                    chain_der=[b"d"]),
    )
    assert len(run_query(db, "chain_issuer:CN=Corp*", scan_id=h.scan_id)) == 1


def test_jarm_column_and_pivot(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    jarm = "29d3fd00029d29d00042d43d00041d" + "a" * 32
    for ip in ("10.0.0.5", "10.0.0.6"):
        writer.upsert_discovered_service(db, h, ip, 443, "tcp")
        writer.update_service_from_probe(
            db, h, ip, 443, "tcp",
            _tls_result(chain_meta=[], chain_der=[], jarm=jarm),
        )
    rows = run_query(db, f"jarm:{jarm}", scan_id=h.scan_id)
    assert {r["ip"] for r in rows} == {"10.0.0.5", "10.0.0.6"}
    assert rows[0]["jarm"] == jarm


def test_jarm_wildcard_is_accepted() -> None:
    sql, params = compile("jarm:29d3*")
    assert params == ["29d3%"]


# --- findings ----------------------------------------------------------------

def _row(raw) -> ServiceRow:
    return ServiceRow(ip="10.0.0.5", port=443, service="tls", banner="TLS 1.2", raw=raw)


def test_weak_key_becomes_a_high_finding() -> None:
    findings = detect(_row({"chain_hygiene": {"weak_key": ["RSA 1024-bit at depth 0"]}}), _NOW)
    weak = [f for f in findings if f.category == "weak-crypto"]
    assert len(weak) == 1
    assert weak[0].severity == "high"


def test_deprecated_signature_becomes_a_medium_finding() -> None:
    findings = detect(_row({"chain_hygiene": {"weak_signature": ["sha1 at depth 1"]}}), _NOW)
    assert [f.severity for f in findings if f.category == "weak-crypto"] == ["medium"]


def test_broken_chain_shape_is_reported() -> None:
    findings = detect(
        _row({"chain_hygiene": {"out_of_order": True, "incomplete_chain": True}}), _NOW
    )
    assert {f.category for f in findings} == {"tls-chain"}
    assert len(findings) == 2


def test_san_mismatch_is_never_a_finding() -> None:
    """Stored for querying, deliberately not surfaced — lodan dials by IP, so
    a name-based cert legitimately fails to cover the address."""
    findings = detect(_row({"chain_hygiene": {"san_mismatch": True}}), _NOW)
    assert findings == []


def test_legacy_protocol_acceptance_is_reported() -> None:
    findings = detect(
        _row({"tls_matrix": {"accepted_versions": ["TLS 1.0", "TLS 1.2"]}}), _NOW
    )
    versions = [f for f in findings if f.category == "tls-version"]
    assert len(versions) == 1
    assert "TLS 1.0" in versions[0].title


def test_modern_only_matrix_produces_no_findings() -> None:
    findings = detect(
        _row({"tls_matrix": {"accepted_versions": ["TLS 1.2", "TLS 1.3"],
                             "weak_cipher": None, "accepts_static_rsa": False}}),
        _NOW,
    )
    assert findings == []


def test_null_cipher_acceptance_is_high_severity() -> None:
    findings = detect(
        _row({"tls_matrix": {"weak_cipher": "TLS_RSA_WITH_NULL_SHA",
                             "weak_families": ["null"]}}),
        _NOW,
    )
    assert [f.severity for f in findings] == ["high"]


def test_3des_acceptance_is_medium_severity() -> None:
    findings = detect(
        _row({"tls_matrix": {"weak_cipher": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                             "weak_families": ["3des"]}}),
        _NOW,
    )
    assert [f.severity for f in findings] == ["medium"]


def test_static_rsa_is_a_low_forward_secrecy_finding() -> None:
    findings = detect(_row({"tls_matrix": {"accepts_static_rsa": True}}), _NOW)
    assert [(f.category, f.severity) for f in findings] == [("weak-crypto", "low")]


def test_absent_matrix_and_chain_produce_nothing() -> None:
    assert detect(_row({"tls_version": 0x0303}), _NOW) == []


def test_findings_persist_through_the_scan_pass(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(db, h, "10.0.0.5", 443, "tcp")
    writer.update_service_from_probe(
        db, h, "10.0.0.5", 443, "tcp",
        _tls_result(
            chain_meta=[_meta(0, "aa" * 32, "CN=l", "CN=c", key_bits=1024)],
            chain_der=[b"d"],
            hygiene={"weak_key": ["RSA 1024-bit at depth 0"]},
            matrix={"accepted_versions": ["TLS 1.0"], "weak_cipher": None,
                    "accepts_static_rsa": False},
        ),
    )
    assert run_findings(db, h.scan_id, now=_NOW) >= 2
    categories = {f["category"] for f in iter_findings(db, scan_id=h.scan_id)}
    assert {"weak-crypto", "tls-version"} <= categories
