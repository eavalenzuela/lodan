"""Cross-protocol public-key strength scoring, including ROCA.

All offline arithmetic. The ROCA cases include an empirical false-positive
check against genuine RSA keys and random integers, because a CVE claim
backed by a wrong test is worse than no claim at all.
"""
from __future__ import annotations

import json
import math
import random
import struct
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from lodan.enrich.keyposture import (
    _ROCA_PRIMES,
    ROCA_CVE,
    PublicKey,
    enrich_key_posture,
    parse_ssh_public_key,
    roca_fingerprint,
    score,
)
from lodan.store import writer
from lodan.store.db import bootstrap, connect


@pytest.fixture
def db(tmp_path: Path):
    dbp = tmp_path / "l.db"
    bootstrap(dbp)
    conn = connect(dbp)
    yield conn
    conn.close()


def _ssh_string(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def _ssh_rsa_blob(modulus: int, exponent: int = 65537) -> bytes:
    def mpint(n: int) -> bytes:
        raw = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
        return _ssh_string(raw)
    return _ssh_string(b"ssh-rsa") + mpint(exponent) + mpint(modulus)


# --- ROCA --------------------------------------------------------------------

def test_roca_does_not_flag_genuine_rsa_keys() -> None:
    for _ in range(4):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        assert roca_fingerprint(key.public_key().public_numbers().n) is False


def test_roca_does_not_flag_random_integers() -> None:
    """The fingerprint is a necessary condition with a tiny false-positive
    rate; this pins that it is actually tiny."""
    rng = random.Random(20260730)
    flagged = sum(
        roca_fingerprint(rng.getrandbits(2048) | 1) for _ in range(500)
    )
    assert flagged == 0


def test_roca_flags_rsalib_shaped_moduli() -> None:
    """RSALib primes satisfy p = k*M + 65537^a mod M, so N = pq is congruent
    to a power of 65537 modulo every prime dividing M."""
    M = math.prod(_ROCA_PRIMES)
    rng = random.Random(1)
    for c in range(1, 25):
        n = pow(65537, c, M) + M * rng.getrandbits(64)
        assert roca_fingerprint(n) is True


def test_roca_ignores_degenerate_input() -> None:
    assert roca_fingerprint(0) is False
    assert roca_fingerprint(1) is False
    assert roca_fingerprint(-5) is False


# --- SSH key blob parsing ----------------------------------------------------

def test_parse_ssh_rsa_blob_recovers_the_modulus() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    modulus = key.public_key().public_numbers().n
    parsed = parse_ssh_public_key(_ssh_rsa_blob(modulus))
    assert parsed is not None
    assert parsed.key_type == "rsa"
    assert parsed.modulus == modulus
    assert parsed.bits == 2048


def test_parse_ssh_ed25519_blob() -> None:
    blob = _ssh_string(b"ssh-ed25519") + _ssh_string(b"\x01" * 32)
    parsed = parse_ssh_public_key(blob)
    assert parsed is not None
    assert parsed.key_type == "ed25519"
    assert parsed.bits == 256


def test_parse_ssh_ecdsa_blob_reads_the_curve() -> None:
    blob = (
        _ssh_string(b"ecdsa-sha2-nistp384")
        + _ssh_string(b"nistp384")
        + _ssh_string(b"\x04" + b"\x00" * 96)
    )
    parsed = parse_ssh_public_key(blob)
    assert parsed is not None
    assert parsed.key_type == "ec"
    assert parsed.curve == "nistp384"
    assert parsed.bits == 384


def test_parse_ssh_dss_blob_sizes_from_p() -> None:
    p = (1 << 1023) | 1
    blob = (
        _ssh_string(b"ssh-dss")
        + _ssh_string(p.to_bytes(128, "big"))
        + _ssh_string(b"\x01") + _ssh_string(b"\x01") + _ssh_string(b"\x01")
    )
    parsed = parse_ssh_public_key(blob)
    assert parsed is not None
    assert parsed.key_type == "dsa"
    assert parsed.bits == 1024


@pytest.mark.parametrize("bad", [b"", b"\x00\x00", b"\xff\xff\xff\xff", b"\x00\x00\x00\x40x"])
def test_parse_ssh_blob_returns_none_on_garbage(bad: bytes) -> None:
    """Truncated or nonsense blobs yield None rather than raising."""
    assert parse_ssh_public_key(bad) is None


def test_parse_ssh_blob_of_an_unknown_algorithm_keeps_the_name() -> None:
    """An algorithm we don't model is still worth recording by name."""
    parsed = parse_ssh_public_key(_ssh_string(b"ssh-future-alg") + _ssh_string(b"\x01"))
    assert parsed is not None
    assert parsed.key_type == "ssh-future-alg"
    assert parsed.bits is None
    assert score(parsed).weak_reason is None   # unknown != weak


# --- scoring -----------------------------------------------------------------

def test_rsa_1024_is_a_medium_weak_key() -> None:
    v = score(PublicKey(source="ssh-hostkey", label="ssh-rsa", key_type="rsa", bits=1024))
    assert v.weak_reason == "RSA 1024-bit"
    assert v.weak_severity == "medium"


def test_rsa_512_is_high() -> None:
    v = score(PublicKey(source="tls-chain", label="CN=x", key_type="rsa", bits=512))
    assert v.weak_severity == "high"


def test_rsa_2048_is_clean() -> None:
    v = score(PublicKey(source="tls-chain", label="CN=x", key_type="rsa", bits=2048))
    assert v.weak_reason is None
    assert v.roca is False


def test_dsa_is_flagged_regardless_of_size() -> None:
    v = score(PublicKey(source="ssh-hostkey", label="ssh-dss", key_type="dsa", bits=3072))
    assert v.weak_severity == "high"
    assert "deprecated" in v.weak_reason


def test_small_curve_is_flagged() -> None:
    v = score(PublicKey(source="tls-chain", label="CN=x", key_type="ec", bits=163))
    assert v.weak_severity == "high"


def test_p256_is_clean() -> None:
    assert score(
        PublicKey(source="tls-chain", label="CN=x", key_type="ec", bits=256)
    ).weak_reason is None


def test_ed25519_is_clean() -> None:
    assert score(
        PublicKey(source="ssh-hostkey", label="ssh-ed25519", key_type="ed25519", bits=256)
    ).weak_reason is None


# --- persistence -------------------------------------------------------------

def _ssh_service(conn, handle, ip, port, blob: bytes) -> None:
    writer.upsert_discovered_service(conn, handle, ip, port, "tcp")
    raw = json.dumps({
        "banner": "SSH-2.0-OpenSSH_9.3",
        "host_keys": [{"algo": "ssh-rsa", "sha256": "a" * 64, "blob": blob.hex()}],
    })
    conn.execute(
        "UPDATE services SET service = 'ssh', raw = ? WHERE scan_id = ? AND ip = ? AND port = ?",
        (raw, handle.scan_id, ip, port),
    )


def test_weak_ssh_host_key_becomes_a_finding(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    _ssh_service(db, h, "10.0.0.5", 22, _ssh_rsa_blob(weak.public_key().public_numbers().n))

    weak_count, roca = enrich_key_posture(db, h.scan_id)
    assert weak_count == 1
    assert roca == 0
    row = db.execute(
        "SELECT category, severity, title FROM findings WHERE scan_id = ?", (h.scan_id,)
    ).fetchone()
    assert row[0] == "weak-key"
    assert row[1] == "medium"
    assert "RSA 1024-bit" in row[2]
    assert "SSH host key" in row[2]


def test_strong_ssh_host_key_produces_nothing(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    strong = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _ssh_service(db, h, "10.0.0.5", 22, _ssh_rsa_blob(strong.public_key().public_numbers().n))
    assert enrich_key_posture(db, h.scan_id) == (0, 0)
    assert db.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0


def test_roca_hit_files_both_a_finding_and_a_cve(db) -> None:
    """Posture verdicts go to findings; a real advisory id goes to vulns."""
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    M = math.prod(_ROCA_PRIMES)
    modulus = pow(65537, 7, M) + M * (1 << 900)
    _ssh_service(db, h, "10.0.0.5", 22, _ssh_rsa_blob(modulus))

    _weak, roca = enrich_key_posture(db, h.scan_id)
    assert roca == 1
    finding = db.execute(
        "SELECT severity, title FROM findings WHERE scan_id = ? AND category = 'weak-key' "
        "AND title LIKE 'ROCA%'", (h.scan_id,)
    ).fetchone()
    assert finding[0] == "high"
    vuln = db.execute(
        "SELECT cve, confidence, source FROM vulns WHERE scan_id = ?", (h.scan_id,)
    ).fetchone()
    assert vuln[0] == ROCA_CVE
    assert vuln[2] == "keyposture"
    # Below 1.0: the fingerprint is a necessary condition, not a factorization.
    assert 0 < vuln[1] < 1.0


def test_weak_cert_key_in_the_chain_is_scored(db) -> None:
    """Reaches intermediates, not just the leaf."""
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Weak CA")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Weak CA")]))
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)

    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(db, h, "10.0.0.5", 443, "tcp")
    db.execute(
        "INSERT INTO chain_certs (scan_id, ip, port, position, sha256, subject, der) "
        "VALUES (?, ?, ?, 1, 'ab', 'CN=Weak CA', ?)",
        (h.scan_id, "10.0.0.5", 443, der),
    )
    weak_count, _roca = enrich_key_posture(db, h.scan_id)
    assert weak_count == 1
    (title,) = db.execute(
        "SELECT title FROM findings WHERE scan_id = ?", (h.scan_id,)
    ).fetchone()
    assert "chain depth 1" in title


def test_ec_key_from_a_cert_is_not_flagged(db) -> None:
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ec")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ec")]))
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    db.execute(
        "INSERT INTO chain_certs (scan_id, ip, port, position, sha256, subject, der) "
        "VALUES (?, ?, ?, 0, 'ab', 'CN=ec', ?)",
        (h.scan_id, "10.0.0.5", 443, cert.public_bytes(serialization.Encoding.DER)),
    )
    assert enrich_key_posture(db, h.scan_id) == (0, 0)


def test_enrich_key_posture_is_idempotent(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    _ssh_service(db, h, "10.0.0.5", 22, _ssh_rsa_blob(weak.public_key().public_numbers().n))
    first = enrich_key_posture(db, h.scan_id)
    second = enrich_key_posture(db, h.scan_id)
    assert first == second
    assert db.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1


def test_empty_scan_scores_nothing(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    assert enrich_key_posture(db, h.scan_id) == (0, 0)


def test_malformed_blob_is_skipped_not_fatal(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(db, h, "10.0.0.5", 22, "tcp")
    db.execute(
        "UPDATE services SET service = 'ssh', raw = ? WHERE scan_id = ?",
        (json.dumps({"host_keys": [{"algo": "ssh-rsa", "blob": "zzz-not-hex"}]}),
         h.scan_id),
    )
    assert enrich_key_posture(db, h.scan_id) == (0, 0)
