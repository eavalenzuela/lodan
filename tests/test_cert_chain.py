"""Full-chain certificate parsing and hygiene analysis.

Certificates are minted in-process with `cryptography`, so nothing here needs
a network, a fixture file, or a real CA.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from lodan.probes.cert_chain import ChainCert, analyse_chain, parse_cert, parse_chain_full

_NOW = datetime(2026, 7, 30, tzinfo=UTC)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _mint(
    subject: str,
    issuer: str | None = None,
    *,
    key=None,
    issuer_key=None,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    hash_algo=None,
    is_ca: bool = False,
    sans: list[str] | None = None,
) -> tuple[bytes, object]:
    """Return (DER, private_key). Self-signed unless an issuer is given."""
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer_key = issuer_key or key
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer or subject))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or (_NOW - timedelta(days=30)))
        .not_valid_after(not_after or (_NOW + timedelta(days=365)))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([_san_entry(s) for s in sans]), critical=False
        )
    cert = builder.sign(issuer_key, hash_algo or hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER), key


def _san_entry(value: str):
    try:
        from ipaddress import ip_address
        return x509.IPAddress(ip_address(value))
    except ValueError:
        return x509.DNSName(value)


# --- per-cert parsing --------------------------------------------------------

def test_parse_cert_extracts_identity_and_key() -> None:
    der, _ = _mint("leaf.example.com", sans=["leaf.example.com", "10.0.0.5"])
    cert = parse_cert(der, 0)
    assert cert.position == 0
    assert cert.subject == "CN=leaf.example.com"
    assert cert.issuer == "CN=leaf.example.com"
    assert cert.key_type == "rsa"
    assert cert.key_bits == 2048
    assert cert.sig_algo == "sha256"
    assert cert.self_signed is True
    assert set(cert.sans) == {"leaf.example.com", "10.0.0.5"}
    assert len(cert.sha256) == 64


def test_parse_cert_reads_ec_keys() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    der, _ = _mint("ec.example.com", key=key)
    cert = parse_cert(der, 0)
    assert cert.key_type == "ec"
    assert cert.key_bits == 256
    assert cert.curve == "secp256r1"


def test_parse_cert_survives_garbage_der() -> None:
    """A hostile responder must not sink the row — we still get a fingerprint."""
    cert = parse_cert(b"\x30\x82not-a-certificate", 1)
    assert cert.parse_error is not None
    assert cert.position == 1
    assert len(cert.sha256) == 64
    assert cert.subject is None


def test_parse_cert_records_ca_flag() -> None:
    der, _ = _mint("Root CA", is_ca=True)
    assert parse_cert(der, 0).is_ca is True
    der, _ = _mint("leaf.example.com")
    assert parse_cert(der, 0).is_ca is False


# --- chain hygiene -----------------------------------------------------------

def test_healthy_chain_has_no_complaints() -> None:
    ca_der, ca_key = _mint("Corp CA", is_ca=True)
    leaf_der, _ = _mint("leaf.example.com", issuer="Corp CA", issuer_key=ca_key)
    parsed = parse_chain_full([leaf_der, ca_der], now=_NOW)
    h = parsed.hygiene
    assert not h.expired and not h.expires_soon and not h.not_yet_valid
    assert not h.self_signed and not h.out_of_order and not h.incomplete_chain
    assert h.weak_key == () and h.weak_signature == ()


def test_expired_leaf_is_flagged() -> None:
    der, _ = _mint(
        "old.example.com",
        not_before=_NOW - timedelta(days=800), not_after=_NOW - timedelta(days=1),
    )
    h = parse_chain_full([der], now=_NOW).hygiene
    assert h.expired is True
    assert h.expires_soon is False
    assert h.days_until_expiry is not None and h.days_until_expiry < 0


def test_expiring_soon_leaf_is_flagged() -> None:
    der, _ = _mint("soon.example.com", not_after=_NOW + timedelta(days=10))
    h = parse_chain_full([der], now=_NOW).hygiene
    assert h.expired is False
    assert h.expires_soon is True
    assert h.days_until_expiry == 10


def test_not_yet_valid_leaf_is_flagged() -> None:
    der, _ = _mint(
        "future.example.com",
        not_before=_NOW + timedelta(days=5), not_after=_NOW + timedelta(days=365),
    )
    assert parse_chain_full([der], now=_NOW).hygiene.not_yet_valid is True


def test_self_signed_leaf_is_flagged() -> None:
    der, _ = _mint("self.example.com")
    assert parse_chain_full([der], now=_NOW).hygiene.self_signed is True


def test_weak_rsa_key_is_flagged_at_any_depth() -> None:
    weak_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    ca_der, _ = _mint("Weak CA", key=weak_ca_key, is_ca=True)
    leaf_der, _ = _mint("leaf.example.com", issuer="Weak CA", issuer_key=weak_ca_key)
    h = parse_chain_full([leaf_der, ca_der], now=_NOW).hygiene
    assert len(h.weak_key) == 1
    assert "1024" in h.weak_key[0]
    assert "depth 1" in h.weak_key[0]


@pytest.mark.parametrize("algo", ["sha1", "md5"])
def test_deprecated_signature_hash_is_flagged(algo: str) -> None:
    """Built from a parsed cert directly — modern `cryptography` refuses to
    *sign* with SHA-1/MD5, but lodan still has to recognise one on the wire."""
    cert = ChainCert(
        position=0, sha256="ab" * 32, subject="CN=old.example.com",
        issuer="CN=Old CA", sig_algo=algo, key_type="rsa", key_bits=2048,
        not_after=(_NOW + timedelta(days=365)).isoformat(),
    )
    h = analyse_chain((cert,), now=_NOW)
    assert any(algo in s for s in h.weak_signature)


def test_modern_signature_hash_is_not_flagged() -> None:
    der, _ = _mint("good.example.com")
    assert parse_chain_full([der], now=_NOW).hygiene.weak_signature == ()


def test_out_of_order_chain_is_flagged() -> None:
    """Leaf's issuer must be the next cert's subject."""
    ca_der, ca_key = _mint("Corp CA", is_ca=True)
    other_der, _ = _mint("Unrelated CA", is_ca=True)
    leaf_der, _ = _mint("leaf.example.com", issuer="Corp CA", issuer_key=ca_key)
    h = parse_chain_full([leaf_der, other_der, ca_der], now=_NOW).hygiene
    assert h.out_of_order is True


def test_lone_non_ca_leaf_is_an_incomplete_chain() -> None:
    ca_der, ca_key = _mint("Corp CA", is_ca=True)
    leaf_der, _ = _mint("leaf.example.com", issuer="Corp CA", issuer_key=ca_key)
    assert parse_chain_full([leaf_der], now=_NOW).hygiene.incomplete_chain is True


def test_omitted_root_is_not_an_incomplete_chain() -> None:
    """Servers routinely omit the root; the client is expected to hold it."""
    ca_der, ca_key = _mint("Corp CA", is_ca=True)
    leaf_der, _ = _mint("leaf.example.com", issuer="Corp CA", issuer_key=ca_key)
    h = parse_chain_full([leaf_der, ca_der], now=_NOW).hygiene
    assert h.incomplete_chain is False
    assert h.out_of_order is False


def test_self_signed_lone_cert_is_not_incomplete() -> None:
    der, _ = _mint("self.example.com")
    h = parse_chain_full([der], now=_NOW).hygiene
    assert h.incomplete_chain is False
    assert h.self_signed is True


def test_san_mismatch_tracks_the_dialled_ip() -> None:
    der, _ = _mint("web.example.com", sans=["web.example.com"])
    assert parse_chain_full([der], now=_NOW, ip="10.0.0.5").hygiene.san_mismatch is True
    der2, _ = _mint("web.example.com", sans=["web.example.com", "10.0.0.5"])
    assert parse_chain_full([der2], now=_NOW, ip="10.0.0.5").hygiene.san_mismatch is False


def test_san_mismatch_is_false_without_a_target_ip() -> None:
    der, _ = _mint("web.example.com", sans=["web.example.com"])
    assert parse_chain_full([der], now=_NOW).hygiene.san_mismatch is False


def test_empty_chain_yields_empty_verdicts() -> None:
    parsed = parse_chain_full([], now=_NOW)
    assert parsed.certs == ()
    assert parsed.hygiene.expired is False
    assert analyse_chain((), now=_NOW).days_until_expiry is None


def test_chain_positions_are_assigned_in_order() -> None:
    ca_der, ca_key = _mint("Corp CA", is_ca=True)
    leaf_der, _ = _mint("leaf.example.com", issuer="Corp CA", issuer_key=ca_key)
    parsed = parse_chain_full([leaf_der, ca_der], now=_NOW)
    assert [c.position for c in parsed.certs] == [0, 1]
    assert parsed.certs[0].subject == "CN=leaf.example.com"
    assert parsed.certs[1].subject == "CN=Corp CA"


def test_as_dict_is_json_shaped() -> None:
    der, _ = _mint("leaf.example.com", sans=["a.example.com"])
    d = parse_cert(der, 0).as_dict()
    assert d["sans"] == ["a.example.com"]
    assert isinstance(d["position"], int)
    import json
    json.dumps(d)   # must not raise


@pytest.mark.parametrize("bad", [b"", b"\x00", b"\xff" * 32])
def test_malformed_chain_entries_do_not_raise(bad: bytes) -> None:
    parsed = parse_chain_full([bad], now=_NOW)
    assert parsed.certs[0].parse_error is not None
    assert parsed.hygiene.expired is False
