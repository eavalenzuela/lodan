"""Full certificate-chain parsing and hygiene analysis.

The TLS probe has always received the server's whole Certificate flight and
kept only `chain[0]`. Everything below the leaf — the intermediates, their key
sizes, their signature algorithms, whether the chain even links up — arrived
unsolicited and was thrown away.

This module parses every cert in the chain and derives hygiene verdicts from
it. Pure parsing: the bytes are already in hand, nothing here touches a
network. Each cert's DER is retained so offline key-strength analysis (ROCA,
modulus size) can run over it later without a second connection.

A note on what is deliberately *not* a finding: lodan connects by IP address,
so a name-based certificate legitimately does not cover the address we dialled.
`san_mismatch` is therefore computed and stored, but never emitted as a
finding — it would fire on nearly every host in a normal estate and drown the
signal it is meant to carry.
"""
from __future__ import annotations

import contextlib
import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID

EXPIRING_SOON = timedelta(days=30)

# Signature hashes that are broken or deprecated for certificate use.
_WEAK_HASHES = frozenset({"md5", "sha1"})

# Minimum key sizes below which a key is considered weak.
_MIN_RSA_BITS = 2048
_MIN_DSA_BITS = 2048
_MIN_EC_BITS = 224


@dataclass(frozen=True)
class ChainCert:
    """One certificate from the server's Certificate message."""

    position: int                      # 0 = leaf, ascending toward the root
    sha256: str
    subject: str | None = None
    issuer: str | None = None
    serial: str | None = None
    key_type: str | None = None        # rsa | ec | dsa | ed25519 | ed448
    key_bits: int | None = None
    curve: str | None = None
    sig_algo: str | None = None        # e.g. "sha256"
    not_before: str | None = None
    not_after: str | None = None
    is_ca: bool | None = None
    self_signed: bool = False
    sans: tuple[str, ...] = ()
    parse_error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "position": self.position,
            "sha256": self.sha256,
            "subject": self.subject,
            "issuer": self.issuer,
            "serial": self.serial,
            "key_type": self.key_type,
            "key_bits": self.key_bits,
            "curve": self.curve,
            "sig_algo": self.sig_algo,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "is_ca": self.is_ca,
            "self_signed": self.self_signed,
            "sans": list(self.sans),
            "parse_error": self.parse_error,
        }


@dataclass(frozen=True)
class ChainHygiene:
    """Verdicts over the chain as a whole."""

    expired: bool = False
    expires_soon: bool = False
    not_yet_valid: bool = False
    self_signed: bool = False
    incomplete_chain: bool = False
    out_of_order: bool = False
    weak_key: tuple[str, ...] = ()        # human-readable per offending cert
    weak_signature: tuple[str, ...] = ()
    san_mismatch: bool = False            # stored, never emitted as a finding
    days_until_expiry: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "expired": self.expired,
            "expires_soon": self.expires_soon,
            "not_yet_valid": self.not_yet_valid,
            "self_signed": self.self_signed,
            "incomplete_chain": self.incomplete_chain,
            "out_of_order": self.out_of_order,
            "weak_key": list(self.weak_key),
            "weak_signature": list(self.weak_signature),
            "san_mismatch": self.san_mismatch,
            "days_until_expiry": self.days_until_expiry,
        }


@dataclass(frozen=True)
class ParsedChain:
    certs: tuple[ChainCert, ...] = ()
    hygiene: ChainHygiene = field(default_factory=ChainHygiene)


def _key_info(cert: x509.Certificate) -> tuple[str | None, int | None, str | None]:
    try:
        key = cert.public_key()
    except Exception:  # noqa: BLE001 — an unparseable key must not sink the cert
        return None, None, None
    if isinstance(key, rsa.RSAPublicKey):
        return "rsa", key.key_size, None
    if isinstance(key, dsa.DSAPublicKey):
        return "dsa", key.key_size, None
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "ec", key.curve.key_size, key.curve.name
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "ed25519", 256, None
    if isinstance(key, ed448.Ed448PublicKey):
        return "ed448", 448, None
    return type(key).__name__, None, None


def _sig_algo(cert: x509.Certificate) -> str | None:
    # Ed25519/Ed448 have no separate hash; accessing the attribute raises.
    try:
        algo = cert.signature_hash_algorithm
    except Exception:  # noqa: BLE001
        return None
    return algo.name if algo is not None else None


def _sans(cert: x509.Certificate) -> tuple[str, ...]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except Exception:  # noqa: BLE001 — missing or malformed SAN is not fatal
        return ()
    out: list[str] = []
    try:
        for name in ext.value:  # type: ignore[attr-defined]
            if isinstance(name, x509.DNSName | x509.UniformResourceIdentifier):
                out.append(name.value)
            elif isinstance(name, x509.IPAddress):
                out.append(str(name.value))
    except Exception:  # noqa: BLE001
        return tuple(out)
    return tuple(out)


def _is_ca(cert: x509.Certificate) -> bool | None:
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
    except Exception:  # noqa: BLE001
        return None
    return bool(getattr(bc.value, "ca", False))


def parse_cert(der: bytes, position: int) -> ChainCert:
    """Parse one DER cert. Never raises — a broken cert still gets a row."""
    sha256 = hashlib.sha256(der).hexdigest()
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as e:  # noqa: BLE001
        return ChainCert(position=position, sha256=sha256,
                         parse_error=str(e) or type(e).__name__)
    try:
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
    except Exception:  # noqa: BLE001
        subject = issuer = None
    key_type, key_bits, curve = _key_info(cert)
    return ChainCert(
        position=position,
        sha256=sha256,
        subject=subject,
        issuer=issuer,
        serial=format(cert.serial_number, "x"),
        key_type=key_type,
        key_bits=key_bits,
        curve=curve,
        sig_algo=_sig_algo(cert),
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=cert.not_valid_after_utc.isoformat(),
        is_ca=_is_ca(cert),
        self_signed=bool(subject and issuer and subject == issuer),
        sans=_sans(cert),
    )


def _covers_ip(leaf: ChainCert, ip: str | None) -> bool:
    if not ip:
        return True                     # nothing to check against
    if ip in leaf.sans:
        return True
    try:
        target = ip_address(ip)
    except ValueError:
        return False
    for entry in leaf.sans:
        try:
            if ip_address(entry) == target:
                return True
        except ValueError:
            continue
    return False


def _weak_key_reason(cert: ChainCert) -> str | None:
    if cert.key_bits is None:
        return None
    if cert.key_type == "rsa" and cert.key_bits < _MIN_RSA_BITS:
        return f"RSA {cert.key_bits}-bit at depth {cert.position}"
    if cert.key_type == "dsa" and cert.key_bits < _MIN_DSA_BITS:
        return f"DSA {cert.key_bits}-bit at depth {cert.position}"
    if cert.key_type == "ec" and cert.key_bits < _MIN_EC_BITS:
        return f"EC {cert.key_bits}-bit at depth {cert.position}"
    return None


def analyse_chain(
    certs: tuple[ChainCert, ...],
    *,
    now: datetime | None = None,
    ip: str | None = None,
) -> ChainHygiene:
    """Derive hygiene verdicts from an already-parsed chain."""
    if not certs:
        return ChainHygiene()
    now = now or datetime.now(UTC)
    leaf = certs[0]

    expired = expires_soon = not_yet_valid = False
    days_left: int | None = None
    if leaf.not_after:
        try:
            not_after = datetime.fromisoformat(leaf.not_after)
            delta = not_after - now
            days_left = delta.days
            expired = delta.total_seconds() <= 0
            expires_soon = not expired and delta <= EXPIRING_SOON
        except ValueError:
            pass
    if leaf.not_before:
        with contextlib.suppress(ValueError):
            not_yet_valid = datetime.fromisoformat(leaf.not_before) > now

    # Chain linkage. Each cert should be issued by the next one along. A
    # missing final link is normal — servers routinely omit the root, which
    # the client is expected to have — so only a break *within* what was sent
    # counts as out-of-order, and a leaf whose issuer is absent entirely (and
    # which isn't self-signed) counts as incomplete.
    out_of_order = False
    for lower, upper in zip(certs, certs[1:], strict=False):
        if lower.issuer and upper.subject and lower.issuer != upper.subject:
            out_of_order = True
            break
    incomplete = (
        len(certs) == 1 and not leaf.self_signed and leaf.is_ca is not True
    )

    weak_keys = tuple(
        reason for reason in (_weak_key_reason(c) for c in certs) if reason
    )
    weak_sigs = tuple(
        f"{c.sig_algo} at depth {c.position}"
        for c in certs
        if c.sig_algo and c.sig_algo.lower() in _WEAK_HASHES
    )

    return ChainHygiene(
        expired=expired,
        expires_soon=expires_soon,
        not_yet_valid=not_yet_valid,
        self_signed=leaf.self_signed,
        incomplete_chain=incomplete,
        out_of_order=out_of_order,
        weak_key=weak_keys,
        weak_signature=weak_sigs,
        san_mismatch=not _covers_ip(leaf, ip),
        days_until_expiry=days_left,
    )


def parse_chain_full(
    chain_der: list[bytes],
    *,
    now: datetime | None = None,
    ip: str | None = None,
) -> ParsedChain:
    """Parse every cert in a Certificate flight and score the chain."""
    certs = tuple(parse_cert(der, i) for i, der in enumerate(chain_der))
    return ParsedChain(certs=certs, hygiene=analyse_chain(certs, now=now, ip=ip))
