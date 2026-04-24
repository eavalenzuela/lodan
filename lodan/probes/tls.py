"""TLS probe: raw ClientHello over TCP, parse ServerHello + cert chain,
compute JA3 / JA3S.

Split into three layers so tests can exercise each without a socket:

    fetch(ip, port, timeout) -> (ClientHelloBytes, bytes)
    parse_stream(ch, raw)    -> ProbeResult   # full ServerHello + cert + JA3/JA3S
    parse_chain(chain_der)   -> ProbeResult   # cert-only, kept for legacy callers

We ship a fixed ClientHello (see tls_parser.build_client_hello) and advertise
TLS 1.2 in supported_versions so ServerHello + Certificate both arrive in
plaintext in one connection. That gives us JA3 (from our own bytes), JA3S
(from ServerHello), and the cert chain together — no handshake completion,
no credentials, no appdata.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID

from lodan.probes.base import ProbeResult
from lodan.probes.tls_parser import (
    ClientHelloBytes,
    build_client_hello,
    collect_handshake_messages,
    extract_cert_chain,
    find_server_hello,
    parse_server_hello,
)

_DEFAULT_TLS_PORTS = frozenset({443, 465, 636, 853, 993, 995, 8443, 9443})
_MAX_RESPONSE_BYTES = 65536

# TLS version numbers we bother to label. Everything else renders as 0xHHHH.
_VERSION_LABELS = {
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}


class TLSProbe:
    name = "tls"
    default_ports = _DEFAULT_TLS_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        ch, raw = await asyncio.wait_for(fetch(ip, port, timeout), timeout=timeout + 1)
        return parse_stream(ch, raw)


async def fetch(ip: str, port: int, timeout: float) -> tuple[ClientHelloBytes, bytes]:
    """Send a raw ClientHello and read up to _MAX_RESPONSE_BYTES of reply."""
    ch = build_client_hello()
    reader, writer = await asyncio.open_connection(ip, port)
    try:
        writer.write(ch.record)
        await writer.drain()
        deadline = asyncio.get_event_loop().time() + timeout
        buf = bytearray()
        while len(buf) < _MAX_RESPONSE_BYTES:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                break
            try:
                chunk = await asyncio.wait_for(
                    reader.read(4096), timeout=remaining
                )
            except TimeoutError:
                break
            if not chunk:
                break
            buf.extend(chunk)
            # Opportunistic early exit: once we've collected a Certificate +
            # ServerHelloDone pair, further reads would block until the
            # server decides we're leaving.
            if _has_finished_marker(bytes(buf)):
                break
        return ch, bytes(buf)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


def _has_finished_marker(raw: bytes) -> bool:
    messages = collect_handshake_messages(raw)
    kinds = {hs_type for hs_type, _body in messages}
    # 14 = ServerHelloDone (TLS 1.2). Past that the server waits on us.
    return 14 in kinds


def parse_stream(ch: ClientHelloBytes, raw: bytes) -> ProbeResult:
    messages = collect_handshake_messages(raw)
    sh_body = find_server_hello(messages)
    if sh_body is None:
        return ProbeResult(
            service="tls",
            banner="tls: no ServerHello",
            ja3=ch.ja3,
            raw={"response_bytes": len(raw), "ja3_string": ch.ja3_string},
        )
    sh = parse_server_hello(sh_body)
    chain = extract_cert_chain(messages)

    cert_fingerprint: str | None = None
    sans: list[str] | None = None
    subject: str | None = None
    issuer: str | None = None
    fingerprint_sha1: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    if chain:
        leaf = x509.load_der_x509_certificate(chain[0])
        cert_fingerprint = hashlib.sha256(chain[0]).hexdigest()
        sans = _extract_sans(leaf) or None
        subject = leaf.subject.rfc4514_string()
        issuer = leaf.issuer.rfc4514_string()
        fingerprint_sha1 = leaf.fingerprint(hashes.SHA1()).hex()
        not_before = leaf.not_valid_before_utc.isoformat()
        not_after = leaf.not_valid_after_utc.isoformat()

    banner_parts: list[str] = [
        f"{_version_label(sh.version)}",
        f"cipher=0x{sh.cipher:04x}",
    ]
    if subject:
        banner_parts.append(f"subject={subject!r}")
    raw_fields: dict[str, Any] = {
        "tls_version": sh.version,
        "tls_version_label": _version_label(sh.version),
        "cipher": sh.cipher,
        "ja3_string": ch.ja3_string,
        "ja3s_string": sh.ja3s_string,
        "server_extensions": sh.extensions,
        "cert_count": len(chain),
    }
    if chain:
        raw_fields.update({
            "cert_subject": subject,
            "cert_issuer": issuer,
            "cert_fingerprint_sha1": fingerprint_sha1,
            "cert_not_valid_before": not_before,
            "cert_not_valid_after": not_after,
        })

    return ProbeResult(
        service="tls",
        banner=" ".join(banner_parts),
        cert_fingerprint=cert_fingerprint,
        cert_sans=sans,
        ja3=ch.ja3,
        ja3s=sh.ja3s,
        raw=raw_fields,
    )


def parse_chain(chain_der: list[bytes]) -> ProbeResult:
    """Cert-only parse kept for callers that already have DER bytes in hand.

    Does not populate JA3 / JA3S — those need the live handshake.
    """
    if not chain_der:
        return ProbeResult(service="tls")
    leaf = x509.load_der_x509_certificate(chain_der[0])
    fingerprint = hashlib.sha256(chain_der[0]).hexdigest()
    sans = _extract_sans(leaf)
    subject = leaf.subject.rfc4514_string()
    issuer = leaf.issuer.rfc4514_string()
    return ProbeResult(
        service="tls",
        banner=f"{subject} (issued by {issuer})",
        cert_fingerprint=fingerprint,
        cert_sans=sans,
        raw={
            "subject": subject,
            "issuer": issuer,
            "not_valid_before": leaf.not_valid_before_utc.isoformat(),
            "not_valid_after": leaf.not_valid_after_utc.isoformat(),
            "fingerprint_sha1": leaf.fingerprint(hashes.SHA1()).hex(),
        },
    )


def _extract_sans(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return []
    san: x509.SubjectAlternativeName = ext.value  # type: ignore[assignment]
    out: list[str] = []
    for name in san:
        if isinstance(name, x509.DNSName):
            out.append(name.value)
        elif isinstance(name, x509.IPAddress):
            out.append(str(name.value))
        elif isinstance(name, x509.UniformResourceIdentifier):
            out.append(name.value)
    return out


def _version_label(version: int) -> str:
    return _VERSION_LABELS.get(version, f"TLS 0x{version:04x}")
