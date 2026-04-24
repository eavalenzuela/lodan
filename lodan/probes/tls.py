"""TLS probe: connect, grab the peer cert, extract SANs + SHA-256 fingerprint.

Split into two halves so tests can exercise the parser without a socket:

    fetch(ip, port, timeout) -> list[bytes]    # DER-encoded cert chain
    parse_chain(chain)       -> ProbeResult

Connect uses a permissive SSL context (verify off, hostname check off) so we
still fingerprint self-signed and expired certs — the whole point is that
lodan sees what's there, not what's valid.

JA3/JA3S land in a later commit once we have a raw ClientHello parser.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID

from lodan.probes.base import ProbeResult

_DEFAULT_TLS_PORTS = frozenset({443, 465, 636, 853, 993, 995, 8443, 9443})


class TLSProbe:
    name = "tls"
    default_ports = _DEFAULT_TLS_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        chain = await asyncio.wait_for(fetch(ip, port), timeout=timeout)
        return parse_chain(chain)


def _permissive_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Broad ciphers/protocols so we can still fingerprint old stacks.
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    return ctx


async def fetch(ip: str, port: int) -> list[bytes]:
    """Return the DER-encoded peer certificate chain."""
    ctx = _permissive_context()
    reader, writer = await asyncio.open_connection(ip, port, ssl=ctx, server_hostname=ip)
    try:
        sslobj: ssl.SSLObject = writer.get_extra_info("ssl_object")  # type: ignore[assignment]
        if sslobj is None:
            raise RuntimeError("no SSL object on the connection")
        # Python's stdlib ssl does not expose the full chain via asyncio; the
        # leaf cert is all we're guaranteed. That's fine for v1 — SAN and
        # fingerprint both live on the leaf.
        der = sslobj.getpeercert(binary_form=True)
        if not der:
            raise RuntimeError("peer did not present a certificate")
        return [der]
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


def parse_chain(chain_der: list[bytes]) -> ProbeResult:
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
