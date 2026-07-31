"""LDAP probe: anonymous rootDSE read.

The rootDSE is the one entry an LDAP server publishes without authentication,
by design (RFC 4512 §5.1) — it names the naming contexts, the supported
controls and extensions, and usually the vendor and version. On a directory
you own that identifies the product (Active Directory, OpenLDAP, 389-DS) and
its domain layout in a single exchange.

Where this stops: lodan sends an **unauthenticated** search for the empty base
DN. The LDAP protocol requires a bind DN field in a bind request, so lodan
does not send a bind request at all — it issues the search directly, which
servers permitting anonymous rootDSE reads answer and others refuse. No
password, no bind DN, no credential of any kind is transmitted, and no part of
the directory below the rootDSE is read.
"""
from __future__ import annotations

import asyncio
import contextlib
from typing import Any

from lodan.probes.base import ProbeResult

_DEFAULT_LDAP_PORTS = frozenset({389, 3268})
_MAX_RESPONSE = 65536

# BER tags
_TAG_INT = 0x02
_TAG_OCTET = 0x04
_TAG_ENUM = 0x0A
_TAG_SEQUENCE = 0x30
_TAG_SET = 0x31
_APP_SEARCH_REQUEST = 0x63
_APP_SEARCH_ENTRY = 0x64
_APP_SEARCH_DONE = 0x65

# rootDSE attributes worth asking for by name. Asking explicitly (rather than
# with "*") is what makes this a bounded read of published metadata.
ROOTDSE_ATTRIBUTES = (
    "namingContexts",
    "defaultNamingContext",
    "supportedLDAPVersion",
    "supportedSASLMechanisms",
    "supportedControl",
    "supportedExtension",
    "vendorName",
    "vendorVersion",
    "dnsHostName",
    "domainFunctionality",
    "forestFunctionality",
)


class LDAPProbe:
    name = "ldap"
    default_ports = _DEFAULT_LDAP_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        raw = await asyncio.wait_for(fetch(ip, port, timeout), timeout=timeout + 1)
        return parse(raw)


# --- BER helpers -------------------------------------------------------------


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(body)) + body


def _int(value: int) -> bytes:
    length = max(1, (value.bit_length() + 8) // 8)
    return _tlv(_TAG_INT, value.to_bytes(length, "big", signed=True))


def build_rootdse_search(*, message_id: int = 1) -> bytes:
    """A base-scope search of the empty DN for the rootDSE attributes."""
    attributes = _tlv(
        _TAG_SEQUENCE,
        b"".join(_tlv(_TAG_OCTET, a.encode("ascii")) for a in ROOTDSE_ATTRIBUTES),
    )
    # (objectClass=*) — presence filter, tag 0x87 with the attribute name.
    present_filter = _tlv(0x87, b"objectClass")
    body = (
        _tlv(_TAG_OCTET, b"")        # baseObject: the empty DN (the rootDSE)
        + _tlv(_TAG_ENUM, b"\x00")   # scope: baseObject
        + _tlv(_TAG_ENUM, b"\x00")   # derefAliases: never
        + _int(1)                    # sizeLimit: one entry is all there is
        + _int(10)                   # timeLimit
        + _tlv(0x01, b"\x00")        # typesOnly: false
        + present_filter
        + attributes
    )
    return _tlv(_TAG_SEQUENCE, _int(message_id) + _tlv(_APP_SEARCH_REQUEST, body))


def _read_tlv(buf: bytes, pos: int) -> tuple[int, bytes, int]:
    if pos + 2 > len(buf):
        raise ValueError("truncated TLV")
    tag = buf[pos]
    length = buf[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or pos + count > len(buf):
            raise ValueError("bad long-form length")
        length = int.from_bytes(buf[pos : pos + count], "big")
        pos += count
    if length > len(buf) - pos:
        raise ValueError("TLV length overruns buffer")
    return tag, buf[pos : pos + length], pos + length


async def fetch(ip: str, port: int, timeout: float) -> bytes:
    reader, writer = await asyncio.open_connection(ip, port)
    try:
        writer.write(build_rootdse_search())
        await writer.drain()
        buf = bytearray()
        deadline = asyncio.get_event_loop().time() + timeout
        while len(buf) < _MAX_RESPONSE:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                break
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=remaining)
            except TimeoutError:
                break
            if not chunk:
                break
            buf.extend(chunk)
            if _has_search_done(bytes(buf)):
                break
        return bytes(buf)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


def _has_search_done(raw: bytes) -> bool:
    return any(tag == _APP_SEARCH_DONE for _msg_id, tag, _body in _iter_messages(raw))


def _iter_messages(raw: bytes):
    pos = 0
    while pos < len(raw):
        try:
            tag, body, pos = _read_tlv(raw, pos)
        except ValueError:
            return
        if tag != _TAG_SEQUENCE:
            return
        try:
            _t, _msg_id_bytes, inner = _read_tlv(body, 0)
            op_tag, op_body, _ = _read_tlv(body, inner)
        except ValueError:
            return
        yield int.from_bytes(_msg_id_bytes, "big"), op_tag, op_body


def parse(raw: bytes | None) -> ProbeResult:
    if not raw:
        return ProbeResult(service="ldap", banner="ldap: no response")
    result_raw: dict[str, Any] = {"response_bytes": len(raw)}
    attributes: dict[str, list[str]] = {}
    result_code: int | None = None

    for _msg_id, tag, body in _iter_messages(raw):
        if tag == _APP_SEARCH_ENTRY:
            attributes.update(_parse_entry(body))
        elif tag == _APP_SEARCH_DONE and body:
            with contextlib.suppress(ValueError):
                _t, code_bytes, _ = _read_tlv(body, 0)
                result_code = int.from_bytes(code_bytes, "big") if code_bytes else None

    result_raw["result_code"] = result_code
    if not attributes:
        # 50 = insufficientAccessRights, 1 = operationsError: anonymous reads
        # are refused. That is itself a useful (and reassuring) result.
        label = (
            "ldap: anonymous rootDSE refused"
            if result_code not in (None, 0)
            else "ldap: no rootDSE attributes"
        )
        return ProbeResult(service="ldap", banner=label, raw=result_raw)

    result_raw["rootdse"] = attributes
    naming = attributes.get("namingContexts") or attributes.get("defaultNamingContext")
    vendor = (attributes.get("vendorName") or [None])[0]
    version = (attributes.get("vendorVersion") or [None])[0]
    host = (attributes.get("dnsHostName") or [None])[0]
    result_raw.update({
        "naming_contexts": naming,
        "vendor": vendor,
        "vendor_version": version,
        "dns_host_name": host,
    })

    parts = [p for p in (vendor, version, host) if p]
    if not parts and naming:
        parts.append(naming[0])
    banner = "LDAP " + " | ".join(parts) if parts else "LDAP (anonymous rootDSE)"
    return ProbeResult(service="ldap", banner=banner[:300], raw=result_raw)


def _parse_entry(body: bytes) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    try:
        _t, _dn, pos = _read_tlv(body, 0)          # objectName (empty for rootDSE)
        _t, attr_list, _ = _read_tlv(body, pos)
    except ValueError:
        return out
    pos = 0
    while pos < len(attr_list):
        try:
            _t, attribute, pos = _read_tlv(attr_list, pos)
            _t, name_bytes, vpos = _read_tlv(attribute, 0)
            vtag, values_body, _ = _read_tlv(attribute, vpos)
        except ValueError:
            break
        if vtag != _TAG_SET:
            continue
        name = name_bytes.decode("ascii", "replace")
        values: list[str] = []
        vp = 0
        while vp < len(values_body):
            try:
                _t, value, vp = _read_tlv(values_body, vp)
            except ValueError:
                break
            values.append(value.decode("utf-8", "replace"))
        if values:
            out[name] = values
    return out
