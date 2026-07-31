"""SNMPv2c probe: sysDescr.0 and sysObjectID.0.

SNMP on UDP/161 is one of the highest-value recon leaks on a range you own —
sysDescr is a full device/OS/firmware string, and sysObjectID identifies the
vendor by IANA enterprise number. lodan's discovery found these ports and was
structurally unable to look at them.

**Why this one probe is opt-in.** SNMPv2c has no bannerable handshake: there
is no way to ask "is SNMP exposed here" without presenting a community
string. lodan sends *only* the single RFC-default `public`, never a second
value and never a guessing loop, and treats any response as an **exposure
finding** — default-community SNMP is itself the misconfiguration being
reported, not a foothold to pivot from. That is the same shape as the existing
Redis-INFO and empty-MQTT-CONNECT reads. But because `public` is a default
access token rather than a bannergrab, it ships behind an explicit operator
opt-in (`[scan] snmp = true`) instead of running by default.

Hand-rolled minimal BER/DER, in the same spirit as the TLS and SSH parsers.
"""
from __future__ import annotations

import asyncio
from typing import Any

from lodan.probes._udp import udp_exchange
from lodan.probes.base import ProbeResult

_DEFAULT_SNMP_PORTS = frozenset({161})

# The single community string lodan will ever send. Not a guess: it is the
# RFC-default, and a device answering it is the finding.
DEFAULT_COMMUNITY = b"public"

OID_SYS_DESCR = (1, 3, 6, 1, 2, 1, 1, 1, 0)
OID_SYS_OBJECT_ID = (1, 3, 6, 1, 2, 1, 1, 2, 0)

_TAG_INT = 0x02
_TAG_OCTET = 0x04
_TAG_NULL = 0x05
_TAG_OID = 0x06
_TAG_SEQUENCE = 0x30
_TAG_GET_REQUEST = 0xA0
_TAG_GET_RESPONSE = 0xA2


class SNMPProbe:
    name = "snmp"
    proto = "udp"
    default_ports = _DEFAULT_SNMP_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        request = build_get([OID_SYS_DESCR, OID_SYS_OBJECT_ID])
        raw = await asyncio.wait_for(
            udp_exchange(ip, port, request, timeout), timeout=timeout + 1
        )
        return parse(raw)


# --- BER encoding ------------------------------------------------------------


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(body)) + body


def _encode_int(value: int) -> bytes:
    length = max(1, (value.bit_length() + 8) // 8)
    return _tlv(_TAG_INT, value.to_bytes(length, "big", signed=True))


def encode_oid(oid: tuple[int, ...]) -> bytes:
    if len(oid) < 2:
        raise ValueError("OID needs at least two arcs")
    body = bytes([oid[0] * 40 + oid[1]])
    for arc in oid[2:]:
        if arc < 0x80:
            body += bytes([arc])
            continue
        chunks = []
        value = arc
        while value:
            chunks.append(value & 0x7F)
            value >>= 7
        chunks.reverse()
        body += bytes([c | 0x80 for c in chunks[:-1]] + [chunks[-1]])
    return _tlv(_TAG_OID, body)


def build_get(oids: list[tuple[int, ...]], *, request_id: int = 1) -> bytes:
    """Assemble an SNMPv2c GetRequest for the given OIDs."""
    varbinds = b"".join(
        _tlv(_TAG_SEQUENCE, encode_oid(oid) + _tlv(_TAG_NULL, b"")) for oid in oids
    )
    pdu = _tlv(
        _TAG_GET_REQUEST,
        _encode_int(request_id)
        + _encode_int(0)                       # error-status
        + _encode_int(0)                       # error-index
        + _tlv(_TAG_SEQUENCE, varbinds),
    )
    return _tlv(
        _TAG_SEQUENCE,
        _encode_int(1)                         # version 1 == SNMPv2c
        + _tlv(_TAG_OCTET, DEFAULT_COMMUNITY)
        + pdu,
    )


# --- BER decoding ------------------------------------------------------------


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
    if pos + length > len(buf):
        raise ValueError("TLV length overruns buffer")
    return tag, buf[pos : pos + length], pos + length


def decode_oid(body: bytes) -> tuple[int, ...]:
    if not body:
        return ()
    arcs = [body[0] // 40, body[0] % 40]
    value = 0
    for byte in body[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(value)
            value = 0
    return tuple(arcs)


def parse(raw: bytes | None) -> ProbeResult:
    """Parse a GetResponse into sysDescr / sysObjectID."""
    if not raw:
        return ProbeResult(service="snmp", banner="snmp: no response")
    result_raw: dict[str, Any] = {"response_bytes": len(raw)}
    try:
        tag, body, _ = _read_tlv(raw, 0)
        if tag != _TAG_SEQUENCE:
            raise ValueError("not an SNMP message")
        pos = 0
        _tag, _version, pos = _read_tlv(body, pos)
        _tag, community, pos = _read_tlv(body, pos)
        result_raw["community_accepted"] = community.decode("ascii", "replace")
        tag, pdu, pos = _read_tlv(body, pos)
        if tag != _TAG_GET_RESPONSE:
            return ProbeResult(
                service="snmp", banner=f"snmp: unexpected PDU 0x{tag:02x}", raw=result_raw
            )
        ppos = 0
        for _ in range(3):                     # request-id, error-status, error-index
            _t, _v, ppos = _read_tlv(pdu, ppos)
        _t, varbind_list, _ = _read_tlv(pdu, ppos)
    except (ValueError, IndexError) as e:
        return ProbeResult(
            service="snmp", banner=f"snmp: malformed response ({e})", raw=result_raw
        )

    values: dict[str, Any] = {}
    vpos = 0
    while vpos < len(varbind_list):
        try:
            _t, varbind, vpos = _read_tlv(varbind_list, vpos)
            _t, oid_body, inner = _read_tlv(varbind, 0)
            vtag, vbody, _ = _read_tlv(varbind, inner)
        except (ValueError, IndexError):
            break
        oid = decode_oid(oid_body)
        if oid == OID_SYS_DESCR and vtag == _TAG_OCTET:
            values["sys_descr"] = vbody.decode("utf-8", "replace").strip()
        elif oid == OID_SYS_OBJECT_ID and vtag == _TAG_OID:
            arcs = decode_oid(vbody)
            values["sys_object_id"] = ".".join(str(a) for a in arcs)
            # 1.3.6.1.4.1.<enterprise> is the IANA vendor number.
            if len(arcs) >= 7 and arcs[:6] == (1, 3, 6, 1, 4, 1):
                values["enterprise"] = arcs[6]

    result_raw.update(values)
    descr = values.get("sys_descr")
    banner = f"SNMP: {descr}" if descr else "SNMP (default community accepted)"
    return ProbeResult(service="snmp", banner=banner[:300], raw=result_raw)
