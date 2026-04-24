"""RDP probe: X.224 Connection Request + RDP Negotiation.

Sends a minimal TPKT / X.224 Connection Request with an RDP Negotiation
Request that asks for all three protocol variants (SSL, CredSSP, CredSSP
Extended). The server answers with either NEG_RSP naming the protocol it
picked, or NEG_FAILURE naming why it refused — both are equally useful as
a fingerprint.

No Cookie: mstshash= line is sent; supplying a username starts to look like
an auth attempt, which lodan will not do.

Split into fetch + parse_response so tests stay offline.
"""
from __future__ import annotations

import asyncio
import contextlib
import struct
from typing import Any

from lodan.probes.base import ProbeResult

_DEFAULT_RDP_PORTS = frozenset({3389})

_PROTOCOL_NAMES = {
    0x00000000: "RDP (standard)",
    0x00000001: "SSL",
    0x00000002: "CredSSP",
    0x00000008: "CredSSP-EX",
}

_FAILURE_CODES = {
    1: "SSL_REQUIRED_BY_SERVER",
    2: "SSL_NOT_ALLOWED_BY_SERVER",
    3: "SSL_CERT_NOT_ON_SERVER",
    4: "INCONSISTENT_FLAGS",
    5: "HYBRID_REQUIRED_BY_SERVER",
    6: "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER",
}

_NEG_RSP_FLAGS = {
    0x01: "EXTENDED_CLIENT_DATA_SUPPORTED",
    0x02: "DYNVC_GFX_PROTOCOL_SUPPORTED",
    0x08: "RESTRICTED_ADMIN_MODE_SUPPORTED",
    0x10: "REDIRECTED_AUTHENTICATION_MODE_SUPPORTED",
}

# SSL | CredSSP | CredSSP-EX — ask for everything, let the server choose.
_REQUESTED_PROTOCOLS = 0x00000001 | 0x00000002 | 0x00000008


class RDPProbe:
    name = "rdp"
    default_ports = _DEFAULT_RDP_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        raw = await asyncio.wait_for(fetch(ip, port), timeout=timeout)
        return parse_response(raw)


def build_cr(requested: int = _REQUESTED_PROTOCOLS) -> bytes:
    """Build a TPKT-wrapped X.224 Connection Request carrying RDP_NEG_REQ."""
    # RDP_NEG_REQ: type(1) flags(1) length(2 LE)=8 requestedProtocols(4 LE)
    neg_req = struct.pack("<BBHI", 0x01, 0x00, 0x0008, requested)
    # X.224 CR: LI + (CR:0xE0 DST-REF:2 SRC-REF:2 Class:1) + neg_req
    x224_body = bytes([0xE0, 0x00, 0x00, 0x00, 0x00, 0x00]) + neg_req
    li = len(x224_body)  # LI does NOT include itself
    x224 = bytes([li]) + x224_body
    # TPKT: ver(3) reserved(0) length(2 BE) — length includes TPKT header.
    tpkt = struct.pack(">BBH", 0x03, 0x00, 4 + len(x224))
    return tpkt + x224


async def fetch(ip: str, port: int) -> bytes:
    reader, writer = await asyncio.open_connection(ip, port)
    try:
        writer.write(build_cr())
        await writer.drain()
        header = await reader.readexactly(4)
        if header[0] != 0x03:
            return header + await reader.read(1024)
        total_len = struct.unpack(">H", header[2:4])[0]
        body = await reader.readexactly(total_len - 4)
        return header + body
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


def parse_response(packet: bytes) -> ProbeResult:
    raw: dict[str, Any] = {"length": len(packet)}
    if len(packet) < 4 or packet[0] != 0x03:
        return ProbeResult(service="rdp", banner="rdp: non-TPKT response", raw=raw)
    tpkt_len = struct.unpack(">H", packet[2:4])[0]
    raw["tpkt_length"] = tpkt_len
    if len(packet) < tpkt_len or tpkt_len < 7:
        return ProbeResult(service="rdp", banner="rdp: truncated TPKT", raw=raw)

    x224 = packet[4:tpkt_len]
    if len(x224) < 2:
        return ProbeResult(service="rdp", banner="rdp: truncated X.224", raw=raw)
    li = x224[0]
    code = x224[1] & 0xF0  # high nibble is the PDU code
    raw["x224_code"] = code

    if code != 0xD0:  # not a Connection Confirm
        return ProbeResult(
            service="rdp",
            banner=f"rdp: unexpected X.224 code 0x{code:02x}",
            raw=raw,
        )

    # After LI(1) + CC(1) + DST(2) + SRC(2) + Class(1) = 7 bytes, optional NEG fields follow.
    neg_offset = 7
    neg = x224[neg_offset : 1 + li]  # everything after fixed CC header
    if len(neg) < 8:
        return ProbeResult(
            service="rdp",
            banner="rdp: CC without negotiation block",
            raw=raw,
        )

    neg_type, flags, length, value = struct.unpack("<BBHI", neg[:8])
    raw["neg_type"] = neg_type
    raw["neg_flags"] = flags
    raw["neg_length"] = length
    raw["neg_value"] = value

    if neg_type == 0x02:  # NEG_RSP
        protocol = _PROTOCOL_NAMES.get(value, f"unknown(0x{value:08x})")
        flag_names = [label for bit, label in _NEG_RSP_FLAGS.items() if flags & bit]
        raw["selected_protocol"] = protocol
        raw["flag_names"] = flag_names
        return ProbeResult(
            service="rdp",
            banner=f"RDP selected={protocol}",
            raw=raw,
        )
    if neg_type == 0x03:  # NEG_FAILURE
        failure = _FAILURE_CODES.get(value, f"unknown({value})")
        raw["failure_code"] = failure
        return ProbeResult(
            service="rdp",
            banner=f"RDP negotiation failed: {failure}",
            raw=raw,
        )
    return ProbeResult(
        service="rdp",
        banner=f"rdp: unknown neg type 0x{neg_type:02x}",
        raw=raw,
    )
