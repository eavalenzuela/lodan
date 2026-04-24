"""SMB probe: raw SMB2 NEGOTIATE.

Talks the wire directly — no impacket dep — because all we need is the
server's choice of dialect and a few fields out of the NEGOTIATE response.
We advertise SMB 2.0.2 through 3.0.2; 3.1.1 is skipped because it requires
a NegotiateContextList with pre-auth integrity capabilities, which is more
than a fingerprint needs.

Two phases, each independently testable:

    fetch(ip, port, timeout) -> bytes    # raw NEGOTIATE response body
    parse_negotiate(raw)     -> ProbeResult
"""
from __future__ import annotations

import asyncio
import contextlib
import struct
import uuid
from typing import Any

from lodan.probes.base import ProbeResult

_DEFAULT_SMB_PORTS = frozenset({445, 139})

DIALECTS: dict[int, str] = {
    0x0202: "SMB 2.0.2",
    0x0210: "SMB 2.1",
    0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2",
    0x0311: "SMB 3.1.1",
}

# SigningRequired flag in the NEGOTIATE response SecurityMode field.
_SEC_SIGNING_REQUIRED = 0x0002

# Capability bits we bother to name. Everything else goes into `raw` verbatim.
_CAPS = {
    0x00000001: "DFS",
    0x00000002: "LEASING",
    0x00000004: "LARGE_MTU",
    0x00000008: "MULTI_CHANNEL",
    0x00000010: "PERSISTENT_HANDLES",
    0x00000020: "DIRECTORY_LEASING",
    0x00000040: "ENCRYPTION",
}


class SMBProbe:
    name = "smb"
    default_ports = _DEFAULT_SMB_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        raw = await asyncio.wait_for(fetch(ip, port), timeout=timeout)
        return parse_negotiate(raw)


def _build_negotiate_request() -> bytes:
    client_guid = uuid.uuid4().bytes
    dialects = [0x0202, 0x0210, 0x0300, 0x0302]
    dialect_count = len(dialects)
    smb2_header = b"".join([
        b"\xfeSMB",
        struct.pack("<H", 0x0040),     # StructureSize
        struct.pack("<H", 0),          # CreditCharge
        struct.pack("<I", 0),          # Status / ChannelSequence+Reserved
        struct.pack("<H", 0x0000),     # Command NEGOTIATE
        struct.pack("<H", 31),         # Credits
        struct.pack("<I", 0),          # Flags
        struct.pack("<I", 0),          # NextCommand
        struct.pack("<Q", 0),          # MessageId
        struct.pack("<I", 0),          # Reserved (async) / Reserved1
        struct.pack("<I", 0),          # TreeId
        struct.pack("<Q", 0),          # SessionId
        b"\x00" * 16,                  # Signature
    ])
    negotiate_req = b"".join([
        struct.pack("<H", 0x0024),             # StructureSize
        struct.pack("<H", dialect_count),
        struct.pack("<H", 0x0001),             # SecurityMode: signing enabled
        struct.pack("<H", 0),                  # Reserved
        struct.pack("<I", 0x00000000),         # Capabilities
        client_guid,
        struct.pack("<Q", 0),                  # ClientStartTime
        b"".join(struct.pack("<H", d) for d in dialects),
    ])
    body = smb2_header + negotiate_req
    netbios = struct.pack(">BBH", 0, 0, len(body))  # type, flags, length(16)
    return netbios + body


async def fetch(ip: str, port: int) -> bytes:
    reader, writer = await asyncio.open_connection(ip, port)
    try:
        writer.write(_build_negotiate_request())
        await writer.drain()
        header = await reader.readexactly(4)
        _type, _flags, length = struct.unpack(">BBH", header)
        body = await reader.readexactly(length)
        return body
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


def parse_negotiate(body: bytes) -> ProbeResult:
    """Parse an SMB2 NEGOTIATE response body (the bytes after the NBSS header).

    Returns a best-effort ProbeResult; malformed/truncated inputs produce
    a result with service='smb' and whatever fields we managed to extract.
    """
    raw: dict[str, Any] = {"length": len(body)}
    if body[:4] != b"\xfeSMB":
        return ProbeResult(service="smb", banner="smb: non-SMB2 response", raw=raw)
    if len(body) < 64 + 64:
        return ProbeResult(service="smb", banner="smb: truncated NEGOTIATE", raw=raw)

    neg = body[64:]

    structure_size = struct.unpack_from("<H", neg, 0)[0]
    security_mode = struct.unpack_from("<H", neg, 2)[0]
    dialect_rev = struct.unpack_from("<H", neg, 4)[0]
    ctx_count = struct.unpack_from("<H", neg, 6)[0]
    server_guid = uuid.UUID(bytes_le=neg[8:24])
    capabilities = struct.unpack_from("<I", neg, 24)[0]
    max_transact = struct.unpack_from("<I", neg, 28)[0]
    max_read = struct.unpack_from("<I", neg, 32)[0]
    max_write = struct.unpack_from("<I", neg, 36)[0]

    dialect_label = DIALECTS.get(dialect_rev, f"0x{dialect_rev:04x}")
    signing_required = bool(security_mode & _SEC_SIGNING_REQUIRED)
    cap_flags = [label for bit, label in _CAPS.items() if capabilities & bit]

    raw.update({
        "structure_size": structure_size,
        "security_mode": security_mode,
        "dialect_revision": dialect_rev,
        "dialect": dialect_label,
        "negotiate_context_count": ctx_count,
        "server_guid": str(server_guid),
        "capabilities": capabilities,
        "capability_flags": cap_flags,
        "max_transact_size": max_transact,
        "max_read_size": max_read,
        "max_write_size": max_write,
        "signing_required": signing_required,
    })

    banner = (
        f"{dialect_label} guid={server_guid} "
        f"signing={'required' if signing_required else 'optional'}"
    )
    return ProbeResult(service="smb", banner=banner, raw=raw)
