"""MongoDB probe: OP_QUERY ismaster (alias of hello).

Mongo 7.0 deprecated OP_QUERY for everything *except* the hello/ismaster
handshake, which is exactly the command we send. That gives us one probe
that works against the widest range of server versions without pulling in
pymongo for what boils down to ~40 lines of wire format.

Wire format reference: https://github.com/mongodb/specifications/blob/master/source/message/message.rst
"""
from __future__ import annotations

import asyncio
import contextlib
import struct
from typing import Any

from lodan.probes.base import ProbeResult

_DEFAULT_MONGO_PORTS = frozenset({27017, 27018, 27019})

_OP_QUERY = 2004
_OP_REPLY = 1
_OP_MSG = 2013


class MongoProbe:
    name = "mongo"
    default_ports = _DEFAULT_MONGO_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        raw = await asyncio.wait_for(fetch(ip, port), timeout=timeout)
        return parse_reply(raw)


def _cstring(s: str) -> bytes:
    return s.encode("utf-8") + b"\x00"


def _bson_int32(name: str, value: int) -> bytes:
    return b"\x10" + _cstring(name) + struct.pack("<i", value)


def _bson_doc(pairs: list[tuple[str, int]]) -> bytes:
    """Build a BSON doc of only int32 fields — enough for {"ismaster": 1}."""
    body = b"".join(_bson_int32(k, v) for k, v in pairs) + b"\x00"
    return struct.pack("<i", 4 + len(body)) + body


def build_ismaster_query() -> bytes:
    query = _bson_doc([("ismaster", 1)])
    body = (
        struct.pack("<i", 0)              # flags
        + _cstring("admin.$cmd")          # fullCollectionName
        + struct.pack("<i", 0)            # numberToSkip
        + struct.pack("<i", 1)            # numberToReturn
        + query
    )
    total = 16 + len(body)
    header = struct.pack(
        "<iiii",
        total,            # messageLength
        1,                # requestID
        0,                # responseTo
        _OP_QUERY,
    )
    return header + body


async def fetch(ip: str, port: int) -> bytes:
    reader, writer = await asyncio.open_connection(ip, port)
    try:
        writer.write(build_ismaster_query())
        await writer.drain()
        header = await reader.readexactly(16)
        (total,) = struct.unpack_from("<i", header, 0)
        if total < 16 or total > 1024 * 1024:
            return header
        body = await reader.readexactly(total - 16)
        return header + body
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


def parse_reply(raw: bytes) -> ProbeResult:
    meta: dict[str, Any] = {"length": len(raw)}
    if len(raw) < 16:
        return ProbeResult(service="mongo", banner="mongo: short header", raw=meta)

    total, _req, _resp_to, op = struct.unpack_from("<iiii", raw, 0)
    meta.update({"message_length": total, "op_code": op})
    if op == _OP_REPLY:
        doc = _extract_first_reply_doc(raw)
    elif op == _OP_MSG:
        doc = _extract_first_msg_doc(raw)
    else:
        return ProbeResult(
            service="mongo",
            banner=f"mongo: unexpected opcode {op}",
            raw=meta,
        )

    if doc is None:
        return ProbeResult(
            service="mongo", banner="mongo: no document in reply", raw=meta
        )

    extracted = _pull_fields(doc)
    meta["fields"] = extracted
    version = extracted.get("version") or "unknown"
    set_name = extracted.get("setName")
    role_bits = []
    if extracted.get("ismaster") or extracted.get("isWritablePrimary"):
        role_bits.append("primary")
    if extracted.get("secondary"):
        role_bits.append("secondary")
    if extracted.get("arbiterOnly"):
        role_bits.append("arbiter")
    banner = f"MongoDB {version}"
    if set_name:
        banner += f" rs={set_name}"
    if role_bits:
        banner += f" ({','.join(role_bits)})"
    return ProbeResult(service="mongo", banner=banner, raw=meta)


def _extract_first_reply_doc(raw: bytes) -> bytes | None:
    # OP_REPLY body: flags(4) cursorID(8) startingFrom(4) numberReturned(4) docs...
    if len(raw) < 16 + 20:
        return None
    doc_start = 16 + 4 + 8 + 4 + 4
    return _read_bson_doc(raw, doc_start)


def _extract_first_msg_doc(raw: bytes) -> bytes | None:
    # OP_MSG body: flagBits(4) Section(kind=0 followed by one BSON doc)
    if len(raw) < 16 + 5:
        return None
    kind = raw[16 + 4]
    if kind != 0:
        return None
    return _read_bson_doc(raw, 16 + 4 + 1)


def _read_bson_doc(raw: bytes, offset: int) -> bytes | None:
    if offset + 4 > len(raw):
        return None
    (length,) = struct.unpack_from("<i", raw, offset)
    if length < 5 or offset + length > len(raw):
        return None
    return raw[offset : offset + length]


def _pull_fields(doc: bytes) -> dict[str, Any]:
    """Very small BSON reader that extracts the few fields ismaster/hello returns
    that we care about. Unknown types are skipped."""
    interesting = {
        "ismaster", "isWritablePrimary", "secondary", "arbiterOnly",
        "setName", "version", "maxBsonObjectSize", "maxWireVersion",
        "minWireVersion", "me", "primary", "readOnly",
    }
    out: dict[str, Any] = {}
    i = 4  # skip total length
    end = len(doc) - 1  # trailing null
    while i < end:
        type_byte = doc[i]
        i += 1
        if type_byte == 0x00:
            break
        name_end = doc.index(b"\x00", i)
        name = doc[i:name_end].decode("utf-8", "replace")
        i = name_end + 1
        try:
            if type_byte == 0x01:  # double
                value = struct.unpack_from("<d", doc, i)[0]
                i += 8
            elif type_byte == 0x02:  # utf-8 string
                (strlen,) = struct.unpack_from("<i", doc, i)
                i += 4
                value = doc[i : i + strlen - 1].decode("utf-8", "replace")
                i += strlen
            elif type_byte == 0x08:  # bool
                value = bool(doc[i])
                i += 1
            elif type_byte == 0x10:  # int32
                value = struct.unpack_from("<i", doc, i)[0]
                i += 4
            elif type_byte == 0x12:  # int64
                value = struct.unpack_from("<q", doc, i)[0]
                i += 8
            else:
                # Unknown types would require full BSON walk logic — bail
                # rather than read garbage.
                break
        except Exception:
            break
        if name in interesting:
            out[name] = value
    return out
