"""MQTT probe: 3.1.1 CONNECT -> CONNACK.

Sends a minimal CONNECT with an empty client id and clean session flag,
reads the CONNACK, and records the return code. The return code alone is
a useful fingerprint: 0 = anon allowed, 4 = bad creds (so auth is on),
5 = not authorized. Everything else ("unacceptable protocol version",
"identifier rejected") also tells us something about the broker.

Never sends Will / Username / Password fields — strictly unauth detection.
"""
from __future__ import annotations

import asyncio
import contextlib
import struct
from typing import Any

from lodan.probes.base import ProbeResult

_DEFAULT_MQTT_PORTS = frozenset({1883, 8883})

_RETURN_CODES = {
    0x00: "accepted",
    0x01: "unacceptable_protocol_version",
    0x02: "identifier_rejected",
    0x03: "server_unavailable",
    0x04: "bad_username_or_password",
    0x05: "not_authorized",
}


class MQTTProbe:
    name = "mqtt"
    default_ports = _DEFAULT_MQTT_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        raw = await asyncio.wait_for(fetch(ip, port), timeout=timeout)
        return parse_connack(raw)


def build_connect() -> bytes:
    """MQTT 3.1.1 CONNECT with empty client id, clean session, keep-alive 60."""
    # Variable header
    var = b"\x00\x04MQTT" + bytes([0x04, 0x02]) + struct.pack(">H", 60)
    # Payload: client id = "" (2-byte length prefix then zero bytes)
    payload = b"\x00\x00"
    body = var + payload
    # Fixed header: type=CONNECT (0x10), remaining length as a single-byte varint
    # (body < 128 so one byte suffices)
    assert len(body) < 128
    return bytes([0x10, len(body)]) + body


async def fetch(ip: str, port: int) -> bytes:
    reader, writer = await asyncio.open_connection(ip, port)
    try:
        writer.write(build_connect())
        await writer.drain()
        return await reader.readexactly(4)  # CONNACK is always 4 bytes
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


def parse_connack(raw: bytes) -> ProbeResult:
    result_raw: dict[str, Any] = {"bytes": raw.hex()}
    if len(raw) < 4 or (raw[0] & 0xF0) != 0x20:
        return ProbeResult(
            service="mqtt", banner="mqtt: non-CONNACK response", raw=result_raw
        )
    remaining_len = raw[1]
    session_present = bool(raw[2] & 0x01)
    rc = raw[3]
    label = _RETURN_CODES.get(rc, f"unknown(0x{rc:02x})")
    result_raw.update(
        {
            "remaining_length": remaining_len,
            "session_present": session_present,
            "return_code": rc,
            "return_code_label": label,
        }
    )
    return ProbeResult(
        service="mqtt",
        banner=f"MQTT CONNACK rc={rc} ({label})",
        raw=result_raw,
    )
