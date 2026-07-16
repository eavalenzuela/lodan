"""MySQL / MariaDB probe: initial handshake packet. Detection-only.

A MySQL-family server sends its Initial Handshake packet the moment a TCP
connection opens — before any authentication — carrying the protocol and server
version, and its capability flags. lodan reads exactly that one packet and stops:
no HandshakeResponse, no username, no password. An error packet (host-based ACL
rejection, "server blocked") is equally informative and reported as such.
"""
from __future__ import annotations

import asyncio
import contextlib
from typing import Any

from lodan.probes.base import ProbeResult

_DEFAULT_MYSQL_PORTS = frozenset({3306, 3307})
_CLIENT_SSL = 0x0800  # CLIENT_SSL bit in the lower capability flags


class MySQLProbe:
    name = "mysql"
    default_ports = _DEFAULT_MYSQL_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        raw = await asyncio.wait_for(fetch(ip, port), timeout=timeout)
        return parse_mysql(raw)


async def fetch(ip: str, port: int) -> bytes:
    reader, writer = await asyncio.open_connection(ip, port)
    try:
        header = await reader.readexactly(4)
        length = int.from_bytes(header[:3], "little")
        body = await reader.readexactly(min(length, 4096))
        return header + body
    except asyncio.IncompleteReadError as e:
        return e.partial
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


def parse_mysql(raw: bytes) -> ProbeResult:
    result_raw: dict[str, Any] = {"length": len(raw)}
    if len(raw) < 5:
        return ProbeResult(service="mysql", banner="mysql: short handshake", raw=result_raw)
    payload = raw[4:]
    proto = payload[0]

    if proto == 0xFF:  # ERR packet in place of a handshake
        code = int.from_bytes(payload[1:3], "little") if len(payload) >= 3 else 0
        msg = payload[3:].decode("utf-8", "replace").strip()
        result_raw.update({"error_code": code, "error": msg})
        return ProbeResult(service="mysql", banner=f"MySQL error {code}: {msg}"[:300], raw=result_raw)

    if proto not in (9, 10):
        return ProbeResult(service="mysql", banner="mysql: unexpected protocol", raw=result_raw)

    end = payload.find(b"\x00", 1)
    if end == -1:
        return ProbeResult(service="mysql", banner="mysql: unterminated version", raw=result_raw)
    version = payload[1:end].decode("utf-8", "replace")

    # After the version NUL: connection_id(4) + auth_data_1(8) + filler(1),
    # then the lower capability flags (2 bytes, little-endian).
    ssl = None
    cap_off = end + 1 + 4 + 8 + 1
    if len(payload) >= cap_off + 2:
        caps_lower = int.from_bytes(payload[cap_off:cap_off + 2], "little")
        ssl = bool(caps_lower & _CLIENT_SSL)

    flavor = "MariaDB" if "mariadb" in version.lower() else "MySQL"
    result_raw.update({"protocol": proto, "server_version": version, "ssl": ssl})
    banner = f"{flavor} {version}"
    if ssl is False:
        banner += " (no SSL)"
    return ProbeResult(service="mysql", banner=banner[:300], raw=result_raw)
