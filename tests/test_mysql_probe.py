from __future__ import annotations

import struct

from lodan.probes.mysql import MySQLProbe, parse_mysql


def _handshake(version: bytes, caps_lower: int = 0x0800) -> bytes:
    payload = (
        b"\x0a" + version + b"\x00"          # protocol 10 + version NUL-terminated
        + b"\x01\x00\x00\x00"                # connection_id
        + b"\x00" * 8                        # auth-plugin-data-part-1
        + b"\x00"                            # filler
        + struct.pack("<H", caps_lower)      # capability flags (lower)
    )
    return struct.pack("<I", len(payload))[:3] + b"\x00" + payload


def test_parse_version_and_ssl() -> None:
    r = parse_mysql(_handshake(b"8.0.35", caps_lower=0x0800))
    assert r.service == "mysql"
    assert "MySQL 8.0.35" in (r.banner or "")
    assert r.raw["ssl"] is True


def test_mariadb_flavor_and_no_ssl() -> None:
    r = parse_mysql(_handshake(b"10.11.6-MariaDB", caps_lower=0x0000))
    assert "MariaDB" in (r.banner or "")
    assert r.raw["ssl"] is False
    assert "no SSL" in (r.banner or "")


def test_error_packet() -> None:
    payload = b"\xff" + struct.pack("<H", 1130) + b"Host not allowed"
    pkt = struct.pack("<I", len(payload))[:3] + b"\x00" + payload
    r = parse_mysql(pkt)
    assert "1130" in (r.banner or "")
    assert r.raw["error_code"] == 1130


def test_short_and_bad_protocol() -> None:
    assert "short handshake" in (parse_mysql(b"\x00\x00").banner or "")


def test_default_ports() -> None:
    assert 3306 in MySQLProbe().default_ports
