from __future__ import annotations

import struct

from lodan.probes.amqp import AMQPProbe, parse_amqp


def _connection_start(product: bytes = b"RabbitMQ", version: bytes = b"3.12.0") -> bytes:
    def field(name: bytes, value: bytes) -> bytes:
        return bytes([len(name)]) + name + b"S" + struct.pack(">I", len(value)) + value

    table = field(b"product", product) + field(b"version", version)
    props = struct.pack(">I", len(table)) + table
    method = struct.pack(">HH", 10, 10) + bytes([0, 9]) + props  # class 10 method 10, v0-9
    frame = bytes([1]) + struct.pack(">H", 0) + struct.pack(">I", len(method)) + method + bytes([0xCE])
    return frame


def test_parse_connection_start() -> None:
    r = parse_amqp(_connection_start())
    assert r.service == "amqp"
    assert r.raw["product"] == "RabbitMQ"
    assert r.raw["server_version"] == "3.12.0"
    assert "RabbitMQ 3.12.0" in (r.banner or "")


def test_version_negotiation_reply() -> None:
    r = parse_amqp(b"AMQP\x00\x00\x09\x01")
    assert "offers" in (r.banner or "")
    assert r.raw["offered_version"] == "0.9.1"


def test_unexpected_reply() -> None:
    assert "unexpected" in (parse_amqp(b"HTTP/1.1").banner or "")


def test_frame_without_fields_still_identifies() -> None:
    method = struct.pack(">HH", 10, 10) + bytes([0, 9, 0, 0, 0, 0])
    frame = bytes([1]) + struct.pack(">H", 0) + struct.pack(">I", len(method)) + method + bytes([0xCE])
    r = parse_amqp(frame)
    assert r.service == "amqp"
    assert "AMQP 0-9" in (r.banner or "")


def test_default_ports() -> None:
    assert 5672 in AMQPProbe().default_ports
