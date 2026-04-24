from __future__ import annotations

import pytest

from lodan.probes.mqtt import MQTTProbe, build_connect, parse_connack


def test_build_connect_has_correct_header_and_vh() -> None:
    pkt = build_connect()
    assert pkt[0] == 0x10  # CONNECT
    # Variable header: 00 04 "MQTT" 04 02 00 3C
    assert pkt[2:4] == b"\x00\x04"
    assert pkt[4:8] == b"MQTT"
    # Protocol level 3.1.1 (0x04), connect flags clean=0x02
    assert pkt[8] == 0x04
    assert pkt[9] == 0x02


@pytest.mark.parametrize("rc,label", [
    (0x00, "accepted"),
    (0x04, "bad_username_or_password"),
    (0x05, "not_authorized"),
])
def test_parse_known_return_codes(rc: int, label: str) -> None:
    raw = bytes([0x20, 0x02, 0x00, rc])
    result = parse_connack(raw)
    assert result.raw["return_code"] == rc
    assert result.raw["return_code_label"] == label
    assert label in (result.banner or "")


def test_parse_unknown_return_code() -> None:
    raw = bytes([0x20, 0x02, 0x00, 0xFE])
    result = parse_connack(raw)
    assert "unknown" in result.raw["return_code_label"]


def test_parse_session_present() -> None:
    raw = bytes([0x20, 0x02, 0x01, 0x00])
    result = parse_connack(raw)
    assert result.raw["session_present"] is True


def test_parse_non_connack() -> None:
    raw = bytes([0x30, 0x02, 0x00, 0x00])  # PUBLISH type
    result = parse_connack(raw)
    assert "non-CONNACK" in (result.banner or "")


def test_parse_short() -> None:
    result = parse_connack(b"\x20")
    assert "non-CONNACK" in (result.banner or "")


def test_default_ports() -> None:
    assert 1883 in MQTTProbe().default_ports
    assert 8883 in MQTTProbe().default_ports
