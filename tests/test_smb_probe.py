from __future__ import annotations

from pathlib import Path

from lodan.probes.smb import (
    DIALECTS,
    SMBProbe,
    _build_negotiate_request,
    parse_negotiate,
)

FIXTURES = Path(__file__).parent / "fixtures" / "smb"


def test_parse_3_0_2_signing_required() -> None:
    body = (FIXTURES / "neg_3_0_2_signing_required.bin").read_bytes()
    result = parse_negotiate(body)
    assert result.service == "smb"
    assert result.raw["dialect"] == "SMB 3.0.2"
    assert result.raw["dialect_revision"] == 0x0302
    assert result.raw["signing_required"] is True
    assert "12345678-1234-5678-1234-567812345678" in result.raw["server_guid"]
    assert "DFS" in result.raw["capability_flags"]
    assert "ENCRYPTION" in result.raw["capability_flags"]
    assert "required" in (result.banner or "")


def test_parse_2_1_signing_optional() -> None:
    body = (FIXTURES / "neg_2_1_signing_optional.bin").read_bytes()
    result = parse_negotiate(body)
    assert result.raw["dialect"] == "SMB 2.1"
    assert result.raw["signing_required"] is False
    assert "LARGE_MTU" in result.raw["capability_flags"]


def test_parse_non_smb2_marker() -> None:
    result = parse_negotiate(b"HTTP/1.1 400 Bad Request\r\n\r\n" + b"\x00" * 200)
    assert result.service == "smb"
    assert "non-SMB2" in (result.banner or "")


def test_parse_truncated() -> None:
    body = b"\xfeSMB" + b"\x00" * 100
    result = parse_negotiate(body)
    assert "truncated" in (result.banner or "")


def test_build_request_has_correct_structure() -> None:
    pkt = _build_negotiate_request()
    # NetBIOS session service header is 4 bytes, SMB2 header is 64, NEGOTIATE body follows.
    assert pkt[0] == 0
    body_len = int.from_bytes(pkt[2:4], "big")
    assert len(pkt) == 4 + body_len
    assert pkt[4:8] == b"\xfeSMB"
    # NEGOTIATE structure size is 0x24 (36) little-endian at offset 4+64.
    assert pkt[68:70] == b"\x24\x00"


def test_dialect_table_has_all_common_values() -> None:
    for d in (0x0202, 0x0210, 0x0300, 0x0302, 0x0311):
        assert d in DIALECTS


def test_probe_default_ports() -> None:
    assert {139, 445} <= SMBProbe().default_ports
