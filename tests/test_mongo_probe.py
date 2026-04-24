from __future__ import annotations

from pathlib import Path

from lodan.probes.mongo import MongoProbe, build_ismaster_query, parse_reply

FIXTURES = Path(__file__).parent / "fixtures" / "mongo"


def test_parse_op_reply_primary() -> None:
    raw = (FIXTURES / "reply_primary_6_0_14.bin").read_bytes()
    result = parse_reply(raw)
    assert result.service == "mongo"
    assert "6.0.14" in (result.banner or "")
    assert "rs=rs0" in (result.banner or "")
    assert "primary" in (result.banner or "")
    assert result.raw["fields"]["setName"] == "rs0"
    assert result.raw["fields"]["ismaster"] is True
    assert result.raw["fields"]["maxWireVersion"] == 17


def test_parse_op_msg_secondary() -> None:
    raw = (FIXTURES / "reply_msg_secondary_7_0_4.bin").read_bytes()
    result = parse_reply(raw)
    assert "7.0.4" in (result.banner or "")
    assert "secondary" in (result.banner or "")


def test_parse_short_header() -> None:
    result = parse_reply(b"\x00" * 10)
    assert "short header" in (result.banner or "")


def test_parse_unexpected_opcode() -> None:
    import struct

    header = struct.pack("<iiii", 16, 1, 0, 9999)
    result = parse_reply(header)
    assert "unexpected opcode 9999" in (result.banner or "")


def test_build_ismaster_query_is_op_query() -> None:
    pkt = build_ismaster_query()
    import struct

    total, req, resp_to, op = struct.unpack_from("<iiii", pkt, 0)
    assert total == len(pkt)
    assert op == 2004  # OP_QUERY
    assert b"admin.$cmd\x00" in pkt
    assert b"ismaster\x00" in pkt


def test_default_ports() -> None:
    assert 27017 in MongoProbe().default_ports
