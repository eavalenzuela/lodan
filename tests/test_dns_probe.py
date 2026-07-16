from __future__ import annotations

import struct

from lodan.probes.dns import DNSProbe, build_query, parse_dns


def _response(txt: bytes | None, rcode: int = 0) -> bytes:
    ancount = 1 if txt is not None else 0
    flags = 0x8180 | rcode
    header = struct.pack(">HHHHHH", 0x1337, flags, 1, ancount, 0, 0)
    question = b"\x07version\x04bind\x00" + struct.pack(">HH", 16, 3)
    msg = header + question
    if txt is not None:
        rdata = bytes([len(txt)]) + txt
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 16, 3, 0, len(rdata)) + rdata
        msg += answer
    return msg


def test_parse_version_bind_txt() -> None:
    r = parse_dns(_response(b"9.16.1-Ubuntu"))
    assert r.service == "dns"
    assert "9.16.1-Ubuntu" in (r.banner or "")
    assert r.raw["version_bind"] == "9.16.1-Ubuntu"


def test_refused() -> None:
    r = parse_dns(_response(None, rcode=5))
    assert "refused" in (r.banner or "")
    assert r.raw["rcode"] == "REFUSED"


def test_no_txt_answer() -> None:
    r = parse_dns(_response(None))
    assert "no version.bind" in (r.banner or "")


def test_short_response() -> None:
    assert "short" in (parse_dns(b"\x00\x00").banner or "")


def test_build_query_is_tcp_framed() -> None:
    q = build_query()
    declared = int.from_bytes(q[:2], "big")
    assert declared == len(q) - 2
    assert b"\x07version\x04bind\x00" in q


def test_default_ports() -> None:
    assert 53 in DNSProbe().default_ports
