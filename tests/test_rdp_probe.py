from __future__ import annotations

from pathlib import Path

from lodan.probes.rdp import RDPProbe, build_cr, parse_response

FIXTURES = Path(__file__).parent / "fixtures" / "rdp"


def test_parse_credssp_with_flags() -> None:
    pkt = (FIXTURES / "cc_credssp_restricted_admin.bin").read_bytes()
    result = parse_response(pkt)
    assert result.service == "rdp"
    assert result.raw["selected_protocol"] == "CredSSP"
    assert "EXTENDED_CLIENT_DATA_SUPPORTED" in result.raw["flag_names"]
    assert "RESTRICTED_ADMIN_MODE_SUPPORTED" in result.raw["flag_names"]
    assert "CredSSP" in (result.banner or "")


def test_parse_ssl_selected() -> None:
    pkt = (FIXTURES / "cc_ssl.bin").read_bytes()
    result = parse_response(pkt)
    assert result.raw["selected_protocol"] == "SSL"


def test_parse_negotiation_failure() -> None:
    pkt = (FIXTURES / "cc_failure_ssl_required.bin").read_bytes()
    result = parse_response(pkt)
    assert result.raw["failure_code"] == "SSL_REQUIRED_BY_SERVER"
    assert "failed" in (result.banner or "")


def test_parse_non_tpkt() -> None:
    result = parse_response(b"HTTP/1.1 400")
    assert "non-TPKT" in (result.banner or "")


def test_parse_truncated_tpkt() -> None:
    # TPKT claiming length 100 but only 10 bytes present
    result = parse_response(b"\x03\x00\x00\x64" + b"\x00" * 6)
    assert "truncated" in (result.banner or "")


def test_parse_unexpected_x224_code() -> None:
    # TPKT + 1-byte LI=2 + code 0xE0 (should be 0xD0) + filler
    body = bytes([0x03, 0x00, 0x00, 0x0B, 0x06, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00])
    result = parse_response(body)
    assert "unexpected X.224" in (result.banner or "")


def test_build_cr_has_tpkt_and_x224_and_neg_req() -> None:
    pkt = build_cr()
    assert pkt[0] == 0x03  # TPKT version
    total = int.from_bytes(pkt[2:4], "big")
    assert total == len(pkt)
    # X.224 CR code is high nibble 0xE0 at offset 5 (after TPKT(4)+LI(1))
    assert pkt[5] & 0xF0 == 0xE0
    # RDP_NEG_REQ at offset 4+7 = 11; type byte 0x01
    assert pkt[11] == 0x01
    # NEG_REQ layout at offset 11: type(1) flags(1) length(2 LE) requestedProtocols(4 LE)
    requested = int.from_bytes(pkt[15:19], "little")
    assert requested == 0x0B


def test_probe_default_ports() -> None:
    assert 3389 in RDPProbe().default_ports
