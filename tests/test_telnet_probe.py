from __future__ import annotations

from lodan.probes.telnet import TelnetProbe, parse_telnet


def test_strips_iac_and_keeps_banner() -> None:
    # IAC DO ECHO(24), IAC WILL SGA(1), then a login banner.
    raw = bytes([255, 253, 24, 255, 251, 1]) + b"Ubuntu 22.04 login: "
    r = parse_telnet(raw)
    assert r.service == "telnet"
    assert "Ubuntu 22.04 login:" in (r.banner or "")
    assert "DO:24" in r.raw["options"]
    assert "WILL:1" in r.raw["options"]


def test_negotiation_only_still_flags_exposure() -> None:
    r = parse_telnet(bytes([255, 253, 24]))
    assert "cleartext admin" in (r.banner or "")


def test_escaped_iac_literal() -> None:
    r = parse_telnet(bytes([255, 255]) + b"x")  # IAC IAC = literal 0xFF then 'x'
    assert "x" in (r.banner or "")


def test_empty() -> None:
    assert "no data" in (parse_telnet(b"").banner or "")


def test_default_ports() -> None:
    assert 23 in TelnetProbe().default_ports
