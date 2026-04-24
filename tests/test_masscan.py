from __future__ import annotations

import shutil
from ipaddress import IPv4Network

import pytest

from lodan.discovery.base import DiscoverySpec
from lodan.discovery.masscan import MasscanBackend, build_argv, parse_list_line


def _spec(tcp: bool = True, udp: bool = False) -> DiscoverySpec:
    return DiscoverySpec(
        targets=[IPv4Network("10.0.0.0/24")],
        ports=[22, 80, 443],
        tcp=tcp,
        udp=udp,
        rate_pps=500,
    )


def test_parse_valid_tcp_line() -> None:
    r = parse_list_line("open tcp 80 10.0.0.5 1734460000")
    assert r is not None
    assert r.ip == "10.0.0.5"
    assert r.port == 80
    assert r.proto == "tcp"


def test_parse_valid_udp_line() -> None:
    r = parse_list_line("open udp 53 10.0.0.7 1734460000")
    assert r is not None
    assert r.proto == "udp"
    assert r.port == 53


@pytest.mark.parametrize("line", [
    "",
    "# masscan banner header",
    "closed tcp 80 10.0.0.5 1734460000",
    "open sctp 80 10.0.0.5 1734460000",
    "open tcp notaport 10.0.0.5 1734460000",
    "open tcp",
])
def test_parse_ignores_noise(line: str) -> None:
    assert parse_list_line(line) is None


def test_build_argv_tcp_only() -> None:
    argv = build_argv(_spec(tcp=True, udp=False))
    assert argv[0] == "masscan"
    assert "T:22,80,443" in argv
    assert not any(a.startswith("U:") for a in argv)
    assert "--rate" in argv
    assert argv[argv.index("--rate") + 1] == "500"
    assert "-oL" in argv
    assert "10.0.0.0/24" in argv


def test_build_argv_tcp_and_udp() -> None:
    argv = build_argv(_spec(tcp=True, udp=True))
    ports_arg = argv[argv.index("-p") + 1]
    assert "T:22,80,443" in ports_arg
    assert "U:22,80,443" in ports_arg


def test_available_reflects_binary_presence() -> None:
    assert MasscanBackend().available() == (shutil.which("masscan") is not None)
