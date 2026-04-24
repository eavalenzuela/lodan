from __future__ import annotations

import shutil
from ipaddress import IPv4Network

import pytest

from lodan.discovery.base import DiscoverySpec
from lodan.discovery.naabu import NaabuBackend, build_argv, parse_json_line


def _spec(tcp: bool = True, udp: bool = False) -> DiscoverySpec:
    return DiscoverySpec(
        targets=[IPv4Network("10.0.0.0/24")],
        ports=[22, 80, 443],
        tcp=tcp,
        udp=udp,
        rate_pps=1500,
    )


def test_build_argv_shape() -> None:
    argv = build_argv(_spec(), "/tmp/targets.txt")
    assert argv[0] == "naabu"
    assert "-list" in argv
    assert argv[argv.index("-list") + 1] == "/tmp/targets.txt"
    assert argv[argv.index("-p") + 1] == "22,80,443"
    assert argv[argv.index("-rate") + 1] == "1500"
    assert "-json" in argv
    assert "-silent" in argv


def test_parse_tcp_line() -> None:
    r = parse_json_line('{"ip":"10.0.0.5","port":80,"protocol":"tcp"}')
    assert r is not None
    assert r.ip == "10.0.0.5"
    assert r.port == 80
    assert r.proto == "tcp"


def test_parse_without_protocol_defaults_to_tcp() -> None:
    r = parse_json_line('{"ip":"10.0.0.5","port":22}')
    assert r is not None
    assert r.proto == "tcp"


def test_parse_udp_line() -> None:
    r = parse_json_line('{"ip":"10.0.0.5","port":53,"protocol":"udp"}')
    assert r is not None
    assert r.proto == "udp"


def test_parse_uses_host_when_ip_missing() -> None:
    r = parse_json_line('{"host":"10.0.0.5","port":80}')
    assert r is not None
    assert r.ip == "10.0.0.5"


@pytest.mark.parametrize("line", [
    "",
    "not json",
    "[1,2,3]",
    '{"port":80}',           # missing ip/host
    '{"ip":"10.0.0.5"}',     # missing port
    '{"ip":"10.0.0.5","port":"80"}',  # non-int port
    '{"ip":"10.0.0.5","port":80,"protocol":"sctp"}',  # unsupported proto
])
def test_parse_rejects_bad_lines(line: str) -> None:
    assert parse_json_line(line) is None


def test_available_reflects_binary_presence() -> None:
    assert NaabuBackend().available() == (shutil.which("naabu") is not None)
