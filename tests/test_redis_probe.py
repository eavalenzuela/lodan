from __future__ import annotations

from lodan.probes.redis import RedisProbe, parse_info

_VALID_INFO = (
    b"$320\r\n"
    b"# Server\r\n"
    b"redis_version:7.0.12\r\n"
    b"redis_mode:standalone\r\n"
    b"os:Linux 5.15.0 x86_64\r\n"
    b"arch_bits:64\r\n"
    b"tcp_port:6379\r\n"
    b"run_id:abcdef\r\n"
    b"\r\n"
    b"# Replication\r\n"
    b"role:master\r\n"
    b"connected_slaves:0\r\n"
    b"\r\n"
)


def test_parse_info_happy_path() -> None:
    result = parse_info(_VALID_INFO)
    assert result.service == "redis"
    assert "Redis 7.0.12" in (result.banner or "")
    assert "master" in (result.banner or "")
    assert result.raw["fields"]["redis_version"] == "7.0.12"
    assert result.raw["fields"]["role"] == "master"
    assert result.raw["fields"]["tcp_port"] == "6379"


def test_parse_noauth_reply() -> None:
    result = parse_info(b"-NOAUTH Authentication required.\r\n")
    assert "auth required" in (result.banner or "")
    assert "NOAUTH" in result.raw["auth_line"]


def test_parse_wrongpass_reply() -> None:
    result = parse_info(b"-WRONGPASS invalid username-password pair\r\n")
    assert "auth required" in (result.banner or "")


def test_parse_unexpected_reply() -> None:
    result = parse_info(b"+PONG\r\n")
    assert "unexpected" in (result.banner or "")


def test_parse_malformed_bulk_header() -> None:
    result = parse_info(b"$not-a-number\r\nwhatever\r\n")
    assert "malformed" in (result.banner or "")


def test_default_ports() -> None:
    assert 6379 in RedisProbe().default_ports
    assert 6380 in RedisProbe().default_ports
