"""scapy backend tests.

The real .run() path needs CAP_NET_RAW, so integration-style tests skip
without it. We still cover: availability detection, UDP payload selection,
and the classifier.
"""
from __future__ import annotations

import os
import platform

import pytest

scapy = pytest.importorskip("scapy.all", reason="scapy not installed")

from lodan.discovery.base import DiscoveryResult  # noqa: E402
from lodan.discovery.scapy_backend import ScapyBackend, _classify, _udp_payload  # noqa: E402


def test_udp_payload_dns_is_bind_version_query() -> None:
    payload = _udp_payload(53)
    assert b"version" in payload
    assert b"bind" in payload


def test_udp_payload_ntp_mode_byte() -> None:
    payload = _udp_payload(123)
    assert payload[0] == 0x23  # LI=0 VN=4 Mode=3 (client)
    assert len(payload) == 48


def test_udp_payload_generic_for_other_ports() -> None:
    assert _udp_payload(9999) == b"\x00" * 8


def test_available_is_false_when_not_root() -> None:
    if platform.system() != "Linux":
        pytest.skip("scapy backend is Linux-only for v1")
    got = ScapyBackend().available()
    expected = os.geteuid() == 0
    assert got == expected


def test_classify_syn_ack_is_tcp_open() -> None:
    from scapy.all import IP, TCP

    snd = IP(dst="10.0.0.5") / TCP(dport=22, flags="S")
    rcv = IP(src="10.0.0.5", dst="1.1.1.1") / TCP(sport=22, dport=40000, flags="SA")
    got = _classify(snd, rcv)
    assert got is not None
    assert (got.ip, got.port, got.proto) == ("10.0.0.5", 22, "tcp")


def test_classify_syn_ack_captures_stack_observation() -> None:
    """The SYN-ACK's L3/L4 fields ride along on the discovery result."""
    from scapy.all import IP, TCP

    snd = IP(dst="10.0.0.5") / TCP(dport=443, flags="S")
    rcv = IP(src="10.0.0.5", ttl=62, flags="DF", id=0) / TCP(
        sport=443, dport=40000, flags="SA", window=64240,
        options=[("MSS", 1460), ("SAckOK", b""), ("Timestamp", (123456, 0)),
                 ("NOP", None), ("WScale", 7)],
    )
    got = _classify(snd, rcv)
    assert got is not None and got.stack is not None
    obs = got.stack
    assert obs.ttl == 62
    assert obs.window == 64240
    assert obs.df is True
    assert obs.ip_id == 0
    assert obs.mss == 1460
    assert obs.window_scale == 7
    assert obs.sack_ok is True
    assert obs.timestamps is True
    assert obs.ts_val == 123456
    assert obs.options == ("MSS", "SAckOK", "Timestamp", "NOP", "WScale")


def test_classify_ipv6_syn_ack_uses_hop_limit() -> None:
    """IPv6 has no TTL/ID field — hlim stands in and DF is implicit."""
    from scapy.all import TCP, IPv6

    snd = IPv6(dst="2001:db8::5") / TCP(dport=22, flags="S")
    rcv = IPv6(src="2001:db8::5", hlim=63) / TCP(
        sport=22, dport=40000, flags="SA", window=65160,
        options=[("MSS", 1440)],
    )
    got = _classify(snd, rcv)
    assert got is not None and got.stack is not None
    assert got.ip == "2001:db8::5"
    assert got.stack.ttl == 63
    assert got.stack.df is True
    assert got.stack.ip_id is None


def test_classify_udp_result_has_no_stack() -> None:
    """Only the TCP SYN-ACK path carries a passive fingerprint."""
    from scapy.all import IP, UDP, Raw

    snd = IP(dst="10.0.0.5") / UDP(dport=53)
    rcv = IP(src="10.0.0.5") / UDP(sport=53, dport=40000) / Raw(load=b"\x00")
    got = _classify(snd, rcv)
    assert got is not None and got.stack is None


def test_classify_rst_is_not_open() -> None:
    from scapy.all import IP, TCP

    snd = IP(dst="10.0.0.5") / TCP(dport=22, flags="S")
    rcv = IP(src="10.0.0.5") / TCP(sport=22, flags="RA")
    assert _classify(snd, rcv) is None


def test_classify_udp_response_is_open() -> None:
    from scapy.all import IP, UDP, Raw

    snd = IP(dst="10.0.0.5") / UDP(dport=53)
    rcv = IP(src="10.0.0.5") / UDP(sport=53, dport=40000) / Raw(load=b"\x00" * 4)
    got = _classify(snd, rcv)
    assert got == DiscoveryResult("10.0.0.5", 53, "udp")


def test_classify_icmp_unreachable_is_not_open() -> None:
    from scapy.all import ICMP, IP

    snd = IP(dst="10.0.0.5")
    rcv = IP(src="10.0.0.5") / ICMP(type=3, code=3)
    assert _classify(snd, rcv) is None
