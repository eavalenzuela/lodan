"""UDP probe transport and the datagram fleet.

Every case builds the wire bytes in-process and feeds them to the parser, so
nothing here opens a socket. Requests are verified by parsing them back.
"""
from __future__ import annotations

import struct

import pytest

from lodan.probes import dispatch
from lodan.probes.ike import IKEProbe, build_sa_proposal
from lodan.probes.ike import parse as ike_parse
from lodan.probes.mdns import MDNSProbe, build_service_query, encode_name
from lodan.probes.mdns import parse as mdns_parse
from lodan.probes.memcached import MemcachedProbe, build_stats
from lodan.probes.memcached import parse as memcached_parse
from lodan.probes.netbios import NetBIOSProbe, build_nbstat
from lodan.probes.netbios import parse as netbios_parse
from lodan.probes.ntp import NTPProbe, build_readvar
from lodan.probes.ntp import parse as ntp_parse
from lodan.probes.snmp import (
    OID_SYS_DESCR,
    OID_SYS_OBJECT_ID,
    SNMPProbe,
    build_get,
    decode_oid,
    encode_oid,
)
from lodan.probes.snmp import parse as snmp_parse
from lodan.probes.ssdp import SSDPProbe, build_msearch
from lodan.probes.ssdp import parse as ssdp_parse

# --- dispatch ----------------------------------------------------------------

def test_udp_probes_are_dispatched():
    """pick_probes used to return [] for anything non-TCP."""
    dispatch.register_defaults()
    try:
        assert [p.name for p in dispatch.pick_probes(161, "udp")] == ["snmp"]
        assert [p.name for p in dispatch.pick_probes(123, "udp")] == ["ntp"]
        assert [p.name for p in dispatch.pick_probes(137, "udp")] == ["netbios"]
        assert [p.name for p in dispatch.pick_probes(11211, "udp")] == ["memcached"]
        assert [p.name for p in dispatch.pick_probes(1900, "udp")] == ["ssdp"]
        assert [p.name for p in dispatch.pick_probes(5353, "udp")] == ["mdns"]
        assert [p.name for p in dispatch.pick_probes(500, "udp")] == ["ike"]
    finally:
        dispatch.clear_registry()


def test_udp_probe_does_not_fire_on_the_same_tcp_port():
    """UDP/161 and TCP/161 are different services."""
    dispatch.register_defaults()
    try:
        assert dispatch.pick_probes(161, "tcp") == []
        assert dispatch.pick_probes(123, "tcp") == []
    finally:
        dispatch.clear_registry()


def test_tcp_probes_still_dispatch_unchanged():
    dispatch.register_defaults()
    try:
        assert "ssh" in [p.name for p in dispatch.pick_probes(22, "tcp")]
        assert "ldap" in [p.name for p in dispatch.pick_probes(389, "tcp")]
        assert dispatch.pick_probes(22, "udp") == []
    finally:
        dispatch.clear_registry()


def test_every_udp_probe_declares_its_proto():
    for cls in (SNMPProbe, NTPProbe, NetBIOSProbe, MemcachedProbe,
                SSDPProbe, MDNSProbe, IKEProbe):
        assert cls.proto == "udp"


# --- SNMP --------------------------------------------------------------------

def test_snmp_oid_round_trips():
    for oid in (OID_SYS_DESCR, OID_SYS_OBJECT_ID, (1, 3, 6, 1, 4, 1, 9, 1, 1745)):
        encoded = encode_oid(oid)
        assert decode_oid(encoded[2:]) == oid


def test_snmp_request_carries_only_the_default_community():
    """lodan sends `public`, once, and never a second value."""
    request = build_get([OID_SYS_DESCR])
    assert b"public" in request
    assert request.count(b"public") == 1
    assert request[0] == 0x30


def _snmp_response(descr: bytes, oid: tuple[int, ...] | None = None) -> bytes:
    def tlv(tag, body):
        return bytes([tag, len(body)]) + body

    varbinds = tlv(0x30, encode_oid(OID_SYS_DESCR) + tlv(0x04, descr))
    if oid is not None:
        varbinds += tlv(0x30, encode_oid(OID_SYS_OBJECT_ID) + encode_oid(oid))
    pdu = tlv(
        0xA2,
        tlv(0x02, b"\x01") + tlv(0x02, b"\x00") + tlv(0x02, b"\x00")
        + tlv(0x30, varbinds),
    )
    return tlv(0x30, tlv(0x02, b"\x01") + tlv(0x04, b"public") + pdu)


def test_snmp_parses_sysdescr():
    result = snmp_parse(_snmp_response(b"Linux router 5.15.0 #1 SMP x86_64"))
    assert result.service == "snmp"
    assert "Linux router" in result.banner
    assert result.raw["sys_descr"].startswith("Linux router")
    assert result.raw["community_accepted"] == "public"


def test_snmp_extracts_the_iana_enterprise_number():
    result = snmp_parse(_snmp_response(b"Cisco IOS", (1, 3, 6, 1, 4, 1, 9, 1, 1745)))
    assert result.raw["enterprise"] == 9          # 9 = Cisco
    assert result.raw["sys_object_id"].startswith("1.3.6.1.4.1.9")


def test_snmp_no_response():
    assert "no response" in snmp_parse(None).banner
    assert "no response" in snmp_parse(b"").banner


@pytest.mark.parametrize("bad", [b"\x30", b"\x30\x82", b"\xff" * 20, b"\x30\x05\x02\x01\x01"])
def test_snmp_malformed_does_not_raise(bad: bytes):
    result = snmp_parse(bad)
    assert result.service == "snmp"


# --- NTP ---------------------------------------------------------------------

def test_ntp_readvar_is_mode_6():
    request = build_readvar()
    assert len(request) == 12
    assert request[0] & 0x07 == 6                 # mode 6 (control)
    assert request[1] == 2                        # opcode: read variables


def test_ntp_parses_system_variables():
    payload = b'version="ntpd 4.2.8p15", processor="x86_64", system="Linux/5.15.0"'
    raw = b"\x00" * 12 + payload
    result = ntp_parse(raw, request_bytes=12)
    assert result.raw["variables"]["version"] == "ntpd 4.2.8p15"
    assert result.raw["variables"]["system"] == "Linux/5.15.0"
    assert "ntpd 4.2.8p15" in result.banner


def test_ntp_reports_amplification():
    result = ntp_parse(b"\x00" * 12 + b"x" * 500, request_bytes=12)
    assert result.raw["amplification"] > 5
    assert result.amplification == result.raw["amplification"]
    assert "amplification" in result.banner


def test_ntp_small_reply_is_not_flagged():
    result = ntp_parse(b"\x00" * 12 + b'version="x"', request_bytes=12)
    assert "amplification" not in result.banner


def test_ntp_no_response():
    assert "no response" in ntp_parse(None, request_bytes=12).banner


# --- memcached ---------------------------------------------------------------

def test_memcached_stats_request_has_the_udp_frame_header():
    request = build_stats()
    assert request[:8] == b"\x00\x01\x00\x00\x00\x01\x00\x00"
    assert request.endswith(b"stats\r\n")


def test_memcached_parses_stats():
    body = b"STAT pid 1\r\nSTAT version 1.6.21\r\nSTAT uptime 400\r\nEND\r\n"
    result = memcached_parse(b"\x00" * 8 + body, request_bytes=15)
    assert result.raw["version"] == "1.6.21"
    assert result.raw["stats"]["uptime"] == "400"
    assert "1.6.21" in result.banner


def test_memcached_amplification_is_reported():
    body = b"STAT version 1.6.21\r\n" + b"STAT k v\r\n" * 100 + b"END\r\n"
    result = memcached_parse(b"\x00" * 8 + body, request_bytes=15)
    assert result.amplification > 5
    assert "amplification" in result.banner


def test_memcached_non_memcached_reply():
    result = memcached_parse(b"\x00" * 8 + b"garbage", request_bytes=15)
    assert "unexpected" in result.banner


def test_memcached_no_response():
    assert "no response" in memcached_parse(None, request_bytes=15).banner


# --- NetBIOS -----------------------------------------------------------------

def test_nbstat_request_encodes_the_wildcard_name():
    request = build_nbstat()
    assert request[12] == 32                      # encoded name length
    assert request[13:15] == b"CK"                # '*' -> 0x2A -> 'C','K'
    assert request[-4:] == b"\x00\x21\x00\x01"    # NBSTAT / IN


def _nbstat_response(names: list[tuple[str, int, bool]], mac: bytes) -> bytes:
    header = struct.pack(">HHHHHH", 0x1337, 0x8400, 0, 1, 0, 0)
    # Echoed question name, then the RR header.
    body = bytes([32]) + b"CK" + b"AA" * 15 + b"\x00"
    body += struct.pack(">HH", 0x0021, 0x0001)
    body += struct.pack(">HHIH", 0x0021, 0x0001, 0, 0)
    body += bytes([len(names)])
    for name, suffix, group in names:
        padded = name.ljust(15).encode("ascii")[:15]
        body += padded + bytes([suffix]) + struct.pack(">H", 0x8000 if group else 0x0400)
    body += mac
    return header + body


def test_netbios_parses_names_and_mac():
    raw = _nbstat_response(
        [("FILESRV01", 0x00, False), ("CORP", 0x00, True), ("FILESRV01", 0x20, False)],
        bytes([0x00, 0x50, 0x56, 0xAA, 0xBB, 0xCC]),
    )
    result = netbios_parse(raw)
    assert result.raw["computer_name"] == "FILESRV01"
    assert result.raw["workgroup"] == "CORP"
    assert result.raw["mac"] == "00:50:56:aa:bb:cc"
    assert result.netbios_name == "FILESRV01"
    assert result.mac_oui == "00:50:56"


def test_netbios_no_response():
    assert "no response" in netbios_parse(None).banner
    assert "no response" in netbios_parse(b"short").banner


@pytest.mark.parametrize("bad", [b"\x00" * 12, b"\x00" * 40, b"\xff" * 60])
def test_netbios_malformed_does_not_raise(bad: bytes):
    assert netbios_parse(bad).service == "netbios"


# --- SSDP --------------------------------------------------------------------

def test_msearch_is_unicast_to_the_target():
    """Not the 239.255.255.250 group — lodan asks the host it was allowed to."""
    request = build_msearch("10.0.0.5").decode()
    assert "HOST: 10.0.0.5:1900" in request
    assert "239.255.255.250" not in request
    assert "ST: upnp:rootdevice" in request


def test_msearch_brackets_ipv6():
    assert "HOST: [2001:db8::5]:1900" in build_msearch("2001:db8::5").decode()


def test_ssdp_parses_server_header():
    raw = (
        b"HTTP/1.1 200 OK\r\n"
        b"CACHE-CONTROL: max-age=1800\r\n"
        b"SERVER: Linux/3.14 UPnP/1.0 MiniDLNA/1.2.1\r\n"
        b"LOCATION: http://10.0.0.5:8200/rootDesc.xml\r\n"
        b"ST: upnp:rootdevice\r\n\r\n"
    )
    result = ssdp_parse(raw)
    assert "MiniDLNA/1.2.1" in result.banner
    assert result.raw["location"] == "http://10.0.0.5:8200/rootDesc.xml"


def test_ssdp_no_response():
    assert "no response" in ssdp_parse(None).banner


# --- mDNS --------------------------------------------------------------------

def test_mdns_query_sets_the_unicast_response_bit():
    query = build_service_query()
    qclass = struct.unpack(">H", query[-2:])[0]
    assert qclass & 0x8000                       # QU bit
    assert b"_services" in query


def test_mdns_parses_service_types():
    header = struct.pack(">HHHHHH", 0, 0x8400, 0, 2, 0, 0)
    body = b""
    for target in ("_ssh._tcp.local", "_ipp._tcp.local"):
        body += encode_name("_services._dns-sd._udp.local")
        rdata = encode_name(target)
        body += struct.pack(">HHIH", 12, 1, 120, len(rdata)) + rdata
    result = mdns_parse(header + body)
    assert set(result.raw["service_types"]) == {"_ssh._tcp.local", "_ipp._tcp.local"}


def test_mdns_no_response():
    assert "no response" in mdns_parse(None).banner
    assert "no response" in mdns_parse(b"tiny").banner


def test_mdns_survives_a_pointer_loop():
    """A malicious responder can encode a name pointing at itself."""
    header = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0)
    loop = b"\xc0\x0c"                            # pointer back to offset 12
    result = mdns_parse(header + loop + struct.pack(">HHIH", 12, 1, 0, 2) + loop)
    assert result.service == "mdns"               # must terminate, not hang


# --- IKE ---------------------------------------------------------------------

def test_ike_proposal_is_main_mode_not_aggressive():
    """Aggressive mode is what would elicit a crackable hash; deliberately unused."""
    request = build_sa_proposal()
    assert request[18] == 2                       # exchange type 2 = Main Mode
    assert request[16] == 1                       # first payload = SA
    assert struct.unpack_from(">I", request, 24)[0] == len(request)


def test_ike_parses_vendor_ids():
    header = (
        b"\x11\x22\x33\x44\x55\x66\x77\x88"
        + b"\xaa" * 8
        + bytes([13, 0x10, 2, 0x00])              # next payload = Vendor ID
        + struct.pack(">I", 0)
        + struct.pack(">I", 0)
    )
    vid = bytes.fromhex("afcad71368a1f1c96b8696fc77570100")
    payload = bytes([0, 0]) + struct.pack(">H", len(vid) + 4) + vid
    result = ike_parse(header + payload)
    assert "Dead Peer Detection" in result.raw["vendor_labels"]
    assert result.ike_vendor == "Dead Peer Detection"


def test_ike_no_response():
    assert "no response" in ike_parse(None).banner
    assert "no response" in ike_parse(b"short").banner


@pytest.mark.parametrize("bad", [b"\x00" * 28, b"\xff" * 40])
def test_ike_malformed_does_not_raise(bad: bytes):
    assert ike_parse(bad).service == "ike"
