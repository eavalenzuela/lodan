from __future__ import annotations

from lodan.probes.vnc import VNCProbe, parse_vnc


def test_rfb38_none_auth_offered_is_exposure() -> None:
    r = parse_vnc(b"RFB 003.008\n" + bytes([2, 1, 2]))  # count=2, types None + VNC-Auth
    assert r.service == "vnc"
    assert r.raw["no_auth"] is True
    assert "None" in r.raw["security_types"]
    assert "NO AUTH" in (r.banner or "")


def test_rfb38_vnc_auth_only() -> None:
    r = parse_vnc(b"RFB 003.008\n" + bytes([1, 2]))
    assert r.raw["no_auth"] is False
    assert r.raw["security_types"] == ["VNC-Auth"]


def test_rfb33_single_security_type() -> None:
    r = parse_vnc(b"RFB 003.003\n" + (1).to_bytes(4, "big"))
    assert r.raw["no_auth"] is True


def test_version_only() -> None:
    r = parse_vnc(b"RFB 003.008\n")
    assert "003.008" in (r.banner or "")
    assert r.raw["security_types"] == []


def test_not_vnc() -> None:
    assert "no RFB" in (parse_vnc(b"HTTP/1.1 200").banner or "")


def test_default_ports() -> None:
    assert 5900 in VNCProbe().default_ports
