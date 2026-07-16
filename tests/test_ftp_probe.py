from __future__ import annotations

from lodan.probes.ftp import FTPProbe, parse_ftp


def test_parse_greeting_and_features() -> None:
    raw = (
        b"220 ProFTPD 1.3.7 Server ready\r\n"
        b"211-Features:\r\n AUTH TLS\r\n UTF8\r\n MDTM\r\n211 End\r\n"
        b"221 Goodbye\r\n"
    )
    r = parse_ftp(raw)
    assert r.service == "ftp"
    assert "ProFTPD" in (r.banner or "")
    assert "AUTH" in r.raw["features"]
    assert r.raw["auth_tls"] is True


def test_no_auth_tls_flagged() -> None:
    r = parse_ftp(b"220 vsftpd\r\n211-Features:\r\n UTF8\r\n211 End\r\n")
    assert r.raw["auth_tls"] is False
    assert "no AUTH TLS" in (r.banner or "")


def test_empty() -> None:
    assert "no greeting" in (parse_ftp(b"").banner or "")


def test_default_ports() -> None:
    assert 21 in FTPProbe().default_ports
