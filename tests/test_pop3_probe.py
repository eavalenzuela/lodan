from __future__ import annotations

from lodan.probes.pop3 import POP3Probe, parse_pop3


def test_parse_greeting_and_capa() -> None:
    raw = (
        b"+OK Dovecot ready.\r\n"
        b"+OK\r\nCAPA\r\nTOP\r\nUIDL\r\nSTLS\r\nUSER\r\n.\r\n"
        b"+OK Logging out.\r\n"
    )
    r = parse_pop3(raw)
    assert r.service == "pop3"
    assert "Dovecot" in (r.banner or "")
    assert r.raw["stls"] is True
    assert "STLS" in r.raw["capabilities"]


def test_no_stls_flagged() -> None:
    r = parse_pop3(b"+OK ready\r\n+OK\r\nTOP\r\nUSER\r\n.\r\n")
    assert r.raw["stls"] is False
    assert "no STLS" in (r.banner or "")


def test_no_greeting() -> None:
    assert "no greeting" in (parse_pop3(b"-ERR\r\n").banner or "")


def test_default_ports() -> None:
    ports = POP3Probe().default_ports
    assert 110 in ports and 995 not in ports  # 995 is TLS
