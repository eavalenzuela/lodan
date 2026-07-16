from __future__ import annotations

from lodan.probes.smtp import SMTPProbe, parse_smtp


def test_parse_greeting_and_starttls() -> None:
    raw = (
        b"220 mx.example.com ESMTP Postfix\r\n"
        b"250-mx.example.com\r\n250-PIPELINING\r\n250-STARTTLS\r\n250 SIZE 10240000\r\n"
        b"221 Bye\r\n"
    )
    r = parse_smtp(raw)
    assert r.service == "smtp"
    assert "Postfix" in (r.banner or "")
    assert r.raw["starttls"] is True
    assert "STARTTLS" in r.raw["capabilities"]


def test_no_starttls_is_flagged() -> None:
    r = parse_smtp(b"220 mail ESMTP\r\n250-mail\r\n250 SIZE 100\r\n221 Bye\r\n")
    assert r.raw["starttls"] is False
    assert "no STARTTLS" in (r.banner or "")


def test_empty_response() -> None:
    r = parse_smtp(b"")
    assert "no greeting" in (r.banner or "")


def test_default_ports() -> None:
    ports = SMTPProbe().default_ports
    assert 25 in ports and 587 in ports
    assert 465 not in ports  # implicit TLS -> TLS probe
