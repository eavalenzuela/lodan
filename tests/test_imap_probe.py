from __future__ import annotations

from lodan.probes.imap import IMAPProbe, parse_imap


def test_parse_capabilities_from_greeting_and_untagged() -> None:
    raw = (
        b"* OK [CAPABILITY IMAP4rev1 STARTTLS] Dovecot ready\r\n"
        b"* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED\r\n"
        b"a1 OK Capability completed\r\n"
    )
    r = parse_imap(raw)
    assert r.service == "imap"
    # Bracket in the greeting must not leak "Dovecot"/"ready" into the caps.
    assert r.raw["capabilities"] == ["IMAP4REV1", "LOGINDISABLED", "STARTTLS"]
    assert r.raw["starttls"] is True
    assert r.raw["login_disabled"] is True


def test_no_greeting() -> None:
    assert "no greeting" in (parse_imap(b"garbage\r\n").banner or "")


def test_default_ports() -> None:
    ports = IMAPProbe().default_ports
    assert 143 in ports and 993 not in ports  # 993 is TLS
