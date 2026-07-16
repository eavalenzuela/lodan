from __future__ import annotations

from lodan.probes.postgres import PostgresProbe, parse_postgres


def test_ssl_offered() -> None:
    r = parse_postgres(b"S")
    assert r.service == "postgresql"
    assert r.raw["ssl"] is True
    assert "SSL offered" in (r.banner or "")


def test_ssl_not_offered() -> None:
    r = parse_postgres(b"N")
    assert r.raw["ssl"] is False
    assert "no SSL" in (r.banner or "")


def test_error_response_still_postgres() -> None:
    assert "rejected" in (parse_postgres(b"E").banner or "")


def test_unexpected_and_empty() -> None:
    assert "unexpected" in (parse_postgres(b"Z").banner or "")
    assert "unexpected" in (parse_postgres(b"").banner or "")


def test_default_ports() -> None:
    assert 5432 in PostgresProbe().default_ports
