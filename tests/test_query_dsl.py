from __future__ import annotations

from pathlib import Path

import pytest

from lodan.store import writer
from lodan.store.db import bootstrap, connect
from lodan.store.query import QueryError, compile, parse, run_query


@pytest.fixture
def db(tmp_path: Path):
    dbp = tmp_path / "l.db"
    bootstrap(dbp)
    conn = connect(dbp)
    yield conn
    conn.close()


def _seed_services(db) -> int:
    handle = writer.open_scan(db, "w", ["10.0.0.0/24"])
    scan_id = handle.scan_id
    writer.upsert_discovered_service(db, handle, "10.0.0.5", 22, "tcp")
    writer.upsert_discovered_service(db, handle, "10.0.0.5", 443, "tcp")
    writer.upsert_discovered_service(db, handle, "10.0.0.9", 80, "tcp")

    db.execute(
        "UPDATE services SET banner=?, tech=?, cert_sans=?, service='tls' "
        "WHERE ip=? AND port=?",
        ("nginx/1.25.3", '["nginx"]', '["*.corp.example.com","example.corp"]',
         "10.0.0.5", 443),
    )
    db.execute(
        "UPDATE services SET banner=?, service='ssh' WHERE ip=? AND port=?",
        ("SSH-2.0-OpenSSH_9.3p1", "10.0.0.5", 22),
    )
    db.execute(
        "UPDATE services SET banner=?, tech=?, service='http' WHERE ip=? AND port=?",
        ("Apache/2.4.54 (Ubuntu)", '["apache"]', "10.0.0.9", 80),
    )
    writer.finish_scan(db, handle)
    return scan_id


# ---- parser ----

def test_parse_simple_term() -> None:
    q = parse("port:22")
    assert len(q.groups) == 1
    assert len(q.groups[0].terms) == 1
    t = q.groups[0].terms[0]
    assert (t.key, t.value, t.negated) == ("port", "22", False)


def test_parse_implicit_and() -> None:
    q = parse("port:22 banner:OpenSSH*")
    assert len(q.groups) == 1
    assert len(q.groups[0].terms) == 2


def test_parse_or_groups() -> None:
    q = parse("port:22 OR port:80 AND tech:nginx")
    assert len(q.groups) == 2
    assert len(q.groups[0].terms) == 1
    assert len(q.groups[1].terms) == 2


def test_parse_not() -> None:
    q = parse("NOT service:http AND port:443")
    assert q.groups[0].terms[0].negated is True
    assert q.groups[0].terms[1].negated is False


def test_parse_quoted_value() -> None:
    q = parse('banner:"hello world"')
    assert q.groups[0].terms[0].value == "hello world"


@pytest.mark.parametrize("bad", [
    "",
    "port:",
    ":22",
    "xyz:42",       # unknown key
    "port:22 OR",   # dangling op
    "NOT",          # NOT with no term
])
def test_parser_rejects_invalid(bad: str) -> None:
    with pytest.raises(QueryError):
        parse(bad)


def test_port_rejects_non_int() -> None:
    with pytest.raises(QueryError):
        compile("port:abc")


def test_port_rejects_wildcard() -> None:
    with pytest.raises(QueryError):
        compile("port:22*")


# ---- compilation + execution ----

def test_exact_port(db) -> None:
    _seed_services(db)
    rows = run_query(db, "port:443")
    assert len(rows) == 1
    assert rows[0]["ip"] == "10.0.0.5"


def test_and_two_terms(db) -> None:
    _seed_services(db)
    rows = run_query(db, "port:443 AND tech:nginx")
    assert len(rows) == 1
    assert rows[0]["port"] == 443


def test_or(db) -> None:
    _seed_services(db)
    rows = run_query(db, "tech:nginx OR tech:apache")
    ports = {r["port"] for r in rows}
    assert ports == {443, 80}


def test_banner_fts_prefix(db) -> None:
    _seed_services(db)
    rows = run_query(db, "banner:OpenSSH*")
    assert len(rows) == 1
    assert rows[0]["ip"] == "10.0.0.5" and rows[0]["port"] == 22


def test_sans_leading_wildcard_falls_back_to_like(db) -> None:
    _seed_services(db)
    rows = run_query(db, "sans:*.corp.example.com")
    assert len(rows) == 1
    assert rows[0]["port"] == 443


def test_ip_wildcard(db) -> None:
    _seed_services(db)
    rows = run_query(db, "ip:10.0.0.*")
    assert {r["ip"] for r in rows} == {"10.0.0.5", "10.0.0.9"}


def test_not(db) -> None:
    _seed_services(db)
    rows = run_query(db, "NOT service:ssh AND ip:10.0.0.5")
    assert len(rows) == 1
    assert rows[0]["port"] == 443


def test_scoped_to_scan(db) -> None:
    scan_id = _seed_services(db)
    # Seed a second scan with no matches for port 443
    h2 = writer.open_scan(db, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(db, h2, "10.0.0.5", 22, "tcp")
    writer.finish_scan(db, h2)

    rows = run_query(db, "port:443", scan_id=scan_id)
    assert len(rows) == 1
    rows = run_query(db, "port:443", scan_id=h2.scan_id)
    assert rows == []


def test_cve_join(db) -> None:
    scan_id = _seed_services(db)
    db.execute(
        "INSERT INTO vulns (scan_id, ip, port, cve, cpe, confidence, source) "
        "VALUES (?, ?, ?, ?, 'cpe:x', 0.7, 'test')",
        (scan_id, "10.0.0.9", 80, "CVE-2023-0001"),
    )
    rows = run_query(db, "cve:CVE-2023-0001")
    assert len(rows) == 1
    assert rows[0]["port"] == 80


def test_fts_triggers_track_updates(db) -> None:
    handle = writer.open_scan(db, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(db, handle, "10.0.0.5", 443, "tcp")
    db.execute("UPDATE services SET banner=? WHERE ip=? AND port=?",
               ("Caddy v2.7.6", "10.0.0.5", 443))
    rows = run_query(db, "banner:Caddy*")
    assert len(rows) == 1
    # Now update the banner again; the old banner should no longer match.
    db.execute("UPDATE services SET banner=? WHERE ip=? AND port=?",
               ("nginx/1.25.3", "10.0.0.5", 443))
    assert run_query(db, "banner:Caddy*") == []
    assert len(run_query(db, "banner:nginx*")) == 1
