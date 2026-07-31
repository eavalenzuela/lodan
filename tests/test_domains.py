"""Authorized-domain scope: DNS parsing, CNAME containment, subdomain listing.

The containment rules are the security-relevant part of this feature, so they
are tested as pure functions with no resolver in the loop.
"""
from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from lodan import dnsq, domains
from lodan.store import writer
from lodan.store.db import bootstrap, connect

_AUTHORIZED = ["corp.example.com", "example.net"]


@pytest.fixture
def db(tmp_path: Path):
    dbp = tmp_path / "l.db"
    bootstrap(dbp)
    conn = connect(dbp)
    yield conn
    conn.close()


# --- normalization -----------------------------------------------------------

@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("corp.example.com", "corp.example.com"),
        ("CORP.Example.COM", "corp.example.com"),
        ("corp.example.com.", "corp.example.com"),
        ("  corp.example.com  ", "corp.example.com"),
    ],
)
def test_normalize_domain(raw: str, expected: str) -> None:
    assert domains.normalize_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    ["", "   ", "https://example.com", "example.com/path", "not a domain",
     "no-tld", "-bad.example.com"],
)
def test_normalize_domain_rejects_junk(raw: str) -> None:
    with pytest.raises(domains.DomainError):
        domains.normalize_domain(raw)


def test_wildcard_domains_cannot_be_authorized() -> None:
    """A wildcard would authorize names the operator never enumerated."""
    with pytest.raises(domains.DomainError, match="wildcard"):
        domains.normalize_domain("*.example.com")


# --- containment -------------------------------------------------------------

@pytest.mark.parametrize(
    "candidate",
    ["corp.example.com", "git.corp.example.com", "a.b.corp.example.com", "example.net"],
)
def test_is_within_accepts_the_domain_and_its_subdomains(candidate: str) -> None:
    assert domains.is_within(candidate, _AUTHORIZED) is True


@pytest.mark.parametrize(
    "candidate",
    [
        "example.com",                      # parent, not authorized
        "notcorp.example.com",              # suffix-adjacent, not a subdomain
        "corp.example.com.evil.test",       # authorized name as a prefix
        "evil.test",
        "",
    ],
)
def test_is_within_rejects_everything_else(candidate: str) -> None:
    assert domains.is_within(candidate, _AUTHORIZED) is False


def test_is_within_is_case_insensitive() -> None:
    assert domains.is_within("GIT.Corp.Example.COM", _AUTHORIZED) is True


# --- evaluate: the CNAME rule ------------------------------------------------

def test_direct_a_records_are_authorized() -> None:
    resolution = dnsq.Resolution(domain="corp.example.com", a=["10.0.0.5"])
    scope = domains.evaluate(resolution, _AUTHORIZED)
    assert scope.addresses == ["10.0.0.5"]
    assert scope.refused == []
    assert scope.authorized is True


def test_aaaa_records_are_authorized_too() -> None:
    resolution = dnsq.Resolution(domain="corp.example.com", aaaa=["2001:db8::5"])
    assert domains.evaluate(resolution, _AUTHORIZED).addresses == ["2001:db8::5"]


def test_cname_to_a_third_party_is_refused() -> None:
    """The whole point: those addresses belong to someone else."""
    resolution = dnsq.Resolution(
        domain="www.corp.example.com",
        a=["203.0.113.9"],
        cnames=[("www.corp.example.com", "d111.cloudfront.net")],
    )
    scope = domains.evaluate(resolution, _AUTHORIZED)
    assert scope.addresses == []
    assert scope.authorized is False
    assert scope.refused[0][0] == "d111.cloudfront.net"
    assert "CNAME" in scope.refused[0][1]


def test_cname_within_the_authorized_domains_is_allowed() -> None:
    """You asserted ownership of both ends."""
    resolution = dnsq.Resolution(
        domain="www.corp.example.com",
        a=["10.0.0.5"],
        cnames=[("www.corp.example.com", "web01.corp.example.com")],
    )
    scope = domains.evaluate(resolution, _AUTHORIZED)
    assert scope.addresses == ["10.0.0.5"]
    assert scope.refused == []


def test_cname_across_two_authorized_domains_is_allowed() -> None:
    resolution = dnsq.Resolution(
        domain="corp.example.com",
        a=["10.0.0.5"],
        cnames=[("corp.example.com", "host.example.net")],
    )
    assert domains.evaluate(resolution, _AUTHORIZED).addresses == ["10.0.0.5"]


def test_one_bad_link_in_a_chain_refuses_the_whole_answer() -> None:
    resolution = dnsq.Resolution(
        domain="www.corp.example.com",
        a=["203.0.113.9"],
        cnames=[
            ("www.corp.example.com", "edge.corp.example.com"),
            ("edge.corp.example.com", "anycast.cdn.test"),
        ],
    )
    scope = domains.evaluate(resolution, _AUTHORIZED)
    assert scope.addresses == []
    assert [t for t, _ in scope.refused] == ["anycast.cdn.test"]


def test_resolution_error_propagates_and_authorizes_nothing() -> None:
    resolution = dnsq.Resolution(domain="corp.example.com", error="NXDOMAIN")
    scope = domains.evaluate(resolution, _AUTHORIZED)
    assert scope.addresses == []
    assert scope.error == "NXDOMAIN"


# --- scope networks ----------------------------------------------------------

def test_scope_networks_are_single_hosts() -> None:
    scopes = [domains.DomainScope(domain="d", addresses=["10.0.0.5", "2001:db8::5"])]
    nets = domains.scope_networks(scopes)
    assert [str(n) for n in nets] == ["10.0.0.5/32", "2001:db8::5/128"]


def test_scope_networks_skips_garbage() -> None:
    scopes = [domains.DomainScope(domain="d", addresses=["not-an-ip"])]
    assert domains.scope_networks(scopes) == []


# --- resolve_scope -----------------------------------------------------------

async def _fake_resolver(domain: str, *, timeout: float = 3.0):
    table = {
        "corp.example.com": dnsq.Resolution(domain=domain, a=["10.0.0.5"]),
        "cdn.example.net": dnsq.Resolution(
            domain=domain, a=["203.0.113.1"],
            cnames=[("cdn.example.net", "x.cloudfront.net")],
        ),
    }
    return table.get(domain, dnsq.Resolution(domain=domain, error="NXDOMAIN"))


@pytest.mark.asyncio
async def test_resolve_scope_applies_the_rules_per_domain() -> None:
    scopes = await domains.resolve_scope(
        ["corp.example.com", "cdn.example.net", "missing.example.net"],
        resolver=_fake_resolver,
    )
    by_domain = {s.domain: s for s in scopes}
    assert by_domain["corp.example.com"].addresses == ["10.0.0.5"]
    assert by_domain["cdn.example.net"].addresses == []       # refused CNAME
    assert by_domain["missing.example.net"].error == "NXDOMAIN"


@pytest.mark.asyncio
async def test_resolve_scope_reports_an_invalid_domain_without_resolving() -> None:
    scopes = await domains.resolve_scope(["not a domain"], resolver=_fake_resolver)
    assert scopes[0].addresses == []
    assert "invalid domain" in scopes[0].error


# --- persistence + subdomains ------------------------------------------------

def test_record_resolutions_round_trips(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    scopes = [
        domains.DomainScope(domain="corp.example.com", addresses=["10.0.0.5"]),
        domains.DomainScope(
            domain="cdn.example.net",
            refused=[("x.cloudfront.net", "CNAME points outside the authorized domains")],
        ),
    ]
    assert domains.record_resolutions(db, h.scan_id, scopes) == 2
    rows = dict(
        db.execute(
            "SELECT domain, addresses FROM domain_resolutions WHERE scan_id = ?",
            (h.scan_id,),
        ).fetchall()
    )
    assert json.loads(rows["corp.example.com"]) == ["10.0.0.5"]
    assert json.loads(rows["cdn.example.net"]) == []


def test_record_resolutions_is_idempotent(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    scopes = [domains.DomainScope(domain="corp.example.com", addresses=["10.0.0.5"])]
    domains.record_resolutions(db, h.scan_id, scopes)
    domains.record_resolutions(db, h.scan_id, scopes)
    assert db.execute("SELECT COUNT(*) FROM domain_resolutions").fetchone()[0] == 1


def _service_with_sans(conn, handle, ip, port, sans):
    writer.upsert_discovered_service(conn, handle, ip, port, "tcp")
    conn.execute(
        "UPDATE services SET cert_sans = ? WHERE scan_id = ? AND ip = ? AND port = ?",
        (json.dumps(sans), handle.scan_id, ip, port),
    )


def test_enumerate_subdomains_from_cert_sans(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    _service_with_sans(db, h, "10.0.0.5", 443, [
        "git.corp.example.com", "wiki.corp.example.com", "corp.example.com",
        "unrelated.evil.test",
    ])
    found = domains.enumerate_subdomains(db, _AUTHORIZED)
    names = [entry["subdomain"] for entry in found]
    assert names == ["git.corp.example.com", "wiki.corp.example.com"]
    # The authorized domain itself isn't a subdomain of itself.
    assert "corp.example.com" not in names
    # Out-of-scope names are not listed at all.
    assert "unrelated.evil.test" not in names


def test_enumerate_subdomains_records_where_it_was_seen(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    _service_with_sans(db, h, "10.0.0.5", 443, ["git.corp.example.com"])
    _service_with_sans(db, h, "10.0.0.6", 8443, ["git.corp.example.com"])
    found = domains.enumerate_subdomains(db, _AUTHORIZED)
    assert found[0]["seen_on"] == ["10.0.0.5:443", "10.0.0.6:8443"]


def test_enumerate_subdomains_strips_wildcards_and_flags_them(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    _service_with_sans(db, h, "10.0.0.5", 443, ["*.apps.corp.example.com"])
    found = domains.enumerate_subdomains(db, _AUTHORIZED)
    assert found[0]["subdomain"] == "apps.corp.example.com"
    assert found[0]["wildcard"] is True


def test_enumerate_subdomains_without_authorized_domains(db) -> None:
    assert domains.enumerate_subdomains(db, []) == []


def test_enumerate_subdomains_tolerates_bad_json(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(db, h, "10.0.0.5", 443, "tcp")
    db.execute("UPDATE services SET cert_sans = 'not json' WHERE scan_id = ?", (h.scan_id,))
    assert domains.enumerate_subdomains(db, _AUTHORIZED) == []


# --- DNS wire format ---------------------------------------------------------

def _answer(name: str, rtype: int, rdata: bytes) -> bytes:
    return dnsq.encode_name(name) + struct.pack(">HHIH", rtype, 1, 300, len(rdata)) + rdata


def _response(question: str, answers: bytes, count: int, *, rcode: int = 0) -> bytes:
    header = struct.pack(">HHHHHH", 0x1234, 0x8180 | rcode, 1, count, 0, 0)
    return header + dnsq.encode_name(question) + struct.pack(">HH", 1, 1) + answers


def test_build_query_is_a_recursive_a_lookup() -> None:
    query = dnsq.build_query("corp.example.com", dnsq.TYPE_A, transaction_id=0x1234)
    assert query[:2] == b"\x12\x34"
    assert struct.unpack_from(">H", query, 2)[0] & 0x0100      # RD
    assert b"corp" in query and b"example" in query
    assert query[-4:] == struct.pack(">HH", dnsq.TYPE_A, 1)


def test_parse_a_record() -> None:
    raw = _response("corp.example.com", _answer("corp.example.com", 1, bytes([10, 0, 0, 5])), 1)
    answers = dnsq.parse_response(raw)
    assert [(a.rtype, a.value) for a in answers] == [(1, "10.0.0.5")]


def test_parse_aaaa_record_is_compressed() -> None:
    # 2001:0db8:0000:0000:0000:0000:0000:0005 — eight 16-bit groups.
    rdata = bytes.fromhex("20010db8" + "0" * 20 + "0005")
    assert len(rdata) == 16
    raw = _response("corp.example.com", _answer("corp.example.com", 28, rdata), 1)
    assert dnsq.parse_response(raw)[0].value == "2001:db8::5"


def test_parse_cname_chain() -> None:
    body = _answer("www.corp.example.com", 5, dnsq.encode_name("cdn.example.org"))
    body += _answer("cdn.example.org", 1, bytes([203, 0, 113, 9]))
    answers = dnsq.parse_response(_response("www.corp.example.com", body, 2))
    assert answers[0].rtype == dnsq.TYPE_CNAME
    assert answers[0].value == "cdn.example.org"
    assert answers[1].value == "203.0.113.9"


def test_nxdomain_is_an_empty_answer_not_an_error() -> None:
    assert dnsq.parse_response(_response("nope.example.com", b"", 0, rcode=3)) == []


def test_servfail_raises() -> None:
    with pytest.raises(dnsq.DNSError):
        dnsq.parse_response(_response("x.example.com", b"", 0, rcode=2))


@pytest.mark.parametrize("bad", [b"", b"\x00" * 4, b"\xff" * 30])
def test_parse_response_rejects_malformed(bad: bytes) -> None:
    with pytest.raises(dnsq.DNSError):
        dnsq.parse_response(bad)


def test_parse_response_survives_a_pointer_loop() -> None:
    header = struct.pack(">HHHHHH", 1, 0x8180, 0, 1, 0, 0)
    with pytest.raises(dnsq.DNSError):
        dnsq.parse_response(header + b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 0, 4))


def test_nameservers_parses_resolv_conf(tmp_path: Path) -> None:
    conf = tmp_path / "resolv.conf"
    conf.write_text(
        "# comment\n; other comment\nsearch corp.example.com\n"
        "nameserver 10.0.0.1\nnameserver 2001:db8::1\n"
    )
    assert dnsq.nameservers(conf) == ["10.0.0.1", "2001:db8::1"]


def test_nameservers_on_a_missing_file(tmp_path: Path) -> None:
    assert dnsq.nameservers(tmp_path / "nope") == []


@pytest.mark.asyncio
async def test_resolve_without_a_configured_resolver_fails_honestly() -> None:
    """No silent getaddrinfo fallback: it hides the CNAME chain, and a weak
    check that looks like the strong one is worse than an honest failure."""
    result = await dnsq.resolve("corp.example.com", servers=[])
    assert result.addresses == []
    assert "no resolver configured" in result.error
