"""Canonicalization of probe output (lodan.normalize)."""
from __future__ import annotations

import json

from lodan import normalize


def test_banner_collapses_whitespace_and_trims() -> None:
    assert normalize.banner("  Apache/2.4   (Ubuntu)\r\n") == "Apache/2.4 (Ubuntu)"
    assert normalize.banner("nginx\t\t1.25") == "nginx 1.25"


def test_banner_drops_control_bytes_but_keeps_case() -> None:
    assert normalize.banner("OpenSSH_9.6p1\x00\x01 Ubuntu") == "OpenSSH_9.6p1 Ubuntu"
    # Case is meaningful in banners and preserved.
    assert normalize.banner("MyProduct") == "MyProduct"


def test_banner_none_and_empty() -> None:
    assert normalize.banner(None) is None
    assert normalize.banner("   \r\n\t ") is None


def test_ip_canonicalizes_ipv6_and_passes_ipv4() -> None:
    assert normalize.ip("2001:DB8:0:0:0:0:0:1") == "2001:db8::1"
    assert normalize.ip("2001:db8::1") == "2001:db8::1"
    assert normalize.ip("10.0.0.5") == "10.0.0.5"
    assert normalize.ip(None) is None
    # Non-IP text passes through trimmed rather than raising.
    assert normalize.ip("  not-an-ip  ") == "not-an-ip"


def test_host_for_url_brackets_ipv6_only() -> None:
    assert normalize.host_for_url("2001:db8::1") == "[2001:db8::1]"
    assert normalize.host_for_url("10.0.0.5") == "10.0.0.5"
    assert normalize.host_for_url("example.com") == "example.com"


def test_fingerprint_lowercases_and_trims() -> None:
    assert normalize.fingerprint("  AABBCC  ") == "aabbcc"
    assert normalize.fingerprint(None) is None


def test_tech_lowercases_dedupes_sorts() -> None:
    assert normalize.tech(["Nginx", "nginx", "Apache", "NGINX "]) == ["apache", "nginx"]
    assert normalize.tech([]) == []
    assert normalize.tech(None) is None


def test_sans_lowercases_dedupes_sorts() -> None:
    assert normalize.sans(["WWW.Corp.Example.com", "www.corp.example.com", "10.0.0.5"]) == [
        "10.0.0.5",
        "www.corp.example.com",
    ]


def test_json_helpers_match_normalized_lists() -> None:
    assert normalize.tech_json(["B", "a", "a"]) == json.dumps(["a", "b"])
    assert normalize.sans_json(None) is None
    assert normalize.sans_json([]) == json.dumps([])


def test_ordering_variance_produces_identical_json() -> None:
    # The whole point: two detection orders collapse to one stored string, so
    # the exact-match `changed` diff sees no difference.
    assert normalize.tech_json(["apache", "php", "mysql"]) == normalize.tech_json(
        ["mysql", "apache", "php"]
    )
