"""LDAP anonymous rootDSE probe.

Responses are assembled as BER in-process; no server, no socket.
"""
from __future__ import annotations

import pytest

from lodan.probes.ldap import (
    ROOTDSE_ATTRIBUTES,
    build_rootdse_search,
    parse,
)


def _tlv(tag: int, body: bytes) -> bytes:
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    length = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + body


def _attribute(name: str, values: list[str]) -> bytes:
    value_set = _tlv(0x31, b"".join(_tlv(0x04, v.encode()) for v in values))
    return _tlv(0x30, _tlv(0x04, name.encode()) + value_set)


def _search_entry(attributes: dict[str, list[str]], *, message_id: int = 1) -> bytes:
    attrs = _tlv(0x30, b"".join(_attribute(k, v) for k, v in attributes.items()))
    entry = _tlv(0x64, _tlv(0x04, b"") + attrs)
    return _tlv(0x30, _tlv(0x02, bytes([message_id])) + entry)


def _search_done(code: int, *, message_id: int = 1) -> bytes:
    done = _tlv(0x65, _tlv(0x0A, bytes([code])) + _tlv(0x04, b"") + _tlv(0x04, b""))
    return _tlv(0x30, _tlv(0x02, bytes([message_id])) + done)


# --- request -----------------------------------------------------------------

def test_request_sends_no_bind_and_no_credential():
    """The whole point: an unauthenticated search, never a bind."""
    request = build_rootdse_search()
    assert request[0] == 0x30
    # 0x60 is bindRequest — it must not appear anywhere in what we send.
    assert 0x60 not in request
    assert 0x63 in request                       # searchRequest


def test_request_asks_for_the_empty_base_dn():
    request = build_rootdse_search()
    # After the message id, the search request opens with a zero-length octet
    # string: the empty DN that identifies the rootDSE.
    assert b"\x63" in request
    assert b"\x04\x00" in request


def test_request_names_the_rootdse_attributes():
    request = build_rootdse_search()
    for attribute in ROOTDSE_ATTRIBUTES:
        assert attribute.encode() in request


# --- responses ---------------------------------------------------------------

def test_parses_active_directory_rootdse():
    raw = _search_entry({
        "namingContexts": ["DC=corp,DC=example,DC=com"],
        "dnsHostName": ["dc01.corp.example.com"],
        "supportedLDAPVersion": ["3", "2"],
    }) + _search_done(0)
    result = parse(raw)
    assert result.service == "ldap"
    assert result.raw["dns_host_name"] == "dc01.corp.example.com"
    assert result.raw["naming_contexts"] == ["DC=corp,DC=example,DC=com"]
    assert "dc01.corp.example.com" in result.banner


def test_parses_openldap_vendor_fields():
    raw = _search_entry({
        "vendorName": ["OpenLDAP Foundation"],
        "vendorVersion": ["OpenLDAP 2.5.13"],
        "namingContexts": ["dc=example,dc=com"],
    }) + _search_done(0)
    result = parse(raw)
    assert result.raw["vendor"] == "OpenLDAP Foundation"
    assert result.raw["vendor_version"] == "OpenLDAP 2.5.13"
    assert "OpenLDAP" in result.banner


def test_refused_anonymous_read_is_a_useful_result():
    """A directory that says no is a good outcome, and worth recording."""
    result = parse(_search_done(50))             # insufficientAccessRights
    assert "refused" in result.banner
    assert result.raw["result_code"] == 50


def test_success_with_no_attributes():
    result = parse(_search_done(0))
    assert "no rootDSE attributes" in result.banner


def test_multivalued_attributes_are_kept():
    raw = _search_entry({
        "namingContexts": ["dc=a,dc=com", "dc=b,dc=com"],
    }) + _search_done(0)
    assert parse(raw).raw["rootdse"]["namingContexts"] == ["dc=a,dc=com", "dc=b,dc=com"]


def test_no_response():
    assert "no response" in parse(None).banner
    assert "no response" in parse(b"").banner


@pytest.mark.parametrize(
    "bad",
    [b"\x30", b"\x30\x82", b"\xff" * 32, b"\x30\x05\x02\x01\x01\x63", b"\x00" * 40],
)
def test_malformed_does_not_raise(bad: bytes):
    assert parse(bad).service == "ldap"


def test_long_form_lengths_are_handled():
    """A real AD rootDSE runs well past 127 bytes."""
    raw = _search_entry({
        "supportedControl": [f"1.2.840.113556.1.4.{n}" for n in range(30)],
    }) + _search_done(0)
    result = parse(raw)
    assert len(result.raw["rootdse"]["supportedControl"]) == 30
