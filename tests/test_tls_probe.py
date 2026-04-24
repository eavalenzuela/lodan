from __future__ import annotations

from pathlib import Path

import pytest

from lodan.probes.tls import TLSProbe, parse_chain

FIXTURES = Path(__file__).parent / "fixtures" / "tls"


@pytest.fixture
def example_der() -> bytes:
    return (FIXTURES / "example_corp.der").read_bytes()


def test_parse_chain_extracts_fingerprint_and_sans(example_der: bytes) -> None:
    result = parse_chain([example_der])
    assert result.service == "tls"
    assert result.cert_fingerprint is not None
    assert len(result.cert_fingerprint) == 64  # sha256 hex
    assert "example.corp" in (result.cert_sans or [])
    assert "*.corp.example.com" in (result.cert_sans or [])
    assert "10.0.0.5" in (result.cert_sans or [])
    assert "example.corp" in (result.banner or "")


def test_parse_chain_empty_is_noop() -> None:
    result = parse_chain([])
    assert result.service == "tls"
    assert result.cert_fingerprint is None
    assert result.cert_sans is None


def test_raw_includes_validity_and_sha1(example_der: bytes) -> None:
    result = parse_chain([example_der])
    assert "not_valid_before" in result.raw
    assert "not_valid_after" in result.raw
    assert "fingerprint_sha1" in result.raw


def test_default_ports_cover_common_tls() -> None:
    probe = TLSProbe()
    for p in (443, 8443, 993, 995, 465):
        assert p in probe.default_ports
