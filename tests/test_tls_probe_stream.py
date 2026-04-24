"""parse_stream end-to-end tests.

Synthesize a plausible TLS 1.2 response stream (ServerHello + Certificate +
ServerHelloDone) using the existing DER fixture, feed it to parse_stream,
and check that JA3 + JA3S + cert fields all land on the ProbeResult.
"""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from lodan.probes.tls import parse_stream
from lodan.probes.tls_parser import build_client_hello

FIXTURES = Path(__file__).parent / "fixtures" / "tls"


def _u24(n: int) -> bytes:
    return struct.pack(">I", n)[1:]


def _record(ct: int, fragment: bytes) -> bytes:
    return struct.pack(">BHH", ct, 0x0303, len(fragment)) + fragment


def _handshake(hs_type: int, body: bytes) -> bytes:
    return bytes([hs_type]) + _u24(len(body)) + body


def _server_hello_body(
    cipher: int = 0xc02f,
    extensions: list[tuple[int, bytes]] | None = None,
    version: int = 0x0303,
) -> bytes:
    exts = extensions or []
    ext_body = b"".join(struct.pack(">HH", t, len(d)) + d for t, d in exts)
    return b"".join([
        struct.pack(">H", version),
        b"\x00" * 32,
        b"\x00",
        struct.pack(">H", cipher),
        b"\x00",
        struct.pack(">H", len(ext_body)),
        ext_body,
    ])


def _certificate_body(ders: list[bytes]) -> bytes:
    inner = b"".join(_u24(len(d)) + d for d in ders)
    return _u24(len(inner)) + inner


def _build_response(sh_body: bytes, cert_ders: list[bytes], with_done: bool = True) -> bytes:
    messages = _handshake(2, sh_body) + _handshake(11, _certificate_body(cert_ders))
    if with_done:
        messages += _handshake(14, b"")  # ServerHelloDone
    return _record(22, messages)


def test_parse_stream_populates_ja3_ja3s_and_cert() -> None:
    ch = build_client_hello()
    der = (FIXTURES / "example_corp.der").read_bytes()
    raw = _build_response(
        _server_hello_body(cipher=0xc02f, extensions=[(23, b""), (11, b"\x01\x00")]),
        [der],
    )
    result = parse_stream(ch, raw)
    assert result.service == "tls"
    assert result.ja3 == ch.ja3
    assert result.ja3s is not None
    assert len(result.ja3s) == 32
    assert result.cert_fingerprint is not None
    assert "example.corp" in (result.cert_sans or [])
    assert "TLS 1.2" in (result.banner or "")
    assert result.raw["cipher"] == 0xc02f
    assert result.raw["cert_count"] == 1


def test_parse_stream_without_certificate() -> None:
    ch = build_client_hello()
    raw = _record(22, _handshake(2, _server_hello_body()))
    result = parse_stream(ch, raw)
    assert result.ja3 is not None
    assert result.ja3s is not None
    assert result.cert_fingerprint is None
    assert result.cert_sans is None
    assert result.raw["cert_count"] == 0


def test_parse_stream_no_server_hello() -> None:
    ch = build_client_hello()
    # Server sent a fatal alert without a ServerHello.
    raw = _record(21, b"\x02\x28")
    result = parse_stream(ch, raw)
    assert "no ServerHello" in (result.banner or "")
    # JA3 is still ours to report even when the server refused.
    assert result.ja3 == ch.ja3
    assert result.ja3s is None


def test_parse_stream_surfaces_tls_1_3_via_supported_versions() -> None:
    ch = build_client_hello()
    raw = _record(
        22,
        _handshake(
            2,
            _server_hello_body(extensions=[(43, struct.pack(">H", 0x0304))]),
        ),
    )
    result = parse_stream(ch, raw)
    assert result.raw["tls_version"] == 0x0304
    assert "TLS 1.3" in (result.banner or "")


@pytest.mark.parametrize("cert_count", [1, 2, 3])
def test_parse_stream_counts_chain(cert_count: int) -> None:
    ch = build_client_hello()
    der = (FIXTURES / "example_corp.der").read_bytes()
    raw = _build_response(_server_hello_body(), [der] * cert_count)
    result = parse_stream(ch, raw)
    assert result.raw["cert_count"] == cert_count
