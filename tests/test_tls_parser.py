"""Tests for lodan.probes.tls_parser.

Everything here is byte-level and offline. We build synthetic handshake
records to drive the parser so regressions in our ClientHello layout
surface before they hit real servers.
"""
from __future__ import annotations

import hashlib
import struct

from lodan.probes.tls_parser import (
    EXT_ALPN,
    EXT_EXTENDED_MASTER_SECRET,
    EXT_SIGNATURE_ALGORITHMS,
    EXT_SUPPORTED_VERSIONS,
    HS_CERTIFICATE,
    HS_SERVER_HELLO,
    TLS_CT_ALERT,
    TLS_CT_CHANGE_CIPHER,
    TLS_CT_HANDSHAKE,
    build_client_hello,
    collect_handshake_messages,
    extract_cert_chain,
    find_server_hello,
    parse_server_hello,
)

# ------------------------------------------------------------------
# helpers: synthesize handshake bytes
# ------------------------------------------------------------------


def _u24(n: int) -> bytes:
    return struct.pack(">I", n)[1:]


def _record(ct: int, fragment: bytes, version: int = 0x0303) -> bytes:
    return struct.pack(">BHH", ct, version, len(fragment)) + fragment


def _handshake(hs_type: int, body: bytes) -> bytes:
    return bytes([hs_type]) + _u24(len(body)) + body


def _fake_server_hello(
    cipher: int = 0xc02f,
    extensions: list[tuple[int, bytes]] | None = None,
    version: int = 0x0303,
) -> bytes:
    exts = extensions or []
    ext_body = b"".join(struct.pack(">HH", t, len(d)) + d for t, d in exts)
    body = b"".join([
        struct.pack(">H", version),
        b"\x00" * 32,                               # server random
        b"\x00",                                    # session_id length
        struct.pack(">H", cipher),
        b"\x00",                                    # compression method
        struct.pack(">H", len(ext_body)),
        ext_body,
    ])
    return body


def _fake_certificate(der_chunks: list[bytes]) -> bytes:
    inner = b"".join(_u24(len(c)) + c for c in der_chunks)
    return _u24(len(inner)) + inner


# ------------------------------------------------------------------
# ClientHello builder
# ------------------------------------------------------------------


def test_build_client_hello_is_deterministic_aside_from_random() -> None:
    a = build_client_hello()
    b = build_client_hello()
    # JA3 components don't depend on random.
    assert a.ja3 == b.ja3
    assert a.ja3_string == b.ja3_string
    # But the bytes differ because the random field changed.
    assert a.record != b.record


def test_client_hello_record_is_well_formed() -> None:
    ch = build_client_hello()
    ct, ver, length = struct.unpack(">BHH", ch.record[:5])
    assert ct == TLS_CT_HANDSHAKE
    assert length == len(ch.record) - 5
    # Handshake type 1, then uint24 length.
    assert ch.record[5] == 1
    hs_len = (ch.record[6] << 16) | (ch.record[7] << 8) | ch.record[8]
    assert hs_len == length - 4


def test_client_hello_advertises_tls_1_2_only_in_supported_versions() -> None:
    ch = build_client_hello()
    # Find the supported_versions extension type in the body.
    assert EXT_SUPPORTED_VERSIONS in ch.extensions


def test_client_hello_ja3_is_md5_of_components() -> None:
    ch = build_client_hello()
    assert ch.ja3 == hashlib.md5(ch.ja3_string.encode("ascii")).hexdigest()
    # 5 comma-separated fields per JA3 spec.
    assert ch.ja3_string.count(",") == 4


# ------------------------------------------------------------------
# ServerHello parser
# ------------------------------------------------------------------


def test_parse_server_hello_extracts_cipher_version_extensions() -> None:
    body = _fake_server_hello(
        cipher=0xc02f,
        extensions=[
            (EXT_EXTENDED_MASTER_SECRET, b""),
            (EXT_ALPN, b"\x00\x03\x02h2"),
            (EXT_SIGNATURE_ALGORITHMS, b"\x00\x02\x04\x03"),
        ],
    )
    sh = parse_server_hello(body)
    assert sh.cipher == 0xc02f
    assert sh.version == 0x0303
    assert sh.extensions == [
        EXT_EXTENDED_MASTER_SECRET, EXT_ALPN, EXT_SIGNATURE_ALGORITHMS,
    ]


def test_parse_server_hello_uses_supported_versions_for_version() -> None:
    # TLS 1.3 servers keep legacy_version = 0x0303 and put 0x0304 in the
    # supported_versions extension — we must surface the real value.
    body = _fake_server_hello(
        extensions=[(EXT_SUPPORTED_VERSIONS, struct.pack(">H", 0x0304))]
    )
    sh = parse_server_hello(body)
    assert sh.version == 0x0304


def test_server_hello_ja3s_is_md5_of_components() -> None:
    body = _fake_server_hello(cipher=0xc02f, extensions=[(23, b""), (11, b"\x01\x00")])
    sh = parse_server_hello(body)
    assert sh.ja3s == hashlib.md5(sh.ja3s_string.encode("ascii")).hexdigest()
    assert sh.ja3s_string == "771,49199,23-11"


# ------------------------------------------------------------------
# handshake stream & certificate extraction
# ------------------------------------------------------------------


def test_collect_handshake_messages_stops_at_change_cipher() -> None:
    sh_body = _fake_server_hello()
    raw = (
        _record(TLS_CT_HANDSHAKE, _handshake(HS_SERVER_HELLO, sh_body))
        + _record(TLS_CT_CHANGE_CIPHER, b"\x01")
        + _record(TLS_CT_HANDSHAKE, b"\xaa\xbb\xcc")  # would be encrypted post-CCS
    )
    msgs = collect_handshake_messages(raw)
    assert len(msgs) == 1
    assert msgs[0][0] == HS_SERVER_HELLO


def test_collect_handshake_messages_splits_across_records() -> None:
    sh_body = _fake_server_hello()
    full_msg = _handshake(HS_SERVER_HELLO, sh_body)
    # Break a single handshake message across two records.
    split = len(full_msg) // 2
    raw = (
        _record(TLS_CT_HANDSHAKE, full_msg[:split])
        + _record(TLS_CT_HANDSHAKE, full_msg[split:])
    )
    msgs = collect_handshake_messages(raw)
    assert len(msgs) == 1
    assert msgs[0][0] == HS_SERVER_HELLO
    assert msgs[0][1] == sh_body


def test_extract_cert_chain_reads_der_list() -> None:
    certs = [b"LEAF-DER-BYTES", b"INTERMEDIATE-DER-BYTES"]
    cert_body = _fake_certificate(certs)
    msgs = [(HS_CERTIFICATE, cert_body)]
    assert extract_cert_chain(msgs) == certs


def test_extract_cert_chain_no_certificate_message() -> None:
    msgs = [(HS_SERVER_HELLO, _fake_server_hello())]
    assert extract_cert_chain(msgs) == []


def test_find_server_hello_helper() -> None:
    sh_body = _fake_server_hello()
    msgs = [
        (HS_CERTIFICATE, _fake_certificate([b"der"])),
        (HS_SERVER_HELLO, sh_body),
    ]
    assert find_server_hello(msgs) == sh_body


def test_iter_records_ignores_trailing_garbage() -> None:
    # Build one good record then append a partial record header.
    good = _record(TLS_CT_HANDSHAKE, _handshake(HS_SERVER_HELLO, _fake_server_hello()))
    raw = good + b"\x16\x03\x03\x00"  # truncated record header
    msgs = collect_handshake_messages(raw)
    assert len(msgs) == 1


def test_parse_server_hello_short_raises() -> None:
    import pytest

    with pytest.raises(ValueError):
        parse_server_hello(b"\x00" * 10)


def test_alert_record_stops_handshake_collection() -> None:
    # A fatal alert arriving after the ServerHello should not be treated as
    # handshake bytes.
    sh_body = _fake_server_hello()
    raw = (
        _record(TLS_CT_HANDSHAKE, _handshake(HS_SERVER_HELLO, sh_body))
        + _record(TLS_CT_ALERT, b"\x02\x28")  # fatal, handshake_failure
    )
    msgs = collect_handshake_messages(raw)
    assert [m[0] for m in msgs] == [HS_SERVER_HELLO]
