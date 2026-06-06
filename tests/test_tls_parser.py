"""Tests for lodan.probes.tls_parser.

Everything here is byte-level and offline. We build synthetic handshake
records to drive the parser so regressions in our ClientHello layout
surface before they hit real servers.
"""
from __future__ import annotations

import hashlib
import re
import struct

from lodan.probes.tls_parser import (
    EXT_ALPN,
    EXT_EXTENDED_MASTER_SECRET,
    EXT_SERVER_NAME,
    EXT_SIGNATURE_ALGORITHMS,
    EXT_SUPPORTED_VERSIONS,
    HS_CERTIFICATE,
    HS_SERVER_HELLO,
    TLS_CT_ALERT,
    TLS_CT_CHANGE_CIPHER,
    TLS_CT_HANDSHAKE,
    ClientHelloBytes,
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


# ------------------------------------------------------------------
# JA4 / JA4S
# ------------------------------------------------------------------


def _sha12(s: str) -> str:
    return hashlib.sha256(s.encode("ascii")).hexdigest()[:12]


def test_ja4_overall_shape() -> None:
    ch = build_client_hello()
    # ja4_a is human-readable; ja4_b / ja4_c are 12-hex truncated sha256.
    assert re.fullmatch(r"t\d{2}[di]\d{2}\d{2}.._[0-9a-f]{12}_[0-9a-f]{12}", ch.ja4)


def test_ja4_a_encodes_counts_version_sni_alpn() -> None:
    ch = build_client_hello()
    ja4_a = ch.ja4.split("_")[0]
    # TLS over TCP, TLS 1.2 advertised, no SNI -> "i".
    assert ja4_a.startswith("t12i")
    # cipher count then extension count, both zero-padded to 2 digits.
    assert ja4_a[4:6] == f"{len(ch.ciphers):02d}"
    assert ja4_a[6:8] == f"{len(ch.extensions):02d}"
    # first ALPN is b"h2" -> first+last char.
    assert ja4_a[8:10] == "h2"


def test_ja4_b_is_sorted_cipher_hash() -> None:
    ch = build_client_hello()
    ja4_b = ch.ja4.split("_")[1]
    expected = _sha12(",".join(f"{c:04x}" for c in sorted(ch.ciphers)))
    assert ja4_b == expected


def test_ja4_c_excludes_sni_alpn_sorts_exts_and_appends_sigalgs() -> None:
    ch = build_client_hello()
    ja4_c = ch.ja4.split("_")[2]
    hash_exts = sorted(e for e in ch.extensions if e not in (EXT_SERVER_NAME, EXT_ALPN))
    ext_str = ",".join(f"{e:04x}" for e in hash_exts)
    ext_str += "_" + ",".join(f"{a:04x}" for a in ch.sig_algs)  # sig algs NOT sorted
    assert ja4_c == _sha12(ext_str)


def test_ja4_filters_grease() -> None:
    # GREASE values (e.g. 0x0a0a) must be dropped from counts and hashes.
    ch = ClientHelloBytes(
        record=b"",
        version=0x0303,
        ciphers=[0x0a0a, 0x1301, 0x1302],
        extensions=[0x0a0a, EXT_SUPPORTED_VERSIONS],
        groups=[],
        point_formats=[],
        sig_algs=[0x0403],
        alpn=[b"h2"],
        supported_versions=[0x0a0a, 0x0303],
        has_sni=False,
    )
    ja4_a, ja4_b, _ja4_c = ch.ja4.split("_")
    assert ja4_a == "t12i" + "02" + "01" + "h2"  # 2 ciphers, 1 ext after GREASE
    assert ja4_b == _sha12("1301,1302")


def test_ja4_no_sni_vs_sni_flag() -> None:
    base = dict(
        record=b"", version=0x0303, ciphers=[0x1301], extensions=[EXT_SERVER_NAME],
        groups=[], point_formats=[], sig_algs=[], alpn=[], supported_versions=[0x0303],
    )
    with_sni = ClientHelloBytes(**base, has_sni=True)
    without = ClientHelloBytes(**base, has_sni=False)
    assert with_sni.ja4.split("_")[0][3] == "d"
    assert without.ja4.split("_")[0][3] == "i"


def test_ja4s_shape_and_components() -> None:
    body = _fake_server_hello(
        cipher=0xc02f,
        extensions=[
            (EXT_EXTENDED_MASTER_SECRET, b""),
            (EXT_ALPN, b"\x00\x03\x02h2"),
        ],
    )
    sh = parse_server_hello(body)
    assert sh.alpn == "h2"
    ja4s_a, ja4s_b, ja4s_c = sh.ja4s.split("_")
    # t + version(12) + ext count(02) + alpn(h2)
    assert ja4s_a == "t1202h2"
    # single chosen cipher as 4-hex, not hashed.
    assert ja4s_b == "c02f"
    # extensions hashed IN ORDER (not sorted).
    assert ja4s_c == _sha12(f"{EXT_EXTENDED_MASTER_SECRET:04x},{EXT_ALPN:04x}")


def test_ja4_r_is_unhashed_form_of_ja4() -> None:
    ch = build_client_hello()
    a, b, c = ch.ja4.split("_")
    # ja4_r's ext segment contains an internal "_" (exts_sigalgs), so split
    # yields [a, cipher_raw, ext_raw, sigalg_raw].
    ra, cipher_raw, *ext_parts = ch.ja4_r.split("_")
    ext_raw = "_".join(ext_parts)
    assert ra == a                          # ja4_a is identical
    assert _sha12(cipher_raw) == b          # hashing cipher_raw reproduces ja4_b
    assert _sha12(ext_raw) == c             # hashing ext_raw reproduces ja4_c
    # The raw cipher list is sorted, lowercase, 4-hex.
    assert cipher_raw == ",".join(f"{x:04x}" for x in sorted(ch.ciphers))


def test_ja4s_r_is_unhashed_form_of_ja4s() -> None:
    body = _fake_server_hello(
        cipher=0xc02f,
        extensions=[(EXT_EXTENDED_MASTER_SECRET, b""), (EXT_ALPN, b"\x00\x03\x02h2")],
    )
    sh = parse_server_hello(body)
    a, b, c = sh.ja4s.split("_")
    ra, rb, ext_raw = sh.ja4s_r.split("_")
    assert (ra, rb) == (a, b)               # a and the single cipher are unchanged
    assert _sha12(ext_raw) == c             # hashing the raw ext list reproduces ja4s_c
    assert ext_raw == f"{EXT_EXTENDED_MASTER_SECRET:04x},{EXT_ALPN:04x}"


def test_ja4s_no_alpn_no_extensions() -> None:
    body = _fake_server_hello(cipher=0x009c, extensions=[])
    sh = parse_server_hello(body)
    assert sh.alpn is None
    ja4s_a, ja4s_b, ja4s_c = sh.ja4s.split("_")
    assert ja4s_a == "t1200" + "00"  # 0 extensions, no ALPN -> "00"
    assert ja4s_b == "009c"
    assert ja4s_c == "000000000000"


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
