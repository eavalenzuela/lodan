"""Hand-rolled TLS 1.2 ClientHello + ServerHello parser.

The stdlib `ssl` module hides the extension ordering we need to compute JA3
and JA3S, so we emit a fixed ClientHello of our own and parse the server's
plaintext handshake response. Advertising only TLS 1.2 in supported_versions
forces the server to pick 1.2, which keeps the ServerHello and Certificate
messages in the clear — JA3S + cert chain both come out of one connection.

Pure parsing / byte munging here. The network call itself lives in tls.py.

References:
- RFC 5246 (TLS 1.2)
- https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967
  (original JA3/JA3S spec)
"""
from __future__ import annotations

import hashlib
import secrets
import struct
from dataclasses import dataclass

# Content types
TLS_CT_CHANGE_CIPHER = 20
TLS_CT_ALERT = 21
TLS_CT_HANDSHAKE = 22
TLS_CT_APPDATA = 23

# Handshake types
HS_CLIENT_HELLO = 1
HS_SERVER_HELLO = 2
HS_CERTIFICATE = 11
HS_SERVER_HELLO_DONE = 14

# TLS / JA3 GREASE values (RFC 8701); filtered out of JA3 fields.
_GREASE = frozenset(0x0a0a | (i << 12) | (i << 4) for i in range(16))

# Extension types we refer to by name.
EXT_SERVER_NAME = 0
EXT_SUPPORTED_GROUPS = 10
EXT_EC_POINT_FORMATS = 11
EXT_SIGNATURE_ALGORITHMS = 13
EXT_ALPN = 16
EXT_EXTENDED_MASTER_SECRET = 23
EXT_SESSION_TICKET = 35
EXT_SUPPORTED_VERSIONS = 43
EXT_PSK_KEY_EXCHANGE_MODES = 45
EXT_KEY_SHARE = 51
EXT_RENEGOTIATION_INFO = 0xff01


@dataclass(frozen=True)
class ClientHelloBytes:
    record: bytes             # full TLS record ready to put on the wire
    version: int              # legacy_version (0x0303 for our hello)
    ciphers: list[int]        # in order, GREASE-free (we send none)
    extensions: list[int]     # in order, GREASE-free
    groups: list[int]
    point_formats: list[int]

    @property
    def ja3_string(self) -> str:
        return _ja3_compose(
            self.version, self.ciphers, self.extensions,
            self.groups, self.point_formats,
        )

    @property
    def ja3(self) -> str:
        return hashlib.md5(self.ja3_string.encode("ascii")).hexdigest()


@dataclass(frozen=True)
class ServerHelloParsed:
    version: int
    cipher: int
    extensions: list[int]     # in order

    @property
    def ja3s_string(self) -> str:
        return _ja3s_compose(self.version, self.cipher, self.extensions)

    @property
    def ja3s(self) -> str:
        return hashlib.md5(self.ja3s_string.encode("ascii")).hexdigest()


# ----------------------------------------------------------------------
# ClientHello builder
# ----------------------------------------------------------------------

# A stable, reasonable cipher list. Order matters for JA3.
_CIPHERS: list[int] = [
    0x1301, 0x1302, 0x1303,                             # TLS 1.3 AEAD suites
    0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,     # ECDHE-ECDSA/RSA GCM/CHACHA20
    0xc013, 0xc014,                                     # ECDHE-RSA-AES-SHA
    0x009c, 0x009d, 0x002f, 0x0035,                     # AES-GCM / AES-SHA RSA
]

_SUPPORTED_GROUPS: list[int] = [
    0x001d,  # x25519
    0x0017,  # secp256r1
    0x0018,  # secp384r1
    0x0019,  # secp521r1
]

_EC_POINT_FORMATS: list[int] = [0]  # uncompressed

_SIGNATURE_ALGORITHMS: list[int] = [
    0x0403,  # ecdsa_secp256r1_sha256
    0x0804,  # rsa_pss_rsae_sha256
    0x0401,  # rsa_pkcs1_sha256
    0x0503,  # ecdsa_secp384r1_sha384
    0x0805,  # rsa_pss_rsae_sha384
    0x0501,  # rsa_pkcs1_sha384
    0x0806,  # rsa_pss_rsae_sha512
    0x0601,  # rsa_pkcs1_sha512
]

_ALPN_PROTOCOLS: list[bytes] = [b"h2", b"http/1.1"]


def build_client_hello() -> ClientHelloBytes:
    """Assemble a stable ClientHello. JA3 components are deterministic."""
    random_bytes = secrets.token_bytes(32)

    extensions_in_order: list[int] = []
    ext_body = b""

    def add(ext_type: int, data: bytes) -> None:
        nonlocal ext_body
        extensions_in_order.append(ext_type)
        ext_body += struct.pack(">HH", ext_type, len(data)) + data

    # The extension order below is what downstream JA3 implementations see.
    # Rewrite with care; the MD5 is a function of this list.
    add(EXT_EXTENDED_MASTER_SECRET, b"")
    add(EXT_RENEGOTIATION_INFO, b"\x00")
    add(EXT_SUPPORTED_GROUPS, _encode_u16_list_with_len(_SUPPORTED_GROUPS))
    add(EXT_EC_POINT_FORMATS, _encode_u8_list_with_len(_EC_POINT_FORMATS))
    add(EXT_SESSION_TICKET, b"")
    add(EXT_SIGNATURE_ALGORITHMS, _encode_u16_list_with_len(_SIGNATURE_ALGORITHMS))
    add(EXT_ALPN, _encode_alpn(_ALPN_PROTOCOLS))
    # We advertise only TLS 1.2 in supported_versions so the server negotiates
    # 1.2 and leaves the rest of the handshake in plaintext, where we can see
    # the Certificate message.
    add(EXT_SUPPORTED_VERSIONS, _encode_u8_list_with_len([0x03, 0x03]))

    ch_body = b"".join([
        struct.pack(">H", 0x0303),                         # legacy_version = TLS 1.2
        random_bytes,
        b"\x00",                                           # session_id length = 0
        _encode_u16_list_with_len(_CIPHERS),
        b"\x01\x00",                                       # compression methods: [null]
        struct.pack(">H", len(ext_body)),
        ext_body,
    ])
    handshake = struct.pack(">B", HS_CLIENT_HELLO) + _u24(len(ch_body)) + ch_body
    record = struct.pack(">BHH", TLS_CT_HANDSHAKE, 0x0301, len(handshake)) + handshake

    return ClientHelloBytes(
        record=record,
        version=0x0303,
        ciphers=_CIPHERS.copy(),
        extensions=extensions_in_order,
        groups=_SUPPORTED_GROUPS.copy(),
        point_formats=_EC_POINT_FORMATS.copy(),
    )


# ----------------------------------------------------------------------
# Record / handshake parsing
# ----------------------------------------------------------------------


def iter_records(raw: bytes):
    """Walk a stream of TLS records. Yields (content_type, version, fragment).

    Stops at a record that would run past the end of `raw`. ChangeCipherSpec
    and Alert records are surfaced along with handshake records so the caller
    can decide when to stop reading plaintext."""
    pos = 0
    while pos + 5 <= len(raw):
        content_type, version, length = struct.unpack_from(">BHH", raw, pos)
        body_end = pos + 5 + length
        if body_end > len(raw):
            return
        yield content_type, version, raw[pos + 5 : body_end]
        pos = body_end


def collect_handshake_messages(raw: bytes) -> list[tuple[int, bytes]]:
    """Return [(handshake_type, body)] from all plaintext handshake records.

    Handshake messages can straddle records, so we accumulate all handshake
    payloads first, then carve them by the 4-byte (type + u24 length) header.
    Parsing stops at the first ChangeCipherSpec / Alert / AppData record —
    anything after that is encrypted or unrelated.
    """
    handshake_buffer = bytearray()
    for content_type, _version, fragment in iter_records(raw):
        if content_type == TLS_CT_HANDSHAKE:
            handshake_buffer.extend(fragment)
            continue
        if content_type in (TLS_CT_CHANGE_CIPHER, TLS_CT_ALERT, TLS_CT_APPDATA):
            break

    out: list[tuple[int, bytes]] = []
    i = 0
    buf = bytes(handshake_buffer)
    while i + 4 <= len(buf):
        hs_type = buf[i]
        length = _parse_u24(buf, i + 1)
        body_start = i + 4
        body_end = body_start + length
        if body_end > len(buf):
            break
        out.append((hs_type, buf[body_start:body_end]))
        i = body_end
    return out


def parse_server_hello(body: bytes) -> ServerHelloParsed:
    """Parse a ServerHello handshake body."""
    if len(body) < 2 + 32 + 1 + 2 + 1 + 2:
        raise ValueError("ServerHello too short")
    pos = 0
    (version,) = struct.unpack_from(">H", body, pos)
    pos += 2
    pos += 32  # server_random
    sid_len = body[pos]
    pos += 1
    pos += sid_len
    if pos + 3 > len(body):
        raise ValueError("ServerHello truncated before cipher suite")
    (cipher,) = struct.unpack_from(">H", body, pos)
    pos += 2
    pos += 1  # compression_method

    # TLS 1.0/1.1 servers may omit extensions entirely; in that case we stop.
    if pos >= len(body):
        return ServerHelloParsed(version=version, cipher=cipher, extensions=[])

    (ext_total,) = struct.unpack_from(">H", body, pos)
    pos += 2
    end = pos + ext_total
    if end > len(body):
        raise ValueError("ServerHello extensions length overruns body")

    extensions: list[int] = []
    negotiated_version = version
    while pos + 4 <= end:
        ext_type, ext_len = struct.unpack_from(">HH", body, pos)
        pos += 4
        ext_data = body[pos : pos + ext_len]
        pos += ext_len
        extensions.append(ext_type)
        # supported_versions in ServerHello carries the actually-negotiated version
        # even though legacy_version is pinned to 0x0303 in TLS 1.3.
        if ext_type == EXT_SUPPORTED_VERSIONS and len(ext_data) >= 2:
            negotiated_version = struct.unpack(">H", ext_data[:2])[0]
    return ServerHelloParsed(
        version=negotiated_version, cipher=cipher, extensions=extensions,
    )


def extract_cert_chain(messages: list[tuple[int, bytes]]) -> list[bytes]:
    """Return the DER-encoded certs from the first Certificate message.

    TLS 1.2 Certificate payload layout:
      uint24 total_len
      for each cert: uint24 cert_len + cert_bytes
    """
    for hs_type, body in messages:
        if hs_type != HS_CERTIFICATE:
            continue
        if len(body) < 3:
            return []
        total = _parse_u24(body, 0)
        end = 3 + total
        chain: list[bytes] = []
        pos = 3
        while pos + 3 <= end:
            cert_len = _parse_u24(body, pos)
            pos += 3
            if pos + cert_len > end:
                break
            chain.append(body[pos : pos + cert_len])
            pos += cert_len
        return chain
    return []


def find_server_hello(messages: list[tuple[int, bytes]]) -> bytes | None:
    for hs_type, body in messages:
        if hs_type == HS_SERVER_HELLO:
            return body
    return None


# ----------------------------------------------------------------------
# JA3 / JA3S composition
# ----------------------------------------------------------------------


def _ja3_compose(
    version: int,
    ciphers: list[int],
    extensions: list[int],
    groups: list[int],
    point_formats: list[int],
) -> str:
    def join(values: list[int]) -> str:
        return "-".join(str(v) for v in values if v not in _GREASE)

    return ",".join([
        str(version),
        join(ciphers),
        join(extensions),
        join(groups),
        join(point_formats),
    ])


def _ja3s_compose(version: int, cipher: int, extensions: list[int]) -> str:
    ext_str = "-".join(str(v) for v in extensions)
    return f"{version},{cipher},{ext_str}"


# ----------------------------------------------------------------------
# small encoders / decoders
# ----------------------------------------------------------------------


def _u24(value: int) -> bytes:
    return struct.pack(">I", value)[1:]


def _parse_u24(buf: bytes, offset: int) -> int:
    return (buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2]


def _encode_u16_list_with_len(values: list[int]) -> bytes:
    body = b"".join(struct.pack(">H", v) for v in values)
    return struct.pack(">H", len(body)) + body


def _encode_u8_list_with_len(values: list[int]) -> bytes:
    body = bytes(values)
    return struct.pack(">B", len(body)) + body


def _encode_alpn(protocols: list[bytes]) -> bytes:
    body = b"".join(struct.pack(">B", len(p)) + p for p in protocols)
    return struct.pack(">H", len(body)) + body
