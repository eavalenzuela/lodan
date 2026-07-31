"""SSH_MSG_KEXINIT parsing and the deprecated-algorithm audit.

Packets are assembled byte-by-byte in-process, so nothing here needs a
network or an SSH server.
"""
from __future__ import annotations

import struct

import pytest

from lodan.probes.ssh_kex import (
    SSH_MSG_KEXINIT,
    KexInit,
    audit,
    extract_kexinit_payload,
    parse_kexinit,
    split_ident_and_packets,
)

_MODERN = {
    "kex": ["curve25519-sha256", "diffie-hellman-group16-sha512"],
    "hostkey": ["rsa-sha2-512", "ssh-ed25519"],
    "cipher": ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"],
    "mac": ["hmac-sha2-256-etm@openssh.com"],
}
_LEGACY = {
    "kex": ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"],
    "hostkey": ["ssh-rsa", "ssh-dss"],
    "cipher": ["3des-cbc", "arcfour", "aes128-cbc"],
    "mac": ["hmac-md5", "hmac-sha1-96"],
}


def _name_list(names: list[str]) -> bytes:
    body = ",".join(names).encode("ascii")
    return struct.pack(">I", len(body)) + body


def _kexinit_payload(profile: dict) -> bytes:
    return b"".join([
        bytes([SSH_MSG_KEXINIT]),
        b"\x00" * 16,                       # cookie
        _name_list(profile["kex"]),
        _name_list(profile["hostkey"]),
        _name_list(profile["cipher"]),      # c2s
        _name_list(profile["cipher"]),      # s2c
        _name_list(profile["mac"]),         # c2s
        _name_list(profile["mac"]),         # s2c
        _name_list(["none"]),               # compression c2s
        _name_list(["none"]),               # compression s2c
        _name_list([]),                     # languages c2s
        _name_list([]),                     # languages s2c
        b"\x00",                            # first_kex_packet_follows
        struct.pack(">I", 0),               # reserved
    ])


def _binary_packet(payload: bytes, padding: int = 8) -> bytes:
    packet_length = len(payload) + padding + 1
    return (
        struct.pack(">I", packet_length)
        + bytes([padding])
        + payload
        + b"\x00" * padding
    )


# --- payload parsing ---------------------------------------------------------

def test_parse_kexinit_reads_every_name_list() -> None:
    kex = parse_kexinit(_kexinit_payload(_LEGACY))
    assert kex.kex_algorithms == ("diffie-hellman-group1-sha1",
                                  "diffie-hellman-group14-sha1")
    assert kex.server_host_key_algorithms == ("ssh-rsa", "ssh-dss")
    assert kex.encryption_c2s == ("3des-cbc", "arcfour", "aes128-cbc")
    assert kex.mac_s2c == ("hmac-md5", "hmac-sha1-96")
    assert kex.compression_c2s == ("none",)


def test_parse_kexinit_rejects_a_non_kexinit_payload() -> None:
    with pytest.raises(ValueError):
        parse_kexinit(b"\x14"[0:0])          # empty
    with pytest.raises(ValueError):
        parse_kexinit(bytes([21]) + b"\x00" * 16)


def test_parse_kexinit_degrades_on_truncation() -> None:
    """A partial algorithm list still carries signal; a broken responder must
    not cost us the whole probe."""
    full = _kexinit_payload(_LEGACY)
    # Cut just past the first name-list: message byte + cookie + that list,
    # plus a few bytes of the next one so it is genuinely partial.
    first_list_end = 1 + 16 + len(_name_list(_LEGACY["kex"]))
    kex = parse_kexinit(full[: first_list_end + 3])
    assert kex.kex_algorithms == tuple(_LEGACY["kex"])   # first list survived
    assert kex.server_host_key_algorithms == ()          # partial list dropped
    assert kex.mac_s2c == ()                             # later lists empty


def test_parse_kexinit_rejects_overrunning_length() -> None:
    payload = bytes([SSH_MSG_KEXINIT]) + b"\x00" * 16 + struct.pack(">I", 9999)
    kex = parse_kexinit(payload)
    assert kex.kex_algorithms == ()


# --- binary packet framing ---------------------------------------------------

def test_extract_kexinit_from_a_binary_packet() -> None:
    raw = _binary_packet(_kexinit_payload(_MODERN))
    payload = extract_kexinit_payload(raw)
    assert payload is not None
    assert parse_kexinit(payload).kex_algorithms[0] == "curve25519-sha256"


def test_extract_skips_a_leading_non_kexinit_packet() -> None:
    other = _binary_packet(bytes([5]) + b"ignore-me")
    raw = other + _binary_packet(_kexinit_payload(_MODERN))
    assert extract_kexinit_payload(raw) is not None


def test_extract_returns_none_on_absurd_packet_length() -> None:
    assert extract_kexinit_payload(struct.pack(">I", 10_000_000) + b"\x08") is None


def test_extract_returns_none_on_truncated_stream() -> None:
    raw = _binary_packet(_kexinit_payload(_MODERN))
    assert extract_kexinit_payload(raw[:20]) is None
    assert extract_kexinit_payload(b"") is None


def test_extract_returns_none_on_degenerate_lengths() -> None:
    assert extract_kexinit_payload(struct.pack(">I", 1) + b"\x00") is None
    # padding_length >= packet_length - 1 leaves no payload
    assert extract_kexinit_payload(struct.pack(">I", 5) + b"\x08" + b"x" * 8) is None


# --- ident splitting ---------------------------------------------------------

def test_split_ident_finds_the_ssh_line() -> None:
    raw = b"SSH-2.0-OpenSSH_9.3\r\n" + _binary_packet(_kexinit_payload(_MODERN))
    ident, rest = split_ident_and_packets(raw)
    assert ident == "SSH-2.0-OpenSSH_9.3"
    assert extract_kexinit_payload(rest) is not None


def test_split_ident_skips_legal_banner_text() -> None:
    """RFC 4253 §4.2 lets a server emit arbitrary lines before its ident."""
    raw = (
        b"************************\r\n"
        b"* Authorized use only. *\r\n"
        b"************************\r\n"
        b"SSH-2.0-OpenSSH_9.3\r\n"
    ) + _binary_packet(_kexinit_payload(_MODERN))
    ident, rest = split_ident_and_packets(raw)
    assert ident == "SSH-2.0-OpenSSH_9.3"
    assert extract_kexinit_payload(rest) is not None


def test_split_ident_without_an_ident_line() -> None:
    ident, rest = split_ident_and_packets(b"no newline here")
    assert ident is None
    assert rest == b""


# --- audit -------------------------------------------------------------------

def test_modern_server_has_nothing_to_flag() -> None:
    assert audit(parse_kexinit(_kexinit_payload(_MODERN))) == ()


def test_legacy_server_flags_every_category() -> None:
    weak = audit(parse_kexinit(_kexinit_payload(_LEGACY)))
    categories = {w.category for w in weak}
    assert categories == {"kex", "host-key", "cipher", "mac"}


def test_group1_sha1_is_high_severity() -> None:
    weak = audit(KexInit(kex_algorithms=("diffie-hellman-group1-sha1",)))
    assert [(w.algorithm, w.severity) for w in weak] == [
        ("diffie-hellman-group1-sha1", "high")
    ]


def test_dss_host_key_is_high_and_rsa_sha1_is_medium() -> None:
    weak = audit(KexInit(server_host_key_algorithms=("ssh-dss", "ssh-rsa")))
    by_algo = {w.algorithm: w.severity for w in weak}
    assert by_algo == {"ssh-dss": "high", "ssh-rsa": "medium"}


def test_rsa_sha2_host_keys_are_not_flagged() -> None:
    assert audit(KexInit(server_host_key_algorithms=("rsa-sha2-256", "rsa-sha2-512"))) == ()


def test_unlisted_cbc_cipher_is_caught_by_the_class_rule() -> None:
    """The exact table can't enumerate every CBC suite; the suffix rule does."""
    weak = audit(KexInit(encryption_c2s=("aes192-cbc",)))
    assert [(w.algorithm, w.reason, w.severity) for w in weak] == [
        ("aes192-cbc", "CBC mode", "low")
    ]


def test_exact_cipher_entry_wins_over_the_cbc_class_rule() -> None:
    weak = audit(KexInit(encryption_c2s=("3des-cbc",)))
    assert len(weak) == 1
    assert weak[0].reason == "3DES"
    assert weak[0].severity == "medium"


def test_null_cipher_and_mac_are_high() -> None:
    weak = audit(KexInit(encryption_c2s=("none",), mac_c2s=("none",)))
    assert {w.severity for w in weak} == {"high"}


def test_directional_lists_are_deduplicated() -> None:
    """Offering hmac-md5 both ways is one problem, not two."""
    weak = audit(KexInit(mac_c2s=("hmac-md5",), mac_s2c=("hmac-md5",)))
    assert len(weak) == 1


def test_audit_output_is_stably_ordered() -> None:
    kex = parse_kexinit(_kexinit_payload(_LEGACY))
    assert audit(kex) == audit(kex)
    ordered = [(w.category, w.algorithm) for w in audit(kex)]
    assert ordered == sorted(ordered)


def test_empty_kexinit_flags_nothing() -> None:
    assert audit(KexInit()) == ()
