"""SSH_MSG_KEXINIT capture and algorithm audit.

The SSH probe records a banner and a host-key fingerprint, which misses the
place deprecated crypto actually hides: a server can present a perfectly modern
version string while still offering `diffie-hellman-group1-sha1`, CBC ciphers
and `hmac-md5` in its algorithm lists.

RFC 4253 §7.1 has the server send `SSH_MSG_KEXINIT` — its full offered
algorithm set — immediately after the identification exchange and *before* any
authentication. Reading it costs one protocol-mandatory identification line
and no credential of any kind.

Where this stops: lodan sends its own identification string (required by the
protocol before the server will proceed) and reads the server's KEXINIT. It
never sends its own KEXINIT, so key exchange never begins, no Diffie-Hellman
happens, and nothing resembling authentication is reached.

Parsing is a small hand-rolled binary reader, in the same spirit as the
hand-rolled TLS parser: bounds-checked, and it degrades to a partial result
rather than raising at anything malformed.
"""
from __future__ import annotations

import asyncio
import contextlib
import struct
from dataclasses import dataclass

SSH_MSG_KEXINIT = 20
_IDENT = b"SSH-2.0-lodan\r\n"
_MAX_PACKET = 65536
_MAX_IDENT_LINES = 20          # servers may send banner text before the ident


@dataclass(frozen=True)
class KexInit:
    """The server's offered algorithm sets."""

    kex_algorithms: tuple[str, ...] = ()
    server_host_key_algorithms: tuple[str, ...] = ()
    encryption_c2s: tuple[str, ...] = ()
    encryption_s2c: tuple[str, ...] = ()
    mac_c2s: tuple[str, ...] = ()
    mac_s2c: tuple[str, ...] = ()
    compression_c2s: tuple[str, ...] = ()
    compression_s2c: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, list[str]]:
        return {
            "kex_algorithms": list(self.kex_algorithms),
            "server_host_key_algorithms": list(self.server_host_key_algorithms),
            "encryption_c2s": list(self.encryption_c2s),
            "encryption_s2c": list(self.encryption_s2c),
            "mac_c2s": list(self.mac_c2s),
            "mac_s2c": list(self.mac_s2c),
            "compression_c2s": list(self.compression_c2s),
            "compression_s2c": list(self.compression_s2c),
        }


# --- deprecated algorithm tables ---------------------------------------------
#
# Each entry is (matcher, label, severity). Severity reflects how bad it is to
# still *offer* the algorithm, not how bad the connection lodan made was —
# lodan never negotiates anything.

_WEAK_KEX = {
    "diffie-hellman-group1-sha1": ("1024-bit MODP group with SHA-1", "high"),
    "diffie-hellman-group-exchange-sha1": ("group exchange with SHA-1", "medium"),
    "diffie-hellman-group14-sha1": ("SHA-1 key exchange", "medium"),
    "rsa1024-sha1": ("1024-bit RSA key exchange with SHA-1", "high"),
    "gss-group1-sha1-": ("1024-bit MODP group with SHA-1 (GSS)", "high"),
}

_WEAK_HOST_KEY = {
    "ssh-dss": ("DSA host key (1024-bit, SHA-1)", "high"),
    "ssh-rsa": ("RSA host key with SHA-1 signatures", "medium"),
}

_WEAK_CIPHER_EXACT = {
    "3des-cbc": ("3DES", "medium"),
    "des-cbc": ("single DES", "high"),
    "arcfour": ("RC4", "high"),
    "arcfour128": ("RC4", "high"),
    "arcfour256": ("RC4", "high"),
    "none": ("no encryption", "high"),
    "rijndael-cbc@lysator.liu.se": ("legacy Rijndael CBC", "medium"),
    "blowfish-cbc": ("Blowfish CBC", "medium"),
    "cast128-cbc": ("CAST-128 CBC", "medium"),
}

_WEAK_MAC = {
    "hmac-md5": ("HMAC-MD5", "medium"),
    "hmac-md5-96": ("truncated HMAC-MD5", "medium"),
    "hmac-sha1-96": ("truncated HMAC-SHA1", "low"),
    "hmac-md5-etm@openssh.com": ("HMAC-MD5", "medium"),
    "hmac-md5-96-etm@openssh.com": ("truncated HMAC-MD5", "medium"),
    "hmac-sha1-96-etm@openssh.com": ("truncated HMAC-SHA1", "low"),
    "none": ("no integrity protection", "high"),
    "umac-64@openssh.com": ("64-bit UMAC", "low"),
}


@dataclass(frozen=True)
class WeakAlgorithm:
    category: str        # kex | host-key | cipher | mac
    algorithm: str
    reason: str
    severity: str


def audit(kex: KexInit) -> tuple[WeakAlgorithm, ...]:
    """Flag deprecated algorithms in the server's offer. Pure."""
    out: list[WeakAlgorithm] = []

    for algo in kex.kex_algorithms:
        hit = _WEAK_KEX.get(algo)
        if hit:
            out.append(WeakAlgorithm("kex", algo, hit[0], hit[1]))

    for algo in kex.server_host_key_algorithms:
        hit = _WEAK_HOST_KEY.get(algo)
        if hit:
            out.append(WeakAlgorithm("host-key", algo, hit[0], hit[1]))

    # CBC modes are a class, not a list — flag any of them, but let the exact
    # table win when it has a more specific reason.
    seen_ciphers: set[str] = set()
    for algo in set(kex.encryption_c2s) | set(kex.encryption_s2c):
        if algo in seen_ciphers:
            continue
        seen_ciphers.add(algo)
        hit = _WEAK_CIPHER_EXACT.get(algo)
        if hit:
            out.append(WeakAlgorithm("cipher", algo, hit[0], hit[1]))
        elif algo.endswith("-cbc"):
            out.append(WeakAlgorithm("cipher", algo, "CBC mode", "low"))

    for algo in set(kex.mac_c2s) | set(kex.mac_s2c):
        hit = _WEAK_MAC.get(algo)
        if hit:
            out.append(WeakAlgorithm("mac", algo, hit[0], hit[1]))

    # Stable order so diffs and tests don't depend on set iteration.
    return tuple(sorted(out, key=lambda w: (w.category, w.algorithm)))


# --- binary parsing ----------------------------------------------------------


def _read_name_list(buf: bytes, pos: int) -> tuple[tuple[str, ...], int]:
    """RFC 4251 name-list: uint32 length + comma-separated ASCII."""
    if pos + 4 > len(buf):
        raise ValueError("truncated name-list length")
    (length,) = struct.unpack_from(">I", buf, pos)
    pos += 4
    if length > len(buf) - pos:
        raise ValueError("name-list length overruns packet")
    text = buf[pos : pos + length].decode("ascii", "replace")
    pos += length
    names = tuple(n for n in text.split(",") if n)
    return names, pos


def parse_kexinit(payload: bytes) -> KexInit:
    """Parse a KEXINIT payload (message byte first).

    Degrades gracefully: whatever name-lists were read before a malformed one
    are kept, because a partial algorithm list still carries signal and a
    broken responder must not cost us the whole probe.
    """
    if not payload or payload[0] != SSH_MSG_KEXINIT:
        raise ValueError("not a KEXINIT payload")
    pos = 1 + 16  # message type + cookie
    lists: list[tuple[str, ...]] = []
    for _ in range(10):
        try:
            names, pos = _read_name_list(payload, pos)
        except ValueError:
            break
        lists.append(names)
    while len(lists) < 10:
        lists.append(())
    return KexInit(
        kex_algorithms=lists[0],
        server_host_key_algorithms=lists[1],
        encryption_c2s=lists[2],
        encryption_s2c=lists[3],
        mac_c2s=lists[4],
        mac_s2c=lists[5],
        compression_c2s=lists[6],
        compression_s2c=lists[7],
        # lists[8] / lists[9] are the language lists, always empty in practice.
    )


def extract_kexinit_payload(raw: bytes) -> bytes | None:
    """Pull the first KEXINIT payload out of an SSH binary-packet stream.

    Packet layout (RFC 4253 §6), pre-encryption:
        uint32 packet_length
        byte   padding_length
        byte[] payload        (packet_length - padding_length - 1)
        byte[] random padding
    """
    pos = 0
    while pos + 5 <= len(raw):
        (packet_length,) = struct.unpack_from(">I", raw, pos)
        if packet_length < 2 or packet_length > _MAX_PACKET:
            return None
        padding_length = raw[pos + 4]
        payload_len = packet_length - padding_length - 1
        if payload_len <= 0:
            return None
        start = pos + 5
        end = start + payload_len
        if end > len(raw):
            return None
        payload = raw[start:end]
        if payload and payload[0] == SSH_MSG_KEXINIT:
            return payload
        pos = pos + 4 + packet_length
    return None


def split_ident_and_packets(raw: bytes) -> tuple[str | None, bytes]:
    """Separate the server's identification line(s) from the binary packets.

    A server may emit arbitrary text lines before its `SSH-2.0-...` ident
    (RFC 4253 §4.2 allows it for legal banners); the ident is the first line
    starting with "SSH-".
    """
    ident: str | None = None
    pos = 0
    for _ in range(_MAX_IDENT_LINES):
        nl = raw.find(b"\n", pos)
        if nl == -1:
            return ident, b""
        line = raw[pos:nl].rstrip(b"\r")
        pos = nl + 1
        if line.startswith(b"SSH-"):
            ident = line.decode("ascii", "replace")
            return ident, raw[pos:]
    return ident, raw[pos:]


async def fetch_kexinit(ip: str, port: int, timeout: float) -> KexInit | None:
    """Ident exchange, then read the server's volunteered KEXINIT.

    Returns None rather than raising: an SSH server that refuses this is still
    a perfectly good banner + host-key result.
    """
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        # Protocol-mandatory identification. Not a credential; the server will
        # not proceed to KEXINIT without one.
        writer.write(_IDENT)
        await writer.drain()

        buf = bytearray()
        deadline = asyncio.get_event_loop().time() + timeout
        while len(buf) < _MAX_PACKET:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                break
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=remaining)
            except TimeoutError:
                break
            if not chunk:
                break
            buf.extend(chunk)
            _ident, rest = split_ident_and_packets(bytes(buf))
            if rest and extract_kexinit_payload(rest) is not None:
                break

        _ident, rest = split_ident_and_packets(bytes(buf))
        payload = extract_kexinit_payload(rest) if rest else None
        if payload is None:
            return None
        return parse_kexinit(payload)
    except Exception:  # noqa: BLE001 — a refusal is not an error worth raising
        return None
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
