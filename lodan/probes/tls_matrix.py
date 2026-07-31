"""TLS acceptance matrix and JARM server fingerprinting.

Both features ask the same shape of question — send a specific ClientHello,
read the ServerHello, hang up — and differ only in which hellos they send and
what they do with the answers.

**Acceptance matrix.** lodan's normal probe pins TLS 1.2 so the certificate
arrives in plaintext, which means it structurally cannot answer "is TLS 1.0
still enabled?" or "will this server take 3DES?". The matrix asks each
question with one targeted hello.

Six connections, not eleven: the weak-cipher question is asked with a single
hello offering every weak suite at once. The server answers with the one it
*prefers*, which is enough to establish that weak crypto is on the menu. The
trade-off is that we learn the preferred weak suite rather than the exhaustive
set — worth it to keep the connection count near the original probe's.

**JARM.** Ten standardized hellos whose ordered (version, cipher) answers plus
a digest of the returned extensions form a 62-character fingerprint that
clusters servers by TLS *configuration* rather than by certificate — two hosts
with the same JARM are running the same stack configured the same way.

    Interop caveat: the encoding below follows the published JARM construction
    (30 chars of per-hello cipher/version codes, then 32 chars of truncated
    SHA-256 over the concatenated extension data). It has NOT been
    differentially tested against Salesforce's reference implementation, so
    treat these values as internally consistent — good for clustering and
    diffing *within* a lodan workspace — and verify against the reference
    before comparing them to externally published JARM hashes.

Detection-only throughout: every connection is ClientHello -> read ServerHello
-> close. No handshake is completed, no application data is sent, no
credential of any kind is transmitted, and the count is fixed per port.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
from dataclasses import dataclass

from lodan.probes.tls_parser import (
    HelloSpec,
    ServerHelloParsed,
    build_client_hello,
    collect_handshake_messages,
    find_server_hello,
    parse_server_hello,
)

_MAX_MATRIX_BYTES = 16384

# --- cipher groups the matrix asks about -------------------------------------

# Everything below is offered only to learn whether the server would accept it.
# We never complete the handshake, so no traffic is ever protected by one.
_WEAK_CIPHERS: tuple[int, ...] = (
    # 3DES
    0x000A, 0xC012, 0xC008, 0x0016,
    # RC4
    0x0005, 0x0004, 0xC011, 0xC007,
    # NULL encryption
    0x0001, 0x0002, 0x003B, 0xC006, 0xC010,
    # export-grade
    0x0003, 0x0006, 0x0008, 0x0014,
    # anonymous DH (no authentication at all)
    0x0018, 0x001B, 0x0034, 0x006C,
)

_WEAK_CIPHER_LABELS = {
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    0x0001: "TLS_RSA_WITH_NULL_MD5",
    0x0002: "TLS_RSA_WITH_NULL_SHA",
    0x003B: "TLS_RSA_WITH_NULL_SHA256",
    0xC006: "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
    0xC010: "TLS_ECDHE_RSA_WITH_NULL_SHA",
    0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    0x0006: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
    0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
    0x0014: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
    0x0018: "TLS_DH_anon_WITH_RC4_128_MD5",
    0x001B: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
    0x0034: "TLS_DH_anon_WITH_AES_128_CBC_SHA",
    0x006C: "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
}

_WEAK_FAMILIES = {
    "3des": frozenset({0x000A, 0xC012, 0xC008, 0x0016, 0x001B}),
    "rc4": frozenset({0x0005, 0x0004, 0xC011, 0xC007, 0x0018}),
    "null": frozenset({0x0001, 0x0002, 0x003B, 0xC006, 0xC010}),
    "export": frozenset({0x0003, 0x0006, 0x0008, 0x0014}),
    "anon": frozenset({0x0018, 0x001B, 0x0034, 0x006C}),
}

# Static-RSA key exchange: no forward secrecy. A server that picks one of these
# when offered nothing else has FS available only by client courtesy.
_STATIC_RSA_CIPHERS: tuple[int, ...] = (0x009C, 0x009D, 0x002F, 0x0035, 0x003C, 0x003D)

_VERSION_LABELS = {
    0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3",
}


def _version_hello(name: str, version: int) -> HelloSpec:
    """A hello that asks for exactly one protocol version."""
    if version >= 0x0303:
        return HelloSpec(
            name=name, legacy_version=0x0303, supported_versions=(version,),
            include_supported_versions=True,
        )
    # TLS 1.0/1.1 predate supported_versions; the legacy field is the ask.
    return HelloSpec(
        name=name, legacy_version=version, record_version=version,
        include_supported_versions=False, alpn=(),
    )


MATRIX_HELLOS: tuple[HelloSpec, ...] = (
    _version_hello("tls1.0", 0x0301),
    _version_hello("tls1.1", 0x0302),
    _version_hello("tls1.2", 0x0303),
    _version_hello("tls1.3", 0x0304),
    HelloSpec(
        name="weak-ciphers", legacy_version=0x0303, ciphers=_WEAK_CIPHERS,
        include_supported_versions=False, alpn=(),
    ),
    HelloSpec(
        name="static-rsa", legacy_version=0x0303, ciphers=_STATIC_RSA_CIPHERS,
        include_supported_versions=False, alpn=(),
    ),
)


@dataclass(frozen=True)
class HelloOutcome:
    name: str
    accepted: bool
    version: int | None = None
    cipher: int | None = None
    extensions: tuple[int, ...] = ()
    error: str | None = None


@dataclass(frozen=True)
class MatrixResult:
    accepted_versions: tuple[str, ...] = ()
    rejected_versions: tuple[str, ...] = ()
    weak_cipher: str | None = None          # the suite the server preferred
    weak_families: tuple[str, ...] = ()
    accepts_static_rsa: bool = False
    outcomes: tuple[HelloOutcome, ...] = ()

    def as_dict(self) -> dict:
        return {
            "accepted_versions": list(self.accepted_versions),
            "rejected_versions": list(self.rejected_versions),
            "weak_cipher": self.weak_cipher,
            "weak_families": list(self.weak_families),
            "accepts_static_rsa": self.accepts_static_rsa,
        }


async def _one_hello(
    ip: str, port: int, spec: HelloSpec, timeout: float
) -> HelloOutcome:
    """ClientHello -> read -> close. Never raises."""
    ch = build_client_hello(spec)
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.write(ch.record)
        await writer.drain()
        buf = bytearray()
        deadline = asyncio.get_event_loop().time() + timeout
        while len(buf) < _MAX_MATRIX_BYTES:
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
            if find_server_hello(collect_handshake_messages(bytes(buf))) is not None:
                break
        sh_body = find_server_hello(collect_handshake_messages(bytes(buf)))
        if sh_body is None:
            # No ServerHello means refused — an alert, a reset, or silence.
            return HelloOutcome(spec.name, accepted=False)
        sh: ServerHelloParsed = parse_server_hello(sh_body)
        return HelloOutcome(
            spec.name, accepted=True, version=sh.version, cipher=sh.cipher,
            extensions=tuple(sh.extensions),
        )
    except Exception as e:  # noqa: BLE001 — a refusal is data, not an error
        return HelloOutcome(spec.name, accepted=False, error=str(e) or type(e).__name__)
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()


def summarize_matrix(outcomes: list[HelloOutcome]) -> MatrixResult:
    """Turn per-hello outcomes into the posture summary. Pure."""
    by_name = {o.name: o for o in outcomes}
    accepted: list[str] = []
    rejected: list[str] = []
    for label, version in (
        ("TLS 1.0", 0x0301), ("TLS 1.1", 0x0302),
        ("TLS 1.2", 0x0303), ("TLS 1.3", 0x0304),
    ):
        key = f"tls{label.split()[1]}"
        outcome = by_name.get(key)
        if outcome is None:
            continue
        # A server that answers a 1.0 hello with 1.2 has not accepted 1.0 — it
        # has ignored our ask. Only count it when the negotiated version is the
        # one we asked for.
        if outcome.accepted and outcome.version == version:
            accepted.append(label)
        else:
            rejected.append(label)

    weak = by_name.get("weak-ciphers")
    weak_cipher = None
    families: list[str] = []
    if weak is not None and weak.accepted and weak.cipher is not None:
        weak_cipher = _WEAK_CIPHER_LABELS.get(weak.cipher, f"0x{weak.cipher:04x}")
        families = sorted(
            name for name, suites in _WEAK_FAMILIES.items() if weak.cipher in suites
        )

    static = by_name.get("static-rsa")
    accepts_static = bool(static is not None and static.accepted and static.cipher is not None)

    return MatrixResult(
        accepted_versions=tuple(accepted),
        rejected_versions=tuple(rejected),
        weak_cipher=weak_cipher,
        weak_families=tuple(families),
        accepts_static_rsa=accepts_static,
        outcomes=tuple(outcomes),
    )


async def run_matrix(ip: str, port: int, timeout: float) -> MatrixResult:
    """Run the acceptance matrix against one port. Six sequential connections.

    Sequential rather than concurrent on purpose: six simultaneous handshakes
    to one port looks like a burst to anything watching, and the probe phase
    already bounds per-host concurrency.
    """
    outcomes = [await _one_hello(ip, port, spec, timeout) for spec in MATRIX_HELLOS]
    return summarize_matrix(outcomes)


# --- JARM --------------------------------------------------------------------

# JARM's cipher list, in its canonical order. A suite's *index* here is what
# gets encoded, so this ordering is part of the wire format.
_JARM_CIPHERS: tuple[int, ...] = (
    0x0004, 0x0005, 0x0007, 0x000A, 0x0016, 0x002F, 0x0033, 0x0035, 0x0039, 0x003C,
    0x003D, 0x0041, 0x0045, 0x0067, 0x006B, 0x0084, 0x0088, 0x009C, 0x009D, 0x009E,
    0x009F, 0x00BA, 0x00BE, 0x00C0, 0x00C4, 0xC007, 0xC008, 0xC009, 0xC00A, 0xC011,
    0xC012, 0xC013, 0xC014, 0xC023, 0xC024, 0xC027, 0xC028, 0xC02B, 0xC02C, 0xC02F,
    0xC030, 0xC060, 0xC061, 0xC072, 0xC073, 0xC076, 0xC077, 0xC09C, 0xC09D, 0xC09E,
    0xC09F, 0xC0A0, 0xC0A1, 0xC0A2, 0xC0A3, 0xC0AC, 0xC0AD, 0xC0AE, 0xC0AF, 0xCCA8,
    0xCCA9, 0xCCAA, 0xCCAB, 0xCCAC, 0xCCAD, 0xCCAE, 0x1301, 0x1302, 0x1303, 0x1304,
    0x1305,
)

# Version code table for the second character of each 3-char group.
_JARM_VERSION_CODES = {
    0x0002: "1", 0x0300: "2", 0x0301: "3", 0x0302: "4", 0x0303: "5", 0x0304: "6",
}


def _mutate(ciphers: tuple[int, ...], order: str) -> tuple[int, ...]:
    """JARM's cipher-list mutations."""
    if order == "reverse":
        return tuple(reversed(ciphers))
    if order == "top-half":
        return ciphers[: (len(ciphers) + 1) // 2]
    if order == "bottom-half":
        return ciphers[(len(ciphers) + 1) // 2 :]
    if order == "middle-out":
        mid = len(ciphers) // 2
        out: list[int] = []
        for i in range(mid):
            if mid + i < len(ciphers):
                out.append(ciphers[mid + i])
            if mid - 1 - i >= 0:
                out.append(ciphers[mid - 1 - i])
        return tuple(out)
    return ciphers


def _jarm_specs() -> tuple[HelloSpec, ...]:
    """The ten JARM probes."""
    return (
        HelloSpec(name="j1", legacy_version=0x0303, ciphers=_mutate(_JARM_CIPHERS, "forward"),
                  supported_versions=(0x0303,)),
        HelloSpec(name="j2", legacy_version=0x0303, ciphers=_mutate(_JARM_CIPHERS, "reverse"),
                  supported_versions=(0x0303,)),
        HelloSpec(name="j3", legacy_version=0x0303, ciphers=_mutate(_JARM_CIPHERS, "top-half"),
                  supported_versions=(0x0303,)),
        HelloSpec(name="j4", legacy_version=0x0303, ciphers=_mutate(_JARM_CIPHERS, "bottom-half"),
                  supported_versions=(0x0303,)),
        HelloSpec(name="j5", legacy_version=0x0303, ciphers=_mutate(_JARM_CIPHERS, "middle-out"),
                  supported_versions=(0x0303,)),
        HelloSpec(name="j6", legacy_version=0x0302, ciphers=_mutate(_JARM_CIPHERS, "middle-out"),
                  include_supported_versions=False, alpn=()),
        HelloSpec(name="j7", legacy_version=0x0303, ciphers=_mutate(_JARM_CIPHERS, "forward"),
                  supported_versions=(0x0304,)),
        HelloSpec(name="j8", legacy_version=0x0303, ciphers=_mutate(_JARM_CIPHERS, "reverse"),
                  supported_versions=(0x0304,)),
        HelloSpec(name="j9", legacy_version=0x0303, ciphers=_mutate(_JARM_CIPHERS, "forward"),
                  supported_versions=(0x0304,), alpn=()),
        HelloSpec(name="j10", legacy_version=0x0303, ciphers=_mutate(_JARM_CIPHERS, "middle-out"),
                  supported_versions=(0x0304,)),
    )


JARM_HELLOS = _jarm_specs()

_JARM_EMPTY_GROUP = "000"
_JARM_NULL = "0" * 62


def _cipher_code(cipher: int | None) -> str:
    """Two-character base-36-ish index of the cipher in JARM's table."""
    if cipher is None:
        return "00"
    try:
        index = _JARM_CIPHERS.index(cipher) + 1
    except ValueError:
        return "00"
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    return f"{alphabet[index // 36]}{alphabet[index % 36]}"


def jarm_from_outcomes(outcomes: list[HelloOutcome]) -> str | None:
    """Assemble the 62-char JARM value. Pure.

    Returns None when no hello got an answer — an all-zero JARM would be
    indistinguishable from "a server that refuses everything", and a value
    that means nothing is worse than an absent one.
    """
    if not outcomes or not any(o.accepted for o in outcomes):
        return None
    groups: list[str] = []
    ext_material: list[str] = []
    for outcome in outcomes:
        if not outcome.accepted or outcome.cipher is None:
            groups.append(_JARM_EMPTY_GROUP)
            ext_material.append("")
            continue
        version_code = _JARM_VERSION_CODES.get(outcome.version or 0, "0")
        groups.append(f"{_cipher_code(outcome.cipher)}{version_code}")
        ext_material.append("-".join(f"{e:04x}" for e in outcome.extensions))
    fuzzy = "".join(groups)
    digest = hashlib.sha256("|".join(ext_material).encode("ascii")).hexdigest()[:32]
    jarm = f"{fuzzy}{digest}"
    return None if jarm == _JARM_NULL else jarm


async def run_jarm(ip: str, port: int, timeout: float) -> tuple[str | None, list[HelloOutcome]]:
    """Ten sequential hellos, then the fingerprint."""
    outcomes = [await _one_hello(ip, port, spec, timeout) for spec in JARM_HELLOS]
    return jarm_from_outcomes(outcomes), outcomes


def version_label(version: int) -> str:
    return _VERSION_LABELS.get(version, f"TLS 0x{version:04x}")
