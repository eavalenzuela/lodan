"""Minimal DNS client for resolving authorized domains.

lodan needs something `getaddrinfo` cannot give it: **visibility of the CNAME
chain**. A domain that is a CNAME to somebody else's infrastructure resolves
to addresses that belong to that third party, and scanning those is exactly
what an authorization model exists to prevent. `getaddrinfo` flattens all of
that away and hands back addresses with no indication of how it got there.

So this is a small hand-rolled query/parse pair over UDP, in the same spirit
as the TLS, SSH and SNMP parsers: A and AAAA queries, the answer chain read
back record by record, bounds-checked throughout, with pointer-loop
protection.

Nothing here talks to a scan target — it talks to the operator's own
configured resolver.
"""
from __future__ import annotations

import asyncio
import random
import struct
from dataclasses import dataclass, field
from pathlib import Path

TYPE_A = 1
TYPE_AAAA = 28
TYPE_CNAME = 5
CLASS_IN = 1

_RESOLV_CONF = Path("/etc/resolv.conf")
_DNS_PORT = 53
_MAX_LABEL = 63
_MAX_NAME = 253


class DNSError(Exception):
    """Resolution could not be completed."""


@dataclass(frozen=True)
class Answer:
    name: str
    rtype: int
    value: str


@dataclass
class Resolution:
    """Everything one domain's A + AAAA lookup told us."""

    domain: str
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    cnames: list[tuple[str, str]] = field(default_factory=list)   # (from, to)
    error: str | None = None

    @property
    def addresses(self) -> list[str]:
        return [*self.a, *self.aaaa]

    @property
    def cname_targets(self) -> list[str]:
        return [target for _source, target in self.cnames]


def nameservers(path: Path | None = None) -> list[str]:
    """Read resolver addresses from resolv.conf."""
    conf = path or _RESOLV_CONF
    try:
        text = conf.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            out.append(parts[1])
    return out


# --- wire format -------------------------------------------------------------


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        encoded = label.encode("idna") if not label.isascii() else label.encode("ascii")
        if len(encoded) > _MAX_LABEL:
            raise DNSError(f"label too long in {name!r}")
        out += bytes([len(encoded)]) + encoded
    return out + b"\x00"


def build_query(name: str, rtype: int, *, transaction_id: int | None = None) -> bytes:
    tid = transaction_id if transaction_id is not None else random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)   # RD set
    return header + encode_name(name) + struct.pack(">HH", rtype, CLASS_IN)


def _read_name(buf: bytes, pos: int, depth: int = 0) -> tuple[str, int]:
    """Decode a name, following compression pointers with a depth bound.

    The bound matters: a hostile or broken resolver response can encode a
    pointer that references itself, and this must terminate rather than spin.
    """
    labels: list[str] = []
    jumped = False
    end = pos
    while pos < len(buf):
        length = buf[pos]
        if length == 0:
            pos += 1
            if not jumped:
                end = pos
            break
        if length & 0xC0 == 0xC0:
            if pos + 2 > len(buf) or depth > 10:
                raise DNSError("bad or looping name pointer")
            pointer = struct.unpack_from(">H", buf, pos)[0] & 0x3FFF
            if not jumped:
                end = pos + 2
            jumped = True
            suffix, _ = _read_name(buf, pointer, depth + 1)
            if suffix:
                labels.append(suffix)
            break
        pos += 1
        if pos + length > len(buf):
            raise DNSError("label overruns response")
        labels.append(buf[pos : pos + length].decode("ascii", "replace"))
        pos += length
        if not jumped:
            end = pos
    return ".".join(labels), end


def parse_response(raw: bytes) -> list[Answer]:
    """Read the answer section. Raises DNSError on anything malformed."""
    if len(raw) < 12:
        raise DNSError("response too short")
    _tid, flags, qdcount, ancount, _ns, _ar = struct.unpack_from(">HHHHHH", raw, 0)
    rcode = flags & 0x0F
    if rcode == 3:
        return []                       # NXDOMAIN: a definitive "no such name"
    if rcode != 0:
        raise DNSError(f"resolver returned rcode {rcode}")

    pos = 12
    for _ in range(qdcount):
        _name, pos = _read_name(raw, pos)
        pos += 4

    answers: list[Answer] = []
    for _ in range(ancount):
        name, pos = _read_name(raw, pos)
        if pos + 10 > len(raw):
            raise DNSError("truncated answer header")
        rtype, _rclass, _ttl, rdlength = struct.unpack_from(">HHIH", raw, pos)
        pos += 10
        if pos + rdlength > len(raw):
            raise DNSError("answer rdata overruns response")
        rdata = raw[pos : pos + rdlength]
        if rtype == TYPE_A and rdlength == 4:
            answers.append(Answer(name, rtype, ".".join(str(b) for b in rdata)))
        elif rtype == TYPE_AAAA and rdlength == 16:
            groups = struct.unpack(">8H", rdata)
            answers.append(
                Answer(name, rtype, _compress_v6(":".join(f"{g:x}" for g in groups)))
            )
        elif rtype == TYPE_CNAME:
            target, _ = _read_name(raw, pos)
            answers.append(Answer(name, rtype, target))
        pos += rdlength
    return answers


def _compress_v6(text: str) -> str:
    from ipaddress import ip_address

    try:
        return str(ip_address(text))
    except ValueError:
        return text


# --- transport ---------------------------------------------------------------


class _Collector(asyncio.DatagramProtocol):
    def __init__(self, future: asyncio.Future) -> None:
        self._future = future

    def datagram_received(self, data: bytes, addr) -> None:  # noqa: ARG002
        if not self._future.done():
            self._future.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self._future.done():
            self._future.set_exception(exc)


async def _ask(server: str, payload: bytes, timeout: float) -> bytes:
    loop = asyncio.get_running_loop()
    future: asyncio.Future = loop.create_future()
    transport = None
    try:
        transport, _protocol = await loop.create_datagram_endpoint(
            lambda: _Collector(future), remote_addr=(server, _DNS_PORT)
        )
        transport.sendto(payload)
        return await asyncio.wait_for(future, timeout=timeout)
    finally:
        if transport is not None:
            transport.close()


async def resolve(
    domain: str,
    *,
    timeout: float = 3.0,
    servers: list[str] | None = None,
) -> Resolution:
    """Look up A and AAAA for `domain`, preserving the CNAME chain."""
    resolution = Resolution(domain=domain)
    if len(domain) > _MAX_NAME:
        resolution.error = "domain name too long"
        return resolution
    pool = servers if servers is not None else nameservers()
    if not pool:
        # Deliberately not falling back to getaddrinfo: it hides the CNAME
        # chain, and a weaker check that silently looks like the strong one is
        # worse than an honest failure.
        resolution.error = "no resolver configured (checked /etc/resolv.conf)"
        return resolution

    for rtype in (TYPE_A, TYPE_AAAA):
        answers: list[Answer] | None = None
        last_error: str | None = None
        for server in pool:
            try:
                raw = await _ask(server, build_query(domain, rtype), timeout)
                answers = parse_response(raw)
                break
            except (DNSError, TimeoutError, OSError) as e:
                last_error = str(e) or type(e).__name__
                continue
        if answers is None:
            resolution.error = last_error or "resolution failed"
            continue
        for answer in answers:
            if answer.rtype == TYPE_A:
                resolution.a.append(answer.value)
            elif answer.rtype == TYPE_AAAA:
                resolution.aaaa.append(answer.value)
            elif answer.rtype == TYPE_CNAME:
                pair = (answer.name.rstrip("."), answer.value.rstrip("."))
                if pair not in resolution.cnames:
                    resolution.cnames.append(pair)
    # A and AAAA queries both return the same CNAME chain; dedupe addresses too.
    resolution.a = sorted(set(resolution.a))
    resolution.aaaa = sorted(set(resolution.aaaa))
    return resolution
