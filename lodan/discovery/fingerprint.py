"""Passive TCP/IP stack fingerprinting from the discovery SYN-ACK.

Everything here is pure post-processing of bytes the target already sent in
reply to the discovery SYN — no extra packet, no payload, no traceroute, no
injected timing probe. The SYN-ACK is the richest passive OS signal on the
wire and lodan previously discarded everything below the application layer.

Three orthogonal signals come out of the same handful of header fields:

- `stack_sig` — a canonical, stable string over initial-TTL guess, advertised
  window, MSS, window scale and TCP option *order*. Option order is the part
  banners cannot fake: it is baked into the stack's SYN-ACK builder.
- `hop_count` — initial_ttl - observed_ttl. A topology dimension the
  port/service diff cannot see; a path change shows up here first.
- `clock_key` — a bucketed boot-time estimate from the TCP timestamp, which
  clusters several IPs onto one physical machine.

Signature matching is deliberately conservative: an unmatched stack returns
`None` rather than a guess, because a wrong OS attribution is worse than no
OS attribution in an inventory tool.
"""
from __future__ import annotations

from dataclasses import dataclass

from lodan.discovery.base import StackObservation

# Candidate initial TTLs. 32 is deliberately absent: essentially no modern
# stack ships it, and including it mis-attributes any ordinary ittl-64 host
# more than 32 hops away as a 2-hop exotic. 64 (Linux/BSD/macOS), 128
# (Windows), 255 (Solaris/AIX, most network gear) covers the real population.
_INITIAL_TTLS = (64, 128, 255)

# TCP option kind -> single-letter code. The *sequence* of these is the
# fingerprint; two stacks that offer an identical option set in a different
# order are different stacks.
_OPTION_CODES = {
    "MSS": "M",
    "SAckOK": "S",
    "SAck": "K",
    "Timestamp": "T",
    "WScale": "W",
    "NOP": "N",
    "EOL": "E",
}


def initial_ttl(observed: int | None) -> int | None:
    """Smallest plausible initial TTL >= the observed one."""
    if observed is None or observed <= 0 or observed > 255:
        return None
    for candidate in _INITIAL_TTLS:
        if observed <= candidate:
            return candidate
    return None


def hop_count(observed: int | None) -> int | None:
    """Router hops between us and the responder, or None if unguessable."""
    ittl = initial_ttl(observed)
    if ittl is None or observed is None:
        return None
    return ittl - observed


def option_codes(options: tuple[str, ...]) -> str:
    """Comma-joined option codes in wire order; '-' when there are none."""
    if not options:
        return "-"
    return ",".join(_OPTION_CODES.get(name, "?") for name in options)


def stack_sig(obs: StackObservation | None) -> str | None:
    """Canonical stack signature string.

    Format: ``ittl:window:mss:wscale:options:flags`` — e.g.
    ``64:64240:1460:7:M,S,T,N,W:DF``. Absent sub-signals render as ``*`` so
    the field count is fixed and the string stays parseable/groupable.
    """
    if obs is None:
        return None
    ittl = initial_ttl(obs.ttl)
    if ittl is None:
        return None
    flags = []
    if obs.df:
        flags.append("DF")
    if obs.ip_id == 0:
        flags.append("ID0")
    return ":".join(
        (
            str(ittl),
            str(obs.window),
            str(obs.mss) if obs.mss is not None else "*",
            str(obs.window_scale) if obs.window_scale is not None else "*",
            option_codes(obs.options),
            "+".join(flags) if flags else "-",
        )
    )


def stack_class(sig: str | None) -> str | None:
    """The per-machine-invariant subset of a stack signature.

    `stack_sig` is not safe to compare across ports of one host: the
    advertised TCP window (and often the window scale) is a per-socket
    property that varies with the listening application's SO_RCVBUF, so one
    machine legitimately shows different signatures on :22 and :443.

    Initial TTL, MSS and TCP option order do not vary that way — they come
    from the kernel's stack, and MSS is fixed by the path. This returns
    ``ittl:mss:options``, which is what a correlation pass may compare.
    """
    if not sig:
        return None
    parts = sig.split(":")
    if len(parts) != 6:
        return None
    ittl, _window, mss, _wscale, options, _flags = parts
    return f"{ittl}:{mss}:{options}"


@dataclass(frozen=True)
class StackSig:
    """One OS-family rule. Every non-None field must match to fire.

    Mirrors the `enrich.tech_signatures.TechSig` shape: a flat table of
    declarative constraints, no logic per entry.
    """

    os_family: str
    confidence: float
    ittl: int | None = None
    options: str | None = None          # exact option-code string
    window_scale: int | None = None
    windows: frozenset[int] | None = None
    timestamps: bool | None = None
    max_window: int | None = None


@dataclass(frozen=True)
class OSGuess:
    os_family: str
    confidence: float


# Ordered most- to least-specific; the highest-confidence match wins, ties
# break toward the earlier entry. Option orders below are the SYN-ACK orders
# these stacks actually emit, not the SYN orders (they differ).
SIGNATURES: tuple[StackSig, ...] = (
    # Linux 3.x+ — MSS, SACK-permitted, timestamps, NOP, window scale.
    StackSig("linux", 0.9, ittl=64, options="M,S,T,N,W",
             windows=frozenset({64240, 65160, 29200, 28960, 14600, 5840})),
    StackSig("linux", 0.7, ittl=64, options="M,S,T,N,W"),
    # Linux with timestamps disabled (net.ipv4.tcp_timestamps=0).
    StackSig("linux", 0.6, ittl=64, options="M,N,N,S,N,W"),
    # Windows Vista..11 / Server 2008+ — note W before S, and the NOP padding.
    StackSig("windows", 0.9, ittl=128, options="M,N,W,N,N,S",
             windows=frozenset({8192, 65535, 64240, 8760})),
    StackSig("windows", 0.7, ittl=128, options="M,N,W,N,N,S"),
    # Windows with scaling declined, and legacy XP/2003.
    StackSig("windows", 0.6, ittl=128, options="M,N,N,S"),
    StackSig("windows", 0.5, ittl=128),
    # macOS / iOS (Darwin) — trailing EOL padding is the tell.
    StackSig("macos", 0.85, ittl=64, options="M,N,W,N,N,T,S,E"),
    StackSig("macos", 0.7, ittl=64, options="M,N,W,N,N,T,S,E,E"),
    # FreeBSD.
    StackSig("freebsd", 0.8, ittl=64, options="M,N,W,S,T"),
    # OpenBSD / NetBSD.
    StackSig("openbsd", 0.8, ittl=64, options="M,N,N,S,N,W,N,N,T"),
    # Solaris / AIX and most routers, switches, firewalls, printers.
    StackSig("network-device", 0.6, ittl=255, options="M,N,N,S"),
    StackSig("network-device", 0.5, ittl=255),
    # Minimal embedded stacks (lwIP, uIP, vendor firmware): MSS only, tiny
    # window, no timestamps. Checked last — it is the weakest inference.
    StackSig("embedded", 0.5, ittl=64, options="M", timestamps=False,
             max_window=8192),
    StackSig("embedded", 0.45, ittl=64, options="M,N,N,S", timestamps=False,
             max_window=8192),
)


def _matches(sig: StackSig, obs: StackObservation, codes: str, ittl: int) -> bool:
    if sig.ittl is not None and sig.ittl != ittl:
        return False
    if sig.options is not None and sig.options != codes:
        return False
    if sig.window_scale is not None and sig.window_scale != obs.window_scale:
        return False
    if sig.windows is not None and obs.window not in sig.windows:
        return False
    if sig.timestamps is not None and sig.timestamps != obs.timestamps:
        return False
    return not (sig.max_window is not None and obs.window > sig.max_window)


def os_family(obs: StackObservation | None) -> OSGuess | None:
    """Best-effort OS family for a stack observation, or None if unmatched.

    Returns the highest-confidence matching signature. Unmatched is a first-
    class answer — an inventory tool is better off saying nothing than
    asserting the wrong OS.
    """
    if obs is None:
        return None
    ittl = initial_ttl(obs.ttl)
    if ittl is None:
        return None
    codes = option_codes(obs.options)
    best: StackSig | None = None
    for sig in SIGNATURES:
        if _matches(sig, obs, codes, ittl) and (best is None or sig.confidence > best.confidence):
            best = sig
    if best is None:
        return None
    return OSGuess(os_family=best.os_family, confidence=best.confidence)


# TCP timestamp clock rate. RFC 7323 leaves it implementation-defined; 1000 Hz
# (1 ms tick) is what Linux, modern Windows and the BSDs converged on. A host
# ticking at a different rate lands in a different bucket rather than a wrong
# one, which is the behaviour we want from a clustering key.
DEFAULT_HZ = 1000
DEFAULT_BUCKET_S = 60


def clock_key(
    obs: StackObservation | None,
    *,
    hz: int = DEFAULT_HZ,
    bucket_s: int = DEFAULT_BUCKET_S,
) -> str | None:
    """Bucketed boot-time estimate, for clustering IPs onto one machine.

    `TSval` counts up from boot, so `now - TSval/hz` estimates when the
    responder booted. Two addresses whose estimates land in the same bucket
    are plausibly the same physical host behind different IPs.

    This is a *lead*, not proof: the tick rate is assumed, and two genuinely
    distinct machines booted in the same minute collide. It is a pivot in the
    same sense JA3S is — a grouping to investigate, not an identity.
    """
    if obs is None or not obs.ts_val or obs.observed_at is None:
        return None
    if hz <= 0 or bucket_s <= 0:
        return None
    boot = obs.observed_at - (obs.ts_val / hz)
    return f"{hz}:{int(boot // bucket_s) * bucket_s}"


def consensus(values: list[str | None]) -> str | None:
    """Single agreed value across a host's ports, else None.

    Deliberately unanimous-or-nothing: ports that disagree are exactly the
    NAT / load-balancer signal, so collapsing them to a majority here would
    destroy the evidence rather than surface it.
    """
    seen = {v for v in values if v is not None}
    if len(seen) == 1:
        return seen.pop()
    return None


def modal_hops(values: list[int | None]) -> int | None:
    """Most common hop count across a host's ports; ties break toward the
    shorter path (the closest observed route is the conservative answer)."""
    present = [v for v in values if v is not None]
    if not present:
        return None
    counts: dict[int, int] = {}
    for v in present:
        counts[v] = counts.get(v, 0) + 1
    return min(counts, key=lambda v: (-counts[v], v))
