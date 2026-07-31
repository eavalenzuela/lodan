"""NAT / load-balancer detection and backend counting.

One IP answering on several ports is usually one machine. Sometimes it is a
VIP in front of several, and the give-away is that the per-port fingerprints
disagree in ways a single host cannot produce. This pass is pure correlation
over rows already in the store — it sends nothing.

The whole design turns on which disagreements are *conclusive* and which are
merely interesting, because the naive version of this check is a false-positive
machine:

- **os_family** and the invariant part of **stack_sig** are conclusive. They
  come from the kernel's TCP stack (initial TTL, MSS, TCP option order); one
  machine has exactly one. Linux on :443 and Windows on :3389 is two machines,
  full stop.
- **ssh_hostkey** is conclusive. Two different host keys means two sshd
  instances with separate key material, which in practice means two hosts.
- **ja3s / ja4s / cert_fingerprint** are *suggestive only*. One host running
  nginx on :443 and a Java service on :8443 legitimately presents two TLS
  stacks and two certificates. Counting these would flag most real servers.

So `min_backend_count` is driven only by the conclusive dimensions, and it is
the **max** across them rather than the sum: two SSH keys and two OS families
is evidence of at least two machines, not four. Suggestive disagreements are
recorded as evidence an operator can look at, but never set the flag.

Note the *min* in the name — this is a floor. Ten identical Linux boxes behind
a VIP are indistinguishable from one, and this pass will honestly say 1.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

from lodan.discovery.fingerprint import stack_class

CONCLUSIVE = ("os_family", "stack_class", "ssh_hostkey")
SUGGESTIVE = ("ja3s", "ja4s", "cert_fingerprint")


@dataclass(frozen=True)
class Disagreement:
    """One dimension on which a host's ports do not agree."""

    dimension: str
    values: tuple[str, ...]
    conclusive: bool

    def as_dict(self) -> dict:
        return {
            "dimension": self.dimension,
            "values": list(self.values),
            "conclusive": self.conclusive,
        }


@dataclass(frozen=True)
class TopologyVerdict:
    min_backend_count: int
    nat_suspected: bool
    evidence: tuple[Disagreement, ...]
    measurable: bool
    """Whether any conclusive dimension had a value at all.

    Without one, `min_backend_count == 1` is not a measurement — it is the
    absence of one, and must not be stored. Storing it would let an
    unmeasured host in one scan diff against a measured host in the next and
    report a topology change that never happened.
    """


@dataclass(frozen=True)
class ServiceFingerprints:
    """The identity-bearing fields of one probed port."""

    port: int
    os_family: str | None = None
    stack_sig: str | None = None
    ssh_hostkey: str | None = None
    ja3s: str | None = None
    ja4s: str | None = None
    cert_fingerprint: str | None = None


def _distinct(rows: list[ServiceFingerprints], dimension: str) -> tuple[str, ...]:
    if dimension == "stack_class":
        values = {stack_class(r.stack_sig) for r in rows}
    else:
        values = {getattr(r, dimension) for r in rows}
    return tuple(sorted(v for v in values if v))


def analyse(rows: list[ServiceFingerprints]) -> TopologyVerdict:
    """Correlate one host's per-port fingerprints into a backend estimate."""
    evidence: list[Disagreement] = []
    floor = 1
    measurable = False
    for dimension in CONCLUSIVE:
        values = _distinct(rows, dimension)
        if values:
            measurable = True
        if len(values) > 1:
            floor = max(floor, len(values))
            evidence.append(Disagreement(dimension, values, conclusive=True))
    for dimension in SUGGESTIVE:
        values = _distinct(rows, dimension)
        if len(values) > 1:
            evidence.append(Disagreement(dimension, values, conclusive=False))
    return TopologyVerdict(
        min_backend_count=floor,
        nat_suspected=floor > 1,
        evidence=tuple(evidence),
        measurable=measurable,
    )


def enrich_topology(conn: sqlite3.Connection, scan_id: int) -> int:
    """Write nat_suspected / min_backend_count / evidence onto `hosts`.

    Returns the number of hosts flagged as fronting more than one backend.
    Idempotent — a pure function of rows already stored.
    """
    rows = conn.execute(
        "SELECT ip, port, os_family, stack_sig, ssh_hostkey, ja3s, ja4s, cert_fingerprint "
        "FROM services WHERE scan_id = ?",
        (scan_id,),
    ).fetchall()
    if not rows:
        return 0

    per_ip: dict[str, list[ServiceFingerprints]] = {}
    for ip, port, os_family, stack_sig, hostkey, ja3s, ja4s, cert_fp in rows:
        per_ip.setdefault(ip, []).append(
            ServiceFingerprints(
                port=port, os_family=os_family, stack_sig=stack_sig,
                ssh_hostkey=hostkey, ja3s=ja3s, ja4s=ja4s, cert_fingerprint=cert_fp,
            )
        )

    flagged = 0
    for ip, services in per_ip.items():
        verdict = analyse(services)
        if not verdict.measurable:
            continue
        detail = (
            json.dumps([d.as_dict() for d in verdict.evidence])
            if verdict.evidence else None
        )
        conn.execute(
            """
            INSERT INTO hosts (scan_id, ip, nat_suspected, min_backend_count, backend_evidence)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(scan_id, ip) DO UPDATE SET
                nat_suspected = excluded.nat_suspected,
                min_backend_count = excluded.min_backend_count,
                backend_evidence = excluded.backend_evidence
            """,
            (scan_id, ip, 1 if verdict.nat_suspected else 0,
             verdict.min_backend_count, detail),
        )
        if verdict.nat_suspected:
            flagged += 1
    return flagged
