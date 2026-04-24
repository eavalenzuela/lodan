"""Banner -> CPE -> CVE matching.

Pragmatic, not perfect. The CPE we build from a banner is a best-guess
("cpe:2.3:a:vendor:product:version"); we LIKE-search the shared cve_cpe
table for rows whose CPE starts with that string. Every hit is written to
the per-workspace vulns table with a confidence score so the operator
knows how firm the match is.

Recognizers to start with:
- Apache httpd           "Apache/2.4.54 (Ubuntu)"        -> apache:http_server:2.4.54
- nginx                  "nginx/1.25.3"                  -> nginx:nginx:1.25.3
- OpenSSH                "SSH-2.0-OpenSSH_8.2p1 Ubuntu"  -> openbsd:openssh:8.2p1
- Microsoft IIS          "Microsoft-IIS/10.0"            -> microsoft:internet_information_services:10.0

More recognizers land as we see field data that needs them.
"""
from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass


@dataclass(frozen=True)
class CPEGuess:
    vendor: str
    product: str
    version: str
    confidence: float
    source: str

    @property
    def prefix(self) -> str:
        return f"cpe:2.3:a:{self.vendor}:{self.product}:{self.version}:"


@dataclass(frozen=True)
class CVEMatch:
    cve: str
    cpe: str
    cvss: float | None
    confidence: float
    source: str


# (regex, vendor, product, optional version-normalizer)
_RECOGNIZERS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"Apache/(\d+\.\d+\.\d+)", re.I), "apache", "http_server"),
    (re.compile(r"\bnginx/(\d+\.\d+\.\d+)"), "nginx", "nginx"),
    (re.compile(r"OpenSSH_(\d+(?:\.\d+)?(?:p\d+)?)", re.I), "openbsd", "openssh"),
    (re.compile(r"Microsoft-IIS/(\d+(?:\.\d+)?)", re.I), "microsoft", "internet_information_services"),
    (re.compile(r"lighttpd/(\d+\.\d+\.\d+)"), "lighttpd", "lighttpd"),
    (re.compile(r"Caddy\s+v?(\d+\.\d+\.\d+)"), "caddy", "caddy"),
]


def banner_to_cpes(banner: str | None) -> list[CPEGuess]:
    if not banner:
        return []
    out: list[CPEGuess] = []
    for pat, vendor, product in _RECOGNIZERS:
        m = pat.search(banner)
        if not m:
            continue
        version = m.group(1)
        out.append(
            CPEGuess(
                vendor=vendor,
                product=product,
                version=version,
                confidence=0.7,
                source="banner-regex",
            )
        )
    return out


def match_cpes(cve_conn: sqlite3.Connection, guesses: list[CPEGuess]) -> list[CVEMatch]:
    hits: list[CVEMatch] = []
    for g in guesses:
        prefix = g.prefix
        for cpe, cve, cvss in cve_conn.execute(
            "SELECT cpe, cve, cvss FROM cve_cpe WHERE cpe LIKE ? || '%'",
            (prefix,),
        ):
            hits.append(
                CVEMatch(
                    cve=cve,
                    cpe=cpe,
                    cvss=cvss,
                    confidence=g.confidence,
                    source=g.source,
                )
            )
    return hits


def enrich_cves(
    workspace_conn: sqlite3.Connection,
    cve_conn: sqlite3.Connection,
    scan_id: int,
) -> int:
    """Match every service's banner against the shared CVE DB.

    Returns the number of (scan_id, ip, port, cve) rows inserted. Duplicates
    for a scan collapse via PRIMARY KEY-less INSERT-or-skip semantics: the
    vulns table doesn't have a PK, but we dedupe in-Python before insert so
    re-running the enrichment phase doesn't multiply rows.
    """
    services = workspace_conn.execute(
        """
        SELECT ip, port, banner, raw
        FROM services
        WHERE scan_id = ? AND (banner IS NOT NULL OR raw IS NOT NULL)
        """,
        (scan_id,),
    ).fetchall()
    if not services:
        return 0

    # Clear any prior vuln rows for this scan so re-runs are idempotent.
    workspace_conn.execute("DELETE FROM vulns WHERE scan_id = ?", (scan_id,))

    inserts: list[tuple] = []
    seen: set[tuple[str, int, str]] = set()
    for ip, port, banner, raw in services:
        effective_banner = banner or ""
        if raw:
            effective_banner = effective_banner + " " + _banner_from_raw(raw)
        guesses = banner_to_cpes(effective_banner)
        if not guesses:
            continue
        for match in match_cpes(cve_conn, guesses):
            key = (ip, port, match.cve)
            if key in seen:
                continue
            seen.add(key)
            inserts.append(
                (scan_id, ip, port, match.cve, match.cpe, match.confidence, match.source)
            )

    if not inserts:
        return 0
    workspace_conn.executemany(
        "INSERT INTO vulns (scan_id, ip, port, cve, cpe, confidence, source) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        inserts,
    )
    return len(inserts)


def _banner_from_raw(raw: str | bytes) -> str:
    """Some probes (e.g. SSH) stash the richer banner in raw as JSON; flatten
    the string fields so banner_to_cpes can see them."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    try:
        data = json.loads(raw)
    except Exception:
        return ""
    pieces: list[str] = []
    if isinstance(data, dict):
        for k in ("banner", "title", "server"):
            v = data.get(k)
            if isinstance(v, str):
                pieces.append(v)
        parsed = data.get("parsed")
        if isinstance(parsed, dict):
            sw = parsed.get("software")
            if isinstance(sw, str):
                pieces.append(sw)
    return " ".join(pieces)
