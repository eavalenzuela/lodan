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
from typing import Any

from lodan.enrich import version


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

    @property
    def product_prefix(self) -> str:
        """CPE up to (not including) the version.

        Range-expressed advisories carry a wildcard version, so matching them
        means selecting on vendor+product and evaluating the version against
        the stored bounds rather than string-prefixing the whole CPE.
        """
        return f"cpe:2.3:a:{self.vendor}:{self.product}:"


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


# Structured version fields the probes already parse, keyed by service name.
# Each entry is (path into `raw`, vendor, product). These are authoritative —
# the server reported its own version in a dedicated field rather than in
# prose — so they carry higher confidence than a banner regex.
#
# Without these, whole protocol families get zero CVE coverage: the banner
# recognizers only ever caught web-server and SSH strings, so Redis, Docker,
# MongoDB, Kubernetes, Elasticsearch and MySQL matched nothing at all.
_RAW_RECOGNIZERS: tuple[tuple[str, tuple[str, ...], str, str], ...] = (
    ("redis", ("fields", "redis_version"), "redis", "redis"),
    ("docker", ("payload", "Version"), "docker", "docker"),
    ("kubernetes", ("payload", "gitVersion"), "kubernetes", "kubernetes"),
    ("elasticsearch", ("version",), "elastic", "elasticsearch"),
    ("mongo", ("version",), "mongodb", "mongodb"),
    ("mysql", ("server_version",), "oracle", "mysql"),
)

_RAW_CONFIDENCE = 0.9

# Version strings that carry distro packaging noise ("8.0.35-0ubuntu0.22.04.1",
# "1.28.2+k3s1"). The upstream version is the part before the first '-' or '+'.
_PACKAGING_SUFFIX = re.compile(r"[-+].*$")

_VERSION_LEAD = re.compile(r"^v?\d+(?:\.\d+)*(?:p\d+)?")


def _dig(data: Any, path: tuple[str, ...]) -> Any:
    for key in path:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


def _clean_version(value: Any) -> str | None:
    """Reduce a reported version string to its upstream version number."""
    if not isinstance(value, str):
        return None
    text = _PACKAGING_SUFFIX.sub("", value.strip())
    m = _VERSION_LEAD.match(text)
    if not m:
        return None
    cleaned = m.group(0)
    return cleaned[1:] if cleaned[:1] in ("v", "V") else cleaned


def raw_to_cpes(service: str | None, raw: Any) -> list[CPEGuess]:
    """Build CPEs from the structured version fields a probe stored.

    Higher confidence than `banner_to_cpes` because these come from a field
    the service publishes for exactly this purpose, not from prose that
    happened to contain a number.
    """
    if not isinstance(raw, dict):
        return []
    out: list[CPEGuess] = []
    for svc, path, vendor, product in _RAW_RECOGNIZERS:
        if service != svc:
            continue
        cleaned = _clean_version(_dig(raw, path))
        if cleaned:
            out.append(CPEGuess(
                vendor=vendor, product=product, version=cleaned,
                confidence=_RAW_CONFIDENCE, source="raw-field",
            ))
    # SSH stores its parsed software string; OpenSSH's own version is the one
    # NVD indexes, and ssh.py has already split it out of the banner.
    if service == "ssh":
        software = _dig(raw, ("parsed", "software"))
        if isinstance(software, str):
            m = re.search(r"OpenSSH_(\d+(?:\.\d+)*(?:p\d+)?)", software, re.I)
            if m:
                out.append(CPEGuess(
                    vendor="openbsd", product="openssh", version=m.group(1),
                    confidence=_RAW_CONFIDENCE, source="raw-field",
                ))
    # HTTP's X-Powered-By names the application runtime, which the Server
    # header usually does not.
    headers = raw.get("headers")
    if isinstance(headers, dict):
        powered = headers.get("x-powered-by")
        if isinstance(powered, str):
            m = re.search(r"PHP/(\d+(?:\.\d+)*)", powered, re.I)
            if m:
                out.append(CPEGuess(
                    vendor="php", product="php", version=m.group(1),
                    confidence=_RAW_CONFIDENCE, source="raw-field",
                ))
    return out


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


def _cpe_version(cpe: str) -> str:
    """Field 5 of a CPE 2.3 URI: cpe:2.3:part:vendor:product:version:..."""
    parts = cpe.split(":")
    return parts[5] if len(parts) > 5 else "*"


# A wildcard-version CPE with no bounds means "every version of this product".
# That is a real NVD encoding, but it is also the broadest possible match, so
# it is admitted at reduced confidence rather than at the recognizer's.
_UNBOUNDED_WILDCARD_PENALTY = 0.5


def match_cpes(cve_conn: sqlite3.Connection, guesses: list[CPEGuess]) -> list[CVEMatch]:
    """Match version guesses against the CVE DB, honouring NVD version ranges.

    Two shapes of row have to be handled:

    - A concrete version in the CPE itself ("…:httpd:2.4.54:…"). Compared by
      parsed version equality, so `2.4.54` doesn't spuriously prefix-match
      `2.4.5`.
    - A wildcard version plus range bounds ("…:httpd:*:…" with
      versionEndExcluding 2.4.55). These are the majority of modern advisories
      and could never match under the old exact-prefix LIKE, which is the
      single biggest precision gap this fixes — in both directions, since
      range evaluation also *suppresses* the versions outside the range.
    """
    hits: list[CVEMatch] = []
    for g in guesses:
        for cpe, cve, cvss, v_start, start_incl, v_end, end_incl in cve_conn.execute(
            "SELECT cpe, cve, cvss, version_start, version_start_inclusive, "
            "       version_end, version_end_inclusive "
            "FROM cve_cpe WHERE cpe LIKE ? || '%'",
            (g.product_prefix,),
        ):
            cpe_version = _cpe_version(cpe)
            confidence = g.confidence
            if cpe_version not in ("*", "-"):
                if version.compare(g.version, cpe_version) != 0:
                    continue
            elif v_start is None and v_end is None:
                confidence = round(g.confidence * _UNBOUNDED_WILDCARD_PENALTY, 3)
            elif not version.in_range(
                g.version,
                start=v_start,
                start_inclusive=bool(start_incl),
                end=v_end,
                end_inclusive=bool(end_incl),
            ):
                continue
            hits.append(
                CVEMatch(
                    cve=cve,
                    cpe=cpe,
                    cvss=cvss,
                    confidence=confidence,
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
        SELECT ip, port, service, banner, raw
        FROM services
        WHERE scan_id = ? AND (banner IS NOT NULL OR raw IS NOT NULL)
        """,
        (scan_id,),
    ).fetchall()
    if not services:
        return 0

    # Clear any prior vuln rows for this scan so re-runs are idempotent.
    # `keyposture` rows are written by a separate pass and must survive.
    workspace_conn.execute(
        "DELETE FROM vulns WHERE scan_id = ? AND COALESCE(source,'') != 'keyposture'",
        (scan_id,),
    )

    inserts: list[tuple] = []
    seen: set[tuple[str, int, str]] = set()
    for ip, port, service, banner, raw in services:
        effective_banner = banner or ""
        parsed_raw = _load_raw(raw)
        if raw:
            effective_banner = effective_banner + " " + _banner_from_raw(raw)
        # Structured fields first: when both paths name the same CVE the
        # higher-confidence authoritative reading is the one that sticks.
        guesses = raw_to_cpes(service, parsed_raw) + banner_to_cpes(effective_banner)
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


def _load_raw(raw: Any) -> dict[str, Any] | None:
    if not raw:
        return None
    if isinstance(raw, bytes | bytearray):
        raw = raw.decode("utf-8", "replace")
    if isinstance(raw, dict):
        return raw
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


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
