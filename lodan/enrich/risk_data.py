"""Ingestion for the rising-risk datasets: EPSS, CISA KEV, and EOL.

Mirrors the `cve_data` pattern — fetch a static snapshot out-of-band, park it
in the shared `~/.lodan/data` DB, and let enrichment join against it offline.
None of this touches a scan target.

Why these three:

- **EPSS** (FIRST) scores how likely a CVE is to be exploited in the next 30
  days. CVSS says how bad it would be; EPSS says how likely it is to happen,
  which is what actually orders a remediation queue.
- **KEV** (CISA) is the confirmed-exploited-in-the-wild list. Binary, and it
  outranks any score.
- **EOL** is a genuine wire-derived exposure that CVE matching misses *by
  design*: an out-of-support Apache or Ubuntu has no specific CVE for being
  out of support, but it will never get another patch.

Each parser takes already-fetched data so it can be tested without a network.
"""
from __future__ import annotations

import csv
import io
import json
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
# endoflife.date exposes one JSON document per product.
EOL_URL_TEMPLATE = "https://endoflife.date/api/{product}.json"

# Products lodan can actually detect, mapped to their endoflife.date slug.
# Keeping this explicit (rather than fetching the whole catalogue) keeps the
# download small and the join keys under our control.
EOL_PRODUCTS: dict[str, str] = {
    "ubuntu": "ubuntu",
    "debian": "debian",
    "centos": "centos",
    "rhel": "rhel",
    "apache": "apache",
    "nginx": "nginx",
    "openssh": "openssh",
    "redis": "redis",
    "mongodb": "mongodb",
    "elasticsearch": "elasticsearch",
    "mysql": "mysql",
    "postgresql": "postgresql",
    "kubernetes": "kubernetes",
    "docker-engine": "docker-engine",
    "php": "php",
    "windows-server": "windows-server",
}


@dataclass
class RiskUpdateStats:
    epss_rows: int = 0
    kev_rows: int = 0
    eol_rows: int = 0


def _schema_sql() -> str:
    return (files("lodan.enrich") / "risk_schema.sql").read_text(encoding="utf-8")


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Idempotent; safe on a cve.db that predates these tables."""
    conn.executescript(_schema_sql())


# --- EPSS --------------------------------------------------------------------


def parse_epss_csv(text: str) -> list[tuple[str, float, float | None, str | None]]:
    """Parse the EPSS CSV.

    The published file starts with a `#model_version:...,score_date:...`
    comment line before the header, so comments are skipped rather than
    assumed away.
    """
    scored_on: str | None = None
    rows: list[tuple[str, float, float | None, str | None]] = []
    lines: list[str] = []
    for line in text.splitlines():
        if line.startswith("#"):
            for part in line.lstrip("#").split(","):
                key, _, value = part.partition(":")
                if key.strip() == "score_date":
                    scored_on = value.strip()
            continue
        lines.append(line)
    if not lines:
        return []
    for record in csv.DictReader(io.StringIO("\n".join(lines))):
        cve = (record.get("cve") or "").strip()
        if not cve.upper().startswith("CVE-"):
            continue
        try:
            score = float(record.get("epss") or "")
        except ValueError:
            continue
        try:
            percentile: float | None = float(record.get("percentile") or "")
        except ValueError:
            percentile = None
        rows.append((cve.upper(), score, percentile, scored_on))
    return rows


def upsert_epss(conn: sqlite3.Connection, rows: Iterable[tuple]) -> int:
    rows = list(rows)
    if not rows:
        return 0
    conn.executemany(
        "INSERT INTO epss (cve, score, percentile, scored_on) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(cve) DO UPDATE SET score = excluded.score, "
        "percentile = excluded.percentile, scored_on = excluded.scored_on",
        rows,
    )
    return len(rows)


# --- KEV ---------------------------------------------------------------------


def parse_kev(payload: dict[str, Any] | str) -> list[tuple]:
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except ValueError:
            return []
    if not isinstance(payload, dict):
        return []
    out: list[tuple] = []
    for item in payload.get("vulnerabilities") or ():
        if not isinstance(item, dict):
            continue
        cve = (item.get("cveID") or "").strip().upper()
        if not cve.startswith("CVE-"):
            continue
        ransomware = item.get("knownRansomwareCampaignUse")
        out.append((
            cve,
            item.get("vendorProject"),
            item.get("product"),
            item.get("vulnerabilityName"),
            item.get("dateAdded"),
            item.get("dueDate"),
            1 if isinstance(ransomware, str) and ransomware.lower() == "known" else 0,
            item.get("shortDescription"),
        ))
    return out


def upsert_kev(conn: sqlite3.Connection, rows: Iterable[tuple]) -> int:
    rows = list(rows)
    if not rows:
        return 0
    conn.executemany(
        "INSERT INTO kev (cve, vendor, product, name, date_added, due_date, "
        "ransomware, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(cve) DO UPDATE SET vendor = excluded.vendor, "
        "product = excluded.product, name = excluded.name, "
        "date_added = excluded.date_added, due_date = excluded.due_date, "
        "ransomware = excluded.ransomware, notes = excluded.notes",
        rows,
    )
    return len(rows)


# --- EOL ---------------------------------------------------------------------


def parse_eol(product: str, payload: list | str) -> list[tuple]:
    """Parse one endoflife.date product document.

    `eol` is polymorphic in that feed: a date string when support has an end,
    `true`/`false` when it is simply over or ongoing. Booleans carry no date,
    so `true` is recorded as a distant-past sentinel meaning "already EOL" and
    `false` as NULL meaning "still supported".
    """
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except ValueError:
            return []
    if not isinstance(payload, list):
        return []
    out: list[tuple] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        cycle = entry.get("cycle")
        if cycle is None:
            continue
        eol = entry.get("eol")
        if eol is True:
            eol_date = "1970-01-01"      # already out of support, date unknown
        elif eol is False or eol is None:
            eol_date = None
        elif isinstance(eol, str):
            eol_date = eol
        else:
            eol_date = None
        support = entry.get("support")
        support_date = support if isinstance(support, str) else None
        out.append((
            product, str(cycle), eol_date, support_date,
            str(entry.get("latest")) if entry.get("latest") is not None else None,
        ))
    return out


def upsert_eol(conn: sqlite3.Connection, rows: Iterable[tuple]) -> int:
    rows = list(rows)
    if not rows:
        return 0
    conn.executemany(
        "INSERT INTO eol (product, cycle, eol_date, support_date, latest) "
        "VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(product, cycle) DO UPDATE SET eol_date = excluded.eol_date, "
        "support_date = excluded.support_date, latest = excluded.latest",
        rows,
    )
    return len(rows)


# --- network fetch -----------------------------------------------------------


async def update(
    conn: sqlite3.Connection,
    *,
    products: dict[str, str] | None = None,
    _client: Any = None,
) -> RiskUpdateStats:
    """Refresh all three datasets. Failures on one source don't sink the rest."""
    import gzip

    import httpx

    ensure_schema(conn)
    stats = RiskUpdateStats()
    client = _client or httpx.AsyncClient(timeout=60.0, follow_redirects=True)
    owns_client = _client is None
    try:
        try:
            response = await client.get(EPSS_URL)
            response.raise_for_status()
            body = response.content
            if body[:2] == b"\x1f\x8b":
                body = gzip.decompress(body)
            stats.epss_rows = upsert_epss(
                conn, parse_epss_csv(body.decode("utf-8", "replace"))
            )
        except Exception:  # noqa: BLE001 — one dataset failing is not fatal
            pass

        try:
            response = await client.get(KEV_URL)
            response.raise_for_status()
            stats.kev_rows = upsert_kev(conn, parse_kev(response.json()))
        except Exception:  # noqa: BLE001
            pass

        for key, slug in (products or EOL_PRODUCTS).items():
            try:
                response = await client.get(EOL_URL_TEMPLATE.format(product=slug))
                response.raise_for_status()
                stats.eol_rows += upsert_eol(conn, parse_eol(key, response.json()))
            except Exception:  # noqa: BLE001
                continue
    finally:
        if owns_client:
            await client.aclose()
    return stats


def bootstrap_dirs(path: Path | None = None) -> None:
    from lodan.paths import nvd_dir

    (path or nvd_dir()).mkdir(parents=True, exist_ok=True)
