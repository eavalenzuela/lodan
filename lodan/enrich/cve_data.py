"""NVD 2.0 API ingestion into the shared CVE database.

The NVD 2.0 vulnerabilities endpoint returns pages of 2000 records and
exposes a `lastModStartDate` / `lastModEndDate` filter we use to do
incremental re-fetches — first run pulls everything, subsequent runs
pull only what's changed since the previous successful fetch.

Three layers, each testable in isolation:

    parse_record(vuln_json)      -> list[CVERecord]     # pure, no I/O
    fetch_pages(client, params)  -> AsyncIterator[page] # hits the API
    update(db, progress=...)     -> UpdateStats         # ties it together
"""
from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from importlib.resources import files
from pathlib import Path
from typing import Any

import httpx

from lodan.paths import nvd_db, nvd_dir, nvd_state

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PAGE_SIZE = 2000


@dataclass(frozen=True)
class CVERecord:
    cpe: str
    cve: str
    cvss: float | None
    published: str | None
    last_modified: str | None


@dataclass
class UpdateStats:
    pages: int = 0
    cves_seen: int = 0
    rows_upserted: int = 0
    last_modified: str | None = None


def _schema_sql() -> str:
    return (files("lodan.enrich") / "cve_schema.sql").read_text(encoding="utf-8")


def connect(path: Path | None = None) -> sqlite3.Connection:
    p = path or nvd_db()
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(p, isolation_level=None)
    conn.executescript(_schema_sql())
    return conn


def load_state(path: Path | None = None) -> dict[str, Any]:
    p = path or nvd_state()
    if not p.exists():
        return {}
    return json.loads(p.read_text())


def save_state(state: dict[str, Any], path: Path | None = None) -> None:
    p = path or nvd_state()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(state, indent=2, sort_keys=True))


def parse_record(vuln: dict[str, Any]) -> list[CVERecord]:
    """Turn one NVD 2.0 vulnerability object into 0+ (cpe, cve) rows.

    A single CVE can apply to many CPEs. We flatten configurations.nodes
    across AND/OR groups and emit one CVERecord per CPE criterion.
    """
    cve_block = vuln.get("cve", {})
    cve_id = cve_block.get("id")
    if not cve_id:
        return []

    cvss = _best_cvss(cve_block.get("metrics", {}))
    published = cve_block.get("published")
    modified = cve_block.get("lastModified")

    rows: list[CVERecord] = []
    for config in cve_block.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", True):
                    continue
                cpe = match.get("criteria")
                if not cpe:
                    continue
                rows.append(
                    CVERecord(
                        cpe=cpe,
                        cve=cve_id,
                        cvss=cvss,
                        published=published,
                        last_modified=modified,
                    )
                )
    return rows


def _best_cvss(metrics: dict[str, Any]) -> float | None:
    """Pick the best-available CVSS base score: v3.1 > v3.0 > v2."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        for entry in entries:
            score = entry.get("cvssData", {}).get("baseScore")
            if isinstance(score, (int, float)):
                return float(score)
    return None


async def fetch_pages(
    client: httpx.AsyncClient,
    params: dict[str, Any],
    *,
    api_key: str | None = None,
    max_pages: int | None = None,
) -> AsyncIterator[dict[str, Any]]:
    """Yield NVD 2.0 API pages, following startIndex pagination."""
    headers = {"apiKey": api_key} if api_key else {}
    start = 0
    page_count = 0
    while True:
        q = dict(params)
        q["startIndex"] = start
        q["resultsPerPage"] = NVD_PAGE_SIZE
        response = await client.get(NVD_API_URL, params=q, headers=headers)
        response.raise_for_status()
        page = response.json()
        yield page
        page_count += 1
        total = page.get("totalResults", 0)
        got_so_far = start + page.get("resultsPerPage", 0)
        if got_so_far >= total:
            return
        if max_pages is not None and page_count >= max_pages:
            return
        start = got_so_far


def upsert(conn: sqlite3.Connection, records: list[CVERecord]) -> int:
    if not records:
        return 0
    conn.executemany(
        """
        INSERT INTO cve_cpe (cpe, cve, cvss, published, last_modified)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(cpe, cve) DO UPDATE SET
            cvss = excluded.cvss,
            published = excluded.published,
            last_modified = excluded.last_modified
        """,
        [(r.cpe, r.cve, r.cvss, r.published, r.last_modified) for r in records],
    )
    return len(records)


async def update(
    conn: sqlite3.Connection,
    *,
    state_path: Path | None = None,
    max_pages: int | None = None,
    progress: Callable[[UpdateStats], None] | None = None,
    api_key: str | None = None,
    _client: httpx.AsyncClient | None = None,
) -> UpdateStats:
    """Run one incremental NVD update.

    Uses state.json's `last_modified` to filter pulls to only what's
    changed since the previous successful run; a fresh install pulls
    everything.
    """
    stats = UpdateStats()
    state = load_state(state_path)
    since = state.get("last_modified")
    now_iso = datetime.now(UTC).replace(tzinfo=None).isoformat(timespec="seconds")

    params: dict[str, Any] = {}
    if since:
        # NVD 2.0 requires BOTH start and end dates, end <= start + 120d.
        params["lastModStartDate"] = since
        params["lastModEndDate"] = (
            datetime.now(UTC).replace(tzinfo=None) + timedelta(seconds=1)
        ).isoformat(timespec="seconds")

    api_key = api_key or os.environ.get("LODAN_NVD_KEY")
    client = _client or httpx.AsyncClient(timeout=60)
    try:
        async for page in fetch_pages(
            client, params, api_key=api_key, max_pages=max_pages
        ):
            stats.pages += 1
            batch: list[CVERecord] = []
            for vuln in page.get("vulnerabilities", []):
                stats.cves_seen += 1
                batch.extend(parse_record(vuln))
            stats.rows_upserted += upsert(conn, batch)
            if progress:
                progress(stats)
    finally:
        if _client is None:
            await client.aclose()

    stats.last_modified = now_iso
    save_state({"last_modified": now_iso}, state_path)
    return stats


def bootstrap_dirs() -> None:
    nvd_dir().mkdir(parents=True, exist_ok=True)
