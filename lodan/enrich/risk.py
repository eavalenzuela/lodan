"""Rising-risk scoring: EOL exposure and exploit-aware CVE priority.

lodan's diff engine is topology-only: it notices a host gaining a port or
changing a banner, but has no notion of a host getting *more dangerous while
standing still*. Two things make that happen without anything moving on the
wire — a release crossing its end-of-support date, and a CVE the host already
had becoming known-exploited.

This pass adds both, entirely offline, by joining the EPSS / KEV / EOL
snapshots onto what the scan already found.

`priority` is deliberately not another 0–10 score competing with CVSS. It is
an ordering over what to do first:

    critical  on CISA KEV — confirmed exploited in the wild
    high      EPSS >= 0.1, or CVSS >= 9.0
    medium    EPSS >= 0.01, or CVSS >= 7.0
    low       everything else

KEV outranks every score because "someone is actually using this" is a
different kind of fact from "this would be bad".
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, date, datetime

from lodan.enrich import version as version_cmp

PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

_EPSS_HIGH = 0.1
_EPSS_MEDIUM = 0.01
_CVSS_HIGH = 9.0
_CVSS_MEDIUM = 7.0


def priority_for(
    *, cvss: float | None, epss: float | None, on_kev: bool
) -> str:
    """Order a single vuln for remediation. Pure."""
    if on_kev:
        return "critical"
    if (epss is not None and epss >= _EPSS_HIGH) or (cvss is not None and cvss >= _CVSS_HIGH):
        return "high"
    if (epss is not None and epss >= _EPSS_MEDIUM) or (cvss is not None and cvss >= _CVSS_MEDIUM):
        return "medium"
    return "low"


# --- EOL ---------------------------------------------------------------------

# How a detected product maps onto an endoflife.date product key, and how much
# of the detected version identifies its release cycle. Apache's cycles are
# "2.4"; Ubuntu's are "20.04"; Kubernetes' are "1.28".
_CYCLE_DEPTH = {
    "ubuntu": 2, "debian": 1, "centos": 1, "rhel": 1,
    "apache": 2, "nginx": 2, "openssh": 2, "redis": 2, "mongodb": 2,
    "elasticsearch": 1, "mysql": 2, "postgresql": 1, "kubernetes": 2,
    "docker-engine": 2, "php": 2, "windows-server": 1,
}

# os_guess strings -> (eol product key, version). os_guess already carries the
# release ("Ubuntu 20.04"), so the version comes from the string itself.
_OS_GUESS_PRODUCTS = {
    "ubuntu": "ubuntu",
    "debian": "debian",
    "centos": "centos",
    "red hat": "rhel",
    "windows server": "windows-server",
}

# service name -> eol product key, for the structured version fields.
_SERVICE_PRODUCTS = {
    "redis": "redis",
    "mongo": "mongodb",
    "elasticsearch": "elasticsearch",
    "mysql": "mysql",
    "postgresql": "postgresql",
    "kubernetes": "kubernetes",
    "docker": "docker-engine",
    "ssh": "openssh",
}


def cycle_for(product: str, version: str | None) -> str | None:
    """Reduce a full version to the release cycle EOL data is keyed by."""
    if not version_cmp.looks_like_a_version(version):
        return None
    depth = _CYCLE_DEPTH.get(product, 2)
    parts = str(version).lstrip("vV").split(".")
    if len(parts) < depth:
        return ".".join(parts)
    return ".".join(parts[:depth])


@dataclass(frozen=True)
class EOLVerdict:
    product: str
    cycle: str
    eol_date: str
    days_past: int


def eol_lookup(
    risk_conn: sqlite3.Connection,
    product: str,
    version: str | None,
    *,
    today: date | None = None,
) -> EOLVerdict | None:
    """Is this product/version past its end-of-support date?"""
    cycle = cycle_for(product, version)
    if cycle is None:
        return None
    row = risk_conn.execute(
        "SELECT eol_date FROM eol WHERE product = ? AND cycle = ?", (product, cycle)
    ).fetchone()
    if row is None or not row[0]:
        return None
    try:
        eol_date = date.fromisoformat(row[0])
    except ValueError:
        return None
    today = today or datetime.now(UTC).date()
    if eol_date > today:
        return None
    return EOLVerdict(
        product=product, cycle=cycle, eol_date=row[0],
        days_past=(today - eol_date).days,
    )


def _detected_products(service: str | None, os_guess: str | None) -> list[tuple[str, str]]:
    """(eol product key, version) pairs implied by one service row."""
    out: list[tuple[str, str]] = []
    if os_guess:
        lowered = os_guess.lower()
        for needle, product in _OS_GUESS_PRODUCTS.items():
            if lowered.startswith(needle):
                remainder = os_guess[len(needle):].strip()
                if version_cmp.looks_like_a_version(remainder):
                    out.append((product, remainder))
                break
    return out


# --- persistence -------------------------------------------------------------


def enrich_risk(
    workspace_conn: sqlite3.Connection,
    risk_conn: sqlite3.Connection,
    scan_id: int,
    *,
    today: date | None = None,
) -> tuple[int, int]:
    """Score vulns by exploit likelihood and flag EOL software.

    Returns (vulns_prioritized, eol_findings). Idempotent.
    """
    prioritized = _score_vulns(workspace_conn, risk_conn, scan_id)
    eol_count = _flag_eol(workspace_conn, risk_conn, scan_id, today=today)
    return prioritized, eol_count


def _score_vulns(
    workspace_conn: sqlite3.Connection,
    risk_conn: sqlite3.Connection,
    scan_id: int,
) -> int:
    rows = workspace_conn.execute(
        "SELECT rowid, cve FROM vulns WHERE scan_id = ?", (scan_id,)
    ).fetchall()
    if not rows:
        return 0
    cves = sorted({cve for _rowid, cve in rows if cve})
    if not cves:
        return 0

    placeholders = ",".join("?" * len(cves))
    epss = {
        cve: (score, percentile)
        for cve, score, percentile in risk_conn.execute(
            f"SELECT cve, score, percentile FROM epss WHERE cve IN ({placeholders})",
            cves,
        )
    }
    kev = {
        cve: (date_added, bool(ransomware))
        for cve, date_added, ransomware in risk_conn.execute(
            f"SELECT cve, date_added, ransomware FROM kev WHERE cve IN ({placeholders})",
            cves,
        )
    }

    # CVSS lives in the shared CVE DB, not on the workspace vulns row — the
    # workspace only records which CVE matched, not its score.
    cvss_by_cve: dict[str, float] = {}
    if _has_table(risk_conn, "cve_cpe"):
        cvss_by_cve = {
            cve: score
            for cve, score in risk_conn.execute(
                f"SELECT cve, MAX(cvss) FROM cve_cpe WHERE cve IN ({placeholders}) "
                "GROUP BY cve",
                cves,
            )
            if score is not None
        }

    updates = []
    for rowid, cve in rows:
        score, percentile = epss.get(cve, (None, None))
        date_added, ransomware = kev.get(cve, (None, False))
        cvss = cvss_by_cve.get(cve) or None
        updates.append((
            score, percentile,
            1 if cve in kev else 0,
            date_added,
            1 if ransomware else 0,
            priority_for(cvss=cvss, epss=score, on_kev=cve in kev),
            rowid,
        ))
    workspace_conn.executemany(
        "UPDATE vulns SET epss = ?, epss_percentile = ?, kev = ?, kev_date_added = ?, "
        "ransomware = ?, priority = ? WHERE rowid = ?",
        updates,
    )
    return len(updates)


def _has_table(conn: sqlite3.Connection, table: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
    ).fetchone() is not None


def _flag_eol(
    workspace_conn: sqlite3.Connection,
    risk_conn: sqlite3.Connection,
    scan_id: int,
    *,
    today: date | None = None,
) -> int:
    workspace_conn.execute(
        "DELETE FROM findings WHERE scan_id = ? AND category = 'eol'", (scan_id,)
    )
    rows = workspace_conn.execute(
        "SELECT ip, port, service, os_guess FROM services WHERE scan_id = ?",
        (scan_id,),
    ).fetchall()
    import json

    count = 0
    for ip, port, service, os_guess in rows:
        candidates = _detected_products(service, os_guess)
        for product, detected_version in candidates:
            verdict = eol_lookup(risk_conn, product, detected_version, today=today)
            if verdict is None:
                continue
            workspace_conn.execute(
                "INSERT INTO findings (scan_id, ip, port, category, severity, title, detail) "
                "VALUES (?, ?, ?, 'eol', ?, ?, ?)",
                (
                    scan_id, ip, port,
                    "high" if verdict.days_past > 365 else "medium",
                    f"{product} {verdict.cycle} reached end of support on "
                    f"{verdict.eol_date} ({verdict.days_past} days ago).",
                    json.dumps({
                        "product": product, "cycle": verdict.cycle,
                        "eol_date": verdict.eol_date, "days_past": verdict.days_past,
                    }),
                ),
            )
            count += 1
    return count
