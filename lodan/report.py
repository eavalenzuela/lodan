"""Shareable, integrity-checked scan reports.

Renders one completed scan into a self-contained bundle:

    report.html      one offline HTML document (inline CSS, nothing external)
    services.csv     every discovered/probed service
    hosts.csv        per-host enrichment (rDNS / ASN / country)
    vulns.csv        CVE matches (omitted when there are none)
    findings.sarif   the CVE matches as SARIF 2.1.0 results
    manifest.json    sha256 + byte size of every file above, plus scan metadata

The bundle stands alone — hand it to a stakeholder without shipping the
workspace DB. `manifest.json` is the integrity anchor: a recipient recomputes
each file's sha256 and compares. All dynamic values (banners, cert fields, tech)
are HTML-escaped on the way into report.html, since they originate from remote
hosts.

Everything here reads; nothing mutates the workspace. The diff section reuses the
`scan_diffs` rows the scan already computed against its predecessor.
"""
from __future__ import annotations

import csv
import hashlib
import html
import io
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_SERVICE_COLS = (
    "ip", "port", "proto", "service", "banner",
    "cert_fingerprint", "cert_sans", "ja3s", "ja4s", "ssh_hostkey", "tech",
    "stack_sig", "os_family", "hop_count", "os_guess", "jarm",
)
_HOST_COLS = (
    "ip", "rdns", "asn", "asn_org", "country", "os_family", "os_guess",
    "device_type", "hop_count",
)
_VULN_COLS = ("ip", "port", "cve", "cpe", "confidence", "source")
_FINDING_COLS = ("severity", "category", "ip", "port", "title")

_BUNDLE_FILES = (
    "report.html", "services.csv", "hosts.csv", "vulns.csv", "findings.csv", "findings.sarif",
)

_SEVERITY_SARIF_LEVEL = {"high": "error", "medium": "warning", "low": "note", "info": "note"}


class ReportError(ValueError):
    pass


@dataclass(frozen=True)
class ScanMeta:
    scan_id: int
    workspace: str
    status: str
    started_at: str | None
    finished_at: str | None
    cidrs: list[str]
    cloud_justification: str | None
    diff_from: int | None


def latest_completed_scan(conn: sqlite3.Connection) -> int | None:
    row = conn.execute(
        "SELECT id FROM scans WHERE status = 'completed' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return row[0] if row else None


def _load_scan_meta(conn: sqlite3.Connection, scan_id: int) -> ScanMeta:
    row = conn.execute(
        "SELECT id, workspace, status, started_at, finished_at, cidrs, cloud_justification "
        "FROM scans WHERE id = ?",
        (scan_id,),
    ).fetchone()
    if row is None:
        raise ReportError(f"no such scan: {scan_id}")
    diff_from = conn.execute(
        "SELECT DISTINCT from_scan_id FROM scan_diffs WHERE to_scan_id = ?", (scan_id,)
    ).fetchone()
    try:
        cidrs = json.loads(row[5]) if row[5] else []
    except (ValueError, TypeError):
        cidrs = []
    return ScanMeta(
        scan_id=row[0], workspace=row[1], status=row[2],
        started_at=row[3], finished_at=row[4], cidrs=cidrs,
        cloud_justification=row[6],
        diff_from=diff_from[0] if diff_from else None,
    )


def _rows(conn: sqlite3.Connection, cols: tuple[str, ...], table: str, scan_id: int) -> list[dict]:
    order = " ORDER BY ip, port" if "port" in cols else " ORDER BY ip"
    cur = conn.execute(
        f"SELECT {', '.join(cols)} FROM {table} WHERE scan_id = ?{order}", (scan_id,)
    )
    return [dict(zip(cols, r, strict=True)) for r in cur]


def _jsonish(value: Any) -> str:
    """Render a cert_sans / tech cell: JSON array -> 'a; b', else the raw text."""
    if value is None:
        return ""
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (ValueError, TypeError):
            return value
        value = parsed
    if isinstance(value, list):
        return "; ".join(str(v) for v in value)
    return str(value)


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------


def _csv(cols: tuple[str, ...], rows: list[dict], flatten: tuple[str, ...] = ()) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for row in rows:
        w.writerow([
            _jsonish(row.get(c)) if c in flatten else ("" if row.get(c) is None else row[c])
            for c in cols
        ])
    return buf.getvalue()


# ---------------------------------------------------------------------------
# SARIF 2.1.0
# ---------------------------------------------------------------------------


def build_sarif(meta: ScanMeta, vulns: list[dict], findings: list[dict], tool_version: str) -> str:
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for f in findings:
        cat = f["category"]
        rules.setdefault(cat, {
            "id": cat,
            "name": cat,
            "shortDescription": {"text": f"lodan exposure finding: {cat}"},
        })
        results.append({
            "ruleId": cat,
            "level": _SEVERITY_SARIF_LEVEL.get(f["severity"], "warning"),
            "message": {"text": f["title"]},
            "locations": [{
                "physicalLocation": {"artifactLocation": {
                    "uri": f"{f['ip']}:{f['port']}" if f.get("port") else f["ip"]
                }}
            }],
            "properties": {"severity": f["severity"], "ip": f["ip"], "port": f.get("port")},
        })
    for v in vulns:
        cve = v["cve"]
        rules.setdefault(cve, {
            "id": cve,
            "name": cve,
            "shortDescription": {"text": f"{cve} matched against a detected service"},
            "helpUri": f"https://nvd.nist.gov/vuln/detail/{cve}",
        })
        results.append({
            "ruleId": cve,
            "level": "warning",
            "message": {"text": f"{cve} may affect {v['ip']}:{v['port']} ({v.get('cpe') or 'cpe unknown'})"},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": f"{v['ip']}:{v['port']}"}}
            }],
            "properties": {
                "ip": v["ip"], "port": v["port"], "cpe": v.get("cpe"),
                "confidence": v.get("confidence"), "source": v.get("source"),
            },
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "lodan",
                "version": tool_version,
                "informationUri": "https://nvd.nist.gov/",
                "rules": list(rules.values()),
            }},
            "properties": {"workspace": meta.workspace, "scan_id": meta.scan_id},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2, sort_keys=True)


# ---------------------------------------------------------------------------
# HTML (self-contained)
# ---------------------------------------------------------------------------

_CSS = """
body{font:14px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:1100px;padding:0 1rem;color:#1a1a1a}
h1,h2{font-weight:600} h1{margin-bottom:.2rem} .sub{color:#666;margin-top:0}
table{border-collapse:collapse;width:100%;margin:.5rem 0 1.5rem;font-size:13px}
th,td{border:1px solid #ddd;padding:.35rem .5rem;text-align:left;vertical-align:top}
th{background:#f4f4f4} tr:nth-child(even){background:#fafafa}
.meta{background:#f7f7f9;border:1px solid #e3e3e8;border-radius:6px;padding:.75rem 1rem;margin:1rem 0}
.meta dt{font-weight:600;color:#444} .meta dd{margin:0 0 .4rem}
.cards{display:flex;gap:1rem;flex-wrap:wrap;margin:1rem 0}
.card{border:1px solid #e3e3e8;border-radius:6px;padding:.6rem 1rem;min-width:6rem}
.card .n{font-size:1.6rem;font-weight:700} .card .l{color:#666;font-size:12px}
code{background:#f0f0f3;padding:.1rem .3rem;border-radius:3px;font-size:12px}
.banner{max-width:34rem;overflow-wrap:anywhere} .foot{color:#888;font-size:12px;margin-top:2rem}
"""


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def _table(cols: tuple[str, ...], rows: list[dict], flatten: tuple[str, ...] = ()) -> str:
    if not rows:
        return "<p><em>none</em></p>"
    head = "".join(f"<th>{_esc(c)}</th>" for c in cols)
    body = []
    for row in rows:
        cells = []
        for c in cols:
            raw = _jsonish(row.get(c)) if c in flatten else row.get(c)
            klass = ' class="banner"' if c == "banner" else ""
            cells.append(f"<td{klass}>{_esc(raw)}</td>")
        body.append("<tr>" + "".join(cells) + "</tr>")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"


def _diff_rows(conn: sqlite3.Connection, meta: ScanMeta) -> list[dict]:
    if meta.diff_from is None:
        return []
    cur = conn.execute(
        "SELECT kind, ip, port FROM scan_diffs WHERE from_scan_id = ? AND to_scan_id = ? "
        "ORDER BY kind, ip, port",
        (meta.diff_from, meta.scan_id),
    )
    return [dict(zip(("kind", "ip", "port"), r, strict=True)) for r in cur]


def render_html(
    meta: ScanMeta,
    services: list[dict],
    hosts: list[dict],
    vulns: list[dict],
    findings: list[dict],
    diffs: list[dict],
    tool_version: str,
    generated_at: str,
) -> str:
    cards = [
        ("services", len(services)),
        ("hosts", len(hosts)),
        ("CVE matches", len(vulns)),
        ("findings", len(findings)),
    ]
    if meta.diff_from is not None:
        cards.append((f"changes vs #{meta.diff_from}", len(diffs)))
    cards_html = "".join(
        f'<div class="card"><div class="n">{n}</div><div class="l">{_esc(label)}</div></div>'
        for label, n in cards
    )
    cloud = (
        f"<dt>cloud opt-in</dt><dd>{_esc(meta.cloud_justification)}</dd>"
        if meta.cloud_justification else ""
    )
    diff_section = ""
    if meta.diff_from is not None:
        diff_section = (
            f"<h2>Changes since scan #{meta.diff_from}</h2>"
            + _table(("kind", "ip", "port"), diffs)
        )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>lodan report — {_esc(meta.workspace)} scan #{meta.scan_id}</title>
<style>{_CSS}</style></head><body>
<h1>lodan scan report</h1>
<p class="sub">workspace <code>{_esc(meta.workspace)}</code> · scan #{meta.scan_id} · {_esc(meta.status)}</p>
<div class="meta"><dl>
<dt>authorized ranges</dt><dd>{_esc(", ".join(meta.cidrs))}</dd>
<dt>started</dt><dd>{_esc(meta.started_at)}</dd>
<dt>finished</dt><dd>{_esc(meta.finished_at)}</dd>
{cloud}
</dl></div>
<div class="cards">{cards_html}</div>
{diff_section}
<h2>Exposure findings</h2>{_table(_FINDING_COLS, findings)}
<h2>Services</h2>{_table(_SERVICE_COLS, services, flatten=("cert_sans", "tech"))}
<h2>Hosts</h2>{_table(_HOST_COLS, hosts)}
<h2>CVE matches</h2>{_table(_VULN_COLS, vulns)}
<p class="foot">Generated by lodan {_esc(tool_version)} at {_esc(generated_at)}.
Integrity: verify each file's sha256 against manifest.json.</p>
</body></html>
"""


# ---------------------------------------------------------------------------
# Bundle assembly + manifest
# ---------------------------------------------------------------------------


def build_content(
    conn: sqlite3.Connection, scan_id: int, tool_version: str, generated_at: str
) -> tuple[ScanMeta, dict[str, str]]:
    """Build every bundle file's text. Pure w.r.t. the DB (read-only)."""
    from lodan import findings as findings_mod

    meta = _load_scan_meta(conn, scan_id)
    services = _rows(conn, _SERVICE_COLS, "services", scan_id)
    hosts = _rows(conn, _HOST_COLS, "hosts", scan_id)
    vulns = _rows(conn, _VULN_COLS, "vulns", scan_id)
    findings = findings_mod.iter_findings(conn, scan_id=scan_id)
    diffs = _diff_rows(conn, meta)

    files = {
        "report.html": render_html(
            meta, services, hosts, vulns, findings, diffs, tool_version, generated_at
        ),
        "services.csv": _csv(_SERVICE_COLS, services, flatten=("cert_sans", "tech")),
        "hosts.csv": _csv(_HOST_COLS, hosts),
        "vulns.csv": _csv(_VULN_COLS, vulns),
        "findings.csv": _csv(_FINDING_COLS, findings),
        "findings.sarif": build_sarif(meta, vulns, findings, tool_version),
    }
    return meta, files


def build_manifest(
    meta: ScanMeta, files: dict[str, str], tool_version: str, generated_at: str
) -> str:
    entries = []
    for name in sorted(files):
        data = files[name].encode("utf-8")
        entries.append({
            "name": name,
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
        })
    manifest = {
        "tool": "lodan",
        "tool_version": tool_version,
        "workspace": meta.workspace,
        "scan_id": meta.scan_id,
        "scan_started_at": meta.started_at,
        "generated_at": generated_at,
        "files": entries,
    }
    return json.dumps(manifest, indent=2, sort_keys=True)


def generate(
    conn: sqlite3.Connection,
    scan_id: int,
    out_dir: Path,
    tool_version: str,
    generated_at: str | None = None,
) -> tuple[Path, list[str]]:
    """Write the full bundle to `out_dir`. Returns (out_dir, filenames written)."""
    stamp = generated_at or datetime.now(UTC).isoformat(timespec="seconds")
    meta, files = build_content(conn, scan_id, tool_version, stamp)
    manifest = build_manifest(meta, files, tool_version, stamp)

    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for name in _BUNDLE_FILES:
        (out_dir / name).write_text(files[name], encoding="utf-8")
        written.append(name)
    (out_dir / "manifest.json").write_text(manifest, encoding="utf-8")
    written.append("manifest.json")
    return out_dir, written
