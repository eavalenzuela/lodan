"""FastAPI + Jinja2 + HTMX dashboard.

The app is a factory: `create_app(workspace)` returns a FastAPI instance
wired to one workspace. Read-only — never writes to the workspace DB.
"""
# `from __future__ import annotations` is deliberately NOT used in this
# module: FastAPI resolves handler signatures at registration time via
# get_type_hints(), which can't see closure-local aliases like `DB` when
# every annotation is a forward-ref string.
import json
import sqlite3
from importlib.resources import files
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from lodan.paths import workspace_config, workspace_db
from lodan.store.db import connect


def _templates_dir() -> Path:
    return Path(str(files("lodan.ui") / "templates"))


def _static_dir() -> Path:
    return Path(str(files("lodan.ui") / "static"))


def create_app(workspace: str) -> FastAPI:
    if not workspace_config(workspace).exists():
        raise FileNotFoundError(f"no such workspace: {workspace}")

    app = FastAPI(title=f"lodan: {workspace}")
    templates = Jinja2Templates(directory=str(_templates_dir()))
    templates.env.filters["short_fp"] = _short_fp
    templates.env.filters["from_json"] = _from_json_filter

    static_dir = _static_dir()
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    def _db() -> sqlite3.Connection:
        conn = connect(workspace_db(workspace))
        try:
            yield conn
        finally:
            conn.close()

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request, db: sqlite3.Connection = Depends(_db)) -> HTMLResponse:  # noqa: B008
        summary = _dashboard_summary(db)
        return templates.TemplateResponse(
            request, "dashboard.html",
            {"workspace": workspace, "summary": summary},
        )

    @app.get("/hosts", response_class=HTMLResponse)
    def hosts_page(
        request: Request,
        db: sqlite3.Connection = Depends(_db),  # noqa: B008
        scan: int | None = None,
        q: str | None = None,
    ) -> HTMLResponse:
        scan_id = scan or _latest_scan_id(db)
        hosts = _hosts_rows(db, scan_id, q) if scan_id else []
        return templates.TemplateResponse(
            request, "hosts.html",
            {"workspace": workspace, "hosts": hosts, "scan_id": scan_id, "q": q},
        )

    @app.get("/hosts/rows", response_class=HTMLResponse)
    def hosts_rows_partial(
        request: Request,
        db: sqlite3.Connection = Depends(_db),  # noqa: B008
        scan: int | None = None,
        q: str | None = None,
    ) -> HTMLResponse:
        scan_id = scan or _latest_scan_id(db)
        hosts = _hosts_rows(db, scan_id, q) if scan_id else []
        return templates.TemplateResponse(
            request, "_hosts_rows.html",
            {"hosts": hosts, "scan_id": scan_id},
        )

    @app.get("/services", response_class=HTMLResponse)
    def services_page(
        request: Request,
        db: sqlite3.Connection = Depends(_db),  # noqa: B008
        scan: int | None = None,
        q: str | None = None,
    ) -> HTMLResponse:
        scan_id = scan or _latest_scan_id(db)
        services = _services_rows(db, scan_id, q) if scan_id else []
        return templates.TemplateResponse(
            request, "services.html",
            {"workspace": workspace, "services": services, "scan_id": scan_id, "q": q},
        )

    @app.get("/services/rows", response_class=HTMLResponse)
    def services_rows_partial(
        request: Request,
        db: sqlite3.Connection = Depends(_db),  # noqa: B008
        scan: int | None = None,
        q: str | None = None,
    ) -> HTMLResponse:
        scan_id = scan or _latest_scan_id(db)
        services = _services_rows(db, scan_id, q) if scan_id else []
        return templates.TemplateResponse(
            request, "_services_rows.html",
            {"services": services, "scan_id": scan_id},
        )

    @app.get("/host/{ip}", response_class=HTMLResponse)
    def host_detail(
        request: Request,
        ip: str,
        db: sqlite3.Connection = Depends(_db),  # noqa: B008
        scan: int | None = None,
    ) -> HTMLResponse:
        scan_id = scan or _latest_scan_id(db)
        if scan_id is None:
            raise HTTPException(404, detail="no scans in this workspace")
        host = _host_row(db, scan_id, ip)
        if host is None:
            raise HTTPException(404, detail=f"no host {ip} in scan {scan_id}")
        services = _services_for_host(db, scan_id, ip)
        vulns = _vulns_for_host(db, scan_id, ip)
        return templates.TemplateResponse(
            request, "host_detail.html",
            {
                "workspace": workspace,
                "scan_id": scan_id,
                "host": host,
                "services": services,
                "vulns": vulns,
            },
        )

    @app.get("/pivot/cert/{fp}", response_class=HTMLResponse)
    def pivot_cert(
        request: Request,
        fp: str,
        db: sqlite3.Connection = Depends(_db),  # noqa: B008
    ) -> HTMLResponse:
        matches = _pivot_exact(db, "cert_fingerprint", fp)
        return templates.TemplateResponse(
            request, "pivot.html",
            {"workspace": workspace, "kind": "cert_fingerprint",
             "needle": fp, "matches": matches},
        )

    @app.get("/pivot/favicon/{value}", response_class=HTMLResponse)
    def pivot_favicon(
        request: Request,
        value: str,
        db: sqlite3.Connection = Depends(_db),  # noqa: B008
    ) -> HTMLResponse:
        try:
            hash_int = int(value)
        except ValueError:
            raise HTTPException(400, detail="favicon hash must be a signed int32") from None
        matches = _pivot_exact(db, "favicon_mmh3", hash_int)
        return templates.TemplateResponse(
            request, "pivot.html",
            {"workspace": workspace, "kind": "favicon_mmh3",
             "needle": str(hash_int), "matches": matches},
        )

    @app.get("/pivot/ja3s/{fp}", response_class=HTMLResponse)
    def pivot_ja3s(
        request: Request,
        fp: str,
        db: sqlite3.Connection = Depends(_db),  # noqa: B008
    ) -> HTMLResponse:
        matches = _pivot_exact(db, "ja3s", fp)
        return templates.TemplateResponse(
            request, "pivot.html",
            {"workspace": workspace, "kind": "ja3s",
             "needle": fp, "matches": matches},
        )

    @app.get("/pivot/san", response_class=HTMLResponse)
    def pivot_san(
        request: Request,
        db: sqlite3.Connection = Depends(_db),  # noqa: B008
        q: str | None = None,
    ) -> HTMLResponse:
        matches = _pivot_san(db, q) if q else []
        return templates.TemplateResponse(
            request, "pivot.html",
            {"workspace": workspace, "kind": "san",
             "needle": q, "matches": matches},
        )

    @app.get("/healthz", response_class=HTMLResponse)
    def healthz() -> HTMLResponse:
        return HTMLResponse("ok")

    @app.exception_handler(sqlite3.OperationalError)
    async def _sqlite_err(request: Request, exc: sqlite3.OperationalError):
        raise HTTPException(500, detail=f"db error: {exc}") from exc

    return app


def _dashboard_summary(db: sqlite3.Connection) -> dict:
    scans = db.execute(
        "SELECT id, started_at, finished_at, status FROM scans ORDER BY id DESC LIMIT 20"
    ).fetchall()
    latest = scans[0] if scans else None
    totals = {"services": 0, "hosts": 0, "vulns": 0}
    last_diff = None
    if latest is not None:
        latest_id = latest[0]
        totals["services"] = db.execute(
            "SELECT COUNT(*) FROM services WHERE scan_id = ?", (latest_id,)
        ).fetchone()[0]
        totals["hosts"] = db.execute(
            "SELECT COUNT(*) FROM hosts WHERE scan_id = ?", (latest_id,)
        ).fetchone()[0]
        totals["vulns"] = db.execute(
            "SELECT COUNT(*) FROM vulns WHERE scan_id = ?", (latest_id,)
        ).fetchone()[0]
        diff = db.execute(
            """
            SELECT from_scan_id, to_scan_id, kind, COUNT(*)
            FROM scan_diffs
            WHERE to_scan_id = ?
            GROUP BY from_scan_id, to_scan_id, kind
            """,
            (latest_id,),
        ).fetchall()
        if diff:
            by_kind: dict[str, int] = {}
            from_id = diff[0][0]
            for _f, _t, kind, count in diff:
                by_kind[kind] = count
            last_diff = {
                "from_scan_id": from_id,
                "to_scan_id": latest_id,
                "by_kind": by_kind,
                "total": sum(by_kind.values()),
            }

    return {
        "scans": [
            {
                "id": s[0],
                "started_at": s[1],
                "finished_at": s[2],
                "status": s[3],
            }
            for s in scans
        ],
        "latest": {"id": latest[0], "started_at": latest[1]} if latest else None,
        "totals": totals,
        "last_diff": last_diff,
    }


def _latest_scan_id(db: sqlite3.Connection) -> int | None:
    row = db.execute(
        "SELECT id FROM scans WHERE status = 'completed' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return row[0] if row else None


def _hosts_rows(db: sqlite3.Connection, scan_id: int, q: str | None) -> list[dict]:
    """Every IP seen in this scan's services, left-joined with any hosts row
    so enrichment-skipped scans still render."""
    query = (
        "SELECT s.ip, h.rdns, h.asn, h.asn_org, h.country, COUNT(*) AS svc_count "
        "FROM services s "
        "LEFT JOIN hosts h ON h.scan_id = s.scan_id AND h.ip = s.ip "
        "WHERE s.scan_id = ?"
    )
    params: list = [scan_id]
    if q:
        query += (
            " AND (s.ip LIKE ? OR COALESCE(h.rdns,'') LIKE ? "
            "   OR COALESCE(h.asn_org,'') LIKE ?)"
        )
        like = f"%{q}%"
        params.extend([like, like, like])
    query += " GROUP BY s.ip, h.rdns, h.asn, h.asn_org, h.country ORDER BY s.ip"
    rows = db.execute(query, params).fetchall()
    return [
        {
            "ip": r[0], "rdns": r[1], "asn": r[2], "asn_org": r[3], "country": r[4],
            "service_count": r[5],
        }
        for r in rows
    ]


def _services_rows(db: sqlite3.Connection, scan_id: int, q: str | None) -> list[dict]:
    query = (
        "SELECT ip, port, proto, service, banner, cert_fingerprint, tech "
        "FROM services WHERE scan_id = ?"
    )
    params: list = [scan_id]
    if q:
        query += (
            " AND (ip LIKE ? OR COALESCE(banner,'') LIKE ? "
            "   OR COALESCE(cert_sans,'') LIKE ? OR COALESCE(tech,'') LIKE ?)"
        )
        like = f"%{q}%"
        params.extend([like, like, like, like])
    query += " ORDER BY ip, port"

    return [
        {
            "ip": r[0], "port": r[1], "proto": r[2], "service": r[3],
            "banner": r[4], "cert_fingerprint": r[5], "tech": r[6],
        }
        for r in db.execute(query, params).fetchall()
    ]


def _host_row(db: sqlite3.Connection, scan_id: int, ip: str) -> dict | None:
    row = db.execute(
        "SELECT ip, rdns, asn, asn_org, country FROM hosts WHERE scan_id = ? AND ip = ?",
        (scan_id, ip),
    ).fetchone()
    if row is not None:
        return {
            "ip": row[0], "rdns": row[1], "asn": row[2],
            "asn_org": row[3], "country": row[4],
        }
    # Host might not have a row if enrichment was off; synthesize a minimal one
    # as long as the IP shows up in services.
    hit = db.execute(
        "SELECT 1 FROM services WHERE scan_id = ? AND ip = ? LIMIT 1", (scan_id, ip)
    ).fetchone()
    if hit:
        return {"ip": ip, "rdns": None, "asn": None, "asn_org": None, "country": None}
    return None


def _services_for_host(db: sqlite3.Connection, scan_id: int, ip: str) -> list[dict]:
    return [
        {
            "port": r[0], "proto": r[1], "service": r[2], "banner": r[3],
            "cert_fingerprint": r[4], "tech": r[5],
        }
        for r in db.execute(
            "SELECT port, proto, service, banner, cert_fingerprint, tech "
            "FROM services WHERE scan_id = ? AND ip = ? ORDER BY port",
            (scan_id, ip),
        )
    ]


def _vulns_for_host(db: sqlite3.Connection, scan_id: int, ip: str) -> list[dict]:
    return [
        {"port": r[0], "cve": r[1], "cpe": r[2], "confidence": r[3], "source": r[4]}
        for r in db.execute(
            "SELECT port, cve, cpe, confidence, source FROM vulns "
            "WHERE scan_id = ? AND ip = ? ORDER BY port, cve",
            (scan_id, ip),
        )
    ]


def _pivot_exact(db: sqlite3.Connection, column: str, value) -> list[dict]:
    if column not in ("cert_fingerprint", "favicon_mmh3", "ja3s"):
        raise ValueError(f"not a pivotable column: {column}")
    rows = db.execute(
        f"SELECT scan_id, ip, port, service, banner, {column} "
        f"FROM services WHERE {column} = ? ORDER BY scan_id DESC, ip, port",
        (value,),
    ).fetchall()
    return [_pivot_row(r) for r in rows]


def _pivot_san(db: sqlite3.Connection, needle: str) -> list[dict]:
    # cert_sans is stored as a JSON array string; substring LIKE against the
    # raw text is enough for v1. Operator-supplied * maps to %, and we always
    # wrap the pattern in % so a bare "*.corp" finds it as a substring of
    # the JSON-encoded array.
    needle_sql = "%" + needle.replace("*", "%") + "%"
    rows = db.execute(
        "SELECT scan_id, ip, port, service, banner, cert_sans "
        "FROM services WHERE cert_sans IS NOT NULL AND cert_sans LIKE ? "
        "ORDER BY scan_id DESC, ip, port",
        (needle_sql,),
    ).fetchall()
    return [_pivot_row(r) for r in rows]


def _pivot_row(r) -> dict:
    return {
        "scan_id": r[0], "ip": r[1], "port": r[2],
        "service": r[3], "banner": r[4], "matched_value": str(r[5]) if r[5] is not None else "",
    }


def _short_fp(value: str | None, length: int = 12) -> str:
    if not value:
        return ""
    return value[:length] + ("…" if len(value) > length else "")


def _from_json_filter(value: str | None):
    if value is None:
        return None
    try:
        return json.loads(value)
    except Exception:
        return value
