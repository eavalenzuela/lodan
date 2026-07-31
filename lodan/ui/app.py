"""FastAPI + Jinja2 + HTMX dashboard.

The app is a factory: `create_app(workspace)` returns a FastAPI instance
wired to one workspace. Read-only — never writes to the workspace DB.
"""
# `from __future__ import annotations` is deliberately NOT used in this
# module: FastAPI resolves handler signatures at registration time via
# get_type_hints(), which can't see closure-local aliases like `DB` when
# every annotation is a forward-ref string.
import contextlib
import json
import re
import sqlite3
from importlib.resources import files
from pathlib import Path
from urllib.parse import urlencode, urlparse

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from lodan import manage
from lodan.paths import workspace_config, workspace_db
from lodan.store.db import connect
from lodan.ui.jobs import JobBusy, JobManager


def _templates_dir() -> Path:
    return Path(str(files("lodan.ui") / "templates"))


def _static_dir() -> Path:
    return Path(str(files("lodan.ui") / "static"))


def create_app(
    workspace: str,
    read_only: bool = False,
    job_manager: JobManager | None = None,
    allowed_hosts: set[str] | None = None,
) -> FastAPI:
    """Build the per-workspace app.

    `read_only=True` disables every management/mutation endpoint (they return
    403 and the write forms are hidden), leaving the browse-only surface — the
    posture you want when sharing a workspace with a viewer. `job_manager` is
    injectable for tests; production gets a fresh in-process one.

    `allowed_hosts`, when set, restricts *mutation* requests to those Host-header
    hostnames — the anti-DNS-rebinding defense for a no-token loopback bind
    (`serve` pins it to the loopback names). None disables the check (embedding
    / tests). Reads are never Host-restricted.
    """
    if not workspace_config(workspace).exists():
        raise FileNotFoundError(f"no such workspace: {workspace}")

    jobs = job_manager or JobManager()

    app = FastAPI(title=f"lodan: {workspace}")
    templates = Jinja2Templates(directory=str(_templates_dir()))
    templates.env.filters["short_fp"] = _short_fp
    templates.env.filters["from_json"] = _from_json_filter
    templates.env.globals["read_only"] = read_only

    static_dir = _static_dir()
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    def _db() -> sqlite3.Connection:
        conn = connect(workspace_db(workspace))
        try:
            yield conn
        finally:
            conn.close()

    def _guard_writable(request: Request) -> None:
        if read_only:
            raise HTTPException(403, detail="this instance is read-only")
        # Anti-DNS-rebinding: the Host header must be one we trust. Comparing
        # Origin to Host is not enough — a rebound attacker.com resolves to
        # 127.0.0.1 and sends Origin==Host==attacker.com. Pinning the Host to
        # the loopback names the browser can't be tricked into sending for a
        # foreign domain is what actually stops it.
        if allowed_hosts is not None:
            hostname = urlparse(f"//{request.headers.get('host', '')}").hostname or ""
            if hostname.lower() not in allowed_hosts:
                raise HTTPException(403, detail="untrusted Host header")
        # Lightweight CSRF defense: modern browsers attach Origin to state-
        # changing requests. If it's present it must match the Host we're
        # served on, so a page on another origin can't drive scans or edit
        # scope. Non-browser clients (tests, curl) send no Origin and pass.
        origin = request.headers.get("origin")
        if origin and urlparse(origin).netloc != request.headers.get("host", ""):
            raise HTTPException(403, detail="cross-origin request refused")

    def _redirect_manage(notice: str, level: str = "ok") -> RedirectResponse:
        # Post/Redirect/Get so a browser refresh doesn't re-submit the form.
        qs = urlencode({"notice": notice, "level": level})
        return RedirectResponse(url=f"/manage?{qs}", status_code=303)

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

    @app.get("/query", response_class=HTMLResponse)
    def query_page(
        request: Request,
        db: sqlite3.Connection = Depends(_db),  # noqa: B008
        q: str | None = None,
        scan: int | None = None,
    ) -> HTMLResponse:
        from lodan.store.query import QueryError, run_query

        rows: list[dict] = []
        error: str | None = None
        limit = 200
        if q:
            try:
                rows = run_query(db, q, scan_id=scan, limit=limit)
            except QueryError as e:
                error = str(e)
        return templates.TemplateResponse(
            request, "query.html",
            {"workspace": workspace, "q": q, "rows": rows,
             "error": error, "limit": limit},
        )

    @app.get("/diffs", response_class=HTMLResponse)
    def diffs_timeline(
        request: Request,
        db: sqlite3.Connection = Depends(_db),  # noqa: B008
    ) -> HTMLResponse:
        pairs = _diff_pairs(db)
        return templates.TemplateResponse(
            request, "diffs.html", {"workspace": workspace, "pairs": pairs}
        )

    @app.get("/diff/{from_scan_id}/{to_scan_id}", response_class=HTMLResponse)
    def diff_detail(
        request: Request,
        from_scan_id: int,
        to_scan_id: int,
        db: sqlite3.Connection = Depends(_db),  # noqa: B008
    ) -> HTMLResponse:
        findings = _diff_findings(db, from_scan_id, to_scan_id)
        return templates.TemplateResponse(
            request, "diff_detail.html",
            {
                "workspace": workspace,
                "from_scan_id": from_scan_id,
                "to_scan_id": to_scan_id,
                "findings": findings,
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
        from lodan.store.writer import favicon_label
        return templates.TemplateResponse(
            request, "pivot.html",
            {"workspace": workspace, "kind": "favicon_mmh3",
             "needle": str(hash_int), "matches": matches,
             "label": favicon_label(db, hash_int)},
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

    @app.get("/pivot/ja4s/{fp}", response_class=HTMLResponse)
    def pivot_ja4s(
        request: Request,
        fp: str,
        db: sqlite3.Connection = Depends(_db),  # noqa: B008
    ) -> HTMLResponse:
        matches = _pivot_exact(db, "ja4s", fp)
        return templates.TemplateResponse(
            request, "pivot.html",
            {"workspace": workspace, "kind": "ja4s",
             "needle": fp, "matches": matches},
        )

    @app.get("/pivot/hostkey/{fp}", response_class=HTMLResponse)
    def pivot_hostkey(
        request: Request,
        fp: str,
        db: sqlite3.Connection = Depends(_db),  # noqa: B008
    ) -> HTMLResponse:
        matches = _pivot_exact(db, "ssh_hostkey", fp)
        return templates.TemplateResponse(
            request, "pivot.html",
            {"workspace": workspace, "kind": "ssh_hostkey",
             "needle": fp, "matches": matches},
        )

    @app.get("/pivot/stack/{sig}", response_class=HTMLResponse)
    def pivot_stack(
        request: Request,
        sig: str,
        db: sqlite3.Connection = Depends(_db),  # noqa: B008
    ) -> HTMLResponse:
        """Every port sharing one passive stack signature."""
        matches = _pivot_exact(db, "stack_sig", sig)
        return templates.TemplateResponse(
            request, "pivot.html",
            {"workspace": workspace, "kind": "stack_sig",
             "needle": sig, "matches": matches},
        )

    @app.get("/pivot/clock/{key}", response_class=HTMLResponse)
    def pivot_clock(
        request: Request,
        key: str,
        db: sqlite3.Connection = Depends(_db),  # noqa: B008
    ) -> HTMLResponse:
        """Addresses whose TCP-timestamp boot estimate lands in one bucket.

        A grouping to investigate, not an identity claim — see
        `discovery.fingerprint.clock_key`.
        """
        matches = _pivot_exact(db, "clock_key", key)
        return templates.TemplateResponse(
            request, "pivot.html",
            {"workspace": workspace, "kind": "clock_key",
             "needle": key, "matches": matches},
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

    # ---- management: scans -------------------------------------------------

    def _scan_status_partial(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request, "_scan_status.html", {"job": jobs.current(workspace)}
        )

    @app.post("/scan/run", response_class=HTMLResponse)
    def scan_run(request: Request) -> HTMLResponse:
        _guard_writable(request)
        with contextlib.suppress(JobBusy):
            jobs.start(workspace)  # already running -> just show the live status
        return _scan_status_partial(request)

    @app.get("/scan/status", response_class=HTMLResponse)
    def scan_status(request: Request) -> HTMLResponse:
        return _scan_status_partial(request)

    # ---- management: config ------------------------------------------------

    @app.get("/manage", response_class=HTMLResponse)
    def manage_page(
        request: Request, notice: str | None = None, level: str | None = None
    ) -> HTMLResponse:
        cfg = manage.load(workspace)
        return templates.TemplateResponse(
            request, "manage.html",
            {
                "workspace": workspace,
                "cfg": cfg,
                "job": jobs.current(workspace),
                "backends": ["auto", "masscan", "naabu", "scapy"],
                "notice": notice,
                "level": level or "ok",
            },
        )

    @app.post("/manage/scope/add")
    def scope_add(request: Request, targets: str = Form(...)):  # noqa: B008
        _guard_writable(request)
        raws = [t for t in re.split(r"[\s,]+", targets) if t]
        if not raws:
            return _redirect_manage("no targets provided", "err")
        try:
            res = manage.add_cidrs(workspace, raws)
        except manage.ManageError as e:
            return _redirect_manage(str(e), "err")
        parts = []
        if res.added:
            parts.append("added " + ", ".join(res.added))
        if res.skipped:
            parts.append("already in scope: " + ", ".join(res.skipped))
        level = "ok"
        if res.cloud_warnings:
            parts.append(
                "⚠ " + "; ".join(res.cloud_warnings)
                + " — scans refuse these unless cloud_provider_allowed is set"
            )
            level = "warn"
        return _redirect_manage("; ".join(parts) or "no change", level)

    @app.post("/manage/scope/remove")
    def scope_remove(request: Request, cidr: str = Form(...)):  # noqa: B008
        _guard_writable(request)
        try:
            removed = manage.remove_cidr(workspace, cidr)
        except manage.ManageError as e:
            return _redirect_manage(str(e), "err")
        return _redirect_manage(
            f"removed {cidr}" if removed else f"{cidr} was not in scope",
            "ok" if removed else "warn",
        )

    @app.post("/manage/cloud")
    def cloud_policy(  # noqa: B008
        request: Request,
        allowed: bool = Form(False),
        justification: str = Form(""),
    ):
        _guard_writable(request)
        try:
            manage.set_cloud_policy(workspace, allowed, justification)
        except manage.ManageError as e:
            return _redirect_manage(str(e), "err")
        return _redirect_manage("cloud-provider policy updated")

    @app.post("/manage/scan")
    def scan_settings(  # noqa: B008
        request: Request,
        backend: str = Form(...),
        ports: str = Form(...),
        rate_pps: int = Form(...),
        concurrency: int = Form(...),
        per_host_concurrency: int = Form(...),
        probe_timeout_s: float = Form(...),
        retries: int = Form(...),
        tcp: bool = Form(False),
        udp: bool = Form(False),
    ):
        _guard_writable(request)
        updates = {
            "backend": backend, "ports": ports, "rate_pps": rate_pps,
            "concurrency": concurrency, "per_host_concurrency": per_host_concurrency,
            "probe_timeout_s": probe_timeout_s, "retries": retries,
            "tcp": tcp, "udp": udp,
        }
        try:
            manage.update_scan(workspace, updates)
        except manage.ManageError as e:
            return _redirect_manage(str(e), "err")
        return _redirect_manage("scan settings saved")

    @app.post("/manage/enrich")
    def enrich_settings(  # noqa: B008
        request: Request,
        rdns: bool = Form(False),
        asn: bool = Form(False),
        geoip: bool = Form(False),
        cve: bool = Form(False),
        favicon: bool = Form(False),
        tech: bool = Form(False),
        keep_raw: bool = Form(False),
    ):
        _guard_writable(request)
        updates = {
            "rdns": rdns, "asn": asn, "geoip": geoip, "cve": cve,
            "favicon": favicon, "tech": tech, "keep_raw": keep_raw,
        }
        try:
            manage.update_enrich(workspace, updates)
        except manage.ManageError as e:
            return _redirect_manage(str(e), "err")
        return _redirect_manage("enrichment settings saved")

    @app.post("/manage/diff")
    def diff_settings(request: Request, default_from: str = Form(...)):  # noqa: B008
        _guard_writable(request)
        try:
            manage.set_diff_default_from(workspace, default_from)
        except manage.ManageError as e:
            return _redirect_manage(str(e), "err")
        return _redirect_manage("diff default saved")

    @app.post("/manage/retention")
    def retention_settings(  # noqa: B008
        request: Request,
        keep_last_n: str = Form(""),
        keep_monthly: str = Form(""),
    ):
        _guard_writable(request)

        def _opt_int(s: str) -> int | None:
            s = s.strip()
            return int(s) if s else None

        try:
            kln, km = _opt_int(keep_last_n), _opt_int(keep_monthly)
        except ValueError:
            return _redirect_manage("retention values must be whole numbers", "err")
        try:
            manage.set_retention(workspace, kln, km)
        except manage.ManageError as e:
            return _redirect_manage(str(e), "err")
        return _redirect_manage("retention policy saved")

    @app.post("/favicon-label")
    def favicon_label_set(  # noqa: B008
        request: Request,
        mmh3: int = Form(...),
        label: str = Form(""),
    ):
        _guard_writable(request)
        from lodan.store.writer import set_favicon_label

        conn = connect(workspace_db(workspace))
        try:
            set_favicon_label(conn, mmh3, label.strip())
        finally:
            conn.close()
        return RedirectResponse(url=f"/pivot/favicon/{mmh3}", status_code=303)

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
        "SELECT s.ip, h.rdns, h.asn, h.asn_org, h.country, "
        "COALESCE(h.os_guess, h.os_family), h.hop_count, h.device_type, "
        "COUNT(*) AS svc_count "
        "FROM services s "
        "LEFT JOIN hosts h ON h.scan_id = s.scan_id AND h.ip = s.ip "
        "WHERE s.scan_id = ?"
    )
    params: list = [scan_id]
    if q:
        query += (
            " AND (s.ip LIKE ? OR COALESCE(h.rdns,'') LIKE ? "
            "   OR COALESCE(h.asn_org,'') LIKE ? OR COALESCE(h.os_family,'') LIKE ?"
            "   OR COALESCE(h.os_guess,'') LIKE ? OR COALESCE(h.device_type,'') LIKE ?)"
        )
        like = f"%{q}%"
        params.extend([like] * 6)
    query += (
        " GROUP BY s.ip, h.rdns, h.asn, h.asn_org, h.country, h.os_guess, h.os_family,"
        " h.hop_count, h.device_type"
        " ORDER BY s.ip"
    )
    rows = db.execute(query, params).fetchall()
    return [
        {
            "ip": r[0], "rdns": r[1], "asn": r[2], "asn_org": r[3], "country": r[4],
            "os": r[5], "hop_count": r[6], "device_type": r[7], "service_count": r[8],
        }
        for r in rows
    ]


def _services_rows(db: sqlite3.Connection, scan_id: int, q: str | None) -> list[dict]:
    query = (
        "SELECT ip, port, proto, service, banner, cert_fingerprint, ja3s, ja4s, "
        "ssh_hostkey, tech "
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
            "banner": r[4], "cert_fingerprint": r[5], "ja3s": r[6], "ja4s": r[7],
            "ssh_hostkey": r[8], "tech": r[9],
        }
        for r in db.execute(query, params).fetchall()
    ]


def _host_row(db: sqlite3.Connection, scan_id: int, ip: str) -> dict | None:
    row = db.execute(
        "SELECT ip, rdns, asn, asn_org, country, stack_sig, os_family, os_confidence, "
        "hop_count, os_guess, device_type, device_confidence, "
        "nat_suspected, min_backend_count, backend_evidence "
        "FROM hosts WHERE scan_id = ? AND ip = ?",
        (scan_id, ip),
    ).fetchone()
    if row is not None:
        return {
            "ip": row[0], "rdns": row[1], "asn": row[2],
            "asn_org": row[3], "country": row[4],
            "stack_sig": row[5], "os_family": row[6], "os_confidence": row[7],
            "hop_count": row[8], "os_guess": row[9], "device_type": row[10],
            "device_confidence": row[11],
            "nat_suspected": bool(row[12]), "min_backend_count": row[13],
            "backend_evidence": _load_json_list(row[14]),
        }
    # Host might not have a row if enrichment was off; synthesize a minimal one
    # as long as the IP shows up in services.
    hit = db.execute(
        "SELECT 1 FROM services WHERE scan_id = ? AND ip = ? LIMIT 1", (scan_id, ip)
    ).fetchone()
    if hit:
        return {
            "ip": ip, "rdns": None, "asn": None, "asn_org": None, "country": None,
            "stack_sig": None, "os_family": None, "os_confidence": None,
            "hop_count": None, "os_guess": None, "device_type": None,
            "device_confidence": None, "nat_suspected": False,
            "min_backend_count": None, "backend_evidence": [],
        }
    return None


def _load_json_list(raw) -> list:
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except Exception:
        return []
    return parsed if isinstance(parsed, list) else []


def _services_for_host(db: sqlite3.Connection, scan_id: int, ip: str) -> list[dict]:
    return [
        {
            "port": r[0], "proto": r[1], "service": r[2], "banner": r[3],
            "cert_fingerprint": r[4], "ja3s": r[5], "ja4s": r[6],
            "ssh_hostkey": r[7], "tech": r[8],
            "stack_sig": r[9], "os_family": r[10], "clock_key": r[11],
        }
        for r in db.execute(
            "SELECT port, proto, service, banner, cert_fingerprint, ja3s, ja4s, "
            "ssh_hostkey, tech, stack_sig, os_family, clock_key "
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


def _diff_pairs(db: sqlite3.Connection) -> list[dict]:
    rows = db.execute(
        """
        SELECT from_scan_id, to_scan_id, kind, COUNT(*)
        FROM scan_diffs
        GROUP BY from_scan_id, to_scan_id, kind
        """
    ).fetchall()
    pairs: dict[tuple[int, int], dict] = {}
    for f, t, kind, count in rows:
        entry = pairs.setdefault(
            (f, t),
            {
                "from_scan_id": f, "to_scan_id": t,
                "counts": {"new_service": 0, "gone_service": 0, "changed": 0,
                           "new_cert": 0, "new_host": 0, "path_changed": 0,
                           "topology_change": 0, "risk_increased": 0,
                           "total": 0},
            },
        )
        entry["counts"][kind] = count
        entry["counts"]["total"] += count
    return sorted(pairs.values(), key=lambda p: p["to_scan_id"], reverse=True)


def _diff_findings(
    db: sqlite3.Connection, from_scan_id: int, to_scan_id: int
) -> dict[str, list[dict]]:
    rows = db.execute(
        "SELECT kind, ip, port, detail FROM scan_diffs "
        "WHERE from_scan_id = ? AND to_scan_id = ? ORDER BY kind, ip, port",
        (from_scan_id, to_scan_id),
    ).fetchall()
    findings: dict[str, list[dict]] = {}
    for kind, ip, port, detail in rows:
        try:
            parsed = json.loads(detail) if detail else {}
        except Exception:
            parsed = {}
        findings.setdefault(kind, []).append(
            {"ip": ip, "port": port, "detail": parsed}
        )
    return findings


_PIVOT_COLUMNS = (
    "cert_fingerprint", "favicon_mmh3", "ja3s", "ja4s", "ssh_hostkey",
    "stack_sig", "clock_key",
)


def _pivot_exact(db: sqlite3.Connection, column: str, value) -> list[dict]:
    if column not in _PIVOT_COLUMNS:
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
