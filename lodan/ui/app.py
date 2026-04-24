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
