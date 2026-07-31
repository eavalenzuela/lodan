"""Opt-in change notifications: push a diff summary when a rescan finds drift.

Wired into the scan orchestrator right after the auto-diff. It fires ONLY when
the diff against the previous scan is non-empty and at least one sink (webhook
or email) is configured — a quiet rescan stays quiet, which is the whole point.
Sink failures are captured and returned (the caller records them); a broken
webhook or mail server never fails the scan.
"""
from __future__ import annotations

import asyncio
import json
import os
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any

import httpx

from lodan.config import NotifyBlock
from lodan.diff.scanner import DiffCounts

_LABELS = (
    ("new_service", "new service(s)"),
    ("gone_service", "gone service(s)"),
    ("changed", "changed"),
    ("new_cert", "new cert(s)"),
    ("new_host", "new host(s)"),
    ("path_changed", "path/stack changed"),
    ("topology_change", "topology changed"),
)


@dataclass(frozen=True)
class SinkResult:
    sink: str
    ok: bool
    detail: str


def render_text(workspace: str, scan_id: int, diff_from: int, counts: DiffCounts) -> str:
    parts = [f"{getattr(counts, key)} {label}" for key, label in _LABELS if getattr(counts, key)]
    detail = ", ".join(parts) if parts else "changes"
    return (
        f"lodan: {counts.total} change(s) in workspace '{workspace}' "
        f"(scan {diff_from} → {scan_id}): {detail}"
    )


def build_summary(
    workspace: str,
    scan_id: int,
    diff_from: int,
    counts: DiffCounts,
    examples: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "tool": "lodan",
        "event": "scan_diff",
        "workspace": workspace,
        "scan_id": scan_id,
        "diff_from": diff_from,
        "counts": counts.as_dict(),
        "examples": examples,
        "text": render_text(workspace, scan_id, diff_from, counts),
    }


async def _post_webhook(
    cfg: NotifyBlock, summary: dict[str, Any], client: httpx.AsyncClient | None
) -> SinkResult:
    owns = client is None
    client = client or httpx.AsyncClient(timeout=cfg.timeout_s)
    try:
        resp = await client.post(cfg.webhook_url, json=summary)
        resp.raise_for_status()
        return SinkResult("webhook", True, f"HTTP {resp.status_code}")
    finally:
        if owns:
            await client.aclose()


def build_email(cfg: NotifyBlock, summary: dict[str, Any]) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = cfg.email_from
    msg["To"] = cfg.email_to
    msg["Subject"] = f"[lodan] {summary['counts']['total']} change(s) in {summary['workspace']}"
    body = (
        summary["text"]
        + "\n\ncounts:\n"
        + json.dumps(summary["counts"], indent=2, sort_keys=True)
    )
    if summary["examples"]:
        body += "\n\nexamples:\n" + "\n".join(
            f"  {e['kind']} {e['ip']}" + (f":{e['port']}" if e.get("port") else "")
            for e in summary["examples"]
        )
    msg.set_content(body)
    return msg


def _send_email_sync(cfg: NotifyBlock, msg: EmailMessage) -> SinkResult:
    with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=cfg.timeout_s) as server:
        if cfg.smtp_starttls:
            server.starttls()
        user = os.environ.get("LODAN_SMTP_USERNAME")
        password = os.environ.get("LODAN_SMTP_PASSWORD")
        if user and password:
            server.login(user, password)
        server.send_message(msg)
    n = len([r for r in cfg.email_to.split(",") if r.strip()])
    return SinkResult("email", True, f"sent to {n} recipient(s)")


async def send(
    cfg: NotifyBlock,
    summary: dict[str, Any],
    *,
    webhook_client: httpx.AsyncClient | None = None,
) -> list[SinkResult]:
    """Dispatch `summary` to every enabled sink. Never raises — each sink's
    failure is captured as a SinkResult with ok=False."""
    results: list[SinkResult] = []
    if cfg.webhook_enabled:
        try:
            results.append(await _post_webhook(cfg, summary, webhook_client))
        except Exception as e:  # noqa: BLE001 — any transport/HTTP error is non-fatal
            results.append(SinkResult("webhook", False, repr(e)))
    if cfg.email_enabled:
        try:
            msg = build_email(cfg, summary)
            results.append(await asyncio.to_thread(_send_email_sync, cfg, msg))
        except Exception as e:  # noqa: BLE001 — SMTP failures must not fail the scan
            results.append(SinkResult("email", False, repr(e)))
    return results
