"""Change-notification sinks: summary shape, webhook dispatch, email build,
failure isolation, and the fire-only-when-changed gate."""
from __future__ import annotations

import asyncio
import json

import httpx

from lodan import notify
from lodan.config import NotifyBlock
from lodan.diff.scanner import DiffCounts


def _counts() -> DiffCounts:
    return DiffCounts(new_service=2, new_host=1)


def test_render_text_lists_nonzero_kinds() -> None:
    text = notify.render_text("home-lab", 8, 7, _counts())
    assert "3 change(s)" in text
    assert "2 new service(s)" in text
    assert "1 new host(s)" in text
    assert "scan 7 → 8" in text
    # Zero-count kinds are omitted.
    assert "gone service" not in text


def test_build_summary_shape() -> None:
    s = notify.build_summary("w", 8, 7, _counts(), [{"kind": "new_service", "ip": "10.0.0.9", "port": 443}])
    assert s["event"] == "scan_diff"
    assert s["counts"]["total"] == 3
    assert s["examples"][0]["ip"] == "10.0.0.9"
    assert "change(s)" in s["text"]


def test_webhook_posts_summary_json() -> None:
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        return httpx.Response(200)

    async def _run():
        cfg = NotifyBlock(webhook_url="https://hooks.example.com/x")
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        summary = notify.build_summary("w", 8, 7, _counts(), [])
        try:
            return await notify.send(cfg, summary, webhook_client=client)
        finally:
            await client.aclose()

    results = asyncio.run(_run())
    assert len(results) == 1
    assert results[0].sink == "webhook"
    assert results[0].ok
    assert seen["url"] == "https://hooks.example.com/x"
    assert seen["body"]["counts"]["total"] == 3


def test_webhook_failure_is_captured_not_raised() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    async def _run():
        cfg = NotifyBlock(webhook_url="https://hooks.example.com/x")
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            return await notify.send(
                cfg, notify.build_summary("w", 2, 1, _counts(), []), webhook_client=client
            )
        finally:
            await client.aclose()

    results = asyncio.run(_run())
    assert results[0].sink == "webhook"
    assert results[0].ok is False


def test_disabled_config_sends_nothing() -> None:
    results = asyncio.run(
        notify.send(NotifyBlock(), notify.build_summary("w", 2, 1, _counts(), []))
    )
    assert results == []


def test_build_email_headers_and_body() -> None:
    cfg = NotifyBlock(email_to="a@example.com, b@example.com", email_from="lodan@host")
    summary = notify.build_summary("w", 8, 7, _counts(), [{"kind": "new_host", "ip": "10.0.0.9", "port": None}])
    msg = notify.build_email(cfg, summary)
    assert msg["To"] == "a@example.com, b@example.com"
    assert msg["From"] == "lodan@host"
    assert "3 change(s)" in msg["Subject"]
    body = msg.get_content()
    assert "new_host 10.0.0.9" in body
    assert '"total": 3' in body
