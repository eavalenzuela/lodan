"""Kubernetes API server / kubelet detector. Unauth detection only.

Targets the unauthenticated endpoints every K8s component exposes:
- kube-apiserver (6443)     -> GET /version returns {gitVersion, platform, ...}
- kubelet read-only (10250) -> GET /pods without auth usually 401s; /metrics
                               sometimes opens; but /healthz is reliably hit

We try /version first. If that 404s or isn't JSON, fall back to /healthz
so kubelet shows up as "kubernetes (kubelet)" rather than "non-Kubernetes".
"""
from __future__ import annotations

import asyncio
from typing import Any

import httpx

from lodan import __version__
from lodan.probes.base import ProbeResult

_DEFAULT_K8S_PORTS = frozenset({6443, 10250, 10255, 10257, 10259})

_USER_AGENT = f"lodan/{__version__}"


class KubernetesProbe:
    name = "kubernetes"
    default_ports = _DEFAULT_K8S_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        capture = await asyncio.wait_for(fetch(ip, port, timeout), timeout=timeout + 1)
        return parse(capture)


async def fetch(ip: str, port: int, timeout: float) -> dict[str, Any]:
    # K8s endpoints are TLS by default, except the legacy 10255 read-only kubelet.
    scheme = "http" if port == 10255 else "https"
    base = f"{scheme}://{ip}:{port}"
    out: dict[str, Any] = {}
    async with httpx.AsyncClient(
        verify=False,
        timeout=timeout,
        follow_redirects=False,
        headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
    ) as client:
        for path in ("/version", "/healthz"):
            try:
                response = await client.get(base + path)
            except httpx.HTTPError as e:
                out[path] = {"_error": repr(e)}
                continue
            out[path] = {
                "status": response.status_code,
                "body": response.text[:4096],
                "content_type": response.headers.get("content-type", ""),
            }
    return out


def parse(capture: dict[str, Any]) -> ProbeResult:
    raw: dict[str, Any] = dict(capture)
    version_resp = capture.get("/version") or {}
    health_resp = capture.get("/healthz") or {}
    import json as _json

    payload = None
    try:
        if version_resp.get("status") == 200 and "json" in version_resp.get("content_type", ""):
            payload = _json.loads(version_resp.get("body") or "")
    except Exception:
        payload = None

    if isinstance(payload, dict) and "gitVersion" in payload:
        raw["payload"] = payload
        version = payload.get("gitVersion", "?")
        platform = payload.get("platform", "?")
        go_version = payload.get("goVersion", "?")
        banner = f"Kubernetes {version} ({platform}, {go_version})"
        return ProbeResult(service="kubernetes", banner=banner, raw=raw)

    healthz_body = (health_resp.get("body") or "").strip()
    if healthz_body in ("ok", "+ok"):
        return ProbeResult(
            service="kubernetes",
            banner="kubernetes (healthz=ok, likely kubelet)",
            raw=raw,
        )
    if version_resp.get("status") == 401 or health_resp.get("status") == 401:
        return ProbeResult(
            service="kubernetes",
            banner="kubernetes API (auth required)",
            raw=raw,
        )
    return ProbeResult(
        service="kubernetes",
        banner="kubernetes: no recognizable endpoint",
        raw=raw,
    )
