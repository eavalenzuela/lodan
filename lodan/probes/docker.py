"""Docker remote API detector. Unauth detection only.

GET /version against the default Docker daemon ports. A well-formed
response gives us ApiVersion, Version, Os, Arch, GoVersion, KernelVersion.

This does not authenticate, does not list containers, does not pull
images. Presence of the endpoint is itself the high-signal finding —
exposed Docker APIs are a serious misconfiguration.
"""
from __future__ import annotations

import asyncio
from typing import Any

import httpx

from lodan import __version__
from lodan.probes.base import ProbeResult

_DEFAULT_DOCKER_PORTS = frozenset({2375, 2376})
_TLS_PORTS = frozenset({2376})

_USER_AGENT = f"lodan/{__version__}"


class DockerProbe:
    name = "docker"
    default_ports = _DEFAULT_DOCKER_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        payload = await asyncio.wait_for(fetch(ip, port, timeout), timeout=timeout + 1)
        return parse(payload)


async def fetch(ip: str, port: int, timeout: float) -> dict[str, Any] | None:
    scheme = "https" if port in _TLS_PORTS else "http"
    url = f"{scheme}://{ip}:{port}/version"
    try:
        async with httpx.AsyncClient(
            verify=False,
            timeout=timeout,
            follow_redirects=False,
            headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
        ) as client:
            response = await client.get(url)
    except httpx.HTTPError as e:
        return {"_error": repr(e)}
    return {
        "status": response.status_code,
        "headers": dict(response.headers),
        "body": response.text[:8192],
    }


def parse(capture: dict[str, Any] | None) -> ProbeResult:
    raw: dict[str, Any] = dict(capture or {})
    if capture is None or "_error" in raw:
        return ProbeResult(
            service="docker",
            banner="docker: no response" + (f" ({raw.get('_error')})" if '_error' in raw else ""),
            raw=raw,
        )
    status = capture.get("status")
    body = capture.get("body") or ""
    import json as _json

    try:
        payload = _json.loads(body)
    except Exception:
        payload = None

    if not isinstance(payload, dict) or "ApiVersion" not in payload:
        return ProbeResult(
            service="docker",
            banner=f"docker: non-Docker response (HTTP {status})",
            raw=raw,
        )

    raw["payload"] = payload
    version = payload.get("Version", "?")
    api = payload.get("ApiVersion", "?")
    os_ = payload.get("Os", "?")
    arch = payload.get("Arch", "?")
    banner = f"Docker {version} (API {api}) {os_}/{arch}"
    return ProbeResult(service="docker", banner=banner, raw=raw)
