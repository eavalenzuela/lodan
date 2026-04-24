"""HTTP probe: status, headers, title, favicon mmh3.

Split into fetch + parse so tests can skip the network. Handles http and
https based on port; TLS verification is off for the same reason the TLS
probe keeps it off — we want to see what's there, not what's valid.

Tech detection is a separate module that reads from ProbeResult.raw and
updates ProbeResult.tech; it lands in the M2c commit.
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Any

import httpx
import mmh3

from lodan import __version__
from lodan.probes.base import ProbeResult

_USER_AGENT = f"lodan/{__version__}"
_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

HTTPS_PORTS = frozenset({443, 8443, 9443, 10443})
HTTP_PORTS = frozenset({80, 81, 591, 631, 8000, 8008, 8080, 8081, 8888, 9000, 9090})


@dataclass(frozen=True)
class HTTPCapture:
    status: int
    headers: dict[str, str]
    body: bytes
    scheme: str
    favicon_bytes: bytes | None


class HTTPProbe:
    name = "http"
    default_ports = HTTP_PORTS | HTTPS_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        capture = await fetch(ip, port, timeout)
        return parse_capture(capture)


def _scheme_for_port(port: int) -> str:
    return "https" if port in HTTPS_PORTS else "http"


async def fetch(ip: str, port: int, timeout: float) -> HTTPCapture:
    scheme = _scheme_for_port(port)
    base = f"{scheme}://{ip}:{port}"
    headers = {"User-Agent": _USER_AGENT, "Accept": "*/*"}
    async with httpx.AsyncClient(
        verify=False,
        timeout=timeout,
        follow_redirects=False,
        headers=headers,
    ) as client:
        response = await client.get(base + "/")
        favicon_bytes = None
        try:
            fav = await client.get(base + "/favicon.ico")
            if fav.status_code == 200 and fav.content:
                favicon_bytes = fav.content
        except httpx.HTTPError:
            favicon_bytes = None
        return HTTPCapture(
            status=response.status_code,
            headers={k.lower(): v for k, v in response.headers.items()},
            body=response.content,
            scheme=scheme,
            favicon_bytes=favicon_bytes,
        )


def parse_capture(capture: HTTPCapture) -> ProbeResult:
    title = _extract_title(capture.body)
    server = capture.headers.get("server")
    favicon_hash = shodan_mmh3(capture.favicon_bytes) if capture.favicon_bytes else None
    banner_parts: list[str] = [f"HTTP/{capture.status}"]
    if server:
        banner_parts.append(server)
    if title:
        banner_parts.append(f"title={title!r}")
    raw: dict[str, Any] = {
        "status": capture.status,
        "scheme": capture.scheme,
        "title": title,
        "server": server,
        "headers": capture.headers,
    }
    return ProbeResult(
        service="http",
        banner=" ".join(banner_parts),
        favicon_mmh3=favicon_hash,
        raw=raw,
    )


def _extract_title(body: bytes) -> str | None:
    match = _TITLE_RE.search(body[:65536])
    if not match:
        return None
    raw = match.group(1).decode("utf-8", "replace").strip()
    return re.sub(r"\s+", " ", raw) or None


def shodan_mmh3(raw: bytes) -> int:
    """Shodan-compatible favicon hash: mmh3 over the base64-encoded bytes,
    chunked to 76 chars per line with trailing newline."""
    b64 = base64.encodebytes(raw)
    return mmh3.hash(b64)
