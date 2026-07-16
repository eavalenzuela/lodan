"""Elasticsearch probe: unauthenticated `GET /` cluster info. Detection-only.

Elasticsearch answers `GET /` with a JSON document naming the node, cluster, and
version when it is reachable without authentication — the classic "open ES"
exposure. No credentials are sent (same posture as the HTTP probe). A `401`
means auth is enforced, which is the safe configuration and reported as such.
"""
from __future__ import annotations

import json
from typing import Any

import httpx

from lodan import normalize
from lodan.probes.base import ProbeResult

_DEFAULT_ES_PORTS = frozenset({9200, 9201})
_USER_AGENT = "lodan/probe"


class ElasticProbe:
    name = "elastic"
    default_ports = _DEFAULT_ES_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        async with httpx.AsyncClient(
            verify=False, timeout=timeout, follow_redirects=False,
            headers={"User-Agent": _USER_AGENT},
        ) as client:
            resp = await client.get(f"http://{normalize.host_for_url(ip)}:{port}/")
            return parse_elastic(resp.status_code, resp.content)


def parse_elastic(status: int, body: bytes) -> ProbeResult:
    result_raw: dict[str, Any] = {"status": status, "length": len(body)}
    if status in (401, 403):
        return ProbeResult(
            service="elasticsearch",
            banner=f"Elasticsearch (auth required, HTTP {status})",
            raw=result_raw,
        )
    try:
        doc = json.loads(body)
    except (ValueError, TypeError):
        return ProbeResult(
            service="elasticsearch" if b"elastic" in body.lower() else "http",
            banner=f"elastic: non-JSON reply (HTTP {status})",
            raw=result_raw,
        )
    if not isinstance(doc, dict):
        return ProbeResult(service="http", banner=f"HTTP {status}", raw=result_raw)

    version = doc.get("version") or {}
    number = version.get("number") if isinstance(version, dict) else None
    lucene = version.get("lucene_version") if isinstance(version, dict) else None
    name = doc.get("name")
    cluster = doc.get("cluster_name")
    tagline = doc.get("tagline")
    result_raw.update({
        "name": name, "cluster_name": cluster, "version": number,
        "lucene_version": lucene, "tagline": tagline,
        "unauthenticated": status == 200,
    })
    label = f"Elasticsearch {number}" if number else "Elasticsearch"
    if cluster:
        label += f" cluster={cluster}"
    if status == 200:
        label += " (unauthenticated)"
    return ProbeResult(service="elasticsearch", banner=label[:300], raw=result_raw)
