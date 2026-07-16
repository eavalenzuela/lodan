from __future__ import annotations

from lodan.probes.elastic import ElasticProbe, parse_elastic


def test_unauthenticated_cluster_info() -> None:
    body = (
        b'{"name":"node-1","cluster_name":"prod",'
        b'"version":{"number":"8.11.0","lucene_version":"9.8.0"},'
        b'"tagline":"You Know, for Search"}'
    )
    r = parse_elastic(200, body)
    assert r.service == "elasticsearch"
    assert "8.11.0" in (r.banner or "")
    assert "unauthenticated" in (r.banner or "")
    assert r.raw["unauthenticated"] is True
    assert r.raw["cluster_name"] == "prod"


def test_auth_required() -> None:
    r = parse_elastic(401, b'{"error":"unauthorized"}')
    assert "auth required" in (r.banner or "")
    assert r.raw["status"] == 401


def test_non_json_body() -> None:
    r = parse_elastic(200, b"<html>not elastic</html>")
    assert r.raw["status"] == 200


def test_default_ports() -> None:
    assert 9200 in ElasticProbe().default_ports
