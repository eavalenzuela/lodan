from __future__ import annotations

import pytest

from lodan.probes.http import (
    HTTP_PORTS,
    HTTPS_PORTS,
    HTTPCapture,
    HTTPProbe,
    _extract_title,
    parse_capture,
    shodan_mmh3,
)


def _capture(
    status: int = 200,
    headers: dict[str, str] | None = None,
    body: bytes = b"",
    scheme: str = "http",
    favicon: bytes | None = None,
) -> HTTPCapture:
    return HTTPCapture(
        status=status,
        headers={k.lower(): v for k, v in (headers or {}).items()},
        body=body,
        scheme=scheme,
        favicon_bytes=favicon,
    )


def test_parse_extracts_server_and_title() -> None:
    result = parse_capture(
        _capture(
            status=200,
            headers={"Server": "nginx/1.25.3"},
            body=b"<html><head><title>Welcome</title></head></html>",
        )
    )
    assert result.service == "http"
    assert "HTTP/200" in (result.banner or "")
    assert "nginx/1.25.3" in (result.banner or "")
    assert "Welcome" in (result.banner or "")
    assert result.raw["title"] == "Welcome"
    assert result.raw["server"] == "nginx/1.25.3"


def test_parse_without_server_header() -> None:
    result = parse_capture(_capture(status=404, body=b"<html></html>"))
    assert result.raw["server"] is None
    assert "HTTP/404" in (result.banner or "")


def test_favicon_hash_is_mmh3_of_base64() -> None:
    # tiny 1-byte "favicon"
    result = parse_capture(_capture(favicon=b"\x00"))
    assert result.favicon_mmh3 == shodan_mmh3(b"\x00")


def test_favicon_absent_gives_none() -> None:
    result = parse_capture(_capture(favicon=None))
    assert result.favicon_mmh3 is None


@pytest.mark.parametrize(
    "body,expected",
    [
        (b"<title>Hi</title>", "Hi"),
        (b"<TITLE>Upper</TITLE>", "Upper"),
        (b"<title>   multi\n  line   title  </title>", "multi line title"),
        (b"no title here", None),
        (b"<title></title>", None),
    ],
)
def test_extract_title(body: bytes, expected: str | None) -> None:
    assert _extract_title(body) == expected


def test_extract_title_ignores_past_64kb() -> None:
    body = b"A" * 70000 + b"<title>late</title>"
    assert _extract_title(body) is None


def test_https_and_http_ports_disjoint() -> None:
    assert HTTPS_PORTS.isdisjoint(HTTP_PORTS)


def test_probe_exposes_combined_default_ports() -> None:
    probe = HTTPProbe()
    assert 80 in probe.default_ports
    assert 443 in probe.default_ports
    assert 8080 in probe.default_ports
