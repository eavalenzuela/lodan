"""Tests for the IP2Location-backed country resolver.

The DB binding itself is third-party; we test our coercion (sentinel
handling) and the unavailable-DB degradation without a real BIN.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from lodan.enrich.geoip import CountryResolver, _coerce_country


@pytest.mark.parametrize(
    "value, expected",
    [
        ("US", "US"),
        ("  GB  ", "GB"),
        ("-", None),
        ("", None),
        ("Not_Supported", None),
        ("Invalid IP address.", None),
        (None, None),
    ],
)
def test_coerce_country(value, expected) -> None:
    assert _coerce_country(value) == expected


def test_resolver_unavailable_returns_none(tmp_path: Path) -> None:
    r = CountryResolver(db_path=tmp_path / "missing.bin")
    assert r.available is False
    assert r.lookup("8.8.8.8") is None


class _FakeRec:
    def __init__(self, code: str) -> None:
        self.country_short = code


def test_resolver_reads_country_short(tmp_path: Path, monkeypatch) -> None:
    # Point at a path that "exists" so available is True, then stub the binding.
    bin_path = tmp_path / "DB1.BIN"
    bin_path.write_bytes(b"x")
    r = CountryResolver(db_path=bin_path)

    class _FakeDB:
        def get_all(self, ip: str):
            return _FakeRec("DE")

    monkeypatch.setattr(r, "_open", lambda: _FakeDB())
    assert r.lookup("1.2.3.4") == "DE"
