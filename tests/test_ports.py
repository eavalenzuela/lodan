from __future__ import annotations

import pytest

from lodan.discovery.ports import TOP_100, parse_ports


def test_explicit_list() -> None:
    assert parse_ports("22,80,443") == [22, 80, 443]


def test_dedupes_and_sorts() -> None:
    assert parse_ports("80,22,22,443") == [22, 80, 443]


def test_range() -> None:
    assert parse_ports("20-23") == [20, 21, 22, 23]


def test_combined() -> None:
    got = parse_ports("22,80,1000-1002,top-100")
    assert 22 in got
    assert 80 in got
    assert 1000 in got
    assert 1002 in got
    assert set(TOP_100).issubset(set(got))


def test_rejects_empty() -> None:
    with pytest.raises(ValueError):
        parse_ports("")


def test_rejects_bad_range() -> None:
    with pytest.raises(ValueError):
        parse_ports("10-5")


def test_rejects_out_of_range() -> None:
    with pytest.raises(ValueError):
        parse_ports("70000")


def test_rejects_unknown_preset() -> None:
    with pytest.raises(ValueError):
        parse_ports("top-9999")
