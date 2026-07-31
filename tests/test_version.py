"""Version comparison for CVE range evaluation.

Real-world versions are not semver. These cases are the shapes lodan actually
sees on the wire.
"""
from __future__ import annotations

import pytest

from lodan.enrich.version import compare, in_range, looks_like_a_version, parse_version


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("2.4.9", "2.4.54"),        # numeric, not lexical
        ("1.9", "1.10"),
        ("2.4.54", "2.5"),
        ("1.0", "2.0"),
        ("8.2", "8.2p1"),           # OpenSSH portable suffix is a LATER release
        ("8.2p1", "8.2p2"),
        ("8.2p9", "8.3"),
        ("1.0rc1", "1.0"),          # pre-release marker precedes the release
        ("1.0beta2", "1.0"),
        ("1.0alpha", "1.0beta"),
        ("7.4", "8.0"),
    ],
)
def test_ordering(lower: str, higher: str) -> None:
    assert compare(lower, higher) == -1
    assert compare(higher, lower) == 1


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("1.0", "1.0.0"),           # trailing zeros carry no information
        ("1.0.0.0", "1"),
        ("2.4.54", "2.4.54"),
        ("v1.28.2", "1.28.2"),      # leading v stripped (k8s gitVersion)
        ("V2.0", "2.0"),
    ],
)
def test_equality(a: str, b: str) -> None:
    assert compare(a, b) == 0


def test_unparseable_sorts_lowest() -> None:
    assert compare(None, "1.0") == -1
    assert compare("", "1.0") == -1
    assert compare("unknown", "1.0") == -1
    assert compare(None, None) == 0


def test_parse_version_tokenizes_mixed_runs() -> None:
    assert parse_version("8.2p1") == (
        (2, 8, ""), (2, 2, ""), (1, 0, "p"), (2, 1, ""),
    )


def test_trailing_zeros_are_equal_without_being_stripped() -> None:
    """Padding in `compare` handles this, not truncation in `parse_version` —
    stripping would misalign `1.0` against `1.0rc1`."""
    assert parse_version("1.0.0") != parse_version("1")
    assert compare("1.0.0", "1") == 0
    assert compare("1.0", "1.0rc1") == 1


def test_looks_like_a_version_rejects_placeholders() -> None:
    assert looks_like_a_version("1.2.3") is True
    assert looks_like_a_version("v1.2.3") is True
    assert looks_like_a_version("unknown") is False
    assert looks_like_a_version("") is False
    assert looks_like_a_version(None) is False


# --- range evaluation --------------------------------------------------------

def test_end_excluding_is_half_open() -> None:
    assert in_range("2.4.54", end="2.4.55", end_inclusive=False) is True
    assert in_range("2.4.55", end="2.4.55", end_inclusive=False) is False
    assert in_range("2.4.56", end="2.4.55", end_inclusive=False) is False


def test_end_including_admits_the_bound() -> None:
    assert in_range("2.4.55", end="2.4.55", end_inclusive=True) is True
    assert in_range("2.4.56", end="2.4.55", end_inclusive=True) is False


def test_start_including_admits_the_bound() -> None:
    assert in_range("2.4.0", start="2.4.0", start_inclusive=True) is True
    assert in_range("2.3.9", start="2.4.0", start_inclusive=True) is False


def test_start_excluding_rejects_the_bound() -> None:
    assert in_range("2.4.0", start="2.4.0", start_inclusive=False) is False
    assert in_range("2.4.1", start="2.4.0", start_inclusive=False) is True


def test_closed_range() -> None:
    kwargs = {"start": "2.4.0", "start_inclusive": True,
              "end": "2.4.55", "end_inclusive": False}
    assert in_range("2.4.30", **kwargs) is True
    assert in_range("2.3.99", **kwargs) is False
    assert in_range("2.4.55", **kwargs) is False


def test_unbounded_both_sides_admits_anything_parseable() -> None:
    assert in_range("1.2.3") is True


def test_unparseable_version_is_excluded_not_assumed() -> None:
    """A false-positive CVE costs an operator more than a missed one."""
    assert in_range(None, end="9.9") is False
    assert in_range("", end="9.9") is False
    assert in_range("unknown", end="9.9") is False


def test_openssh_range_evaluation() -> None:
    """The portable-suffix ordering has to hold inside a range too."""
    assert in_range("8.2p1", start="8.0", start_inclusive=True,
                    end="8.3", end_inclusive=False) is True
    assert in_range("8.3p1", start="8.0", start_inclusive=True,
                    end="8.3", end_inclusive=False) is False
