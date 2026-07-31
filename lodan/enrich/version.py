"""Software version comparison for CVE range evaluation.

NVD expresses most modern advisories as ranges ("affects httpd up to 2.4.54")
rather than as an enumeration of concrete versions, so matching them needs an
ordering over version strings — and real-world versions are not semver. lodan
has to compare `8.2p1` (OpenSSH portable), `v1.28.2` (Kubernetes gitVersion),
`8.0.35-0ubuntu0.22.04.1` (Debian-packaged MySQL) and `2.4.54` against each
other and against NVD's bounds.

The scheme: tokenize into runs of digits and runs of letters, then compare
component-wise with three ranks —

    2  numeric component      (compared by value, so 54 > 9)
    1  ordinary alpha suffix  (OpenSSH's "p" in 8.2p1 — a release *after* 8.2)
    0  pre-release marker     ("rc", "beta", … — a release *before* the final)

When one side runs out of components, what it pads with depends on what the
*other* side has at that position — and that is what makes every direction
come out right at once:

    other is numeric      pad (2, 0, "")   so 1.0 == 1.0.0, and 1.0 < 1.0.1
    other is alpha        pad (1, 0, "")   so 8.2 < 8.2p1   ("" sorts below "p")
    other is pre-release  pad (1, 0, "")   so 1.0 > 1.0rc1  (rank 1 beats rank 0)

A fixed pad cannot satisfy all three: padding numerically makes `8.2 > 8.2p1`,
and padding at rank 1 makes `1.0 < 1.0.0`.
"""
from __future__ import annotations

import re

_TOKEN_RE = re.compile(r"\d+|[A-Za-z]+")

# Alpha tokens that mark a build *preceding* the corresponding release.
_PRERELEASE = frozenset({
    "rc", "alpha", "beta", "dev", "pre", "preview", "snapshot", "milestone",
})

_NUMERIC = 2
_ALPHA = 1
_PRE = 0

def _pad_against(other: tuple[int, int, str]) -> tuple[int, int, str]:
    """What an absent component compares as, given what it is compared to."""
    if other[0] == _NUMERIC:
        return (_NUMERIC, 0, "")
    return (_ALPHA, 0, "")


def parse_version(value: str | None) -> tuple[tuple[int, int, str], ...]:
    """Tokenize a version string into a comparable key."""
    if not value:
        return ()
    text = value.strip()
    if text[:1] in ("v", "V"):
        text = text[1:]
    parts: list[tuple[int, int, str]] = []
    for token in _TOKEN_RE.findall(text):
        if token.isdigit():
            parts.append((_NUMERIC, int(token), ""))
        else:
            lowered = token.lower()
            rank = _PRE if lowered in _PRERELEASE else _ALPHA
            parts.append((rank, 0, lowered))
    return tuple(parts)


def looks_like_a_version(value: str | None) -> bool:
    """Does this string begin with a number?

    `unknown`, `?` and similar placeholders tokenize fine but are not
    versions, and treating them as one puts them below every bound — which
    would make them match every "up to X" advisory in the database.
    """
    parsed = parse_version(value)
    return bool(parsed) and parsed[0][0] == _NUMERIC


def compare(left: str | None, right: str | None) -> int:
    """Three-way compare two version strings. Unparseable sorts lowest."""
    a = parse_version(left)
    b = parse_version(right)
    width = max(len(a), len(b))
    for i in range(width):
        if i >= len(a):
            x, y = _pad_against(b[i]), b[i]
        elif i >= len(b):
            x, y = a[i], _pad_against(a[i])
        else:
            x, y = a[i], b[i]
        if x != y:
            return -1 if x < y else 1
    return 0


def in_range(
    version: str | None,
    *,
    start: str | None = None,
    start_inclusive: bool = False,
    end: str | None = None,
    end_inclusive: bool = False,
) -> bool:
    """Is `version` inside the (possibly half-open) NVD range?

    An absent bound is unbounded on that side. An unparseable version can't be
    placed, so it is excluded rather than assumed to be in range — a
    false-positive CVE is more expensive to an operator than a missed one they
    can still find via the concrete-version path.
    """
    if not looks_like_a_version(version):
        return False
    if start is not None:
        cmp_start = compare(version, start)
        if cmp_start < 0 or (cmp_start == 0 and not start_inclusive):
            return False
    if end is not None:
        cmp_end = compare(version, end)
        if cmp_end > 0 or (cmp_end == 0 and not end_inclusive):
            return False
    return True
