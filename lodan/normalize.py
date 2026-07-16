"""Canonicalize probe output so cosmetic variance doesn't churn diffs or
split pivots.

Applied at the storage boundary (`writer.update_service_from_probe`): whatever
lands in the `services` table is already canonical. The `changed` diff compares
stored `banner` / `tech` / `cert_fingerprint` by exact match, and the pivots
group on `tech` / `cert_sans` / `cert_fingerprint`, so normalizing once here is
what makes a re-scan of an unchanged service compare equal (no noisy `changed`)
and makes two hosts serving the same value collate on it.

Everything is a pure function of its input — trivially testable, no I/O.
"""
from __future__ import annotations

import json
from ipaddress import ip_address


def ip(value: str | None) -> str | None:
    """Canonicalize an IP address string for stable storage / diffs / pivots.

    IPv4 is returned unchanged; IPv6 is compressed and lower-cased
    (``2001:DB8:0:0:0:0:0:1`` -> ``2001:db8::1``) so the same host never splits
    a pivot or shows as a spurious diff just because a backend rendered it
    differently. A value that doesn't parse as an IP is returned trimmed as-is.
    """
    if value is None:
        return None
    stripped = value.strip()
    try:
        return str(ip_address(stripped))
    except ValueError:
        return stripped or None


def host_for_url(host: str) -> str:
    """Bracket an IPv6 literal for use in a URL authority (``[::1]``); IPv4 and
    hostnames pass through. Colons only appear in IPv6 literals here."""
    return f"[{host}]" if ":" in host else host


def banner(value: str | None) -> str | None:
    """Collapse whitespace and drop control bytes from a free-form banner.

    Case is *preserved* — product and version strings ("OpenSSH_9.6p1") carry
    meaning there — but trailing CRLF, alignment padding, and embedded control
    characters (common in raw protocol banners) are incidental and removed. An
    all-whitespace / empty banner canonicalizes to None.
    """
    if value is None:
        return None
    # Keep printable chars and whitespace; str.split() then folds every
    # whitespace run to a single space and trims the ends.
    kept = "".join(ch for ch in value if ch.isprintable() or ch.isspace())
    cleaned = " ".join(kept.split())
    return cleaned or None


def fingerprint(value: str | None) -> str | None:
    """Lower-case + trim a hex fingerprint so case never splits a pivot.

    Our own probes already emit lower-case sha256, so this is defensive: a
    fingerprint arriving upper-cased from anywhere still collates.
    """
    if value is None:
        return None
    cleaned = value.strip().lower()
    return cleaned or None


def tech(items: list[str] | None) -> list[str] | None:
    """Normalize a tech list: trim, lower-case, dedupe, sort.

    Tech names are identifiers ("nginx" == "Nginx" == "NGINX"), so folding case
    collapses the same technology onto one value, and sorting makes detection
    order irrelevant to the `changed` diff.
    """
    if items is None:
        return None
    seen: set[str] = set()
    for item in items:
        name = " ".join(str(item).split()).lower()
        if name:
            seen.add(name)
    return sorted(seen)


def sans(items: list[str] | None) -> list[str] | None:
    """Normalize cert SANs: trim, lower-case, dedupe, sort.

    DNS names are case-insensitive, so folding case lets `sans:` pivots collate,
    and sorting removes cert-encoding-order churn from the diff. IP/URI SANs
    lower-case harmlessly (hostnames dominate real-world SAN lists).
    """
    if items is None:
        return None
    seen: set[str] = set()
    for item in items:
        name = " ".join(str(item).split()).lower()
        if name:
            seen.add(name)
    return sorted(seen)


def tech_json(items: list[str] | None) -> str | None:
    normalized = tech(items)
    return json.dumps(normalized) if normalized is not None else None


def sans_json(items: list[str] | None) -> str | None:
    normalized = sans(items)
    return json.dumps(normalized) if normalized is not None else None
