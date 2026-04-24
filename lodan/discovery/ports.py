"""Port spec parser.

Accepts:
- "top-N" where N is a preset name in TOP_PORTS.
- "1-1024" range.
- "22,80,443" explicit list.
- Combinations: "22,80,1000-1010,top-100".
"""
from __future__ import annotations

# Curated nmap-inspired top-100 TCP ports. Good enough as a sensible default
# for v1. Later commits can ship the full 1000-port list as a data file.
TOP_100 = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
    2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
    8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152,
    49153, 49154, 49155, 49156, 49157,
]

TOP_PORTS: dict[str, list[int]] = {
    "top-100": TOP_100,
}


def parse_ports(spec: str) -> list[int]:
    out: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if chunk.startswith("top-"):
            if chunk not in TOP_PORTS:
                raise ValueError(f"unknown port preset: {chunk}")
            out.update(TOP_PORTS[chunk])
            continue
        if "-" in chunk:
            lo_s, hi_s = chunk.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi or lo < 1 or hi > 65535:
                raise ValueError(f"invalid port range: {chunk}")
            out.update(range(lo, hi + 1))
            continue
        p = int(chunk)
        if not 1 <= p <= 65535:
            raise ValueError(f"port out of range: {p}")
        out.add(p)
    if not out:
        raise ValueError(f"empty port spec: {spec!r}")
    return sorted(out)
