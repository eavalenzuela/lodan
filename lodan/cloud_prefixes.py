"""Starter list of public cloud provider prefixes.

Intentionally coarse and incomplete. `lodan update` will eventually refresh
this from each provider's published range feed; until then we ship a curated
set that covers the most common footguns so an operator cannot accidentally
scan AWS/GCP/Azure without flipping `cloud_provider_allowed=true`.

Source: the /8-to-/11 aggregate ranges each provider publishes. Keep this
list short and obvious — we want to block the "oh I typo'd my CIDR" case,
not claim comprehensive cloud detection.
"""
from __future__ import annotations

from ipaddress import IPv4Network

CLOUD_PREFIXES: dict[str, list[IPv4Network]] = {
    "aws": [
        IPv4Network("3.0.0.0/8"),
        IPv4Network("13.32.0.0/15"),
        IPv4Network("18.128.0.0/9"),
        IPv4Network("52.0.0.0/11"),
        IPv4Network("54.64.0.0/11"),
    ],
    "gcp": [
        IPv4Network("34.64.0.0/10"),
        IPv4Network("35.184.0.0/13"),
        IPv4Network("104.196.0.0/14"),
    ],
    "azure": [
        IPv4Network("13.64.0.0/11"),
        IPv4Network("20.0.0.0/8"),
        IPv4Network("40.64.0.0/10"),
        IPv4Network("52.96.0.0/12"),
    ],
    "oci": [
        IPv4Network("129.146.0.0/16"),
        IPv4Network("132.145.0.0/16"),
    ],
    "digitalocean": [
        IPv4Network("104.131.0.0/16"),
        IPv4Network("159.203.0.0/16"),
        IPv4Network("167.71.0.0/16"),
    ],
}


def all_prefixes() -> list[tuple[str, IPv4Network]]:
    return [(provider, net) for provider, nets in CLOUD_PREFIXES.items() for net in nets]
