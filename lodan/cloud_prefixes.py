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

from ipaddress import IPv4Network, IPv6Network, ip_network

Network = IPv4Network | IPv6Network


def _net(cidr: str) -> Network:
    return ip_network(cidr)


CLOUD_PREFIXES: dict[str, list[Network]] = {
    "aws": [
        _net("3.0.0.0/8"),
        _net("13.32.0.0/15"),
        _net("18.128.0.0/9"),
        _net("52.0.0.0/11"),
        _net("54.64.0.0/11"),
        _net("2600:1f00::/24"),   # AWS EC2 IPv6
        _net("2600:9000::/28"),   # CloudFront IPv6
    ],
    "gcp": [
        _net("34.64.0.0/10"),
        _net("35.184.0.0/13"),
        _net("104.196.0.0/14"),
        _net("2600:1900::/28"),   # Google Cloud IPv6
    ],
    "azure": [
        _net("13.64.0.0/11"),
        _net("20.0.0.0/8"),
        _net("40.64.0.0/10"),
        _net("52.96.0.0/12"),
        _net("2603:1000::/24"),   # Microsoft Azure IPv6
    ],
    "oci": [
        _net("129.146.0.0/16"),
        _net("132.145.0.0/16"),
        _net("2603:c000::/25"),   # Oracle Cloud IPv6
    ],
    "digitalocean": [
        _net("104.131.0.0/16"),
        _net("159.203.0.0/16"),
        _net("167.71.0.0/16"),
        _net("2604:a880::/32"),   # DigitalOcean IPv6
    ],
}


def all_prefixes() -> list[tuple[str, Network]]:
    return [(provider, net) for provider, nets in CLOUD_PREFIXES.items() for net in nets]
