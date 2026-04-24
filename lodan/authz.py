"""Authorization guard for scan targets.

Two checks, applied at config load *and* right before each probe batch:

1. Every target must be covered by one of the workspace's `authorized_ranges`.
2. No target may overlap a well-known cloud prefix unless the workspace opts in
   with `cloud_provider_allowed = true` and a non-empty justification string.

Rejections surface as `AuthorizationError` so the CLI and the scan loop can
handle them uniformly.
"""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network

from lodan.cloud_prefixes import all_prefixes
from lodan.config import WorkspaceBlock


class AuthorizationError(Exception):
    pass


@dataclass(frozen=True)
class CloudHit:
    provider: str
    prefix: IPv4Network


def authorized_networks(ws: WorkspaceBlock) -> list[IPv4Network]:
    return [IPv4Network(c, strict=False) for c in ws.authorized_ranges]


def is_authorized(target: IPv4Address | str, networks: list[IPv4Network]) -> bool:
    t = ip_address(target) if isinstance(target, str) else target
    return any(t in net for net in networks)


def cloud_overlaps(net: IPv4Network) -> list[CloudHit]:
    """Return every cloud prefix that `net` overlaps (either direction)."""
    hits: list[CloudHit] = []
    for provider, cloud_net in all_prefixes():
        if net.overlaps(cloud_net):
            hits.append(CloudHit(provider=provider, prefix=cloud_net))
    return hits


def check_workspace(ws: WorkspaceBlock) -> None:
    """Validate the workspace config's authorized_ranges. Raises on violation.

    Applied at scan start; re-run here rather than trusting the config
    pydantic validator so we catch newly-added cloud prefix data too.
    """
    if not ws.authorized_ranges:
        raise AuthorizationError("workspace has no authorized_ranges; refusing to scan")

    for cidr in ws.authorized_ranges:
        net = ip_network(cidr, strict=False)
        if not isinstance(net, IPv4Network):
            raise AuthorizationError(f"only IPv4 supported in v1: {cidr}")
        hits = cloud_overlaps(net)
        if not hits:
            continue
        if not ws.cloud_provider_allowed:
            names = ", ".join(sorted({h.provider for h in hits}))
            raise AuthorizationError(
                f"{cidr} overlaps cloud prefix(es) [{names}] but "
                f"cloud_provider_allowed=false. Flip it and set "
                f"cloud_provider_justification to proceed."
            )
        if not ws.cloud_provider_justification.strip():
            raise AuthorizationError(
                f"{cidr} overlaps cloud prefix but cloud_provider_justification is empty"
            )


def check_target(target: IPv4Address | str, networks: list[IPv4Network]) -> None:
    """Raise if `target` is not covered by any authorized network."""
    if not is_authorized(target, networks):
        raise AuthorizationError(f"target {target} is not in authorized_ranges")
