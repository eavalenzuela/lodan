from __future__ import annotations

import pytest

from lodan.authz import (
    AuthorizationError,
    authorized_networks,
    check_target,
    check_workspace,
    cloud_overlaps,
    is_authorized,
)
from lodan.config import WorkspaceBlock


def ws(
    ranges: list[str],
    *,
    cloud_allowed: bool = False,
    justification: str = "",
) -> WorkspaceBlock:
    return WorkspaceBlock(
        name="t",
        authorized_ranges=ranges,
        cloud_provider_allowed=cloud_allowed,
        cloud_provider_justification=justification,
    )


def test_private_range_passes() -> None:
    check_workspace(ws(["10.0.0.0/24"]))


def test_empty_ranges_rejected() -> None:
    with pytest.raises(AuthorizationError, match="no authorized_ranges"):
        check_workspace(ws([]))


def test_aws_range_rejected_without_opt_in() -> None:
    with pytest.raises(AuthorizationError, match="cloud prefix"):
        check_workspace(ws(["3.5.0.0/16"]))


def test_aws_range_rejected_without_justification() -> None:
    with pytest.raises(AuthorizationError, match="justification"):
        check_workspace(ws(["3.5.0.0/16"], cloud_allowed=True, justification="   "))


def test_aws_range_allowed_with_opt_in() -> None:
    check_workspace(
        ws(
            ["3.5.0.0/16"],
            cloud_allowed=True,
            justification="own account 123456; bug bounty program #42",
        )
    )


def test_is_authorized_inside_and_outside() -> None:
    nets = authorized_networks(ws(["10.0.0.0/24", "192.168.1.0/24"]))
    assert is_authorized("10.0.0.5", nets)
    assert is_authorized("192.168.1.254", nets)
    assert not is_authorized("10.0.1.5", nets)
    assert not is_authorized("8.8.8.8", nets)


def test_check_target_raises() -> None:
    nets = authorized_networks(ws(["10.0.0.0/24"]))
    with pytest.raises(AuthorizationError):
        check_target("8.8.8.8", nets)


def test_cloud_overlap_finds_aws() -> None:
    from ipaddress import IPv4Network

    hits = cloud_overlaps(IPv4Network("3.5.0.0/16"))
    assert any(h.provider == "aws" for h in hits)


def test_cloud_overlap_empty_for_private() -> None:
    from ipaddress import IPv4Network

    assert cloud_overlaps(IPv4Network("10.0.0.0/24")) == []


# --- IPv6 ---------------------------------------------------------------


def test_ipv6_range_passes_workspace_check() -> None:
    check_workspace(ws(["2001:db8::/32"]))  # must not raise


def test_ipv6_target_membership() -> None:
    nets = authorized_networks(ws(["2001:db8::/32", "10.0.0.0/24"]))
    assert is_authorized("2001:db8::5", nets)
    assert not is_authorized("2001:dead::1", nets)


def test_cross_family_is_false_not_error() -> None:
    """A v6 target against a v4-only allowlist (and vice versa) must be a clean
    'not authorized', never a TypeError from `addr in net`."""
    v4_only = authorized_networks(ws(["10.0.0.0/24"]))
    v6_only = authorized_networks(ws(["2001:db8::/32"]))
    assert is_authorized("2001:db8::5", v4_only) is False
    assert is_authorized("10.0.0.5", v6_only) is False


def test_ipv6_cloud_overlap_and_cross_family_safe() -> None:
    from ipaddress import ip_network

    hits = cloud_overlaps(ip_network("2600:1f00:abcd::/48"))  # inside AWS v6
    assert any(h.provider == "aws" for h in hits)
    # A v4 net compared against the (now mixed) prefix list must not raise.
    assert cloud_overlaps(ip_network("10.0.0.0/24")) == []


def test_ipv6_cloud_guard_blocks_without_optin() -> None:
    with pytest.raises(AuthorizationError):
        check_workspace(ws(["2600:1f00:abcd::/48"]))  # AWS v6, no opt-in
    # With opt-in + justification it passes.
    check_workspace(ws(["2600:1f00:abcd::/48"], cloud_allowed=True, justification="lab"))
