"""Passive stack-fingerprint derivation tests.

All offline: every case builds a StackObservation directly, so nothing here
needs scapy, a raw socket, or a network.
"""
from __future__ import annotations

import pytest

from lodan.discovery.base import StackObservation
from lodan.discovery.fingerprint import (
    clock_key,
    consensus,
    hop_count,
    initial_ttl,
    modal_hops,
    option_codes,
    os_family,
    stack_sig,
)


def _obs(**kw) -> StackObservation:
    base = {"ttl": 64, "window": 64240, "df": True}
    base.update(kw)
    return StackObservation(**base)


# --- initial TTL / hop count -------------------------------------------------

@pytest.mark.parametrize(
    ("observed", "expected"),
    [(64, 64), (63, 64), (1, 64), (128, 128), (120, 128), (255, 255), (200, 255)],
)
def test_initial_ttl_rounds_up_to_candidate(observed: int, expected: int) -> None:
    assert initial_ttl(observed) == expected


@pytest.mark.parametrize("bad", [None, 0, -1, 256])
def test_initial_ttl_rejects_impossible(bad: int | None) -> None:
    assert initial_ttl(bad) is None


def test_hop_count_is_distance_from_initial_ttl() -> None:
    assert hop_count(64) == 0     # same L2 segment
    assert hop_count(58) == 6
    assert hop_count(120) == 8


def test_hop_count_none_when_ttl_unusable() -> None:
    assert hop_count(None) is None
    assert hop_count(0) is None


def test_ttl_32_is_read_as_a_distant_linux_host_not_an_ittl_32_stack() -> None:
    """32 is not a candidate initial TTL — see the module docstring."""
    assert initial_ttl(32) == 64
    assert hop_count(32) == 32


# --- option codes / signature string -----------------------------------------

def test_option_codes_preserve_wire_order() -> None:
    assert option_codes(("MSS", "SAckOK", "Timestamp", "NOP", "WScale")) == "M,S,T,N,W"
    assert option_codes(("MSS", "NOP", "WScale", "NOP", "NOP", "SAckOK")) == "M,N,W,N,N,S"


def test_option_codes_empty_and_unknown() -> None:
    assert option_codes(()) == "-"
    assert option_codes(("MSS", "Mood")) == "M,?"


def test_stack_sig_is_stable_and_fully_populated() -> None:
    sig = stack_sig(_obs(
        ttl=62, window=64240, mss=1460, window_scale=7, ip_id=12345,
        options=("MSS", "SAckOK", "Timestamp", "NOP", "WScale"),
    ))
    assert sig == "64:64240:1460:7:M,S,T,N,W:DF"


def test_stack_sig_marks_absent_subsignals_with_star() -> None:
    sig = stack_sig(_obs(ttl=64, window=8192, df=False, options=("MSS",), mss=1460))
    assert sig == "64:8192:1460:*:M:-"


def test_stack_sig_records_zero_ip_id() -> None:
    sig = stack_sig(_obs(ip_id=0, mss=1460, window_scale=7, options=("MSS",)))
    assert sig.endswith(":DF+ID0")


def test_stack_sig_none_without_observation_or_usable_ttl() -> None:
    assert stack_sig(None) is None
    assert stack_sig(_obs(ttl=0)) is None


def test_same_host_two_hops_further_keeps_its_signature() -> None:
    """hop_count moves, stack_sig does not — that separation is the point."""
    near = _obs(ttl=64, mss=1460, window_scale=7, options=("MSS", "SAckOK", "Timestamp"))
    far = _obs(ttl=62, mss=1460, window_scale=7, options=("MSS", "SAckOK", "Timestamp"))
    assert stack_sig(near) == stack_sig(far)
    assert hop_count(near.ttl) != hop_count(far.ttl)


# --- OS family ---------------------------------------------------------------

def test_modern_linux_syn_ack() -> None:
    guess = os_family(_obs(
        ttl=64, window=64240, mss=1460, window_scale=7, sack_ok=True, timestamps=True,
        options=("MSS", "SAckOK", "Timestamp", "NOP", "WScale"),
    ))
    assert guess is not None
    assert guess.os_family == "linux"
    assert guess.confidence >= 0.9


def test_windows_syn_ack() -> None:
    guess = os_family(_obs(
        ttl=128, window=65535, mss=1460, window_scale=8, sack_ok=True,
        options=("MSS", "NOP", "WScale", "NOP", "NOP", "SAckOK"),
    ))
    assert guess is not None
    assert guess.os_family == "windows"


def test_macos_syn_ack_identified_by_trailing_eol() -> None:
    guess = os_family(_obs(
        ttl=64, window=65535, mss=1460, window_scale=6, timestamps=True,
        options=("MSS", "NOP", "WScale", "NOP", "NOP", "Timestamp", "SAckOK", "EOL"),
    ))
    assert guess is not None
    assert guess.os_family == "macos"


def test_network_device_from_ittl_255() -> None:
    guess = os_family(_obs(
        ttl=250, window=4128, mss=536, options=("MSS", "NOP", "NOP", "SAckOK"),
    ))
    assert guess is not None
    assert guess.os_family == "network-device"


def test_embedded_stack_mss_only_tiny_window() -> None:
    guess = os_family(_obs(
        ttl=64, window=2920, mss=1460, timestamps=False, options=("MSS",),
    ))
    assert guess is not None
    assert guess.os_family == "embedded"


def test_unrecognized_stack_returns_none_rather_than_guessing() -> None:
    """A wrong OS attribution is worse than none in an inventory tool."""
    assert os_family(_obs(ttl=64, window=1234, options=("Timestamp", "MSS"))) is None
    assert os_family(None) is None
    assert os_family(_obs(ttl=0)) is None


def test_linux_without_timestamps_still_matches_linux() -> None:
    guess = os_family(_obs(
        ttl=64, window=29200, mss=1460, window_scale=7, timestamps=False,
        options=("MSS", "NOP", "NOP", "SAckOK", "NOP", "WScale"),
    ))
    assert guess is not None
    assert guess.os_family == "linux"


# --- clock key ---------------------------------------------------------------

def test_clock_key_buckets_boot_time() -> None:
    # Booted 1000s before observation at t=1_000_000 -> boot ~= 999_000.
    key = clock_key(_obs(ts_val=1_000_000, observed_at=1_000_000.0), hz=1000, bucket_s=60)
    assert key == f"1000:{int(999_000 // 60) * 60}"


def test_two_ips_on_one_machine_share_a_clock_key() -> None:
    """Same boot instant, sampled a few ms apart, must collate."""
    a = clock_key(_obs(ts_val=5_000_000, observed_at=1_700_000_000.0))
    b = clock_key(_obs(ts_val=5_000_120, observed_at=1_700_000_000.12))
    assert a is not None and a == b


def test_separately_booted_machines_get_different_clock_keys() -> None:
    a = clock_key(_obs(ts_val=5_000_000, observed_at=1_700_000_000.0))
    b = clock_key(_obs(ts_val=900_000_000, observed_at=1_700_000_000.0))
    assert a != b


def test_clock_key_none_without_timestamps() -> None:
    assert clock_key(_obs(ts_val=None, observed_at=1.0)) is None
    assert clock_key(_obs(ts_val=0, observed_at=1.0)) is None
    assert clock_key(_obs(ts_val=1000, observed_at=None)) is None
    assert clock_key(None) is None


def test_clock_key_rejects_nonsense_parameters() -> None:
    obs = _obs(ts_val=1000, observed_at=1.0)
    assert clock_key(obs, hz=0) is None
    assert clock_key(obs, bucket_s=0) is None


# --- host-level rollup -------------------------------------------------------

def test_consensus_requires_unanimity() -> None:
    assert consensus(["a", "a", None]) == "a"
    assert consensus([None, None]) is None
    assert consensus(["a", "b"]) is None   # disagreement is the NAT signal


def test_modal_hops_picks_most_common_then_shortest() -> None:
    assert modal_hops([3, 3, 5]) == 3
    assert modal_hops([3, 5]) == 3          # tie -> shorter path
    assert modal_hops([None, 7, None]) == 7
    assert modal_hops([None, None]) is None
    assert modal_hops([]) is None
