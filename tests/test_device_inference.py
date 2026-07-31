"""OS/distro mining and device-type fusion.

Entirely offline: layer 1 is pure text over probe output, layer 2 is pure
scoring over a feature vector.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from lodan.diff.scanner import compute_and_store
from lodan.enrich.device import (
    MIN_DEVICE_SCORE,
    HostFeatures,
    classify,
    enrich_devices,
    os_guess_for,
)
from lodan.store import writer
from lodan.store.db import bootstrap, connect
from lodan.store.query import run_query


@pytest.fixture
def db(tmp_path: Path):
    dbp = tmp_path / "l.db"
    bootstrap(dbp)
    conn = connect(dbp)
    yield conn
    conn.close()


def _ssh_raw(software: str, comment: str | None) -> dict:
    return {"parsed": {"version": "2.0", "software": software, "comment": comment}}


# --- layer 1: OS / distro from version strings -------------------------------

@pytest.mark.parametrize(
    ("software", "comment", "expected"),
    [
        ("OpenSSH_8.2p1", "Ubuntu-4ubuntu0.5", "Ubuntu 20.04"),
        ("OpenSSH_7.6p1", "Ubuntu-4ubuntu0.7", "Ubuntu 18.04"),
        ("OpenSSH_8.9p1", "Ubuntu-3ubuntu0.4", "Ubuntu 22.04"),
        ("OpenSSH_9.6p1", "Ubuntu-3ubuntu13.5", "Ubuntu 24.04"),
        ("OpenSSH_7.4p1", "Debian-10+deb9u7", "Debian 9"),
        ("OpenSSH_7.9p1", "Debian-10+deb10u2", "Debian 10"),
        ("OpenSSH_9.2p1", "Debian-2+deb12u2", "Debian 12"),
    ],
)
def test_openssh_comment_pins_the_distro_release(
    software: str, comment: str, expected: str
) -> None:
    guess = os_guess_for("ssh", f"SSH-2.0-{software} {comment}", _ssh_raw(software, comment))
    assert guess is not None
    assert guess.os_guess == expected
    assert guess.confidence >= 0.9


def test_unknown_openssh_version_still_names_the_distro() -> None:
    """A release we don't have pinned degrades to the distro, not to nothing."""
    guess = os_guess_for("ssh", "", _ssh_raw("OpenSSH_10.1p1", "Ubuntu-1ubuntu1"))
    assert guess is not None
    assert guess.os_guess == "Ubuntu"
    assert guess.confidence < 0.9


def test_openssh_for_windows() -> None:
    guess = os_guess_for("ssh", "", _ssh_raw("OpenSSH_for_Windows_8.1", None))
    assert guess is not None
    assert guess.os_guess == "Windows"


def test_raspbian_distinguished_from_debian() -> None:
    guess = os_guess_for("ssh", "", _ssh_raw("OpenSSH_7.9p1", "Raspbian-10+deb10u2"))
    assert guess is not None
    assert guess.os_guess == "Raspbian"


def test_bare_openssh_banner_yields_nothing() -> None:
    """No distro tag means no distro claim."""
    assert os_guess_for("ssh", "SSH-2.0-OpenSSH_8.2p1", _ssh_raw("OpenSSH_8.2p1", None)) is None


@pytest.mark.parametrize(
    ("version", "expected"),
    [("10.0", "Windows Server 2016+"), ("8.5", "Windows Server 2012 R2"),
     ("7.5", "Windows Server 2008 R2"), ("6.0", "Windows Server 2003")],
)
def test_iis_version_implies_windows_release(version: str, expected: str) -> None:
    guess = os_guess_for("http", f"Microsoft-IIS/{version}", {})
    assert guess is not None
    assert guess.os_guess == expected


def test_unknown_iis_version_degrades_to_windows_server() -> None:
    guess = os_guess_for("http", "Microsoft-IIS/12.5", {})
    assert guess is not None
    assert guess.os_guess == "Windows Server"


@pytest.mark.parametrize(
    ("server", "expected"),
    [
        ("Apache/2.4.41 (Ubuntu)", "Ubuntu"),
        ("Apache/2.4.38 (Debian)", "Debian"),
        ("Apache/2.4.6 (CentOS)", "CentOS"),
        ("Apache/2.4.57 (Red Hat)", "Red Hat"),
        ("Apache/2.4.54 (FreeBSD)", "FreeBSD"),
        ("Apache/2.4.54 (Win64)", "Windows"),
    ],
)
def test_server_header_distro_tag(server: str, expected: str) -> None:
    guess = os_guess_for("http", None, {"headers": {"server": server}})
    assert guess is not None
    assert guess.os_guess == expected


def test_appliance_platforms_named_from_banner() -> None:
    for banner, expected in (
        ("RouterOS 6.49.7", "MikroTik RouterOS"),
        ("VMware ESXi 7.0", "VMware ESXi"),
        ("Synology DiskStation", "Synology DSM"),
    ):
        guess = os_guess_for("http", banner, {})
        assert guess is not None and guess.os_guess == expected


def test_no_signal_returns_none() -> None:
    assert os_guess_for("http", None, {}) is None
    assert os_guess_for(None, "", {}) is None
    assert os_guess_for("http", "some totally generic banner", {}) is None


# --- layer 2: device classification ------------------------------------------

def _features(**kw) -> HostFeatures:
    base = dict(
        ip="10.0.0.5", ports=frozenset(), services=frozenset(), banners="",
        os_families=frozenset(), os_guesses=frozenset(), favicon_labels=frozenset(),
    )
    base.update(kw)
    return HostFeatures(**base)


def test_docker_alone_identifies_a_container_host() -> None:
    v = classify(_features(services=frozenset({"docker"}), ports=frozenset({2375})))
    assert v is not None
    assert v.device_type == "container-host"


def test_printer_from_port_and_banner() -> None:
    v = classify(_features(
        ports=frozenset({9100, 80}), services=frozenset({"http"}),
        banners="hp laserjet mfp m428fdw",
    ))
    assert v is not None
    assert v.device_type == "printer"


def test_nas_beats_server_even_though_it_runs_linux() -> None:
    """A Synology on :22 is a NAS that runs Linux, not a Linux server."""
    v = classify(_features(
        ports=frozenset({22, 80, 445, 5000}),
        services=frozenset({"ssh", "http", "smb"}),
        banners="synology diskstation ds920+",
        os_families=frozenset({"linux"}),
    ))
    assert v is not None
    assert v.device_type == "nas"


def test_router_from_network_device_stack_plus_banner() -> None:
    v = classify(_features(
        ports=frozenset({22, 80, 179}), services=frozenset({"ssh", "http"}),
        banners="mikrotik routeros", os_families=frozenset({"network-device"}),
    ))
    assert v is not None
    assert v.device_type == "router-firewall"


def test_camera_from_rtsp_and_vendor_banner() -> None:
    v = classify(_features(
        ports=frozenset({554, 80}), banners="hikvision web service",
        os_families=frozenset({"embedded"}),
    ))
    assert v is not None
    assert v.device_type == "ip-camera-iot"


def test_hypervisor_from_esxi() -> None:
    v = classify(_features(
        ports=frozenset({443, 902}), services=frozenset({"tls"}),
        banners="vmware esxi 7.0.3",
    ))
    assert v is not None
    assert v.device_type == "hypervisor"


def test_plain_linux_box_is_a_server() -> None:
    v = classify(_features(
        ports=frozenset({22, 80, 443}), services=frozenset({"ssh", "http", "tls"}),
        os_families=frozenset({"linux"}), os_guesses=frozenset({"Ubuntu 22.04"}),
    ))
    assert v is not None
    assert v.device_type == "server"


def test_favicon_label_contributes_to_the_verdict() -> None:
    """An operator-assigned label is evidence like any other signal."""
    without = classify(_features(ports=frozenset({631})))
    with_label = classify(_features(
        ports=frozenset({631}), favicon_labels=frozenset({"brother printer status"}),
    ))
    assert without is None                      # 0.35 alone is under threshold
    assert with_label is not None and with_label.device_type == "printer"


def test_weak_lone_signal_stays_unlabelled() -> None:
    v = classify(_features(ports=frozenset({8080})))
    assert v is None


def test_no_signal_at_all_is_none() -> None:
    assert classify(_features()) is None


def test_confidence_is_capped_and_above_threshold() -> None:
    v = classify(_features(
        ports=frozenset({9100, 515, 631}),
        banners="hp laserjet jetdirect",
        favicon_labels=frozenset({"printer"}),
    ))
    assert v is not None
    assert MIN_DEVICE_SCORE <= v.confidence <= 0.95


# --- persistence -------------------------------------------------------------

def _service(conn, handle, ip, port, service, banner, raw=None, os_family=None, favicon=None):
    writer.upsert_discovered_service(conn, handle, ip, port, "tcp")
    conn.execute(
        "UPDATE services SET service = ?, banner = ?, raw = ?, os_family = ?, "
        "favicon_mmh3 = ? WHERE scan_id = ? AND ip = ? AND port = ?",
        (service, banner, json.dumps(raw or {}), os_family, favicon,
         handle.scan_id, ip, port),
    )


def test_enrich_devices_writes_service_and_host_rows(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    _service(db, h, "10.0.0.5", 22, "ssh", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
             raw=_ssh_raw("OpenSSH_8.2p1", "Ubuntu-4ubuntu0.5"), os_family="linux")
    _service(db, h, "10.0.0.5", 80, "http", "Apache/2.4.41 (Ubuntu)",
             raw={"headers": {"server": "Apache/2.4.41 (Ubuntu)"}}, os_family="linux")

    assert enrich_devices(db, h.scan_id) == 1
    guesses = dict(
        db.execute("SELECT port, os_guess FROM services WHERE scan_id = ?", (h.scan_id,))
    )
    assert guesses[22] == "Ubuntu 20.04"
    assert guesses[80] == "Ubuntu"
    row = db.execute(
        "SELECT os_guess, device_type FROM hosts WHERE scan_id = ? AND ip = ?",
        (h.scan_id, "10.0.0.5"),
    ).fetchone()
    # :22 says "Ubuntu 20.04" and :80 says "Ubuntu" — not unanimous, so the
    # host-level reading stays NULL rather than picking one.
    assert row[0] is None
    assert row[1] == "server"


def test_enrich_devices_host_os_guess_when_unanimous(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    _service(db, h, "10.0.0.5", 22, "ssh", "",
             raw=_ssh_raw("OpenSSH_8.2p1", "Ubuntu-4ubuntu0.5"), os_family="linux")
    _service(db, h, "10.0.0.5", 2222, "ssh", "",
             raw=_ssh_raw("OpenSSH_8.2p1", "Ubuntu-4ubuntu0.5"), os_family="linux")
    enrich_devices(db, h.scan_id)
    (os_guess,) = db.execute(
        "SELECT os_guess FROM hosts WHERE scan_id = ? AND ip = ?", (h.scan_id, "10.0.0.5")
    ).fetchone()
    assert os_guess == "Ubuntu 20.04"


def test_enrich_devices_uses_operator_favicon_labels(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    _service(db, h, "10.0.0.5", 631, "http", "", favicon=4242)
    writer.set_favicon_label(db, 4242, "Brother printer status")
    assert enrich_devices(db, h.scan_id) == 1
    (device,) = db.execute(
        "SELECT device_type FROM hosts WHERE scan_id = ? AND ip = ?", (h.scan_id, "10.0.0.5")
    ).fetchone()
    assert device == "printer"


def test_enrich_devices_is_idempotent(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    _service(db, h, "10.0.0.5", 22, "ssh", "",
             raw=_ssh_raw("OpenSSH_8.2p1", "Ubuntu-4ubuntu0.5"), os_family="linux")
    first = enrich_devices(db, h.scan_id)
    second = enrich_devices(db, h.scan_id)
    assert first == second == 1
    assert db.execute(
        "SELECT COUNT(*) FROM hosts WHERE scan_id = ?", (h.scan_id,)
    ).fetchone()[0] == 1


def test_enrich_devices_preserves_stack_rollup(db) -> None:
    """Device classification must not clobber the feature-1 columns."""
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    _service(db, h, "10.0.0.5", 22, "ssh", "",
             raw=_ssh_raw("OpenSSH_8.2p1", "Ubuntu-4ubuntu0.5"), os_family="linux")
    db.execute(
        "INSERT INTO hosts (scan_id, ip, os_family, hop_count) VALUES (?, ?, 'linux', 3)",
        (h.scan_id, "10.0.0.5"),
    )
    enrich_devices(db, h.scan_id)
    row = db.execute(
        "SELECT os_family, hop_count, device_type FROM hosts WHERE scan_id = ?",
        (h.scan_id,),
    ).fetchone()
    assert row == ("linux", 3, "server")


def test_enrich_devices_empty_scan(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    assert enrich_devices(db, h.scan_id) == 0


def test_dsl_os_guess_and_device_type(db) -> None:
    """device_type lives on `hosts`, so the DSL joins out to it."""
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    _service(db, h, "10.0.0.5", 22, "ssh", "",
             raw=_ssh_raw("OpenSSH_8.2p1", "Ubuntu-4ubuntu0.5"), os_family="linux")
    _service(db, h, "10.0.0.9", 9100, "http", "hp laserjet jetdirect")
    enrich_devices(db, h.scan_id)

    assert [r["ip"] for r in run_query(db, "os_guess:Ubuntu*", scan_id=h.scan_id)] == ["10.0.0.5"]
    assert [r["ip"] for r in run_query(db, "device_type:printer", scan_id=h.scan_id)] == ["10.0.0.9"]
    assert [r["ip"] for r in run_query(db, "device_type:server", scan_id=h.scan_id)] == ["10.0.0.5"]
    combined = run_query(db, "device_type:printer AND port:9100", scan_id=h.scan_id)
    assert [r["ip"] for r in combined] == ["10.0.0.9"]


def test_os_guess_flip_registers_as_a_changed_diff(db) -> None:
    """A distro upgrade under an otherwise stable service is a `changed`."""
    a = writer.open_scan(db, "w", ["10.0.0.0/24"])
    writer.finish_scan(db, a)
    b = writer.open_scan(db, "w", ["10.0.0.0/24"])
    writer.finish_scan(db, b)
    for handle, comment, version in (
        (a, "Ubuntu-4ubuntu0.5", "OpenSSH_8.2p1"),
        (b, "Ubuntu-3ubuntu0.4", "OpenSSH_8.9p1"),
    ):
        _service(db, handle, "10.0.0.5", 22, "ssh", "same-looking banner",
                 raw=_ssh_raw(version, comment))
        enrich_devices(db, handle.scan_id)
    counts = compute_and_store(db, a.scan_id, b.scan_id)
    assert counts.changed == 1
    (raw,) = db.execute("SELECT detail FROM scan_diffs WHERE kind = 'changed'").fetchone()
    assert json.loads(raw)["os_guess"] == {"from": "Ubuntu 20.04", "to": "Ubuntu 22.04"}


def test_enrich_devices_tolerates_malformed_raw(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(db, h, "10.0.0.5", 22, "tcp")
    db.execute(
        "UPDATE services SET service = 'ssh', raw = ? WHERE scan_id = ?",
        (b"\x00not json", h.scan_id),
    )
    assert enrich_devices(db, h.scan_id) >= 0   # must not raise
