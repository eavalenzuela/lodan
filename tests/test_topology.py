"""NAT / load-balancer backend-count correlation.

Pure post-scan analysis — nothing here touches a network. The interesting
cases are the negative ones: a single host that legitimately presents several
TLS stacks or certificates must NOT be flagged.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from lodan.diff.scanner import compute_and_store
from lodan.discovery.fingerprint import stack_class
from lodan.enrich.topology import ServiceFingerprints, analyse, enrich_topology
from lodan.store import writer
from lodan.store.db import bootstrap, connect
from lodan.store.query import QueryError, compile, run_query

_LINUX = "64:64240:1460:7:M,S,T,N,W:DF"
_LINUX_OTHER_WINDOW = "64:29200:1460:7:M,S,T,N,W:DF"
_WINDOWS = "128:65535:1460:8:M,N,W,N,N,S:DF"


@pytest.fixture
def db(tmp_path: Path):
    dbp = tmp_path / "l.db"
    bootstrap(dbp)
    conn = connect(dbp)
    yield conn
    conn.close()


# --- stack_class invariance --------------------------------------------------

def test_stack_class_ignores_the_per_socket_window() -> None:
    """One machine can advertise different windows on different ports."""
    assert stack_class(_LINUX) == stack_class(_LINUX_OTHER_WINDOW)
    assert stack_class(_LINUX) != stack_class(_WINDOWS)


def test_stack_class_handles_absent_or_malformed_input() -> None:
    assert stack_class(None) is None
    assert stack_class("") is None
    assert stack_class("not:a:signature") is None


# --- analyse -----------------------------------------------------------------

def test_single_consistent_host_is_one_backend() -> None:
    v = analyse([
        ServiceFingerprints(22, os_family="linux", stack_sig=_LINUX, ssh_hostkey="k" * 64),
        ServiceFingerprints(443, os_family="linux", stack_sig=_LINUX),
    ])
    assert v.min_backend_count == 1
    assert v.nat_suspected is False
    assert v.evidence == ()


def test_differing_window_alone_does_not_flag_a_host() -> None:
    """The regression this whole module is designed to avoid."""
    v = analyse([
        ServiceFingerprints(22, os_family="linux", stack_sig=_LINUX),
        ServiceFingerprints(443, os_family="linux", stack_sig=_LINUX_OTHER_WINDOW),
    ])
    assert v.min_backend_count == 1
    assert v.nat_suspected is False


def test_two_os_families_is_two_backends() -> None:
    v = analyse([
        ServiceFingerprints(443, os_family="linux", stack_sig=_LINUX),
        ServiceFingerprints(3389, os_family="windows", stack_sig=_WINDOWS),
    ])
    assert v.min_backend_count == 2
    assert v.nat_suspected is True
    dims = {d.dimension for d in v.evidence}
    assert {"os_family", "stack_class"} <= dims
    assert all(d.conclusive for d in v.evidence if d.dimension in dims)


def test_two_ssh_host_keys_is_two_backends() -> None:
    v = analyse([
        ServiceFingerprints(22, ssh_hostkey="a" * 64),
        ServiceFingerprints(2222, ssh_hostkey="b" * 64),
    ])
    assert v.min_backend_count == 2
    assert v.nat_suspected is True


def test_backend_count_is_max_across_dimensions_not_sum() -> None:
    """Two SSH keys AND two OS families is >=2 machines, not >=4."""
    v = analyse([
        ServiceFingerprints(22, os_family="linux", ssh_hostkey="a" * 64),
        ServiceFingerprints(2222, os_family="windows", ssh_hostkey="b" * 64),
    ])
    assert v.min_backend_count == 2


def test_three_distinct_host_keys_is_three_backends() -> None:
    v = analyse([
        ServiceFingerprints(22, ssh_hostkey="a" * 64),
        ServiceFingerprints(2222, ssh_hostkey="b" * 64),
        ServiceFingerprints(2022, ssh_hostkey="c" * 64),
    ])
    assert v.min_backend_count == 3


def test_differing_ja3s_is_suggestive_only() -> None:
    """nginx on :443 and a Java app on :8443 is one host with two TLS stacks."""
    v = analyse([
        ServiceFingerprints(443, os_family="linux", ja3s="ja3s-a", cert_fingerprint="aa" * 32),
        ServiceFingerprints(8443, os_family="linux", ja3s="ja3s-b", cert_fingerprint="bb" * 32),
    ])
    assert v.min_backend_count == 1
    assert v.nat_suspected is False
    assert {d.dimension for d in v.evidence} == {"ja3s", "cert_fingerprint"}
    assert not any(d.conclusive for d in v.evidence)


def test_unmeasurable_host_is_reported_as_such() -> None:
    v = analyse([ServiceFingerprints(80), ServiceFingerprints(8080)])
    assert v.measurable is False


def test_measurable_when_any_conclusive_dimension_has_a_value() -> None:
    assert analyse([ServiceFingerprints(22, ssh_hostkey="a" * 64)]).measurable is True
    assert analyse([ServiceFingerprints(80, os_family="linux")]).measurable is True
    assert analyse([ServiceFingerprints(443, ja3s="x")]).measurable is False


# --- persistence -------------------------------------------------------------

def _svc(conn, handle, ip, port, **cols):
    writer.upsert_discovered_service(conn, handle, ip, port, "tcp")
    if cols:
        sets = ", ".join(f"{k} = ?" for k in cols)
        conn.execute(
            f"UPDATE services SET {sets} WHERE scan_id = ? AND ip = ? AND port = ?",
            (*cols.values(), handle.scan_id, ip, port),
        )


def test_enrich_topology_flags_a_split_host(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    _svc(db, h, "10.0.0.9", 443, os_family="linux", stack_sig=_LINUX)
    _svc(db, h, "10.0.0.9", 3389, os_family="windows", stack_sig=_WINDOWS)
    _svc(db, h, "10.0.0.5", 22, os_family="linux", stack_sig=_LINUX)

    assert enrich_topology(db, h.scan_id) == 1
    rows = dict(
        db.execute(
            "SELECT ip, min_backend_count FROM hosts WHERE scan_id = ?", (h.scan_id,)
        ).fetchall()
    )
    assert rows == {"10.0.0.9": 2, "10.0.0.5": 1}
    (evidence,) = db.execute(
        "SELECT backend_evidence FROM hosts WHERE ip = '10.0.0.9'"
    ).fetchone()
    dims = {e["dimension"] for e in json.loads(evidence)}
    assert "os_family" in dims


def test_enrich_topology_skips_unmeasurable_hosts(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    _svc(db, h, "10.0.0.7", 80)
    assert enrich_topology(db, h.scan_id) == 0
    assert db.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 0


def test_enrich_topology_preserves_other_host_columns(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    _svc(db, h, "10.0.0.5", 22, os_family="linux", stack_sig=_LINUX)
    db.execute(
        "INSERT INTO hosts (scan_id, ip, rdns, device_type) VALUES (?, ?, ?, ?)",
        (h.scan_id, "10.0.0.5", "box.example.com", "server"),
    )
    enrich_topology(db, h.scan_id)
    row = db.execute(
        "SELECT rdns, device_type, min_backend_count FROM hosts WHERE scan_id = ?",
        (h.scan_id,),
    ).fetchone()
    assert row == ("box.example.com", "server", 1)


def test_enrich_topology_is_idempotent(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    _svc(db, h, "10.0.0.9", 443, os_family="linux")
    _svc(db, h, "10.0.0.9", 3389, os_family="windows")
    assert enrich_topology(db, h.scan_id) == enrich_topology(db, h.scan_id) == 1
    assert db.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 1


def test_enrich_topology_empty_scan(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    assert enrich_topology(db, h.scan_id) == 0


# --- query DSL ---------------------------------------------------------------

def test_dsl_nat_and_backend_count(db) -> None:
    h = writer.open_scan(db, "w", ["10.0.0.0/24"])
    _svc(db, h, "10.0.0.9", 443, os_family="linux")
    _svc(db, h, "10.0.0.9", 3389, os_family="windows")
    _svc(db, h, "10.0.0.5", 22, os_family="linux")
    enrich_topology(db, h.scan_id)

    nat = {r["ip"] for r in run_query(db, "nat_suspected:true", scan_id=h.scan_id)}
    assert nat == {"10.0.0.9"}
    clean = {r["ip"] for r in run_query(db, "nat_suspected:false", scan_id=h.scan_id)}
    assert clean == {"10.0.0.5"}
    # min_backend_count is >=, since the stored value is itself a floor.
    assert {r["ip"] for r in run_query(db, "min_backend_count:2", scan_id=h.scan_id)} == {"10.0.0.9"}
    assert {r["ip"] for r in run_query(db, "min_backend_count:1", scan_id=h.scan_id)} == {
        "10.0.0.9", "10.0.0.5"
    }


def test_dsl_rejects_bad_nat_and_count_values() -> None:
    with pytest.raises(QueryError):
        compile("nat_suspected:maybe")
    with pytest.raises(QueryError):
        compile("min_backend_count:*")
    with pytest.raises(QueryError):
        compile("min_backend_count:many")


# --- topology_change diff ----------------------------------------------------

def _two_scans(conn):
    a = writer.open_scan(conn, "w", ["10.0.0.0/24"])
    writer.finish_scan(conn, a)
    b = writer.open_scan(conn, "w", ["10.0.0.0/24"])
    writer.finish_scan(conn, b)
    return a, b


def test_topology_change_on_backend_count_move(db) -> None:
    a, b = _two_scans(db)
    _svc(db, a, "10.0.0.9", 443, os_family="linux")
    _svc(db, b, "10.0.0.9", 443, os_family="linux")
    _svc(db, b, "10.0.0.9", 3389, os_family="windows")
    enrich_topology(db, a.scan_id)
    enrich_topology(db, b.scan_id)

    counts = compute_and_store(db, a.scan_id, b.scan_id)
    assert counts.topology_change == 1
    (raw,) = db.execute(
        "SELECT detail FROM scan_diffs WHERE kind = 'topology_change'"
    ).fetchone()
    assert json.loads(raw)["min_backend_count"] == {"from": 1, "to": 2}


def test_topology_change_when_a_load_balancer_goes_away(db) -> None:
    """2 -> 1 must fire too, not just 1 -> 2."""
    a, b = _two_scans(db)
    _svc(db, a, "10.0.0.9", 443, os_family="linux")
    _svc(db, a, "10.0.0.9", 3389, os_family="windows")
    _svc(db, b, "10.0.0.9", 443, os_family="linux")
    enrich_topology(db, a.scan_id)
    enrich_topology(db, b.scan_id)
    assert compute_and_store(db, a.scan_id, b.scan_id).topology_change == 1


def test_topology_change_on_device_class_flip(db) -> None:
    a, b = _two_scans(db)
    for handle, device in ((a, "server"), (b, "nas")):
        _svc(db, handle, "10.0.0.5", 22, os_family="linux")
        enrich_topology(db, handle.scan_id)
        db.execute(
            "UPDATE hosts SET device_type = ? WHERE scan_id = ?", (device, handle.scan_id)
        )
    counts = compute_and_store(db, a.scan_id, b.scan_id)
    assert counts.topology_change == 1
    (raw,) = db.execute(
        "SELECT detail FROM scan_diffs WHERE kind = 'topology_change'"
    ).fetchone()
    assert json.loads(raw)["device_type"] == {"from": "server", "to": "nas"}


def test_topology_change_silent_when_nothing_moved(db) -> None:
    a, b = _two_scans(db)
    for handle in (a, b):
        _svc(db, handle, "10.0.0.5", 22, os_family="linux")
        enrich_topology(db, handle.scan_id)
    assert compute_and_store(db, a.scan_id, b.scan_id).topology_change == 0


def test_topology_change_ignores_unmeasured_sides(db) -> None:
    """An unmeasured host must not look like it changed."""
    a, b = _two_scans(db)
    _svc(db, a, "10.0.0.5", 22, os_family="linux")
    _svc(db, b, "10.0.0.5", 22)          # no fingerprint this time
    enrich_topology(db, a.scan_id)
    enrich_topology(db, b.scan_id)
    assert compute_and_store(db, a.scan_id, b.scan_id).topology_change == 0
