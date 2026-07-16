from __future__ import annotations

from lodan.probes.rsync import RsyncProbe, parse_rsync


def test_parse_version_and_modules() -> None:
    raw = (
        b"@RSYNCD: 31.0\n"
        b"backup\tDaily backups\n"
        b"data\n"
        b"@RSYNCD: EXIT\n"
    )
    r = parse_rsync(raw)
    assert r.service == "rsync"
    assert r.raw["version"] == "31.0"
    assert r.raw["modules"] == ["backup", "data"]
    assert "backup" in (r.banner or "")


def test_no_modules() -> None:
    r = parse_rsync(b"@RSYNCD: 30.0\n@RSYNCD: EXIT\n")
    assert r.raw["modules"] == []
    assert "30.0" in (r.banner or "")


def test_no_greeting() -> None:
    assert "no greeting" in (parse_rsync(b"garbage\n").banner or "")


def test_default_ports() -> None:
    assert 873 in RsyncProbe().default_ports
