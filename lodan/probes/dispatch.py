"""Map (port, proto) -> Probe.

Probes register themselves via register(). pick_probe() returns the first
probe whose default_ports contains the requested port, or None.

The v1 dispatch is port-based only. Banner sniffing (try-read-256-bytes then
match) lives behind the same interface and lands in a later commit; for now
an unrecognized port is simply not probed.
"""
from __future__ import annotations

from lodan.probes.base import Probe

_REGISTRY: list[tuple[str, type[Probe]]] = []


def register(name: str, cls: type[Probe]) -> None:
    _REGISTRY.append((name, cls))


def clear_registry() -> None:
    """Test hook: drop every registered probe."""
    _REGISTRY.clear()


def register_defaults() -> None:
    from lodan.probes.amqp import AMQPProbe
    from lodan.probes.dns import DNSProbe
    from lodan.probes.docker import DockerProbe
    from lodan.probes.elastic import ElasticProbe
    from lodan.probes.ftp import FTPProbe
    from lodan.probes.http import HTTPProbe
    from lodan.probes.ike import IKEProbe
    from lodan.probes.imap import IMAPProbe
    from lodan.probes.kubernetes import KubernetesProbe
    from lodan.probes.ldap import LDAPProbe
    from lodan.probes.mdns import MDNSProbe
    from lodan.probes.memcached import MemcachedProbe
    from lodan.probes.mongo import MongoProbe
    from lodan.probes.mqtt import MQTTProbe
    from lodan.probes.mysql import MySQLProbe
    from lodan.probes.netbios import NetBIOSProbe
    from lodan.probes.ntp import NTPProbe
    from lodan.probes.pop3 import POP3Probe
    from lodan.probes.postgres import PostgresProbe
    from lodan.probes.rdp import RDPProbe
    from lodan.probes.redis import RedisProbe
    from lodan.probes.rsync import RsyncProbe
    from lodan.probes.smb import SMBProbe
    from lodan.probes.smtp import SMTPProbe
    from lodan.probes.snmp import SNMPProbe
    from lodan.probes.ssdp import SSDPProbe
    from lodan.probes.ssh import SSHProbe
    from lodan.probes.telnet import TelnetProbe
    from lodan.probes.tls import TLSProbe
    from lodan.probes.vnc import VNCProbe

    clear_registry()
    register("tls", TLSProbe)
    register("http", HTTPProbe)
    register("ssh", SSHProbe)
    register("smb", SMBProbe)
    register("rdp", RDPProbe)
    register("mqtt", MQTTProbe)
    register("redis", RedisProbe)
    register("mongo", MongoProbe)
    register("docker", DockerProbe)
    register("kubernetes", KubernetesProbe)
    register("smtp", SMTPProbe)
    register("ftp", FTPProbe)
    register("dns", DNSProbe)
    register("elastic", ElasticProbe)
    register("imap", IMAPProbe)
    register("pop3", POP3Probe)
    register("postgres", PostgresProbe)
    register("mysql", MySQLProbe)
    register("vnc", VNCProbe)
    register("telnet", TelnetProbe)
    register("rsync", RsyncProbe)
    register("amqp", AMQPProbe)
    register("ldap", LDAPProbe)
    # UDP fleet. SNMP is registered here but gated at the runner: it is the
    # one probe that must present a community string, so it needs an explicit
    # operator opt-in rather than running by default.
    register("snmp", SNMPProbe)
    register("ntp", NTPProbe)
    register("memcached", MemcachedProbe)
    register("netbios", NetBIOSProbe)
    register("ssdp", SSDPProbe)
    register("mdns", MDNSProbe)
    register("ike", IKEProbe)


def pick_probes(port: int, proto: str = "tcp") -> list[Probe]:
    """Every probe whose (default_ports, proto) covers the request.

    HTTPS ports match both TLS and HTTP probes; both results merge into the
    services row via COALESCE so neither clobbers the other.

    A probe's `proto` defaults to "tcp" when it doesn't declare one, so the
    twenty-odd existing TCP probes needed no change to keep working — and a
    UDP probe never fires against a TCP port that happens to share a number.
    """
    picks: list[Probe] = []
    for _name, cls in _REGISTRY:
        probe = cls()  # type: ignore[call-arg]
        if getattr(probe, "proto", "tcp") != proto:
            continue
        if port in probe.default_ports:
            picks.append(probe)
    return picks
