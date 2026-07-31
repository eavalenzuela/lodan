"""OS / distro / device-type inference by multi-signal fusion.

Two layers, both pure post-processing of data already collected — this module
issues no traffic of any kind.

**Layer 1 — `os_guess` (per service).** The probes already parse version
strings that name their build environment: an OpenSSH banner comment says
`Ubuntu-4ubuntu0.5`, an IIS version implies a Windows Server release, an
Apache `Server` header carries `(Debian)`. Distributions pin one OpenSSH
version per release, so the software version plus the distro tag in the
comment identifies the release outright.

**Layer 2 — `device_type` (per host).** A weighted rule table over the whole
per-host feature vector: the open-port set, `os_family`/`stack_sig` from the
passive stack fingerprint, banners, operator-assigned favicon labels, and
which services answered at all. No single signal decides — a printer is
"9100 open AND an HP banner AND not a general-purpose OS", and corroborating
signals raise confidence while a lone weak one stays below the reporting
threshold.

Both layers return None rather than guessing. `lodan` is an inventory tool:
an unlabelled host costs an operator a lookup, a mislabelled one costs them
their trust in every other row.
"""
from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from typing import Any

# --- layer 1: OS / distro from version strings -------------------------------

# Distributions ship exactly one OpenSSH version per release, so the pair
# (distro tag in the banner comment, OpenSSH version) pins the release. Only
# entries that are unambiguous belong here.
_OPENSSH_UBUNTU = {
    "6.6.1p1": "14.04",
    "7.2p2": "16.04",
    "7.6p1": "18.04",
    "8.2p1": "20.04",
    "8.9p1": "22.04",
    "9.6p1": "24.04",
}
_OPENSSH_DEBIAN = {
    "6.7p1": "8",
    "7.4p1": "9",
    "7.9p1": "10",
    "8.4p1": "11",
    "9.2p1": "12",
}

# IIS major version -> Windows Server release. IIS is bundled, never
# standalone, so this mapping is exact.
_IIS_WINDOWS = {
    "6.0": "Windows Server 2003",
    "7.0": "Windows Server 2008",
    "7.5": "Windows Server 2008 R2",
    "8.0": "Windows Server 2012",
    "8.5": "Windows Server 2012 R2",
    "10.0": "Windows Server 2016+",
}

_SSH_SOFTWARE_RE = re.compile(r"OpenSSH_(?P<version>\d+(?:\.\d+)*(?:p\d+)?)", re.I)
_IIS_RE = re.compile(r"Microsoft-IIS/(?P<version>\d+\.\d+)", re.I)


@dataclass(frozen=True)
class OSGuess:
    os_guess: str
    confidence: float
    source: str


# Distro tags that appear parenthesised in Apache/nginx `Server` headers and
# in FTP/SMTP greetings. Value is the label we report; None means "the tag is
# the label".
_DISTRO_TAGS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\(Ubuntu\)", re.I), "Ubuntu"),
    (re.compile(r"\(Debian\)", re.I), "Debian"),
    (re.compile(r"\(Raspbian\)", re.I), "Raspbian"),
    (re.compile(r"\(Red ?Hat\)", re.I), "Red Hat"),
    (re.compile(r"\(CentOS\)", re.I), "CentOS"),
    (re.compile(r"\(Rocky(?: Linux)?\)", re.I), "Rocky Linux"),
    (re.compile(r"\(AlmaLinux\)", re.I), "AlmaLinux"),
    (re.compile(r"\(Fedora\)", re.I), "Fedora"),
    (re.compile(r"\(SUSE\)", re.I), "SUSE"),
    (re.compile(r"\(Amazon\)", re.I), "Amazon Linux"),
    (re.compile(r"\(Oracle\)", re.I), "Oracle Linux"),
    (re.compile(r"\(FreeBSD\)", re.I), "FreeBSD"),
    (re.compile(r"\(Win(?:32|64)\)", re.I), "Windows"),
    (re.compile(r"\(Unix\)", re.I), "Unix"),
)

# Free-standing product strings that name their platform outright.
_PLATFORM_PATTERNS: tuple[tuple[re.Pattern[str], str, float], ...] = (
    (re.compile(r"OpenSSH_for_Windows", re.I), "Windows", 0.9),
    (re.compile(r"\bDropbear\b", re.I), "embedded Linux", 0.6),
    (re.compile(r"RouterOS|MikroTik", re.I), "MikroTik RouterOS", 0.9),
    (re.compile(r"\bpfSense\b", re.I), "pfSense", 0.9),
    (re.compile(r"\bOPNsense\b", re.I), "OPNsense", 0.9),
    (re.compile(r"Cisco IOS", re.I), "Cisco IOS", 0.9),
    (re.compile(r"VMware ESXi", re.I), "VMware ESXi", 0.9),
    (re.compile(r"\bSynology\b|DiskStation", re.I), "Synology DSM", 0.85),
    (re.compile(r"\bQNAP\b|QTS", re.I), "QNAP QTS", 0.85),
    (re.compile(r"TrueNAS|FreeNAS", re.I), "TrueNAS", 0.85),
    (re.compile(r"\bUbuntu\b", re.I), "Ubuntu", 0.5),
    (re.compile(r"\bDebian\b", re.I), "Debian", 0.5),
    (re.compile(r"\bCentOS\b", re.I), "CentOS", 0.5),
)


def _ssh_os_guess(parsed: dict[str, Any]) -> OSGuess | None:
    """Read the distro out of an SSH banner's software+comment pair."""
    software = str(parsed.get("software") or "")
    comment = str(parsed.get("comment") or "")
    m = _SSH_SOFTWARE_RE.search(software)
    version = m.group("version") if m else None

    # The comment names the distro; the OpenSSH version names the release.
    if re.search(r"ubuntu", comment, re.I) or re.search(r"ubuntu", software, re.I):
        release = _OPENSSH_UBUNTU.get(version or "")
        if release:
            return OSGuess(f"Ubuntu {release}", 0.9, "ssh-banner")
        return OSGuess("Ubuntu", 0.6, "ssh-banner")
    if re.search(r"debian|raspbian", comment, re.I):
        label = "Raspbian" if re.search(r"raspbian", comment, re.I) else "Debian"
        release = _OPENSSH_DEBIAN.get(version or "")
        if release and label == "Debian":
            return OSGuess(f"Debian {release}", 0.9, "ssh-banner")
        return OSGuess(label, 0.6, "ssh-banner")
    if re.search(r"FreeBSD", comment, re.I) or re.search(r"FreeBSD", software, re.I):
        return OSGuess("FreeBSD", 0.8, "ssh-banner")
    for pattern, label, confidence in _PLATFORM_PATTERNS:
        if pattern.search(software) or pattern.search(comment):
            return OSGuess(label, confidence, "ssh-banner")
    return None


def os_guess_for(service: str | None, banner: str | None, raw: dict[str, Any]) -> OSGuess | None:
    """Best OS/distro reading for one probed service, or None."""
    if service == "ssh":
        parsed = raw.get("parsed")
        if isinstance(parsed, dict):
            hit = _ssh_os_guess(parsed)
            if hit is not None:
                return hit

    # Everything else is text matching over the banner plus the HTTP Server
    # header, which the HTTP probe stores separately from the joined banner.
    haystacks = [banner or ""]
    server = raw.get("server")
    if isinstance(server, str):
        haystacks.append(server)
    headers = raw.get("headers")
    if isinstance(headers, dict):
        for key in ("server", "x-powered-by"):
            value = headers.get(key)
            if isinstance(value, str):
                haystacks.append(value)
    text = " ".join(h for h in haystacks if h)
    if not text:
        return None

    m = _IIS_RE.search(text)
    if m:
        label = _IIS_WINDOWS.get(m.group("version"))
        if label:
            return OSGuess(label, 0.85, "iis-version")
        return OSGuess("Windows Server", 0.6, "iis-version")

    for pattern, label in _DISTRO_TAGS:
        if pattern.search(text):
            return OSGuess(label, 0.8, "server-header")

    for pattern, label, confidence in _PLATFORM_PATTERNS:
        if pattern.search(text):
            return OSGuess(label, confidence, "banner")
    return None


# --- layer 2: device type from the fused host feature vector ------------------


@dataclass(frozen=True)
class HostFeatures:
    """Everything known about one IP after probing, flattened for scoring."""

    ip: str
    ports: frozenset[int]
    services: frozenset[str]
    banners: str                  # every banner on the host, joined + lowercased
    os_families: frozenset[str]   # from the passive stack fingerprint
    os_guesses: frozenset[str]
    favicon_labels: frozenset[str]


@dataclass(frozen=True)
class DeviceRule:
    """One weighted vote for a device class.

    Every constraint that is set must hold for the rule to fire. Weights are
    calibrated so one strong structural signal (`docker` answering) clears the
    reporting threshold alone, while weak circumstantial ones (a single open
    port) need corroboration.
    """

    device_type: str
    weight: float
    ports_any: frozenset[int] | None = None
    services_any: frozenset[str] | None = None
    banner_pattern: re.Pattern[str] | None = None
    os_families_any: frozenset[str] | None = None
    os_guess_pattern: re.Pattern[str] | None = None
    favicon_pattern: re.Pattern[str] | None = None


def _p(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


RULES: tuple[DeviceRule, ...] = (
    # --- container host / orchestrator ---
    DeviceRule("container-host", 0.75, services_any=frozenset({"docker"})),
    DeviceRule("container-host", 0.75, services_any=frozenset({"kubernetes"})),
    DeviceRule("container-host", 0.2, ports_any=frozenset({2375, 2376, 6443, 10250})),
    # --- hypervisor ---
    DeviceRule("hypervisor", 0.8, banner_pattern=_p(r"vmware esxi|vsphere")),
    DeviceRule("hypervisor", 0.7, os_guess_pattern=_p(r"esxi")),
    DeviceRule("hypervisor", 0.5, banner_pattern=_p(r"proxmox")),
    DeviceRule("hypervisor", 0.25, ports_any=frozenset({902, 8006})),
    DeviceRule("hypervisor", 0.3, banner_pattern=_p(r"\bxenserver\b|citrix hypervisor")),
    # --- printer / MFP ---
    DeviceRule("printer", 0.5, ports_any=frozenset({9100, 515})),
    DeviceRule("printer", 0.35, ports_any=frozenset({631})),
    DeviceRule(
        "printer", 0.5,
        banner_pattern=_p(r"jetdirect|laserjet|officejet|\blexmark\b|\bkyocera\b"
                          r"|\bricoh\b|\bxerox\b|brother |\bcanon\b|\bepson\b"),
    ),
    DeviceRule("printer", 0.3, favicon_pattern=_p(r"printer|jetdirect")),
    # --- NAS ---
    DeviceRule("nas", 0.7, banner_pattern=_p(r"synology|diskstation|\bqnap\b|truenas|freenas")),
    DeviceRule("nas", 0.6, os_guess_pattern=_p(r"synology|qnap|truenas")),
    DeviceRule("nas", 0.2, ports_any=frozenset({5000, 5001, 8080}),
               services_any=frozenset({"smb"})),
    DeviceRule("nas", 0.3, favicon_pattern=_p(r"synology|qnap|nas\b")),
    # --- router / firewall / network gear ---
    DeviceRule("router-firewall", 0.5, os_families_any=frozenset({"network-device"})),
    DeviceRule(
        "router-firewall", 0.7,
        banner_pattern=_p(r"mikrotik|routeros|pfsense|opnsense|\bfortigate\b|fortinet"
                          r"|cisco|juniper|\bubiquiti\b|edgerouter|\bpalo alto\b|sonicwall"),
    ),
    DeviceRule("router-firewall", 0.6, os_guess_pattern=_p(r"routeros|pfsense|opnsense|cisco ios")),
    DeviceRule("router-firewall", 0.25, ports_any=frozenset({179, 1723, 500, 4500})),
    # --- IP camera / IoT ---
    DeviceRule("ip-camera-iot", 0.5, ports_any=frozenset({554, 8554, 37777})),
    DeviceRule(
        "ip-camera-iot", 0.6,
        banner_pattern=_p(r"hikvision|\bdahua\b|axis communications|\bfoscam\b"
                          r"|\bamcrest\b|\breolink\b|web service.*camera|ipcam"),
    ),
    DeviceRule("ip-camera-iot", 0.3, os_families_any=frozenset({"embedded"})),
    DeviceRule("ip-camera-iot", 0.3, favicon_pattern=_p(r"camera|nvr\b|hikvision|dahua")),
    DeviceRule("ip-camera-iot", 0.25, services_any=frozenset({"mqtt"}),
               os_families_any=frozenset({"embedded"})),
    # --- general-purpose server (the fallback class) ---
    DeviceRule("server", 0.35, os_families_any=frozenset({"linux", "freebsd", "openbsd"})),
    DeviceRule("server", 0.35, os_families_any=frozenset({"windows"})),
    DeviceRule("server", 0.2, services_any=frozenset({"ssh"})),
    DeviceRule("server", 0.2, services_any=frozenset({"rdp"})),
    DeviceRule("server", 0.15, services_any=frozenset({"http", "tls"})),
    DeviceRule("server", 0.25, os_guess_pattern=_p(r"ubuntu|debian|centos|red hat|rocky"
                                                   r"|almalinux|fedora|suse|windows server")),
    DeviceRule("server", 0.2, services_any=frozenset({"postgres", "mysql", "mongo", "elastic"})),
)

# A host must reach this much accumulated weight before we are willing to put
# a label on it. Below it, `device_type` stays NULL.
MIN_DEVICE_SCORE = 0.5

# Appliance classes outrank "server" when both fire: a Synology answering on
# :22 is a NAS that happens to run Linux, not a server that happens to be a
# NAS. Without this, the broad `server` rules would drown every appliance.
_SPECIFIC_CLASSES = frozenset(
    {"printer", "nas", "router-firewall", "ip-camera-iot", "hypervisor", "container-host"}
)


def _rule_matches(rule: DeviceRule, f: HostFeatures) -> bool:
    if rule.ports_any is not None and not (rule.ports_any & f.ports):
        return False
    if rule.services_any is not None and not (rule.services_any & f.services):
        return False
    if rule.banner_pattern is not None and not rule.banner_pattern.search(f.banners):
        return False
    if rule.os_families_any is not None and not (rule.os_families_any & f.os_families):
        return False
    if rule.os_guess_pattern is not None and not any(
        rule.os_guess_pattern.search(g) for g in f.os_guesses
    ):
        return False
    return not (
        rule.favicon_pattern is not None
        and not any(rule.favicon_pattern.search(label) for label in f.favicon_labels)
    )


@dataclass(frozen=True)
class DeviceVerdict:
    device_type: str
    confidence: float


def classify(f: HostFeatures) -> DeviceVerdict | None:
    """Fuse a host's whole feature vector into one device class, or None."""
    scores: dict[str, float] = {}
    for rule in RULES:
        if _rule_matches(rule, f):
            scores[rule.device_type] = scores.get(rule.device_type, 0.0) + rule.weight
    if not scores:
        return None

    specific = {k: v for k, v in scores.items() if k in _SPECIFIC_CLASSES}
    pool = specific if specific else scores
    winner = max(pool, key=lambda k: (pool[k], k))
    score = pool[winner]
    if score < MIN_DEVICE_SCORE:
        return None
    # Confidence saturates: more corroboration helps, but nothing here is ever
    # certain enough to claim it is.
    return DeviceVerdict(winner, min(0.95, round(score, 2)))


# --- persistence -------------------------------------------------------------


def _loads(raw: Any) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def enrich_devices(conn: sqlite3.Connection, scan_id: int) -> int:
    """Write `services.os_guess` and the host-level device classification.

    Returns the number of hosts that got a `device_type`. Idempotent: both
    layers are pure functions of rows already in the DB, so re-running
    overwrites with the same answer.
    """
    rows = conn.execute(
        "SELECT ip, port, service, banner, raw, os_family, favicon_mmh3 "
        "FROM services WHERE scan_id = ?",
        (scan_id,),
    ).fetchall()
    if not rows:
        return 0

    labels = {
        mmh3: (label or "")
        for mmh3, label in conn.execute("SELECT mmh3, label FROM favicons")
    }

    per_ip: dict[str, dict[str, Any]] = {}
    for ip, port, service, banner, raw, os_family, favicon in rows:
        guess = os_guess_for(service, banner, _loads(raw))
        if guess is not None:
            conn.execute(
                "UPDATE services SET os_guess = ? WHERE scan_id = ? AND ip = ? AND port = ?",
                (guess.os_guess, scan_id, ip, port),
            )
        bucket = per_ip.setdefault(
            ip,
            {"ports": set(), "services": set(), "banners": [], "os_families": set(),
             "os_guesses": set(), "favicon_labels": set()},
        )
        bucket["ports"].add(port)
        if service:
            bucket["services"].add(service)
        if banner:
            bucket["banners"].append(banner)
        if os_family:
            bucket["os_families"].add(os_family)
        if guess is not None:
            bucket["os_guesses"].add(guess.os_guess)
        if favicon is not None and labels.get(favicon):
            bucket["favicon_labels"].add(labels[favicon].lower())

    classified = 0
    for ip, bucket in per_ip.items():
        features = HostFeatures(
            ip=ip,
            ports=frozenset(bucket["ports"]),
            services=frozenset(bucket["services"]),
            banners=" ".join(bucket["banners"]).lower(),
            os_families=frozenset(bucket["os_families"]),
            os_guesses=frozenset(bucket["os_guesses"]),
            favicon_labels=frozenset(bucket["favicon_labels"]),
        )
        verdict = classify(features)
        # Host-level os_guess mirrors the stack-fingerprint rollup: unanimous
        # or nothing, since two ports disagreeing about the distro is the
        # multi-backend signal feature 3 goes looking for.
        guesses = bucket["os_guesses"]
        host_os_guess = next(iter(guesses)) if len(guesses) == 1 else None
        if verdict is None and host_os_guess is None:
            continue
        conn.execute(
            """
            INSERT INTO hosts (scan_id, ip, os_guess, device_type, device_confidence)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(scan_id, ip) DO UPDATE SET
                os_guess = excluded.os_guess,
                device_type = excluded.device_type,
                device_confidence = excluded.device_confidence
            """,
            (
                scan_id, ip, host_os_guess,
                verdict.device_type if verdict else None,
                verdict.confidence if verdict else None,
            ),
        )
        if verdict is not None:
            classified += 1
    return classified
