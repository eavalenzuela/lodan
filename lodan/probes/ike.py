"""IKE / IPsec probe: SA proposal + Vendor ID fingerprinting.

A VPN gateway on UDP/500 answers an IKE Security Association proposal by
selecting a transform and, almost always, returning Vendor ID payloads. Those
VIDs identify the gateway product (Cisco, Fortinet, strongSwan, Windows) more
reliably than anything else that class of device exposes, and the selected
transform reveals whether the gateway still accepts DES or MD5.

lodan sends one Main Mode SA proposal and reads the reply. No tunnel is ever
established: there is no Diffie-Hellman exchange, no identity payload, no
pre-shared key, and no aggressive-mode request (which is the mode that would
elicit a hash worth cracking — deliberately not used).
"""
from __future__ import annotations

import asyncio
import struct
from typing import Any

from lodan.probes._udp import udp_exchange
from lodan.probes.base import ProbeResult

_DEFAULT_IKE_PORTS = frozenset({500})

# Payload types (RFC 2408).
_PAYLOAD_SA = 1
_PAYLOAD_VENDOR_ID = 13
_PAYLOAD_NOTIFY = 11

_EXCHANGE_IDENTITY_PROTECTION = 2   # Main Mode

# Well-known Vendor ID prefixes (hex) -> product. Matched on prefix because
# many VIDs append a version suffix.
_VENDOR_IDS: tuple[tuple[str, str], ...] = (
    ("4048b7d56ebce88525e7de7f00d6c2d3", "IKE fragmentation"),
    ("afcad71368a1f1c96b8696fc77570100", "Dead Peer Detection"),
    ("12f5f28c457168a9702d9fe274cc0100", "Cisco Unity"),
    ("09002689dfd6b712", "XAUTH"),
    ("4f45543637", "strongSwan"),
    ("8f8d83826d246b6fc7a8a6a428c11de8", "Fortinet"),
    ("1e2b516905991c7d7c96fcbfb587e46100", "Windows / Microsoft"),
    ("4a131c81070358455c5728f20e95452f", "NAT-T RFC 3947"),
    ("90cb80913ebb696e086381b5ec427b1f", "NAT-T draft-02"),
)

# Transform attribute values worth calling out.
_ENCRYPTION = {1: "DES", 2: "IDEA", 3: "Blowfish", 4: "RC5", 5: "3DES", 7: "AES"}
_HASH = {1: "MD5", 2: "SHA1", 4: "SHA2-256", 5: "SHA2-384", 6: "SHA2-512"}
_AUTH = {1: "pre-shared key", 3: "RSA signature", 64221: "hybrid"}

WEAK_ENCRYPTION = frozenset({"DES", "IDEA", "RC5"})
WEAK_HASH = frozenset({"MD5"})


class IKEProbe:
    name = "ike"
    proto = "udp"
    default_ports = _DEFAULT_IKE_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        raw = await asyncio.wait_for(
            udp_exchange(ip, port, build_sa_proposal(), timeout), timeout=timeout + 1
        )
        return parse(raw)


def _attribute(attr_type: int, value: int) -> bytes:
    """Basic (short-form) SA attribute: high bit set, 2-byte value."""
    return struct.pack(">HH", 0x8000 | attr_type, value)


def _transform(number: int, encryption: int, hash_algo: int, group: int) -> bytes:
    attrs = (
        _attribute(1, encryption)
        + _attribute(2, hash_algo)
        + _attribute(3, 1)            # auth method: pre-shared key (proposed only)
        + _attribute(4, group)
        + _attribute(11, 1)           # life type: seconds
        + struct.pack(">HHI", 0x000C, 4, 28800)   # life duration
    )
    body = struct.pack(">BBH", number, 1, 0) + attrs   # transform #, IKE id, reserved
    return struct.pack(">BBH", 0, 0, len(body) + 4) + body


def build_sa_proposal(*, cookie: bytes = b"\x11\x22\x33\x44\x55\x66\x77\x88") -> bytes:
    """One Main Mode SA payload offering a small transform set."""
    transforms = b"".join([
        _transform(1, 7, 2, 2),      # AES / SHA1 / MODP-1024
        _transform(2, 5, 2, 2),      # 3DES / SHA1
        _transform(3, 5, 1, 2),      # 3DES / MD5
        _transform(4, 1, 1, 1),      # DES / MD5 — offered to see if it's accepted
    ])
    proposal_body = struct.pack(">BBBB", 1, 1, 0, 4) + transforms
    proposal = struct.pack(">BBH", 0, 0, len(proposal_body) + 4) + proposal_body
    sa_body = struct.pack(">II", 1, 1) + proposal    # DOI = IPSEC, situation
    sa_payload = struct.pack(">BBH", 0, 0, len(sa_body) + 4) + sa_body

    header = (
        cookie
        + b"\x00" * 8                                    # responder cookie: unset
        + bytes([_PAYLOAD_SA, 0x10, _EXCHANGE_IDENTITY_PROTECTION, 0x00])
        + struct.pack(">I", 0)                           # message id
        + struct.pack(">I", 28 + len(sa_payload))        # total length
    )
    return header + sa_payload


def _identify_vendor(payload: bytes) -> str | None:
    hexed = payload.hex()
    for prefix, label in _VENDOR_IDS:
        if hexed.startswith(prefix):
            return label
    return None


def parse(raw: bytes | None) -> ProbeResult:
    if not raw or len(raw) < 28:
        return ProbeResult(service="ike", banner="ike: no response")
    result_raw: dict[str, Any] = {"response_bytes": len(raw)}
    next_payload = raw[16]
    exchange = raw[18]
    result_raw["exchange_type"] = exchange

    vendor_ids: list[str] = []
    vendor_labels: list[str] = []
    selected: dict[str, str] = {}
    notify: int | None = None

    pos = 28
    guard = 0
    while next_payload != 0 and pos + 4 <= len(raw) and guard < 64:
        guard += 1
        this_payload = next_payload
        next_payload = raw[pos]
        length = struct.unpack_from(">H", raw, pos + 2)[0]
        if length < 4 or pos + length > len(raw):
            break
        body = raw[pos + 4 : pos + length]
        if this_payload == _PAYLOAD_VENDOR_ID:
            vendor_ids.append(body.hex())
            label = _identify_vendor(body)
            if label:
                vendor_labels.append(label)
        elif this_payload == _PAYLOAD_SA:
            selected = _parse_selected_transform(body)
        elif this_payload == _PAYLOAD_NOTIFY and len(body) >= 12:
            notify = struct.unpack_from(">H", body, 10)[0]
        pos += length

    result_raw.update({
        "vendor_ids": vendor_ids,
        "vendor_labels": sorted(set(vendor_labels)),
        "selected_transform": selected or None,
        "notify": notify,
    })
    weak = []
    if selected.get("encryption") in WEAK_ENCRYPTION:
        weak.append(selected["encryption"])
    if selected.get("hash") in WEAK_HASH:
        weak.append(selected["hash"])
    if weak:
        result_raw["weak_transform"] = weak

    parts: list[str] = []
    if vendor_labels:
        parts.append(", ".join(sorted(set(vendor_labels))))
    if selected:
        parts.append(
            f"{selected.get('encryption', '?')}/{selected.get('hash', '?')}"
        )
    banner = "IKE " + " | ".join(parts) if parts else "IKE (VPN gateway)"
    return ProbeResult(
        service="ike", banner=banner[:300],
        ike_vendor=", ".join(sorted(set(vendor_labels))) or None,
        raw=result_raw,
    )


def _parse_selected_transform(sa_body: bytes) -> dict[str, str]:
    """Pull the accepted encryption/hash/auth out of the responder's SA."""
    out: dict[str, str] = {}
    # SA body: DOI (4) + situation (4), then a proposal payload, then transforms.
    pos = 8
    if pos + 4 > len(sa_body):
        return out
    proposal_len = struct.unpack_from(">H", sa_body, pos + 2)[0]
    if proposal_len < 8 or pos + proposal_len > len(sa_body):
        return out
    tpos = pos + 4 + 4                     # past proposal header + its fixed fields
    if tpos + 8 > len(sa_body):
        return out
    tpos += 4 + 4                          # transform payload header + fixed fields
    while tpos + 4 <= len(sa_body):
        attr = struct.unpack_from(">H", sa_body, tpos)[0]
        attr_type = attr & 0x7FFF
        if attr & 0x8000:
            value = struct.unpack_from(">H", sa_body, tpos + 2)[0]
            tpos += 4
        else:
            attr_len = struct.unpack_from(">H", sa_body, tpos + 2)[0]
            tpos += 4 + attr_len
            continue
        if attr_type == 1 and value in _ENCRYPTION:
            out["encryption"] = _ENCRYPTION[value]
        elif attr_type == 2 and value in _HASH:
            out["hash"] = _HASH[value]
        elif attr_type == 3 and value in _AUTH:
            out["auth"] = _AUTH[value]
    return out
