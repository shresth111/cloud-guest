"""Pure reduction of collector rows into per-router window summaries.

Input is one 5-minute window from the hub's ``flow_agent.py``: nfacctd rows
aggregated on ``peer_src_ip, src_host, dst_host`` (see
``ops/netflow/nfacctd.conf``), i.e. ``{"peer_ip_src", "ip_src", "ip_dst",
"bytes", "packets", "flows"}``.

Each row is split by which side is *local* (private, CGNAT, link-local --
the venue LAN) and which is *remote*:

* local -> remote: upload. The local IP is a talker (``bytes_up``); the
  remote IP is a destination.
* remote -> local: download. Talker ``bytes_down``; same destination.
* local -> local: ``bytes_internal`` (guest -> router DNS, router -> hub over
  the tunnel, the IPFIX export itself). Never a destination.
* remote -> remote: ``bytes_unclassified``. Should not occur behind NAT;
  counted so the totals still add up, never silently dropped.

The split keys on *which side is private*, not on flow direction, so it does
not depend on whether RouterOS records a reply before or after un-NAT
(DESIGN.md §2, hardware check H2).

Talkers and destinations are reduced **independently**. Nothing here, and
nothing stored, pairs a talker with a destination (DESIGN.md §7).
"""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .constants import TOP_N_STORED, TalkerMatch

__all__ = [
    "ExporterWindow",
    "TalkerTotals",
    "attribute_talkers",
    "is_local_address",
    "reduce_window",
    "top_destinations",
    "top_talkers",
]

_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def is_local_address(value: str) -> bool | None:
    """True for an address that can only be on the venue side of NAT;
    ``None`` for something that is not an IP address at all."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv4Address) and address in _CGNAT:
        return True
    return bool(address.is_private or address.is_link_local or address.is_loopback)


@dataclass
class TalkerTotals:
    bytes_up: int = 0
    bytes_down: int = 0
    flows: int = 0

    @property
    def bytes_total(self) -> int:
        return self.bytes_up + self.bytes_down


@dataclass
class ExporterWindow:
    exporter_address: str
    talkers: dict[str, TalkerTotals] = field(default_factory=dict)
    destinations: dict[str, list[int]] = field(
        default_factory=dict
    )  # ip -> [bytes, flows]
    bytes_total: int = 0
    packets_total: int = 0
    flows_total: int = 0
    bytes_internal: int = 0
    bytes_unclassified: int = 0
    rows_rejected: int = 0


def _int(value: Any) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return 0
    return max(number, 0)


def reduce_window(rows: Iterable[Mapping[str, Any]]) -> dict[str, ExporterWindow]:
    """Group one window's rows by exporter and split them as described in
    the module docstring. A row whose addresses do not parse is counted in
    ``rows_rejected`` and contributes nothing else."""
    out: dict[str, ExporterWindow] = {}
    for row in rows:
        exporter = str(row.get("peer_ip_src") or "").strip()
        if not exporter:
            continue
        window = out.setdefault(exporter, ExporterWindow(exporter_address=exporter))
        src = str(row.get("ip_src") or "").strip()
        dst = str(row.get("ip_dst") or "").strip()
        src_local = is_local_address(src)
        dst_local = is_local_address(dst)
        if src_local is None or dst_local is None:
            window.rows_rejected += 1
            continue
        nbytes = _int(row.get("bytes"))
        nflows = _int(row.get("flows"))
        window.bytes_total += nbytes
        window.packets_total += _int(row.get("packets"))
        window.flows_total += nflows
        if src_local and dst_local:
            window.bytes_internal += nbytes
            continue
        if not src_local and not dst_local:
            window.bytes_unclassified += nbytes
            continue
        local, remote = (src, dst) if src_local else (dst, src)
        talker = window.talkers.setdefault(local, TalkerTotals())
        if src_local:
            talker.bytes_up += nbytes
        else:
            talker.bytes_down += nbytes
        talker.flows += nflows
        dest = window.destinations.setdefault(remote, [0, 0])
        dest[0] += nbytes
        dest[1] += nflows
    return out


def attribute_talkers(
    talker_ips: Iterable[str],
    sessions_by_ip: Mapping[str, list[uuid.UUID]],
) -> dict[str, tuple[TalkerMatch, uuid.UUID | None]]:
    """Exactly one overlapping session -> that session. Several -> ambiguous
    (DHCP reuse inside one window). None -> unmatched. Never the nearest
    session by time: a wrong attribution is worse than none."""
    result: dict[str, tuple[TalkerMatch, uuid.UUID | None]] = {}
    for ip in talker_ips:
        ids = list(dict.fromkeys(sessions_by_ip.get(ip, [])))
        if len(ids) == 1:
            result[ip] = (TalkerMatch.SESSION, ids[0])
        elif len(ids) > 1:
            result[ip] = (TalkerMatch.AMBIGUOUS, None)
        else:
            result[ip] = (TalkerMatch.NONE, None)
    return result


def top_talkers(
    window: ExporterWindow,
    attribution: Mapping[str, tuple[TalkerMatch, uuid.UUID | None]],
    *,
    limit: int = TOP_N_STORED,
) -> tuple[list[dict[str, Any]], int]:
    """Top ``limit`` talkers by total bytes, and the bytes of the rest."""
    ranked = sorted(window.talkers.items(), key=lambda kv: (-kv[1].bytes_total, kv[0]))
    kept = ranked[:limit]
    rest = sum(totals.bytes_total for _, totals in ranked[limit:])
    entries: list[dict[str, Any]] = []
    for ip, totals in kept:
        match, session_id = attribution.get(ip, (TalkerMatch.NONE, None))
        entries.append(
            {
                "ip": ip,
                "bytes_up": totals.bytes_up,
                "bytes_down": totals.bytes_down,
                "flows": totals.flows,
                "match": match.value,
                "guest_session_id": str(session_id) if session_id else None,
            }
        )
    return entries, rest


def top_destinations(
    window: ExporterWindow, *, limit: int = TOP_N_STORED
) -> tuple[list[dict[str, Any]], int]:
    """Top ``limit`` remote addresses by bytes, and the bytes of the rest."""
    ranked = sorted(window.destinations.items(), key=lambda kv: (-kv[1][0], kv[0]))
    entries = [
        {"ip": ip, "bytes": totals[0], "flows": totals[1]}
        for ip, totals in ranked[:limit]
    ]
    rest = sum(totals[0] for _, totals in ranked[limit:])
    return entries, rest
