"""Pure reduction of collector rows into per-router window summaries.

Input is one 5-minute window from the hub's ``flow_agent.py``: nfacctd rows
aggregated on ``peer_src_ip, src_host, dst_host`` (see
``ops/netflow/nfacctd.conf``), i.e. ``{"peer_ip_src", "ip_src", "ip_dst",
"bytes", "packets", "flows"}``, plus -- once the collector aggregates on
them -- ``"ip_proto"``, ``"port_src"`` and ``"port_dst"``.

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

Client traffic (the first two cases) is also reduced by **service**: the
IP protocol plus the *remote* end's port. The local end's port is ephemeral
and is dropped. A window whose rows carry no protocol/port is
``services_measured = False`` and yields no service rows at all -- never a
partial list that would read as the whole.

Talkers, destinations and services are reduced **independently**: nothing
here, and nothing stored, pairs a talker with a destination or with a
service (DESIGN.md §7).

The one pairing that exists has no talker in it: ``destination_services``
keys the *outside* address by its service, for the venue-level destination
buckets (``destination_buckets.py``). The local end is not part of that key.
"""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .constants import (
    OTHER_SERVICE_PORT,
    PROTOCOL_NUMBERS_BY_NAME,
    TOP_N_STORED,
    TOP_SERVICES_STORED,
    TalkerMatch,
)
from .platform_overhead import NO_PLATFORM_ENDPOINTS, PlatformEndpoints

__all__ = [
    "ExporterWindow",
    "TalkerTotals",
    "attribute_talkers",
    "is_local_address",
    "packets_pair",
    "parse_protocol",
    "reduce_window",
    "service_rows",
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
    )  # ip -> [bytes, flows, bytes_up, bytes_down]
    # (protocol, remote port) -> [bytes_up, bytes_down, flows]
    services: dict[tuple[int, int], list[int]] = field(default_factory=dict)
    # (remote address, protocol, remote port) -> [bytes_up, bytes_down, flows].
    # Venue-level: the local end is deliberately not in the key.
    destination_services: dict[tuple[str, int, int], list[int]] = field(
        default_factory=dict
    )
    # Packets, alongside the two maps above and under the same keys:
    # -> [packets_up, packets_down]. Separate maps so the byte/flow triples
    # keep their shape.
    service_packets: dict[tuple[int, int], list[int]] = field(default_factory=dict)
    destination_service_packets: dict[tuple[str, int, int], list[int]] = field(
        default_factory=dict
    )
    rows_with_service: int = 0
    rows_without_service: int = 0
    # Client-traffic service rows whose ``packets`` was absent or unreadable.
    service_rows_without_packets: int = 0
    bytes_total: int = 0
    bytes_up: int = 0
    bytes_down: int = 0
    packets_total: int = 0
    flows_total: int = 0
    bytes_internal: int = 0
    bytes_unclassified: int = 0
    rows_rejected: int = 0
    # Platform overhead (``platform_overhead``): the router's own traffic to
    # the platform. Counted here and in ``bytes_total``; in nothing else --
    # not client traffic, not internal, not a talker, destination or service.
    overhead_bytes_up: int = 0
    overhead_bytes_down: int = 0
    overhead_rows: int = 0

    @property
    def packets_measured(self) -> bool:
        """Every client-traffic service row of the window carried a packet
        count. All or nothing, like ``services_measured``: a bucket summed
        from some rows with packets and some without would be a number that
        looks complete and is not."""
        return self.services_measured and self.service_rows_without_packets == 0

    @property
    def services_measured(self) -> bool:
        """Every row of the window carried a protocol (and ports where the
        protocol has them). All or nothing: one row without them means the
        collector is not aggregating on them, and a partial service list
        would be presented as complete."""
        return self.rows_with_service > 0 and self.rows_without_service == 0


def _count(value: Any) -> int | None:
    """A non-negative counter, or ``None`` when the collector row does not
    carry one. Unlike :func:`_int` this keeps "absent" apart from 0."""
    if value is None or isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def packets_pair(
    window: ExporterWindow, packets: list[int] | None
) -> tuple[int | None, int | None]:
    """(packets_up, packets_down) to store for one bucket, or (None, None)
    when the window's packets were not fully measured -- stored as NULL so
    "not measured" never reads as zero packets."""
    if not window.packets_measured or packets is None:
        return None, None
    return packets[0], packets[1]


def parse_protocol(value: Any) -> int | None:
    """IP protocol number from a collector value: a number, a numeric
    string, or a name (pmacct prints ``tcp`` / ``udp`` / ``icmp`` by
    default). ``None`` when absent or unrecognised -- never a guess."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 <= value <= 255 else None
    text = str(value).strip().lower()
    if not text:
        return None
    if text.isdigit():
        number = int(text)
        return number if number <= 255 else None
    return PROTOCOL_NUMBERS_BY_NAME.get(text)


def _port(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if 0 <= number <= 65535 else None


def _service_key(
    row: Mapping[str, Any], *, remote_is_dst: bool
) -> tuple[int, int] | None:
    """(protocol, remote port) for one row, or ``None`` when the row does not
    carry them. A protocol without ports reports 0 from the collector."""
    protocol = parse_protocol(row.get("ip_proto"))
    port = _port(row.get("port_dst" if remote_is_dst else "port_src"))
    if protocol is None or port is None:
        return None
    return protocol, port


def _int(value: Any) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return 0
    return max(number, 0)


def reduce_window(
    rows: Iterable[Mapping[str, Any]],
    platform: PlatformEndpoints = NO_PLATFORM_ENDPOINTS,
) -> dict[str, ExporterWindow]:
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
        # Decided for every row, whatever its class, so a window of purely
        # internal traffic still knows whether the collector sends ports.
        key = _service_key(row, remote_is_dst=bool(src_local))
        if key is None:
            window.rows_without_service += 1
        else:
            window.rows_with_service += 1
        window.bytes_total += nbytes
        window.packets_total += _int(row.get("packets"))
        window.flows_total += nflows
        overhead = platform.row_direction(row)
        if overhead is not None:
            # The router talking to the platform. Before every other class:
            # it is neither the venue's client traffic nor venue-internal.
            window.overhead_rows += 1
            if overhead == "up":
                window.overhead_bytes_up += nbytes
            else:
                window.overhead_bytes_down += nbytes
            continue
        if src_local and dst_local:
            window.bytes_internal += nbytes
            continue
        if not src_local and not dst_local:
            window.bytes_unclassified += nbytes
            continue
        local, remote = (src, dst) if src_local else (dst, src)
        talker = window.talkers.setdefault(local, TalkerTotals())
        direction = 0 if src_local else 1  # 0 = up, 1 = down
        if src_local:
            talker.bytes_up += nbytes
            window.bytes_up += nbytes
        else:
            talker.bytes_down += nbytes
            window.bytes_down += nbytes
        talker.flows += nflows
        dest = window.destinations.setdefault(remote, [0, 0, 0, 0])
        dest[0] += nbytes
        dest[1] += nflows
        dest[2 + direction] += nbytes
        if key is not None:
            service = window.services.setdefault(key, [0, 0, 0])
            service[direction] += nbytes
            service[2] += nflows
            pair = window.destination_services.setdefault((remote, *key), [0, 0, 0])
            pair[direction] += nbytes
            pair[2] += nflows
            npackets = _count(row.get("packets"))
            if npackets is None:
                window.service_rows_without_packets += 1
            else:
                window.service_packets.setdefault(key, [0, 0])[direction] += npackets
                window.destination_service_packets.setdefault((remote, *key), [0, 0])[
                    direction
                ] += npackets
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
        {
            "ip": ip,
            "bytes": totals[0],
            "bytes_up": totals[2],
            "bytes_down": totals[3],
            "flows": totals[1],
        }
        for ip, totals in ranked[:limit]
    ]
    rest = sum(totals[0] for _, totals in ranked[limit:])
    return entries, rest


def service_rows(
    window: ExporterWindow, *, limit: int = TOP_SERVICES_STORED
) -> list[dict[str, int]]:
    """The window's service buckets: the top ``limit`` (protocol, remote
    port) pairs by bytes, then everything else folded into one row per
    protocol with ``remote_port = OTHER_SERVICE_PORT``.

    Nothing is dropped, so the rows sum to the window's client traffic
    (``bytes_up + bytes_down``) and to its protocol breakdown, and their
    packets to the window's client packets. Empty when the window is not
    ``services_measured``. ``packets_up`` / ``packets_down`` are ``None`` on
    every row when the window's packets were not measured."""
    if not window.services_measured:
        return []
    ranked = sorted(
        window.services.items(), key=lambda kv: (-(kv[1][0] + kv[1][1]), kv[0])
    )

    def _row(protocol: int, port: int, totals: list[int], packets: list[int]) -> dict:
        packets_up, packets_down = packets_pair(window, packets)
        return {
            "protocol": protocol,
            "remote_port": port,
            "bytes_up": totals[0],
            "bytes_down": totals[1],
            "flows": totals[2],
            "packets_up": packets_up,
            "packets_down": packets_down,
        }

    rows = [
        _row(
            protocol, port, totals, window.service_packets.get((protocol, port), [0, 0])
        )
        for (protocol, port), totals in ranked[:limit]
    ]
    folded: dict[int, list[int]] = {}
    folded_packets: dict[int, list[int]] = {}
    for (protocol, port), totals in ranked[limit:]:
        rest = folded.setdefault(protocol, [0, 0, 0])
        for index in range(3):
            rest[index] += totals[index]
        packets = window.service_packets.get((protocol, port), [0, 0])
        rest_packets = folded_packets.setdefault(protocol, [0, 0])
        rest_packets[0] += packets[0]
        rest_packets[1] += packets[1]
    rows.extend(
        _row(protocol, OTHER_SERVICE_PORT, totals, folded_packets[protocol])
        for protocol, totals in sorted(folded.items())
    )
    return rows
