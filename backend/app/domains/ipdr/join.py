"""The IPDR join, pure: flow records + guest sessions -> IPDR records.

1. **Stitch**: an ``upload`` flow record keeps source = guest; a
   ``download`` one is mirrored (guest = its destination). Records of one
   router with the same guest address/port, remote address/port and
   protocol are one connection while the gap between them is at most
   ``STITCH_GAP`` (20 s: the routers' 15 s inactive timeout plus slack; a
   long flow is re-exported every 1 m active timeout). Earliest start,
   latest end, summed bytes. Records without a flow time (window start
   only) stitch only within their window. Internal, platform-tunnel and
   unclassified records are not a guest's connections and are dropped.
2. **Match**: the session that held the guest address on that router at the
   connection's start: ``started_at <= t`` and still open or ``ended_at +
   grace >= t``. Several (a stale ACTIVE row and a newer login on the same
   address): the latest start wins -- DHCP gave the address to the newer
   device. None: user ``unknown``, identity blank.
3. **Whole sessions**: allocation start/end and online time are the
   session's own, never clipped to the day, so a session that crosses
   midnight reads the same on both days.
4. **Ambiguity**: a ``derived`` translation is marked ``ambiguous`` when
   masquerade would have had to remap the port (fixed-port protocol, or
   another guest on the router used the same protocol/port/destination at
   the same time).

See DESIGN.md section 2 and NAT-RESEARCH.md sections 4-5.
"""

from __future__ import annotations

import bisect
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from .constants import (
    ALLOCATION_DYNAMIC,
    FIXED_SOURCE_PORT_BELOW,
    FIXED_SOURCE_PORTS,
    STITCH_GAP,
    TRANSLATION_AMBIGUOUS,
    TRANSLATION_DERIVED,
    TS_FROM_FLOW,
    TS_FROM_WINDOW,
    UNKNOWN_USER,
)
from .formatting import is_email, is_phone, normalize_ip, normalize_mac
from .translation import TranslationResolver

UPLOAD = "upload"
DOWNLOAD = "download"


@dataclass(frozen=True, slots=True)
class FlowInput:
    router_id: uuid.UUID
    window_start: datetime
    flow_start: datetime | None
    direction: str
    src_address: str
    src_port: int | None
    dst_address: str
    dst_port: int | None
    protocol: int | None
    nat_src_address: str | None = None
    nat_src_port: int | None = None
    flow_end: datetime | None = None
    bytes: int = 0
    packets: int | None = None
    ports_merged: bool = False


@dataclass(frozen=True, slots=True)
class SessionInput:
    id: uuid.UUID
    guest_id: uuid.UUID
    router_id: uuid.UUID
    ip_address: str | None
    started_at: datetime
    ended_at: datetime | None
    last_activity_at: datetime | None
    identifier: str | None
    display_name: str | None
    email: str | None
    mac_address: str | None


@dataclass(slots=True)
class Connection:
    router_id: uuid.UUID
    window_start: datetime
    ts: datetime
    ts_end: datetime
    ts_source: str
    guest_ip: str
    guest_port: int | None
    remote_ip: str
    remote_port: int | None
    protocol: int | None
    nat_ip: str | None
    nat_port: int | None
    bytes: int
    packets: int | None
    ports_merged: bool


def _aware(moment: datetime) -> datetime:
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)


def _iso(moment: datetime | None) -> str | None:
    if moment is None:
        return None
    return _aware(moment).astimezone(UTC).isoformat(timespec="microseconds")


def _oriented(flow: FlowInput) -> tuple[Any, ...] | None:
    if flow.direction == UPLOAD:
        guest, guest_port = flow.src_address, flow.src_port
        remote, remote_port = flow.dst_address, flow.dst_port
        nat_ip, nat_port = flow.nat_src_address, flow.nat_src_port
    elif flow.direction == DOWNLOAD:
        guest, guest_port = flow.dst_address, flow.dst_port
        remote, remote_port = flow.src_address, flow.src_port
        # A download record's post-NAT source is the outside end's.
        nat_ip, nat_port = None, None
    else:
        return None
    guest_ip, remote_ip = normalize_ip(guest), normalize_ip(remote)
    if guest_ip is None or remote_ip is None:
        return None
    return guest_ip, guest_port, remote_ip, remote_port, nat_ip, nat_port


def fold_connections(
    flows: Iterable[FlowInput], *, gap: timedelta = STITCH_GAP
) -> list[Connection]:
    """Flow records -> connections (step 1 of the module docstring)."""
    pieces: dict[tuple[Any, ...], list[Connection]] = {}
    for flow in flows:
        oriented = _oriented(flow)
        if oriented is None:
            continue
        guest_ip, guest_port, remote_ip, remote_port, nat_ip, nat_port = oriented
        window = _aware(flow.window_start)
        if flow.flow_start is not None:
            ts, source = _aware(flow.flow_start), TS_FROM_FLOW
            ts_end = _aware(flow.flow_end) if flow.flow_end else ts
        else:
            ts, ts_end, source = window, window, TS_FROM_WINDOW
        key = (flow.router_id, guest_ip, guest_port, remote_ip, remote_port)
        key += (flow.protocol,)
        pieces.setdefault(key, []).append(
            Connection(
                router_id=flow.router_id,
                window_start=window,
                ts=ts,
                ts_end=max(ts, ts_end),
                ts_source=source,
                guest_ip=guest_ip,
                guest_port=guest_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                protocol=flow.protocol,
                nat_ip=nat_ip,
                nat_port=nat_port,
                bytes=flow.bytes or 0,
                packets=flow.packets,
                ports_merged=flow.ports_merged,
            )
        )
    out: list[Connection] = []
    for items in pieces.values():
        items.sort(key=lambda c: (c.ts, c.ts_end))
        current = items[0]
        for piece in items[1:]:
            same_window = piece.window_start == current.window_start
            timed = TS_FROM_FLOW in (piece.ts_source, current.ts_source)
            if (timed and piece.ts - current.ts_end <= gap) or (
                not timed and same_window
            ):
                _absorb(current, piece)
            else:
                out.append(current)
                current = piece
        out.append(current)
    return out


def _absorb(into: Connection, piece: Connection) -> None:
    into.ts_end = max(into.ts_end, piece.ts_end)
    if piece.ts_source == TS_FROM_FLOW:
        into.ts_source = TS_FROM_FLOW
    into.bytes += piece.bytes
    if piece.packets is not None:
        into.packets = (into.packets or 0) + piece.packets
    into.ports_merged = into.ports_merged or piece.ports_merged
    if into.nat_ip is None and piece.nat_ip is not None:
        into.nat_ip, into.nat_port = piece.nat_ip, piece.nat_port


class SessionIndex:
    """Sessions by (router, address), sorted by start."""

    def __init__(self, sessions: Iterable[SessionInput], *, grace: timedelta) -> None:
        self._grace = grace
        self._by_key: dict[tuple[uuid.UUID, str], list[SessionInput]] = {}
        for session in sessions:
            ip = normalize_ip(session.ip_address)
            if ip is None:
                continue
            self._by_key.setdefault((session.router_id, ip), []).append(session)
        self._starts: dict[tuple[uuid.UUID, str], list[datetime]] = {}
        for key, items in self._by_key.items():
            items.sort(key=lambda s: (_aware(s.started_at), str(s.id)))
            self._starts[key] = [_aware(s.started_at) for s in items]

    def match(self, router_id: uuid.UUID, ip: str, at: datetime) -> SessionInput | None:
        key = (router_id, ip)
        items = self._by_key.get(key)
        if not items:
            return None
        at = _aware(at)
        # Sessions that started at or before ``at``, newest first.
        upto = bisect.bisect_right(self._starts[key], at)
        for session in reversed(items[:upto]):
            if session.ended_at is None:
                return session
            if _aware(session.ended_at) + self._grace >= at:
                return session
        return None


def _online_seconds(session: SessionInput) -> int | None:
    end = session.ended_at or session.last_activity_at
    if end is None:
        return None
    return max(0, int((_aware(end) - _aware(session.started_at)).total_seconds()))


def _identity(session: SessionInput | None) -> dict[str, Any]:
    if session is None:
        return {
            "user_known": False,
            "user_id": UNKNOWN_USER,
            "name": None,
            "phone": None,
            "alt_phone": None,
            "email": None,
            "mac": None,
            "guest_id": None,
            "session_id": None,
            "alloc_start": None,
            "alloc_end": None,
            "online_seconds": None,
        }
    identifier = (session.identifier or "").strip() or None
    email = (session.email or "").strip() or None
    if email is None and is_email(identifier):
        email = identifier
    return {
        "user_known": True,
        "user_id": identifier or UNKNOWN_USER,
        "name": (session.display_name or "").strip() or None,
        "phone": identifier if is_phone(identifier) else None,
        # Not collected by the platform.
        "alt_phone": None,
        "email": email,
        "mac": normalize_mac(session.mac_address),
        "guest_id": str(session.guest_id),
        "session_id": str(session.id),
        "alloc_start": _iso(session.started_at),
        "alloc_end": _iso(session.ended_at),
        "online_seconds": _online_seconds(session),
    }


def record_key(record: dict[str, Any]) -> str:
    """Deterministic tie-break for rows with the same instant (cursor)."""
    return "|".join(
        str(record.get(name) if record.get(name) is not None else "")
        for name in (
            "location_id",
            "router_id",
            "window_start",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "protocol",
        )
    )


def sort_key(record: dict[str, Any]) -> tuple[str, str]:
    return (record["ts"], record["rk"])


def build_records(
    flows: Iterable[FlowInput],
    sessions: Iterable[SessionInput],
    translator: TranslationResolver,
    *,
    organization_id: uuid.UUID,
    location_id: uuid.UUID,
    grace: timedelta,
    start: datetime | None = None,
    end: datetime | None = None,
) -> list[dict[str, Any]]:
    """IPDR records of one location, newest first. ``start``/``end`` keep
    only connections whose instant is in ``[start, end)``."""
    index = SessionIndex(sessions, grace=grace)
    records: list[dict[str, Any]] = []
    for conn in fold_connections(flows):
        if start is not None and conn.ts < _aware(start):
            continue
        if end is not None and conn.ts >= _aware(end):
            continue
        session = index.match(conn.router_id, conn.guest_ip, conn.ts)
        translation = translator.translate(
            router_id=conn.router_id,
            at=conn.ts,
            src_ip=conn.guest_ip,
            src_port=conn.guest_port,
            nat_ip=conn.nat_ip,
            nat_port=conn.nat_port,
        )
        record: dict[str, Any] = {
            "ts": _iso(conn.ts),
            "ts_end": _iso(conn.ts_end),
            "ts_source": conn.ts_source,
            "window_start": _iso(conn.window_start),
            "organization_id": str(organization_id),
            "location_id": str(location_id),
            "router_id": str(conn.router_id),
            **_identity(session),
            "src_ip": conn.guest_ip,
            "src_port": conn.guest_port,
            "nat_ip": translation.address,
            "nat_port": translation.port,
            "nat_source": translation.source,
            "allocation": ALLOCATION_DYNAMIC,
            "dst_ip": conn.remote_ip,
            "dst_port": conn.remote_port,
            "protocol": conn.protocol,
            "bytes": conn.bytes,
            "packets": conn.packets,
            "ports_merged": conn.ports_merged,
        }
        record["rk"] = record_key(record)
        records.append(record)
    mark_ambiguous(records)
    records.sort(key=sort_key, reverse=True)
    return records


def _fixed_port(port: int | None) -> bool:
    return port is not None and (
        port < FIXED_SOURCE_PORT_BELOW or port in FIXED_SOURCE_PORTS
    )


def mark_ambiguous(records: list[dict[str, Any]], *, gap: timedelta = STITCH_GAP):
    """``derived`` -> ``ambiguous`` where masquerade would have remapped the
    port: a fixed-port source, or two guests of one router on the same
    (protocol, source port, destination, destination port) at once."""
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for record in records:
        if record["nat_source"] != TRANSLATION_DERIVED:
            continue
        if record["src_port"] is None:
            continue
        if _fixed_port(record["src_port"]):
            record["nat_source"] = TRANSLATION_AMBIGUOUS
            continue
        key = (
            record["router_id"],
            record["protocol"],
            record["src_port"],
            record["dst_ip"],
            record["dst_port"],
        )
        groups.setdefault(key, []).append(record)
    for items in groups.values():
        if len({r["src_ip"] for r in items}) < 2:
            continue
        spans = [
            (datetime.fromisoformat(r["ts"]), datetime.fromisoformat(r["ts_end"]), r)
            for r in items
        ]
        for i, (start_a, end_a, a) in enumerate(spans):
            for start_b, end_b, b in spans[i + 1 :]:
                if a["src_ip"] == b["src_ip"]:
                    continue
                if start_a <= end_b + gap and start_b <= end_a + gap:
                    a["nat_source"] = b["nat_source"] = TRANSLATION_AMBIGUOUS
