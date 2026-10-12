"""Traffic flow: ingestion, the Master overview, and the device config path.

Services over one repository, all Master-only:

* :class:`TrafficFlowIngestService` -- one hub window in, rows out.
* :class:`TrafficFlowStatusService` -- every router in the fleet with an
  honest state (``FlowState``), plus collector health.
* :class:`TrafficFlowSummaryService` -- one venue or router over a range:
  totals, timeline, services, devices, destinations.
* :class:`TrafficFlowOverviewService` -- the first Master page's last N
  minutes per router. Kept for that page; new screens use the two above.
* :class:`TrafficFlowDeviceService` -- preview the rendered lines, and
  apply/remove over 8728 with read-back (``dry_run`` by default). A real
  apply or remove is recorded on ``router_traffic_flow_export``, which is
  the per-router switch.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from fastapi import status
from sqlalchemy import and_, delete, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.exceptions import CloudGuestError
from app.core.config import Settings
from app.core.logging import get_logger
from app.domains.guest.models import GuestSession
from app.domains.location.models import Location
from app.domains.organization.models import Organization
from app.domains.rbac.location_scope import LocationScope, enforce_entity_location
from app.domains.router.models import Router
from app.domains.wireguard.constants import PeerStatus
from app.domains.wireguard.models import WireGuardPeer, WireGuardServer

from .constants import (
    CUSTOMER_MIN_DEVICES_FOR_DESTINATIONS,
    DEFAULT_LIST_LIMIT,
    DEFAULT_QUERY_WINDOW_SECONDS,
    DEFAULT_TIMELINE_SERIES,
    MAX_LIST_LIMIT,
    MAX_QUERY_WINDOW_DAYS,
    MAX_TIMELINE_SERIES,
    RETENTION_DAYS,
    SILENT_AFTER_SECONDS,
    STALE_AFTER_SECONDS,
    WINDOW_SECONDS,
    BlockerCode,
    CustomerCollection,
    FlowState,
    RouterFlowState,
    TrafficFlowSource,
)
from .ingest import (
    attribute_talkers,
    reduce_window,
    service_rows,
    top_destinations,
    top_talkers,
)
from .models import (
    RouterTrafficFlowExport,
    TrafficFlowIngestState,
    TrafficFlowServiceBucket,
    TrafficFlowWindow,
)
from .routeros import (
    TrafficFlowTarget,
    desired_config,
    disabled_config,
    render_removal_lines,
    render_traffic_flow_lines,
    routeros_major_version,
    target_identity,
    traffic_flow_target_for,
)
from .summary import (
    ServiceStepRow,
    build_summary,
    empty_summary,
    timeline_step_seconds,
)

logger = get_logger(__name__)

__all__ = [
    "TrafficFlowDeviceService",
    "TrafficFlowError",
    "TrafficFlowIngestService",
    "TrafficFlowCustomerService",
    "TrafficFlowOverviewService",
    "TrafficFlowRepository",
    "TrafficFlowStatusService",
    "TrafficFlowSummaryService",
    "flow_state",
    "traffic_flow_target_for",
]

#: Entries shown per list in the overview.
OVERVIEW_TOP_N = 10


class TrafficFlowError(CloudGuestError):
    def __init__(self, message: str, *, code: str, status_code: int) -> None:
        super().__init__(message, status_code=status_code, data={"code": code})
        self.code = code


# ---------------------------------------------------------------------------
# repository
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ExporterRouter:
    router_id: uuid.UUID
    organization_id: uuid.UUID | None
    location_id: uuid.UUID | None


@dataclass(frozen=True, slots=True)
class FleetRouter:
    """One router as the fleet status lists it, with its export row."""

    router_id: uuid.UUID
    router_name: str | None
    vendor: str | None
    organization_id: uuid.UUID | None
    organization_name: str | None
    location_id: uuid.UUID | None
    location_name: str | None
    export: RouterTrafficFlowExport | None


@dataclass(frozen=True, slots=True)
class RouterActivity:
    """What is held for one router, and how much arrived recently."""

    newest_window_start: datetime
    newest_window_seconds: int
    windows_recent: int
    bytes_recent: int


@dataclass(frozen=True, slots=True)
class SummaryScope:
    router_id: uuid.UUID | None = None
    location_id: uuid.UUID | None = None

    def conditions(self, model: Any) -> list[Any]:
        out: list[Any] = []
        if self.router_id is not None:
            out.append(model.router_id == self.router_id)
        if self.location_id is not None:
            out.append(model.location_id == self.location_id)
        return out


def service_step_statement(
    scope: SummaryScope, *, since: datetime, until: datetime, step_seconds: int
) -> Any:
    """Service buckets in range, summed per (timeline step, protocol, remote
    port). The step is the epoch floor, the same grid
    ``summary.step_start_of`` uses for windows."""
    bucket = TrafficFlowServiceBucket
    step = func.to_timestamp(
        func.floor(func.extract("epoch", bucket.window_start) / step_seconds)
        * step_seconds
    ).label("step_start")
    return (
        select(
            step,
            bucket.protocol,
            bucket.remote_port,
            func.coalesce(func.sum(bucket.bytes_up), 0),
            func.coalesce(func.sum(bucket.bytes_down), 0),
            func.coalesce(func.sum(bucket.flows), 0),
        )
        .where(
            bucket.window_start >= since,
            bucket.window_start < until,
            *scope.conditions(bucket),
        )
        .group_by(step, bucket.protocol, bucket.remote_port)
    )


def router_activity_statement(recent_since: datetime) -> Any:
    window = TrafficFlowWindow
    recent = window.window_start >= recent_since
    return select(
        window.router_id,
        func.max(window.window_start),
        func.max(window.window_seconds),
        func.count().filter(recent),
        func.coalesce(func.sum(window.bytes_up + window.bytes_down).filter(recent), 0),
    ).group_by(window.router_id)


def service_bucket_insert_statement(rows: list[dict[str, Any]]) -> Any:
    return (
        pg_insert(TrafficFlowServiceBucket)
        .values(rows)
        .on_conflict_do_nothing(constraint="uq_traffic_flow_service_buckets_key")
    )


class TrafficFlowRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # -- per-router switch ----------------------------------------------
    async def get_export(self, router_id: uuid.UUID) -> RouterTrafficFlowExport | None:
        return (
            await self.session.execute(
                select(RouterTrafficFlowExport).where(
                    RouterTrafficFlowExport.router_id == router_id,
                    RouterTrafficFlowExport.is_deleted.is_(False),
                )
            )
        ).scalar_one_or_none()

    async def save_export(
        self, row: RouterTrafficFlowExport
    ) -> RouterTrafficFlowExport:
        self.session.add(row)
        await self.session.flush()
        return row

    async def export_enabled(self, router_id: uuid.UUID) -> bool:
        row = await self.get_export(router_id)
        return bool(row is not None and row.enabled)

    async def enabled_export_router_ids(self) -> set[uuid.UUID]:
        stmt = select(RouterTrafficFlowExport.router_id).where(
            RouterTrafficFlowExport.enabled.is_(True),
            RouterTrafficFlowExport.is_deleted.is_(False),
        )
        return set((await self.session.execute(stmt)).scalars().all())

    # -- fleet status -----------------------------------------------------
    async def fleet_routers(
        self,
        router_id: uuid.UUID | None = None,
        *,
        location_id: uuid.UUID | None = None,
    ) -> list[FleetRouter]:
        """Every live router (or just one, or one venue's), with names and
        its export row."""
        stmt = (
            select(
                Router.id,
                Router.name,
                Router.vendor,
                Router.organization_id,
                Organization.name,
                Router.location_id,
                Location.name,
                RouterTrafficFlowExport,
            )
            .outerjoin(Location, Location.id == Router.location_id)
            .outerjoin(Organization, Organization.id == Router.organization_id)
            .outerjoin(
                RouterTrafficFlowExport,
                and_(
                    RouterTrafficFlowExport.router_id == Router.id,
                    RouterTrafficFlowExport.is_deleted.is_(False),
                ),
            )
            .where(Router.is_deleted.is_(False))
            .order_by(Organization.name, Location.name, Router.name)
        )
        if router_id is not None:
            stmt = stmt.where(Router.id == router_id)
        if location_id is not None:
            stmt = stmt.where(Router.location_id == location_id)
        return [FleetRouter(*row) for row in (await self.session.execute(stmt)).all()]

    async def router_activity(
        self, recent_since: datetime
    ) -> dict[uuid.UUID, RouterActivity]:
        stmt = router_activity_statement(recent_since)
        rows = (await self.session.execute(stmt)).all()
        return {
            rid: RouterActivity(newest, int(seconds), int(count), int(nbytes))
            for rid, newest, seconds, count, nbytes in rows
        }

    # -- summary ----------------------------------------------------------
    async def windows_in_range(
        self, scope: SummaryScope, *, since: datetime, until: datetime
    ) -> list[TrafficFlowWindow]:
        stmt = (
            select(TrafficFlowWindow)
            .where(
                TrafficFlowWindow.window_start >= since,
                TrafficFlowWindow.window_start < until,
                *scope.conditions(TrafficFlowWindow),
            )
            .order_by(TrafficFlowWindow.window_start)
        )
        return list((await self.session.execute(stmt)).scalars().all())

    async def data_bounds(
        self, scope: SummaryScope
    ) -> tuple[datetime | None, datetime | None]:
        stmt = select(
            func.min(TrafficFlowWindow.window_start),
            func.max(TrafficFlowWindow.window_start),
        ).where(*scope.conditions(TrafficFlowWindow))
        oldest, newest = (await self.session.execute(stmt)).one()
        return oldest, newest

    async def service_steps(
        self,
        scope: SummaryScope,
        *,
        since: datetime,
        until: datetime,
        step_seconds: int,
    ) -> list[ServiceStepRow]:
        stmt = service_step_statement(
            scope, since=since, until=until, step_seconds=step_seconds
        )
        return [
            ServiceStepRow(step, int(protocol), int(port), int(up), int(down), int(n))
            for step, protocol, port, up, down, n in (
                await self.session.execute(stmt)
            ).all()
        ]

    async def insert_service_buckets(self, rows: list[dict[str, Any]]) -> None:
        if rows:
            await self.session.execute(service_bucket_insert_statement(rows))

    async def delete_service_buckets_before(
        self, cutoff: datetime, *, limit: int
    ) -> int:
        """Retention, bounded like ``delete_windows_before``."""
        ids = (
            select(TrafficFlowServiceBucket.id)
            .where(TrafficFlowServiceBucket.window_start < cutoff)
            .limit(limit)
            .scalar_subquery()
        )
        result = await self.session.execute(
            delete(TrafficFlowServiceBucket).where(TrafficFlowServiceBucket.id.in_(ids))
        )
        return int(result.rowcount or 0)

    async def exporter_router_map(self) -> dict[str, ExporterRouter]:
        """Tunnel address -> router, for every non-revoked peer. A tunnel
        address is unique per hub; the fleet has one hub."""
        stmt = (
            select(
                WireGuardPeer.tunnel_ip_address,
                Router.id,
                Router.organization_id,
                Router.location_id,
            )
            .join(Router, Router.id == WireGuardPeer.router_id)
            .where(WireGuardPeer.status != PeerStatus.REVOKED.value)
            .where(Router.is_deleted.is_(False))
        )
        rows = (await self.session.execute(stmt)).all()
        return {
            str(ip): ExporterRouter(router_id=rid, organization_id=org, location_id=loc)
            for ip, rid, org, loc in rows
        }

    async def sessions_by_ip(
        self,
        router_id: uuid.UUID,
        ips: Iterable[str],
        *,
        start: datetime,
        end: datetime,
    ) -> dict[str, list[uuid.UUID]]:
        wanted = sorted(set(ips))
        if not wanted:
            return {}
        stmt = select(GuestSession.ip_address, GuestSession.id).where(
            GuestSession.router_id == router_id,
            GuestSession.ip_address.in_(wanted),
            GuestSession.started_at < end,
            or_(GuestSession.ended_at.is_(None), GuestSession.ended_at >= start),
            GuestSession.is_deleted.is_(False),
        )
        out: dict[str, list[uuid.UUID]] = {}
        for ip, session_id in (await self.session.execute(stmt)).all():
            out.setdefault(str(ip), []).append(session_id)
        return out

    async def insert_window(self, values: Mapping[str, Any]) -> bool:
        """ON CONFLICT DO NOTHING on (router, source, window_start). Returns
        whether a row was written."""
        stmt = (
            pg_insert(TrafficFlowWindow)
            .values(id=uuid.uuid4(), **values)
            .on_conflict_do_nothing(constraint="uq_traffic_flow_windows_router_window")
            .returning(TrafficFlowWindow.id)
        )
        result = await self.session.execute(stmt)
        return result.first() is not None

    async def delete_windows_before(self, cutoff: datetime, *, limit: int) -> int:
        """Retention: delete at most ``limit`` windows older than ``cutoff``
        (bounded, so the sweep never holds a long lock on the shared box)."""
        ids = (
            select(TrafficFlowWindow.id)
            .where(TrafficFlowWindow.window_start < cutoff)
            .limit(limit)
            .scalar_subquery()
        )
        result = await self.session.execute(
            delete(TrafficFlowWindow).where(TrafficFlowWindow.id.in_(ids))
        )
        return int(result.rowcount or 0)

    async def get_state(self) -> TrafficFlowIngestState:
        state = await self.session.get(TrafficFlowIngestState, 1)
        if state is None:
            state = TrafficFlowIngestState(id=1, unknown_exporters=[])
            self.session.add(state)
        return state

    async def windows_since(self, since: datetime) -> list[TrafficFlowWindow]:
        stmt = (
            select(TrafficFlowWindow)
            .where(TrafficFlowWindow.window_start >= since)
            .order_by(TrafficFlowWindow.window_start)
        )
        return list((await self.session.execute(stmt)).scalars().all())

    async def router_labels(
        self, router_ids: Iterable[uuid.UUID]
    ) -> dict[uuid.UUID, dict[str, Any]]:
        ids = list(set(router_ids))
        if not ids:
            return {}
        stmt = (
            select(
                Router.id,
                Router.name,
                Router.vendor,
                Location.name,
                Organization.name,
            )
            .outerjoin(Location, Location.id == Router.location_id)
            .outerjoin(Organization, Organization.id == Router.organization_id)
            .where(Router.id.in_(ids))
        )
        return {
            rid: {
                "router_name": rname,
                "vendor": vendor,
                "location_name": lname,
                "organization_name": oname,
            }
            for rid, rname, vendor, lname, oname in (
                await self.session.execute(stmt)
            ).all()
        }

    async def peer_and_server(
        self, router_id: uuid.UUID
    ) -> tuple[WireGuardPeer | None, WireGuardServer | None]:
        peer = (
            await self.session.execute(
                select(WireGuardPeer).where(
                    and_(
                        WireGuardPeer.router_id == router_id,
                        WireGuardPeer.status != PeerStatus.REVOKED.value,
                    )
                )
            )
        ).scalar_one_or_none()
        if peer is None:
            return None, None
        server = await self.session.get(WireGuardServer, peer.server_id)
        return peer, server


# ---------------------------------------------------------------------------
# ingest
# ---------------------------------------------------------------------------


@dataclass
class WindowIngestSummary:
    window_start: datetime
    exporters: int = 0
    written: int = 0
    duplicates: int = 0
    unknown_exporters: tuple[str, ...] = ()
    rows_rejected: int = 0


class TrafficFlowIngestService:
    def __init__(self, repository: TrafficFlowRepository) -> None:
        self.repository = repository

    async def ingest_window(
        self,
        *,
        window_start: datetime,
        window_seconds: int,
        rows: Iterable[Mapping[str, Any]],
        exporter_map: Mapping[str, ExporterRouter] | None = None,
    ) -> WindowIngestSummary:
        if exporter_map is None:
            exporter_map = await self.repository.exporter_router_map()
        window_end = window_start + timedelta(seconds=window_seconds)
        summary = WindowIngestSummary(window_start=window_start)
        unknown: list[str] = []
        for exporter, reduced in reduce_window(rows).items():
            summary.exporters += 1
            summary.rows_rejected += reduced.rows_rejected
            router = exporter_map.get(exporter)
            if router is None:
                unknown.append(exporter)
                continue
            sessions = await self.repository.sessions_by_ip(
                router.router_id,
                reduced.talkers.keys(),
                start=window_start,
                end=window_end,
            )
            attribution = attribute_talkers(reduced.talkers.keys(), sessions)
            talkers, other_talkers = top_talkers(reduced, attribution)
            destinations, other_destinations = top_destinations(reduced)
            identity = {
                "router_id": router.router_id,
                "organization_id": router.organization_id,
                "location_id": router.location_id,
                "source": TrafficFlowSource.MIKROTIK_IPFIX.value,
                "window_start": window_start,
                "window_seconds": window_seconds,
            }
            written = await self.repository.insert_window(
                {
                    **identity,
                    "exporter_address": exporter,
                    "bytes_total": reduced.bytes_total,
                    "bytes_up": reduced.bytes_up,
                    "bytes_down": reduced.bytes_down,
                    "services_measured": reduced.services_measured,
                    "packets_total": reduced.packets_total,
                    "flows_total": reduced.flows_total,
                    "bytes_internal": reduced.bytes_internal,
                    "bytes_unclassified": reduced.bytes_unclassified,
                    "bytes_other_talkers": other_talkers,
                    "bytes_other_destinations": other_destinations,
                    "talker_count": len(reduced.talkers),
                    "destination_count": len(reduced.destinations),
                    "top_talkers": talkers,
                    "top_destinations": destinations,
                    "received_at": datetime.now(UTC),
                }
            )
            if written:
                summary.written += 1
                # Only with a NEW window row: a re-pulled window must not
                # add service rows a second time. (The table's own unique
                # key would refuse them too.)
                await self.repository.insert_service_buckets(
                    [{**identity, **row} for row in service_rows(reduced)]
                )
            else:
                summary.duplicates += 1
        summary.unknown_exporters = tuple(sorted(unknown))
        return summary


# ---------------------------------------------------------------------------
# overview
# ---------------------------------------------------------------------------


def _merge_windows(windows: list[TrafficFlowWindow]) -> dict[str, Any]:
    """Sum stored per-window top-N lists. Approximate by construction: an
    address that was just outside the top N in every window is missed --
    the response says so (``approximate: true``)."""
    talkers: dict[str, dict[str, Any]] = {}
    destinations: dict[str, dict[str, Any]] = {}
    totals = {
        "bytes_total": 0,
        "flows_total": 0,
        "bytes_internal": 0,
        "bytes_unclassified": 0,
    }
    for window in windows:
        for key in totals:
            totals[key] += int(getattr(window, key) or 0)
        for entry in window.top_talkers or []:
            ip = str(entry.get("ip"))
            merged = talkers.setdefault(
                ip,
                {
                    "ip": ip,
                    "bytes_up": 0,
                    "bytes_down": 0,
                    "flows": 0,
                    "sessions": set(),
                    "matches": set(),
                },
            )
            merged["bytes_up"] += int(entry.get("bytes_up") or 0)
            merged["bytes_down"] += int(entry.get("bytes_down") or 0)
            merged["flows"] += int(entry.get("flows") or 0)
            merged["matches"].add(str(entry.get("match") or "none"))
            if entry.get("guest_session_id"):
                merged["sessions"].add(str(entry["guest_session_id"]))
        for entry in window.top_destinations or []:
            ip = str(entry.get("ip"))
            merged_dest = destinations.setdefault(
                ip, {"ip": ip, "bytes": 0, "flows": 0}
            )
            merged_dest["bytes"] += int(entry.get("bytes") or 0)
            merged_dest["flows"] += int(entry.get("flows") or 0)

    talker_list: list[dict[str, Any]] = []
    for merged in talkers.values():
        sessions = sorted(merged.pop("sessions"))
        matches = merged.pop("matches")
        if len(sessions) == 1 and matches == {"session"}:
            merged["match"], merged["guest_session_id"] = "session", sessions[0]
        elif sessions or "ambiguous" in matches:
            # The IP belonged to different sessions across the period.
            merged["match"], merged["guest_session_id"] = "ambiguous", None
        else:
            merged["match"], merged["guest_session_id"] = "none", None
        talker_list.append(merged)
    talker_list.sort(key=lambda t: (-(t["bytes_up"] + t["bytes_down"]), t["ip"]))
    dest_list = sorted(destinations.values(), key=lambda d: (-d["bytes"], d["ip"]))
    return {
        **totals,
        "talkers": talker_list[:OVERVIEW_TOP_N],
        "destinations": dest_list[:OVERVIEW_TOP_N],
    }


class TrafficFlowOverviewService:
    def __init__(
        self,
        repository: TrafficFlowRepository,
        settings: Settings,
        *,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.repository = repository
        self.settings = settings
        self.now = now

    async def overview(self, *, minutes: int) -> dict[str, Any]:
        now = self.now()
        since = now - timedelta(minutes=minutes)
        windows = await self.repository.windows_since(since)
        state = await self.repository.get_state()
        # The per-router switch (it used to be an environment allowlist; the
        # response key keeps its name for the page already built on it).
        allowlist = await self.repository.enabled_export_router_ids()

        by_router: dict[uuid.UUID, list[TrafficFlowWindow]] = {}
        for window in windows:
            by_router.setdefault(window.router_id, []).append(window)
        router_ids = set(by_router) | set(allowlist)
        labels = await self.repository.router_labels(router_ids)

        pull_failed = state.last_pull_ok is False
        routers: list[dict[str, Any]] = []
        for router_id in sorted(router_ids, key=str):
            router_windows = by_router.get(router_id, [])
            newest = max((w.window_start for w in router_windows), default=None)
            allowlisted = router_id in allowlist
            if not self.settings.traffic_flow_enabled:
                router_state = RouterFlowState.DISABLED
            elif router_windows and not allowlisted:
                router_state = RouterFlowState.NOT_ALLOWLISTED
            elif pull_failed:
                router_state = RouterFlowState.COLLECTOR_UNREACHABLE
            elif newest is None:
                router_state = RouterFlowState.NO_WINDOWS
            elif (
                now - (newest + timedelta(seconds=WINDOW_SECONDS))
            ).total_seconds() > (STALE_AFTER_SECONDS):
                router_state = RouterFlowState.STALE
            else:
                router_state = RouterFlowState.OK
            label = labels.get(router_id, {})
            routers.append(
                {
                    "router_id": str(router_id),
                    "router_name": label.get("router_name"),
                    "vendor": label.get("vendor"),
                    "location_name": label.get("location_name"),
                    "organization_name": label.get("organization_name"),
                    "allowlisted": allowlisted,
                    "state": router_state.value,
                    "windows": len(router_windows),
                    "newest_window_start": newest.isoformat() if newest else None,
                    "source": TrafficFlowSource.MIKROTIK_IPFIX.value,
                    "approximate": True,
                    **_merge_windows(router_windows),
                }
            )
        return {
            "enabled": self.settings.traffic_flow_enabled,
            "agent_configured": bool(
                self.settings.traffic_flow_agent_url
                and self.settings.traffic_flow_agent_secret
            ),
            "period_minutes": minutes,
            "generated_at": now.isoformat(),
            "window_seconds": WINDOW_SECONDS,
            "last_pull_at": state.last_pull_at.isoformat()
            if state.last_pull_at
            else None,
            "last_pull_ok": state.last_pull_ok,
            "last_error": state.last_error,
            "last_window_start": (
                state.last_window_start.isoformat() if state.last_window_start else None
            ),
            "unknown_exporters": list(state.unknown_exporters or []),
            "routers": routers,
        }


# ---------------------------------------------------------------------------
# fleet status
# ---------------------------------------------------------------------------


def _is_mikrotik(vendor: str | None) -> bool:
    return (vendor or "").lower() == "mikrotik"


def flow_state(
    *,
    feature_enabled: bool,
    vendor: str | None,
    configured: bool,
    newest_window_end: datetime | None,
    now: datetime,
) -> FlowState:
    """Most-blocking first. Data decides between receiving and silent; the
    switch only decides what "no data" means -- a router that was switched on
    and has sent nothing is unknown, not quiet."""
    if not feature_enabled:
        return FlowState.FEATURE_OFF
    if not _is_mikrotik(vendor):
        return FlowState.UNSUPPORTED_VENDOR
    if newest_window_end is None:
        return FlowState.AWAITING_FIRST_DATA if configured else FlowState.NOT_CONFIGURED
    if (now - newest_window_end).total_seconds() >= SILENT_AFTER_SECONDS:
        return FlowState.SILENT
    return FlowState.RECEIVING


def _iso(moment: datetime | None) -> str | None:
    return moment.isoformat() if moment else None


def _id(value: uuid.UUID | None) -> str | None:
    return str(value) if value is not None else None


def status_row(
    router: FleetRouter,
    activity: RouterActivity | None,
    *,
    feature_enabled: bool,
    now: datetime,
) -> dict[str, Any]:
    export = router.export
    configured = bool(export is not None and export.enabled)
    newest_start = activity.newest_window_start if activity else None
    newest_end = (
        newest_start + timedelta(seconds=activity.newest_window_seconds)
        if activity and newest_start
        else None
    )
    return {
        "router_id": str(router.router_id),
        "router_name": router.router_name,
        "organization_id": _id(router.organization_id),
        "organization_name": router.organization_name,
        "location_id": _id(router.location_id),
        "location_name": router.location_name,
        "vendor": router.vendor,
        "state": flow_state(
            feature_enabled=feature_enabled,
            vendor=router.vendor,
            configured=configured,
            newest_window_end=newest_end,
            now=now,
        ).value,
        "configured": configured,
        "configured_at": _iso(export.configured_at) if export else None,
        "last_verified_at": _iso(export.last_verified_at) if export else None,
        "last_verdict_ok": export.last_verdict_ok if export else None,
        "last_verdict_detail": export.last_verdict_detail if export else None,
        "last_window_start": _iso(newest_start),
        "last_window_end": _iso(newest_end),
        "windows_last_hour": activity.windows_recent if activity else 0,
        "bytes_last_hour": activity.bytes_recent if activity else 0,
    }


class TrafficFlowStatusService:
    def __init__(
        self,
        repository: TrafficFlowRepository,
        settings: Settings,
        *,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.repository = repository
        self.settings = settings
        self.now = now

    async def router_status(self, router_id: uuid.UUID) -> dict[str, Any] | None:
        now = self.now()
        routers = await self.repository.fleet_routers(router_id)
        if not routers:
            return None
        activity = await self.repository.router_activity(now - timedelta(hours=1))
        return status_row(
            routers[0],
            activity.get(router_id),
            feature_enabled=bool(self.settings.traffic_flow_enabled),
            now=now,
        )

    async def status(self) -> dict[str, Any]:
        now = self.now()
        enabled = bool(self.settings.traffic_flow_enabled)
        routers = await self.repository.fleet_routers()
        activity = await self.repository.router_activity(now - timedelta(hours=1))
        state = await self.repository.get_state()
        return {
            "feature_enabled": enabled,
            "generated_at": now.isoformat(),
            "window_seconds": WINDOW_SECONDS,
            "silent_after_seconds": SILENT_AFTER_SECONDS,
            "collector": {
                "agent_configured": bool(
                    self.settings.traffic_flow_agent_url
                    and self.settings.traffic_flow_agent_secret
                ),
                "last_pull_at": _iso(state.last_pull_at),
                "last_pull_ok": state.last_pull_ok,
                "last_error": state.last_error,
                "last_window_start": _iso(state.last_window_start),
                "unknown_exporters": list(state.unknown_exporters or []),
            },
            "routers": [
                status_row(
                    router,
                    activity.get(router.router_id),
                    feature_enabled=enabled,
                    now=now,
                )
                for router in routers
            ],
        }


# ---------------------------------------------------------------------------
# venue summary
# ---------------------------------------------------------------------------


def _aware(moment: datetime) -> datetime:
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)


class TrafficFlowSummaryService:
    def __init__(
        self,
        repository: TrafficFlowRepository,
        settings: Settings,
        *,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.repository = repository
        self.settings = settings
        self.now = now

    async def summary(
        self,
        *,
        router_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        since: datetime | None,
        until: datetime | None,
        limit: int | None = None,
        series: int | None = None,
        min_devices_for_destinations: int = 0,
    ) -> dict[str, Any]:
        if router_id is None and location_id is None:
            # A fleet-wide list would merge the same private address at two
            # venues into one "device".
            raise TrafficFlowError(
                "Give a router_id or a location_id.",
                code="TRAFFIC_FLOW_SCOPE_REQUIRED",
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )
        until = _aware(until) if until else self.now()
        since = (
            _aware(since)
            if since
            else until - timedelta(seconds=DEFAULT_QUERY_WINDOW_SECONDS)
        )
        if since >= until:
            raise TrafficFlowError(
                "since must be before until.",
                code="TRAFFIC_FLOW_BAD_RANGE",
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )
        if until - since > timedelta(days=MAX_QUERY_WINDOW_DAYS):
            # Refused, not clamped: a silently shortened range would be read
            # as the whole range that was asked for.
            raise TrafficFlowError(
                f"The range may not be longer than {MAX_QUERY_WINDOW_DAYS} days.",
                code="TRAFFIC_FLOW_WINDOW_TOO_LARGE",
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )
        size = max(1, min(limit or DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT))
        bands = max(1, min(series or DEFAULT_TIMELINE_SERIES, MAX_TIMELINE_SERIES))
        step_seconds = timeline_step_seconds((until - since).total_seconds())
        if not self.settings.traffic_flow_enabled:
            # Not a query that comes back empty and reads as "no traffic".
            return empty_summary(
                feature_enabled=False,
                since=since,
                until=until,
                window_seconds=WINDOW_SECONDS,
                step_seconds=step_seconds,
                data_oldest=None,
                data_newest=None,
            )
        scope = SummaryScope(router_id=router_id, location_id=location_id)
        oldest, newest = await self.repository.data_bounds(scope)
        windows = await self.repository.windows_in_range(
            scope, since=since, until=until
        )
        rows = (
            await self.repository.service_steps(
                scope, since=since, until=until, step_seconds=step_seconds
            )
            if windows
            else []
        )
        return build_summary(
            windows=windows,
            service_rows=rows,
            since=since,
            until=until,
            window_seconds=WINDOW_SECONDS,
            step_seconds=step_seconds,
            limit=size,
            series=bands,
            data_oldest=oldest,
            data_newest=newest,
            min_devices_for_destinations=min_devices_for_destinations,
        )


# ---------------------------------------------------------------------------
# customer view (one venue, the caller's own)
# ---------------------------------------------------------------------------


class TrafficFlowLocationNotFoundError(CloudGuestError):
    """One answer for "no such venue" and "another organization's venue": a
    customer route must not confirm that somebody else's venue exists."""

    def __init__(self, location_id: uuid.UUID) -> None:
        super().__init__(
            f"Location not found: {location_id}",
            status_code=status.HTTP_404_NOT_FOUND,
            data={"code": "TRAFFIC_FLOW_LOCATION_NOT_FOUND"},
        )


class TrafficFlowCrossLocationError(CloudGuestError):
    def __init__(self) -> None:
        super().__init__(
            "You can only view traffic for your own venues.",
            status_code=status.HTTP_403_FORBIDDEN,
            data={"code": "TRAFFIC_FLOW_CROSS_LOCATION"},
        )


class LocationLookup(Protocol):
    async def get_location(
        self,
        location_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> Any: ...


#: The device fields a customer gets: the local address (as Connected
#: Devices shows it), volumes, and a reference to the guest session when
#: there is exactly one. No name, phone number, MAC or host name -- those
#: stay behind the screens and permissions that already own them.
_CUSTOMER_DEVICE_FIELDS = (
    "router_id",
    "ip",
    "bytes_up",
    "bytes_down",
    "bytes",
    "flows",
    "share_at_least",
    "match",
    "guest_session_id",
)


def customer_collection(states: Iterable[str]) -> CustomerCollection:
    """Fold the venue's per-router states into the three a customer sees."""
    states = list(states)
    if FlowState.RECEIVING.value in states:
        return CustomerCollection.COLLECTING
    if any(state != FlowState.UNSUPPORTED_VENDOR.value for state in states):
        return CustomerCollection.NOT_COLLECTING_YET
    # No router at all, or none that can report traffic.
    return CustomerCollection.NOT_AVAILABLE


class TrafficFlowCustomerService:
    """Read-only venue view for the customer dashboard.

    Three things make a response safe to hand to a customer, and each is
    done here rather than left to a route:

    * **Whose venue.** ``organization_id`` is the caller's organization as
      the request context resolved it -- never a path or body value. The
      venue is loaded and checked against it, then against the caller's
      location grants (``caller_location_scope``, injected at construction
      so no method can forget it). Every read below is then filtered on that
      *loaded* venue's id.
    * **What is in it.** Only the summary's own figures, the three-value
      collection state and two timestamps. No exporter or tunnel address, no
      verdict, no switch state, no collector health.
    * **Privacy.** Devices, destinations and services stay three independent
      lists, a device is an address plus at most a session reference, and
      destinations are withheld for windows with too few devices.
    """

    def __init__(
        self,
        repository: TrafficFlowRepository,
        location_lookup: LocationLookup,
        settings: Settings,
        *,
        caller_location_scope: LocationScope = None,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.repository = repository
        self.location_lookup = location_lookup
        self.settings = settings
        self.caller_location_scope = caller_location_scope
        self.now = now
        self._status = TrafficFlowStatusService(repository, settings, now=now)
        self._summary = TrafficFlowSummaryService(repository, settings, now=now)

    async def _own_location(
        self, location_id: uuid.UUID, organization_id: uuid.UUID
    ) -> uuid.UUID:
        """The id of the venue, once it is known to be the caller's."""
        try:
            location = await self.location_lookup.get_location(
                location_id, requesting_organization_id=organization_id
            )
        except CloudGuestError as exc:
            raise TrafficFlowLocationNotFoundError(location_id) from exc
        # Checked again here, on the loaded row, whatever the lookup did:
        # this comparison is the tenant boundary for everything below.
        if location is None or location.organization_id != organization_id:
            raise TrafficFlowLocationNotFoundError(location_id)
        enforce_entity_location(
            entity_location_id=location.id,
            caller_location_scope=self.caller_location_scope,
            error=TrafficFlowCrossLocationError(),
        )
        return location.id

    async def _collection(self, location_id: uuid.UUID) -> dict[str, Any]:
        now = self.now()
        routers = await self.repository.fleet_routers(location_id=location_id)
        activity = await self.repository.router_activity(now - timedelta(hours=1))
        rows = [
            status_row(
                router,
                activity.get(router.router_id),
                feature_enabled=bool(self.settings.traffic_flow_enabled),
                now=now,
            )
            for router in routers
        ]
        oldest, newest = await self.repository.data_bounds(
            SummaryScope(location_id=location_id)
        )
        return {
            "location_id": str(location_id),
            "collection": customer_collection(row["state"] for row in rows).value,
            "latest_data": _iso(newest + timedelta(seconds=WINDOW_SECONDS))
            if newest
            else None,
            "data_starts": _iso(oldest),
        }

    async def status(
        self, location_id: uuid.UUID, *, organization_id: uuid.UUID
    ) -> dict[str, Any]:
        own = await self._own_location(location_id, organization_id)
        return {
            **await self._collection(own),
            "window_seconds": WINDOW_SECONDS,
            "retention_days": RETENTION_DAYS,
        }

    async def summary(
        self,
        location_id: uuid.UUID,
        *,
        organization_id: uuid.UUID,
        since: datetime | None,
        until: datetime | None,
        limit: int | None = None,
        series: int | None = None,
        router_id: uuid.UUID | None = None,
    ) -> dict[str, Any]:
        own = await self._own_location(location_id, organization_id)
        # ``location_id=own`` is always part of the filter. A ``router_id``
        # only narrows within it: a router of another venue, or of another
        # organization, matches no row.
        data = await self._summary.summary(
            router_id=router_id,
            location_id=own,
            since=since,
            until=until,
            limit=limit,
            series=series,
            min_devices_for_destinations=CUSTOMER_MIN_DEVICES_FOR_DESTINATIONS,
        )
        collection = await self._collection(own)
        data.pop("feature_enabled", None)
        data["devices"] = {
            **data["devices"],
            "items": [
                {key: item.get(key) for key in _CUSTOMER_DEVICE_FIELDS}
                for item in data["devices"]["items"]
            ],
        }
        if "min_devices" not in data["destinations"]:
            # The not-measured shape: nothing was withheld because nothing
            # was there, but the keys are always present for the customer.
            data["destinations"] = {
                "min_devices": CUSTOMER_MIN_DEVICES_FOR_DESTINATIONS,
                "windows_withheld": 0,
                **data["destinations"],
            }
        return {
            "location_id": collection["location_id"],
            "collection": collection["collection"],
            "latest_data": collection["latest_data"],
            **data,
        }


# ---------------------------------------------------------------------------
# device config path
# ---------------------------------------------------------------------------


class _Adapter(Protocol):
    async def read_traffic_flow(
        self, creds: Any, *, identity: Mapping[str, str] | None
    ) -> Any: ...

    async def apply_traffic_flow(self, creds: Any, config: Any) -> Any: ...


class RouterLookup(Protocol):
    async def get_router(self, router_id: uuid.UUID) -> Router: ...

    def get_decrypted_api_secret(self, router: Router) -> str | None: ...


class AuditWriter(Protocol):
    async def create_audit_log_entry(self, **kwargs: Any) -> Any: ...


def _state_dict(state: Any) -> dict[str, Any]:
    return {
        "routeros_version": state.routeros_version,
        "settings": dict(state.settings),
        "ipfix": dict(state.ipfix),
        "targets": [dict(t) for t in state.targets],
        "foreign_targets": state.foreign_targets,
    }


#: Blockers that do not stop a removal: switching export OFF needs no tunnel.
_REMOVAL_IGNORES = frozenset({BlockerCode.NO_TUNNEL})


class TrafficFlowDeviceService:
    def __init__(
        self,
        repository: TrafficFlowRepository,
        router_lookup: RouterLookup,
        settings: Settings,
        *,
        adapter_factory: Callable[[], _Adapter],
        credentials_factory: Callable[[Router, str], Any],
        audit_writer: AuditWriter | None = None,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.repository = repository
        self.router_lookup = router_lookup
        self.settings = settings
        self.adapter_factory = adapter_factory
        self.credentials_factory = credentials_factory
        self.audit_writer = audit_writer
        self.now = now
        self._status = TrafficFlowStatusService(repository, settings, now=now)

    def _has_credentials(self, router: Router) -> bool:
        host = router.management_ip_address or router.public_ip_address
        return bool(
            host
            and router.api_username
            and self.router_lookup.get_decrypted_api_secret(router)
        )

    def _blockers(
        self, router: Router, target: TrafficFlowTarget | None
    ) -> list[tuple[BlockerCode, str]]:
        """Why export cannot be written to this router, credentials aside."""
        reasons: list[tuple[BlockerCode, str]] = []
        if not self.settings.traffic_flow_enabled:
            reasons.append(
                (BlockerCode.FEATURE_OFF, "CLOUDGUEST_TRAFFIC_FLOW_ENABLED is off")
            )
        if not _is_mikrotik(router.vendor):
            reasons.append(
                (
                    BlockerCode.UNSUPPORTED_VENDOR,
                    f"vendor {router.vendor!r} does not export flows (MikroTik only)",
                )
            )
        if target is None:
            reasons.append(
                (
                    BlockerCode.NO_TUNNEL,
                    "router has no WireGuard tunnel; the collector is reached "
                    "over it",
                )
            )
        major = routeros_major_version(router.routeros_version)
        if major is not None and major != 7:
            reasons.append(
                (
                    BlockerCode.ROUTEROS_VERSION,
                    f"RouterOS 7 required (router reports {router.routeros_version})",
                )
            )
        return reasons

    async def _our_identity(
        self, router_id: uuid.UUID, target: TrafficFlowTarget | None
    ) -> dict[str, str] | None:
        """Which target rows on this router are the platform's, for a
        removal: the current collector address and port when the router has
        a tunnel, otherwise the ones recorded when export was applied.
        ``None`` when neither is known -- then nothing is treated as ours,
        and a removal removes no target at all."""
        if target is not None:
            return target_identity(target.collector_address, target.collector_port)
        row = await self.repository.get_export(router_id)
        if row is not None and row.target_host and row.target_port:
            return target_identity(row.target_host, int(row.target_port))
        return None

    async def preview(self, router_id: uuid.UUID) -> dict[str, Any]:
        router = await self.router_lookup.get_router(router_id)
        peer, server = await self.repository.peer_and_server(router.id)
        target = traffic_flow_target_for(peer, server, self.settings)
        mikrotik = _is_mikrotik(router.vendor)
        lines: list[str] = []
        desired: dict[str, Any] | None = None
        if target is not None and mikrotik:
            config = desired_config(target)
            lines = render_traffic_flow_lines(
                config, routeros_version=router.routeros_version
            )
            desired = {
                "target_host": target.collector_address,
                "target_port": target.collector_port,
                "src_address": target.source_address,
                "version": str((config.target or {}).get("version")),
            }
        blockers = self._blockers(router, target)
        if mikrotik and not self._has_credentials(router):
            blockers.append(
                (
                    BlockerCode.NO_API_CREDENTIALS,
                    "router has no API credentials on record; the script below "
                    "can still be pasted by hand",
                )
            )
        return {
            "router_id": str(router.id),
            "status": await self._status.router_status(router.id),
            "eligible": not blockers,
            "blockers": [text for _code, text in blockers],
            "blocker_codes": [code.value for code, _text in blockers],
            "routeros_version": router.routeros_version,
            "desired": desired,
            "paste_script": list(lines),
            "removal_script": render_removal_lines(
                await self._our_identity(router.id, target)
            )
            if mikrotik
            else [],
            # Names from before the per-router switch, kept for the page
            # already built on them.
            "collector_address": target.collector_address if target else None,
            "collector_port": target.collector_port if target else None,
            "source_address": target.source_address if target else None,
            "lines": lines,
        }

    async def remove(
        self, router_id: uuid.UUID, *, actor_user_id: uuid.UUID | None
    ) -> dict[str, Any]:
        """Switch export off on the router, read back, clear the switch."""
        return await self.apply(
            router_id, enabled=False, dry_run=False, actor_user_id=actor_user_id
        )

    async def _record(
        self,
        router_id: uuid.UUID,
        *,
        enabled: bool,
        target: TrafficFlowTarget | None,
        version: str | None,
        ok: bool,
        detail: str,
        actor_user_id: uuid.UUID | None,
    ) -> None:
        now = self.now()
        row = await self.repository.get_export(router_id)
        if row is None:
            row = RouterTrafficFlowExport(router_id=router_id, created_by=actor_user_id)
        row.enabled = enabled
        if enabled and target is not None:
            row.target_host = target.collector_address
            row.target_port = target.collector_port
            row.src_address = target.source_address
            row.export_version = version
            row.configured_at = now
        row.last_verified_at = now
        row.last_verdict_ok = ok
        row.last_verdict_detail = detail
        row.updated_by = actor_user_id
        await self.repository.save_export(row)

    async def apply(
        self,
        router_id: uuid.UUID,
        *,
        enabled: bool,
        dry_run: bool,
        actor_user_id: uuid.UUID | None,
    ) -> dict[str, Any]:
        from wyfy_device_gateway.mikrotik_adapter import MikroTikDeviceError
        from wyfy_device_gateway.mikrotik_traffic_flow import (
            TrafficFlowRefusal,
            diff_traffic_flow,
            plan_traffic_flow,
        )

        router = await self.router_lookup.get_router(router_id)
        peer, server = await self.repository.peer_and_server(router.id)
        target = traffic_flow_target_for(peer, server, self.settings)
        blockers = self._blockers(router, target)
        if not enabled:
            blockers = [b for b in blockers if b[0] not in _REMOVAL_IGNORES]
        if blockers:
            raise TrafficFlowError(
                "; ".join(text for _code, text in blockers),
                code="TRAFFIC_FLOW_NOT_ELIGIBLE",
                status_code=status.HTTP_409_CONFLICT,
            )
        config = (
            desired_config(target)
            if enabled and target
            else disabled_config(await self._our_identity(router.id, target))
        )
        secret = self.router_lookup.get_decrypted_api_secret(router)
        host = router.management_ip_address or router.public_ip_address
        if not host or not router.api_username or not secret:
            raise TrafficFlowError(
                "router has no API credentials on record",
                code="TRAFFIC_FLOW_NO_CREDENTIALS",
                status_code=status.HTTP_409_CONFLICT,
            )
        creds = self.credentials_factory(router, secret)
        adapter = self.adapter_factory()
        try:
            if dry_run:
                state = await adapter.read_traffic_flow(creds, identity=config.identity)
                plan = plan_traffic_flow(state, config)
                return {
                    "router_id": str(router.id),
                    "dry_run": True,
                    "enabled": enabled,
                    "planned_writes": [
                        f"{op} /{'/'.join(path)} "
                        + " ".join(f"{k}={v}" for k, v in fields.items())
                        for op, path, fields in plan
                    ],
                    "differences": list(diff_traffic_flow(state, config)),
                    "before": _state_dict(state),
                }
            result = await adapter.apply_traffic_flow(creds, config)
        except TrafficFlowRefusal as exc:
            raise TrafficFlowError(
                exc.detail, code=exc.code, status_code=status.HTTP_409_CONFLICT
            ) from exc
        except MikroTikDeviceError as exc:
            # Nothing is recorded: the switch and the last verdict describe
            # what a router was last KNOWN to hold.
            raise TrafficFlowError(
                f"router did not answer the traffic-flow "
                f"{'read' if dry_run else 'write'}: {exc}",
                code="TRAFFIC_FLOW_DEVICE_ERROR",
                status_code=status.HTTP_502_BAD_GATEWAY,
            ) from exc

        ok = bool(result.matches)
        detail = (
            "verified"
            if ok
            else "; ".join(str(m) for m in result.mismatches)
            or "read-back did not match"
        )
        await self._record(
            router.id,
            enabled=enabled,
            target=target,
            version=str((config.target or {}).get("version") or "") or None,
            ok=ok,
            detail=detail,
            actor_user_id=actor_user_id,
        )
        if self.audit_writer is not None and result.writes:
            await self.audit_writer.create_audit_log_entry(
                actor_user_id=actor_user_id,
                action="traffic_flow_applied",
                entity_type="router",
                entity_id=router.id,
                description=(
                    f"Traffic flow export {'enabled' if enabled else 'disabled'} "
                    f"on router {router.id}: {len(result.writes)} write(s), read-back "
                    f"{'matches' if result.matches else 'MISMATCH'}"
                ),
                organization_id=router.organization_id,
            )
        logger.info(
            "traffic_flow_applied",
            extra={
                "router_id": str(router.id),
                "enabled": enabled,
                "writes": len(result.writes),
                "matches": result.matches,
            },
        )
        row = await self._status.router_status(router.id)
        return {
            "router_id": str(router.id),
            "dry_run": False,
            "enabled": enabled,
            "ok": ok,
            "detail": detail,
            "state": row["state"] if row else None,
            "writes": list(result.writes),
            "matches": result.matches,
            "mismatches": list(result.mismatches),
            "before": _state_dict(result.before),
            "after": _state_dict(result.after),
        }
