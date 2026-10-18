"""Device Logs data access. Reads the router/peer/location/organization
tables directly (read-only joins for attribution and display names); writes
only this domain's two tables."""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import and_, case, func, insert, literal, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.guest.models import GuestDevice, GuestSession
from app.domains.location.models import Location
from app.domains.organization.models import Organization
from app.domains.router.models import Router
from app.domains.wireguard.models import WireGuardPeer, WireGuardServer

from .constants import Attribution, LogSource
from .models import DeviceLogEvent, GuestDeviceEvent, RouterRemoteLogging

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PeerOwner:
    router_id: uuid.UUID
    organization_id: uuid.UUID | None
    location_id: uuid.UUID | None


@dataclass(frozen=True)
class SessionMatchKey:
    """What one guest session is matched on (see ``session_events``)."""

    organization_id: uuid.UUID
    location_id: uuid.UUID
    router_id: uuid.UUID
    #: Window for MAC-carrying events (DHCP).
    window_start: datetime
    window_end: datetime
    #: Narrower window for IP-only events (hotspot).
    ip_window_start: datetime
    ip_window_end: datetime
    mac_address: str | None
    ip_address: str | None


@dataclass(frozen=True)
class EventFilters:
    since: datetime
    until: datetime
    organization_id: uuid.UUID | None = None
    location_id: uuid.UUID | None = None
    router_id: uuid.UUID | None = None
    max_severity: int | None = None
    text: str | None = None
    unattributed_only: bool = False
    cursor: tuple[datetime, int] | None = None


def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class DeviceLogsRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # -- attribution ----------------------------------------------------
    async def owners_by_tunnel_ip(self, ips: set[str]) -> dict[str, list[PeerOwner]]:
        """Every live router whose WireGuard peer holds one of ``ips``.

        A list per IP, not one owner: ``tunnel_ip_address`` is unique per
        hub, not globally, so with two hubs an address can be ambiguous --
        and the caller must refuse to guess."""
        if not ips:
            return {}
        stmt = (
            select(
                WireGuardPeer.tunnel_ip_address,
                Router.id,
                Router.organization_id,
                Router.location_id,
            )
            .join(Router, Router.id == WireGuardPeer.router_id)
            .where(
                WireGuardPeer.tunnel_ip_address.in_(ips),
                WireGuardPeer.is_deleted.is_(False),
                Router.is_deleted.is_(False),
            )
        )
        result: dict[str, list[PeerOwner]] = {}
        for ip, router_id, org_id, loc_id in (await self.session.execute(stmt)).all():
            result.setdefault(ip, []).append(PeerOwner(router_id, org_id, loc_id))
        return result

    async def insert_events(self, rows: list[dict[str, Any]]) -> list[int]:
        """Insert lines; returns their ids in the order of ``rows``."""
        if not rows:
            return []
        result = await self.session.execute(
            insert(DeviceLogEvent).returning(
                DeviceLogEvent.id, sort_by_parameter_order=True
            ),
            rows,
        )
        ids = [int(i) for i in result.scalars().all()]
        await self.session.flush()
        return ids

    async def insert_guest_events(self, rows: list[dict[str, Any]]) -> int:
        """Insert derived guest events, skipping any that already exist (same
        source line, or the same router event stored twice by a collector
        retry). Returns how many were new."""
        if not rows:
            return 0
        stmt = (
            pg_insert(GuestDeviceEvent)
            .values(rows)
            .on_conflict_do_nothing()
            .returning(GuestDeviceEvent.id)
        )
        inserted = len((await self.session.execute(stmt)).all())
        await self.session.flush()
        return inserted

    async def lines_without_guest_event(
        self, *, after_id: int, limit: int
    ) -> list[DeviceLogEvent]:
        """Backfill page: attributed lines (by tunnel IP, with a router,
        location and organization) that have no derived row yet, oldest id
        first, keyset on id."""
        stmt = (
            select(DeviceLogEvent)
            .outerjoin(
                GuestDeviceEvent,
                GuestDeviceEvent.device_log_event_id == DeviceLogEvent.id,
            )
            .where(
                DeviceLogEvent.id > after_id,
                DeviceLogEvent.attribution == Attribution.TUNNEL_IP.value,
                DeviceLogEvent.router_id.is_not(None),
                DeviceLogEvent.location_id.is_not(None),
                DeviceLogEvent.organization_id.is_not(None),
                GuestDeviceEvent.id.is_(None),
            )
            .order_by(DeviceLogEvent.id)
            .limit(limit)
        )
        return list((await self.session.execute(stmt)).scalars().all())

    async def lines_without_category(self, *, after_id: int, limit: int) -> list[Any]:
        """Classification backfill page: (id, received_at, message, topics)
        of rows with no category yet, keyset on id. Server-written rows
        always carry a category, so these are syslog lines."""
        stmt = (
            select(
                DeviceLogEvent.id,
                DeviceLogEvent.received_at,
                DeviceLogEvent.message,
                DeviceLogEvent.topics,
            )
            .where(DeviceLogEvent.id > after_id, DeviceLogEvent.category.is_(None))
            .order_by(DeviceLogEvent.id)
            .limit(limit)
        )
        return list((await self.session.execute(stmt)).all())

    async def set_classification(self, rows: list[dict[str, Any]]) -> int:
        """Bulk UPDATE by primary key (id, received_at)."""
        if not rows:
            return 0
        await self.session.execute(update(DeviceLogEvent), rows)
        await self.session.flush()
        return len(rows)

    # -- viewer ---------------------------------------------------------
    async def list_events(
        self, filters: EventFilters, *, limit: int
    ) -> list[dict[str, Any]]:
        conditions = [
            DeviceLogEvent.received_at >= filters.since,
            DeviceLogEvent.received_at <= filters.until,
        ]
        if filters.unattributed_only:
            # By attribution, not router_id: portal rows (server-written)
            # have no router but are attributed to a venue.
            conditions.append(
                DeviceLogEvent.attribution == Attribution.UNATTRIBUTED.value
            )
        if filters.organization_id is not None:
            conditions.append(DeviceLogEvent.organization_id == filters.organization_id)
        if filters.location_id is not None:
            conditions.append(DeviceLogEvent.location_id == filters.location_id)
        if filters.router_id is not None:
            conditions.append(DeviceLogEvent.router_id == filters.router_id)
        if filters.max_severity is not None:
            conditions.append(DeviceLogEvent.severity <= filters.max_severity)
        if filters.text:
            conditions.append(
                DeviceLogEvent.message.ilike(
                    f"%{_escape_like(filters.text)}%", escape="\\"
                )
            )
        if filters.cursor is not None:
            at, event_id = filters.cursor
            conditions.append(
                or_(
                    DeviceLogEvent.received_at < at,
                    and_(
                        DeviceLogEvent.received_at == at, DeviceLogEvent.id < event_id
                    ),
                )
            )
        stmt = (
            select(
                DeviceLogEvent,
                Router.name.label("router_name"),
                Location.name.label("location_name"),
                Organization.name.label("organization_name"),
            )
            .outerjoin(Router, Router.id == DeviceLogEvent.router_id)
            .outerjoin(Location, Location.id == DeviceLogEvent.location_id)
            .outerjoin(Organization, Organization.id == DeviceLogEvent.organization_id)
            .where(*conditions)
            .order_by(DeviceLogEvent.received_at.desc(), DeviceLogEvent.id.desc())
            .limit(limit)
        )
        rows = []
        for event, router_name, location_name, organization_name in (
            await self.session.execute(stmt)
        ).all():
            rows.append(
                {
                    "event": event,
                    "router_name": router_name,
                    "location_name": location_name,
                    "organization_name": organization_name,
                }
            )
        return rows

    async def last_received_by_router(
        self, router_ids: list[uuid.UUID]
    ) -> dict[uuid.UUID, datetime]:
        if not router_ids:
            return {}
        stmt = (
            select(DeviceLogEvent.router_id, func.max(DeviceLogEvent.received_at))
            .where(
                DeviceLogEvent.router_id.in_(router_ids),
                # "Receiving" means the router's own syslog, not RADIUS rows
                # the platform wrote about it.
                DeviceLogEvent.source == LogSource.SYSLOG.value,
            )
            .group_by(DeviceLogEvent.router_id)
        )
        return {rid: at for rid, at in (await self.session.execute(stmt)).all()}

    async def count_unattributed_since(self, since: datetime) -> int:
        stmt = select(func.count()).where(
            DeviceLogEvent.attribution == Attribution.UNATTRIBUTED.value,
            DeviceLogEvent.received_at >= since,
        )
        return int((await self.session.execute(stmt)).scalar_one())

    # -- routers --------------------------------------------------------
    async def get_router_context(
        self, router_id: uuid.UUID
    ) -> (
        tuple[
            Router, WireGuardPeer | None, WireGuardServer | None, str | None, str | None
        ]
        | None
    ):
        router = (
            await self.session.execute(
                select(Router).where(
                    Router.id == router_id, Router.is_deleted.is_(False)
                )
            )
        ).scalar_one_or_none()
        if router is None:
            return None
        peer = (
            await self.session.execute(
                select(WireGuardPeer).where(
                    WireGuardPeer.router_id == router_id,
                    WireGuardPeer.is_deleted.is_(False),
                )
            )
        ).scalar_one_or_none()
        server = None
        if peer is not None:
            server = (
                await self.session.execute(
                    select(WireGuardServer).where(WireGuardServer.id == peer.server_id)
                )
            ).scalar_one_or_none()
        location_name = (
            await self.session.execute(
                select(Location.name).where(Location.id == router.location_id)
            )
        ).scalar_one_or_none()
        organization_name = (
            await self.session.execute(
                select(Organization.name).where(
                    Organization.id == router.organization_id
                )
            )
        ).scalar_one_or_none()
        return router, peer, server, location_name, organization_name

    async def get_config(self, router_id: uuid.UUID) -> RouterRemoteLogging | None:
        return (
            await self.session.execute(
                select(RouterRemoteLogging).where(
                    RouterRemoteLogging.router_id == router_id,
                    RouterRemoteLogging.is_deleted.is_(False),
                )
            )
        ).scalar_one_or_none()

    async def save_config(self, row: RouterRemoteLogging) -> RouterRemoteLogging:
        self.session.add(row)
        await self.session.flush()
        return row

    async def list_configs(
        self,
    ) -> list[tuple[Any, ...]]:
        """(config, router name, location name, organization name,
        organization id, location id) per configured router."""
        stmt = (
            select(
                RouterRemoteLogging,
                Router.name,
                Location.name,
                Organization.name,
                Router.organization_id,
                Router.location_id,
            )
            .join(Router, Router.id == RouterRemoteLogging.router_id)
            .outerjoin(Location, Location.id == Router.location_id)
            .outerjoin(Organization, Organization.id == Router.organization_id)
            .where(
                RouterRemoteLogging.is_deleted.is_(False),
                Router.is_deleted.is_(False),
            )
            .order_by(Organization.name, Location.name, Router.name)
        )
        return [tuple(r) for r in (await self.session.execute(stmt)).all()]  # type: ignore[misc]

    # -- customer: one guest session's device events ------------------------
    async def device_mac(self, device_id: uuid.UUID | None) -> str | None:
        if device_id is None:
            return None
        mac = (
            await self.session.execute(
                select(GuestDevice.mac_address).where(GuestDevice.id == device_id)
            )
        ).scalar_one_or_none()
        return mac.strip().upper() if mac else None

    async def first_guest_line_at(
        self, *, organization_id: uuid.UUID, location_id: uuid.UUID
    ) -> datetime | None:
        """When this venue's routers were first heard from (any attributed
        line). None: no router at this venue has ever sent device logs."""
        stmt = select(func.min(DeviceLogEvent.received_at)).where(
            DeviceLogEvent.organization_id == organization_id,
            DeviceLogEvent.location_id == location_id,
            DeviceLogEvent.router_id.is_not(None),
            DeviceLogEvent.source == LogSource.SYSLOG.value,
        )
        return (await self.session.execute(stmt)).scalar_one_or_none()

    async def candidate_guest_events(
        self, key: SessionMatchKey, *, limit: int
    ) -> list[GuestDeviceEvent]:
        """Events at the session's venue, inside its window, carrying its
        device's MAC -- or, for MAC-less hotspot lines, its IP on its own
        router. Candidates only: the caller still drops any that another
        session also matches."""
        key_match = []
        if key.mac_address:
            key_match.append(
                and_(
                    GuestDeviceEvent.mac_address.is_not(None),
                    GuestDeviceEvent.mac_address == key.mac_address,
                    GuestDeviceEvent.occurred_at >= key.window_start,
                    GuestDeviceEvent.occurred_at <= key.window_end,
                )
            )
        if key.ip_address:
            key_match.append(
                and_(
                    GuestDeviceEvent.mac_address.is_(None),
                    GuestDeviceEvent.ip_address == key.ip_address,
                    GuestDeviceEvent.router_id == key.router_id,
                    GuestDeviceEvent.occurred_at >= key.ip_window_start,
                    GuestDeviceEvent.occurred_at <= key.ip_window_end,
                )
            )
        if not key_match:
            return []
        stmt = (
            select(GuestDeviceEvent)
            .where(
                GuestDeviceEvent.organization_id == key.organization_id,
                GuestDeviceEvent.location_id == key.location_id,
                or_(*key_match),
            )
            .order_by(GuestDeviceEvent.occurred_at, GuestDeviceEvent.id)
            .limit(limit)
        )
        return list((await self.session.execute(stmt)).scalars().all())

    async def sessions_matching_events(
        self,
        event_ids: list[int],
        *,
        now: datetime,
        lead: timedelta,
        trail: timedelta,
        ip_skew: timedelta,
        open_statuses: tuple[str, ...],
    ) -> dict[int, int]:
        """For each event id, how many guest sessions (any guest, same
        organization and venue) it matches under the same rule. 1 means
        unambiguous."""
        if not event_ids:
            return {}
        session_end = case(
            (GuestSession.ended_at.is_not(None), GuestSession.ended_at),
            (GuestSession.status.in_(open_statuses), literal(now)),
            else_=GuestSession.last_activity_at,
        )
        stmt = (
            select(GuestDeviceEvent.id, func.count(func.distinct(GuestSession.id)))
            .join(
                GuestSession,
                and_(
                    GuestSession.organization_id == GuestDeviceEvent.organization_id,
                    GuestSession.location_id == GuestDeviceEvent.location_id,
                    GuestSession.is_deleted.is_(False),
                ),
            )
            .outerjoin(GuestDevice, GuestDevice.id == GuestSession.device_id)
            .where(
                GuestDeviceEvent.id.in_(event_ids),
                or_(
                    and_(
                        GuestDeviceEvent.mac_address.is_not(None),
                        func.upper(func.trim(GuestDevice.mac_address))
                        == GuestDeviceEvent.mac_address,
                        GuestSession.started_at - lead <= GuestDeviceEvent.occurred_at,
                        GuestDeviceEvent.occurred_at <= session_end + trail,
                    ),
                    and_(
                        GuestDeviceEvent.mac_address.is_(None),
                        GuestSession.ip_address == GuestDeviceEvent.ip_address,
                        GuestSession.router_id == GuestDeviceEvent.router_id,
                        GuestSession.started_at - ip_skew
                        <= GuestDeviceEvent.occurred_at,
                        GuestDeviceEvent.occurred_at <= session_end + ip_skew,
                    ),
                ),
            )
            .group_by(GuestDeviceEvent.id)
        )
        return {
            int(event_id): int(count)
            for event_id, count in (await self.session.execute(stmt)).all()
        }


# -- customer NetLogs ---------------------------------------------------------


@dataclass(frozen=True)
class CustomerFilters:
    """One organization's lines. ``organization_id`` is mandatory and is
    applied to every query built from this -- there is no "all tenants"
    form, and unattributed (NULL-organization) lines can never match."""

    organization_id: uuid.UUID
    since: datetime
    until: datetime
    #: The caller's location confinement: None = whole organization; a
    #: tuple = only these (an empty tuple matches nothing).
    allowed_location_ids: tuple[uuid.UUID, ...] | None = None
    location_id: uuid.UUID | None = None
    router_id: uuid.UUID | None = None
    severities: tuple[int, ...] = ()
    max_severity: int | None = None
    categories: tuple[str, ...] = ()
    protocols: tuple[str, ...] = ()
    statuses: tuple[str, ...] = ()
    text: str | None = None
    cursor: tuple[datetime, int] | None = None


_IP_LIKE = re.compile(r"^[0-9a-fA-F:.]{3,45}$")
_MAC_LIKE = re.compile(r"^[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}$")


def customer_conditions(f: CustomerFilters) -> list[Any]:
    conditions: list[Any] = [
        DeviceLogEvent.organization_id == f.organization_id,
        DeviceLogEvent.organization_id.is_not(None),
        DeviceLogEvent.received_at >= f.since,
        DeviceLogEvent.received_at <= f.until,
    ]
    if f.allowed_location_ids is not None:
        conditions.append(DeviceLogEvent.location_id.in_(f.allowed_location_ids))
    if f.location_id is not None:
        conditions.append(DeviceLogEvent.location_id == f.location_id)
    if f.router_id is not None:
        conditions.append(DeviceLogEvent.router_id == f.router_id)
    if f.severities:
        conditions.append(DeviceLogEvent.severity.in_(f.severities))
    if f.max_severity is not None:
        conditions.append(DeviceLogEvent.severity <= f.max_severity)
    if f.categories:
        named = [c for c in f.categories if c != "other"]
        if "other" in f.categories:
            conditions.append(
                or_(
                    DeviceLogEvent.category.in_([*named, "other"]),
                    DeviceLogEvent.category.is_(None),
                )
            )
        else:
            conditions.append(DeviceLogEvent.category.in_(named))
    if f.protocols:
        conditions.append(DeviceLogEvent.protocol.in_(f.protocols))
    if f.statuses:
        conditions.append(DeviceLogEvent.status.in_(f.statuses))
    if f.text:
        pattern = f"%{_escape_like(f.text)}%"
        matches = [
            DeviceLogEvent.message.ilike(pattern, escape="\\"),
            DeviceLogEvent.hostname.ilike(pattern, escape="\\"),
        ]
        if _IP_LIKE.match(f.text):
            matches += [
                DeviceLogEvent.src_ip == f.text,
                DeviceLogEvent.dst_ip == f.text,
            ]
        if _MAC_LIKE.match(f.text):
            matches.append(
                DeviceLogEvent.device_mac == f.text.upper().replace("-", ":")
            )
        conditions.append(or_(*matches))
    if f.cursor is not None:
        at, event_id = f.cursor
        conditions.append(
            or_(
                DeviceLogEvent.received_at < at,
                and_(DeviceLogEvent.received_at == at, DeviceLogEvent.id < event_id),
            )
        )
    return conditions


class CustomerLogsRepository:
    """Reads for the customer NetLogs page. Every query takes a
    ``CustomerFilters`` (organization mandatory) or an explicit
    organization id."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def list_events(
        self, filters: CustomerFilters, *, limit: int
    ) -> list[dict[str, Any]]:
        stmt = (
            select(
                DeviceLogEvent,
                Router.name.label("router_name"),
                Location.name.label("location_name"),
            )
            .outerjoin(Router, Router.id == DeviceLogEvent.router_id)
            .outerjoin(Location, Location.id == DeviceLogEvent.location_id)
            .where(*customer_conditions(filters))
            .order_by(DeviceLogEvent.received_at.desc(), DeviceLogEvent.id.desc())
            .limit(limit)
        )
        return [
            {"event": e, "router_name": rn, "location_name": ln}
            for e, rn, ln in (await self.session.execute(stmt)).all()
        ]

    async def summary_buckets(
        self, filters: CustomerFilters, *, tz: str
    ) -> list[tuple[Any, str, int | None, int]]:
        """(local day, category, severity, count) for the range."""
        day = func.date(func.timezone(tz, DeviceLogEvent.received_at)).label("day")
        category = func.coalesce(DeviceLogEvent.category, "other").label("category")
        stmt = (
            select(day, category, DeviceLogEvent.severity, func.count())
            .where(*customer_conditions(filters))
            .group_by(day, category, DeviceLogEvent.severity)
        )
        return [tuple(r) for r in (await self.session.execute(stmt)).all()]  # type: ignore[misc]

    async def top_routers(
        self, filters: CustomerFilters, *, limit: int
    ) -> list[tuple[Any, ...]]:
        """(router id, name, location id, location name, total, errors,
        warnings), busiest first. Lines with no router are not a router."""
        errors = func.count().filter(DeviceLogEvent.severity <= 3)
        warnings = func.count().filter(DeviceLogEvent.severity == 4)
        total = func.count()
        stmt = (
            select(
                DeviceLogEvent.router_id,
                Router.name,
                Router.location_id,
                Location.name,
                total,
                errors,
                warnings,
            )
            .join(Router, Router.id == DeviceLogEvent.router_id)
            .outerjoin(Location, Location.id == Router.location_id)
            .where(*customer_conditions(filters), DeviceLogEvent.router_id.is_not(None))
            .group_by(
                DeviceLogEvent.router_id, Router.name, Router.location_id, Location.name
            )
            .order_by(total.desc(), DeviceLogEvent.router_id)
            .limit(limit)
        )
        return [tuple(r) for r in (await self.session.execute(stmt)).all()]

    async def router_owner(
        self, router_id: uuid.UUID
    ) -> tuple[uuid.UUID | None, uuid.UUID | None] | None:
        """(organization id, location id) of a router -- deleted ones too:
        their lines are still in the table."""
        row = (
            await self.session.execute(
                select(Router.organization_id, Router.location_id).where(
                    Router.id == router_id
                )
            )
        ).one_or_none()
        return (row[0], row[1]) if row is not None else None

    async def location_organization(self, location_id: uuid.UUID) -> uuid.UUID | None:
        return (
            await self.session.execute(
                select(Location.organization_id).where(Location.id == location_id)
            )
        ).scalar_one_or_none()

    async def organization_location_ids(
        self, organization_id: uuid.UUID
    ) -> list[uuid.UUID]:
        return list(
            (
                await self.session.execute(
                    select(Location.id).where(
                        Location.organization_id == organization_id
                    )
                )
            )
            .scalars()
            .all()
        )


async def insert_server_event(session: AsyncSession, row: dict[str, Any]) -> bool:
    """Insert one platform-written row (RADIUS decision, portal sign-in
    failure) inside a SAVEPOINT, so a failure rolls back only this insert
    and never the caller's transaction. Returns False instead of raising."""
    try:
        async with session.begin_nested():
            await session.execute(insert(DeviceLogEvent).values(**row))
    except Exception as exc:  # noqa: BLE001 -- logging must never break auth
        logger.warning(
            "device_logs_server_event_insert_failed",
            extra={"error_type": type(exc).__name__, "error": str(exc)[:300]},
        )
        return False
    return True
