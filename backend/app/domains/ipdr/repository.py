"""IPDR SQL. Every read that returns IPDR data is narrowed to one
organization by the caller (``service``); the builder reads one location at
a time."""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any

from sqlalchemy import and_, delete, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.connected_devices.models import ConnectedDevice
from app.domains.device_logs.guest_events import GuestEventKind
from app.domains.device_logs.models import GuestDeviceEvent
from app.domains.dhcp.models import DhcpPool
from app.domains.guest.models import Guest, GuestDevice, GuestSession
from app.domains.location.models import Location
from app.domains.mac_authorization.constants import MacAuthorizationType
from app.domains.mac_authorization.models import MacAuthorizationEntry
from app.domains.monitored_hardware.models import MonitoredHardware
from app.domains.router.models import Router
from app.domains.traffic_flow.flow_record_models import (
    TrafficFlowRecord,
    TrafficFlowRecordCap,
)

from .constants import LEASE_LOOKAHEAD, LEASE_LOOKBACK
from .formatting import normalize_ip, normalize_mac
from .join import (
    DOWNLOAD,
    UPLOAD,
    FlowInput,
    Infrastructure,
    InventorySighting,
    LeaseEvent,
    SessionInput,
)
from .models import IpdrDayFile, IpdrDaySubject

#: A window that starts this much before the day can still hold a flow whose
#: own start is inside it.
_WINDOW_SLACK = timedelta(minutes=10)
_SUBJECT_CHUNK = 5000


@dataclass(frozen=True, slots=True)
class DayFileRow:
    id: int
    organization_id: uuid.UUID
    location_id: uuid.UUID
    day: date
    store: str
    object_key: str
    sha256: str
    row_count: int
    records_incomplete: bool


def _day_file(row: Any) -> DayFileRow:
    return DayFileRow(
        id=row.id,
        organization_id=row.organization_id,
        location_id=row.location_id,
        day=row.day,
        store=row.store,
        object_key=row.object_key,
        sha256=row.sha256,
        row_count=row.row_count,
        records_incomplete=row.records_incomplete,
    )


def _macs(values: Iterable[str | None]) -> frozenset[str]:
    return frozenset(m for m in (normalize_mac(v) for v in values) if m)


class IpdrRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # -- ownership -----------------------------------------------------------
    async def location_organization(self, location_id: uuid.UUID) -> uuid.UUID | None:
        return (
            await self.session.execute(
                select(Location.organization_id).where(Location.id == location_id)
            )
        ).scalar_one_or_none()

    async def router_owner(
        self, router_id: uuid.UUID
    ) -> tuple[uuid.UUID | None, uuid.UUID | None] | None:
        row = (
            await self.session.execute(
                select(Router.organization_id, Router.location_id).where(
                    Router.id == router_id
                )
            )
        ).one_or_none()
        return (row[0], row[1]) if row is not None else None

    async def organization_location_ids(
        self, organization_id: uuid.UUID
    ) -> list[uuid.UUID]:
        rows = await self.session.execute(
            select(Location.id).where(Location.organization_id == organization_id)
        )
        return sorted(rows.scalars().all(), key=str)

    # -- builder inputs ------------------------------------------------------
    async def locations_with_flows(
        self, start: datetime, end: datetime
    ) -> list[tuple[uuid.UUID, uuid.UUID]]:
        """(location, organization) pairs with guest flow records in range."""
        statement = (
            select(TrafficFlowRecord.location_id, Location.organization_id)
            .join(Location, Location.id == TrafficFlowRecord.location_id)
            .where(
                TrafficFlowRecord.window_start >= start - _WINDOW_SLACK,
                TrafficFlowRecord.window_start < end,
                TrafficFlowRecord.direction.in_((UPLOAD, DOWNLOAD)),
            )
            .distinct()
        )
        rows = (await self.session.execute(statement)).all()
        return sorted(((r[0], r[1]) for r in rows), key=lambda p: str(p[0]))

    async def flows(
        self, location_id: uuid.UUID, start: datetime, end: datetime
    ) -> list[FlowInput]:
        """Guest flow records of one location whose window can hold an
        instant in ``[start, end)``. The exact cut is the builder's."""
        r = TrafficFlowRecord
        statement = select(
            r.router_id,
            r.window_start,
            r.flow_start,
            r.flow_end,
            r.direction,
            r.src_address,
            r.src_port,
            r.dst_address,
            r.dst_port,
            r.protocol,
            r.nat_src_address,
            r.nat_src_port,
            r.bytes,
            r.packets,
            r.ports_merged,
            r.nat_event,
        ).where(
            r.location_id == location_id,
            r.window_start >= start - _WINDOW_SLACK,
            r.window_start < end,
            r.direction.in_((UPLOAD, DOWNLOAD)),
        )
        return [
            FlowInput(
                router_id=row.router_id,
                window_start=row.window_start,
                flow_start=row.flow_start,
                flow_end=row.flow_end,
                direction=row.direction,
                src_address=str(row.src_address),
                src_port=row.src_port,
                dst_address=str(row.dst_address),
                dst_port=row.dst_port,
                protocol=row.protocol,
                nat_src_address=(
                    str(row.nat_src_address) if row.nat_src_address else None
                ),
                nat_src_port=row.nat_src_port,
                bytes=row.bytes or 0,
                packets=row.packets,
                ports_merged=bool(row.ports_merged),
                nat_event=row.nat_event,
            )
            for row in (await self.session.execute(statement)).all()
        ]

    async def sessions(
        self,
        router_ids: Iterable[uuid.UUID],
        start: datetime,
        end: datetime,
        *,
        grace: timedelta,
    ) -> list[SessionInput]:
        """Sessions of these routers that overlap ``[start - grace, end)`` --
        by overlap, not by start, so a session from before midnight is in.
        Soft-deleted rows are included: who held an address does not change
        when a row is later deleted."""
        ids = list(router_ids)
        if not ids:
            return []
        s = GuestSession
        statement = (
            select(
                s.id,
                s.guest_id,
                s.router_id,
                s.ip_address,
                s.started_at,
                s.ended_at,
                s.last_activity_at,
                Guest.identifier,
                Guest.display_name,
                Guest.email,
                GuestDevice.mac_address,
            )
            .join(Guest, Guest.id == s.guest_id)
            .outerjoin(GuestDevice, GuestDevice.id == s.device_id)
            .where(
                s.router_id.in_(ids),
                s.ip_address.is_not(None),
                s.started_at < end,
                or_(s.ended_at.is_(None), s.ended_at >= start - grace),
            )
        )
        return [
            SessionInput(
                id=row.id,
                guest_id=row.guest_id,
                router_id=row.router_id,
                ip_address=row.ip_address,
                started_at=row.started_at,
                ended_at=row.ended_at,
                last_activity_at=row.last_activity_at,
                identifier=row.identifier,
                display_name=row.display_name,
                email=row.email,
                mac_address=row.mac_address,
            )
            for row in (await self.session.execute(statement)).all()
        ]

    async def router_public_ips(
        self, router_ids: Iterable[uuid.UUID]
    ) -> dict[uuid.UUID, str | None]:
        ids = list(router_ids)
        if not ids:
            return {}
        rows = await self.session.execute(
            select(Router.id, Router.public_ip_address).where(Router.id.in_(ids))
        )
        return {row[0]: row[1] for row in rows.all()}

    async def lease_events(
        self, router_ids: Iterable[uuid.UUID], start: datetime, end: datetime
    ) -> list[LeaseEvent]:
        """The routers' DHCP assign/release lines around ``[start, end)``,
        for the MAC and allocation of an address that has no session."""
        ids = list(router_ids)
        if not ids:
            return []
        e = GuestDeviceEvent
        kinds = (GuestEventKind.IP_ASSIGNED.value, GuestEventKind.IP_RELEASED.value)
        statement = select(
            e.router_id, e.ip_address, e.mac_address, e.kind, e.occurred_at
        ).where(
            e.router_id.in_(ids),
            e.kind.in_(kinds),
            e.occurred_at >= start - LEASE_LOOKBACK,
            e.occurred_at < end + LEASE_LOOKAHEAD,
        )
        return [
            LeaseEvent(
                router_id=row.router_id,
                ip_address=row.ip_address,
                mac_address=row.mac_address,
                assigned=row.kind == GuestEventKind.IP_ASSIGNED.value,
                at=row.occurred_at,
            )
            for row in (await self.session.execute(statement)).all()
        ]

    async def inventory_sightings(
        self, router_ids: Iterable[uuid.UUID]
    ) -> list[InventorySighting]:
        """The device inventory's current address per MAC on these routers
        (a snapshot: used only while its sighting covers the instant)."""
        ids = list(router_ids)
        if not ids:
            return []
        d = ConnectedDevice
        statement = select(
            d.router_id,
            d.ip_address,
            d.mac_address,
            d.connected_at,
            d.last_seen_at,
            d.is_active,
        ).where(
            d.router_id.in_(ids),
            d.ip_address.is_not(None),
            d.is_deleted.is_(False),
        )
        return [
            InventorySighting(
                router_id=row.router_id,
                ip_address=row.ip_address,
                mac_address=row.mac_address,
                since=row.connected_at,
                until=None if row.is_active else row.last_seen_at,
            )
            for row in (await self.session.execute(statement)).all()
        ]

    async def infrastructure(
        self,
        location_id: uuid.UUID,
        organization_id: uuid.UUID,
        router_ids: Iterable[uuid.UUID],
    ) -> Infrastructure:
        """What marks an address as not a guest's: the routers' own LAN
        addresses, the location's monitored hardware, and authorised-MAC
        bypass entries of the organisation (org-wide or this location)."""
        ids = list(router_ids)
        gateways: dict[uuid.UUID, set[str]] = {}
        if ids:
            rows = await self.session.execute(
                select(DhcpPool.router_id, DhcpPool.gateway_ip_address).where(
                    DhcpPool.router_id.in_(ids),
                    DhcpPool.gateway_ip_address.is_not(None),
                    DhcpPool.is_deleted.is_(False),
                )
            )
            for router_id, address in rows.all():
                ip = normalize_ip(address)
                if ip is not None:
                    gateways.setdefault(router_id, set()).add(ip)
        monitored = await self.session.execute(
            select(MonitoredHardware.mac_address).where(
                MonitoredHardware.location_id == location_id,
                MonitoredHardware.is_deleted.is_(False),
            )
        )
        m = MacAuthorizationEntry
        authorized = await self.session.execute(
            select(m.mac_address).where(
                m.organization_id == organization_id,
                or_(m.location_id.is_(None), m.location_id == location_id),
                # Permanent only: a temporary entry is often a guest's own
                # device let through for a while, not infrastructure.
                m.authorization_type == MacAuthorizationType.PERMANENT.value,
                m.is_enabled.is_(True),
                m.is_deleted.is_(False),
            )
        )
        return Infrastructure(
            router_addresses={k: frozenset(v) for k, v in gateways.items()},
            monitored_macs=_macs(monitored.scalars().all()),
            authorized_macs=_macs(authorized.scalars().all()),
        )

    async def records_incomplete(
        self, location_id: uuid.UUID, start: datetime, end: datetime
    ) -> bool:
        """A router of the location hit the flow-record daily cap on a UTC
        day overlapping ``[start, end)``."""
        c = TrafficFlowRecordCap
        found = await self.session.execute(
            select(func.count())
            .select_from(c)
            .where(
                c.location_id == location_id,
                c.day >= start.date(),
                c.day <= end.date(),
                c.capped_at.is_not(None),
            )
        )
        return bool(found.scalar_one())

    # -- index ---------------------------------------------------------------
    async def day_files(
        self,
        organization_id: uuid.UUID,
        location_ids: tuple[uuid.UUID, ...] | None,
        first: date,
        last: date,
    ) -> list[DayFileRow]:
        f = IpdrDayFile
        conditions = [f.organization_id == organization_id, f.day >= first]
        conditions.append(f.day <= last)
        if location_ids is not None:
            conditions.append(f.location_id.in_(location_ids))
        rows = await self.session.execute(select(f).where(and_(*conditions)))
        return [_day_file(row) for row in rows.scalars().all()]

    async def day_file(self, location_id: uuid.UUID, day: date) -> DayFileRow | None:
        row = (
            await self.session.execute(
                select(IpdrDayFile).where(
                    IpdrDayFile.location_id == location_id, IpdrDayFile.day == day
                )
            )
        ).scalar_one_or_none()
        return _day_file(row) if row is not None else None

    async def days_with_subject(
        self,
        organization_id: uuid.UUID,
        first: date,
        last: date,
        kind: str,
        digest: str,
    ) -> set[tuple[uuid.UUID, date]]:
        f, s = IpdrDayFile, IpdrDaySubject
        rows = await self.session.execute(
            select(f.location_id, f.day)
            .join(s, s.day_file_id == f.id)
            .where(
                f.organization_id == organization_id,
                f.day >= first,
                f.day <= last,
                s.kind == kind,
                s.digest == digest,
            )
        )
        return {(row[0], row[1]) for row in rows.all()}

    async def save_day_file(
        self, values: dict[str, Any], subjects: Iterable[tuple[str, str]]
    ) -> int:
        """Insert or repoint the (location, day) row at a new object, and
        replace its subjects."""
        statement = (
            pg_insert(IpdrDayFile)
            .values(**values)
            .on_conflict_do_update(
                constraint="uq_ipdr_day_files_location_day",
                set_={
                    k: values[k]
                    for k in values
                    if k not in ("location_id", "day", "organization_id")
                },
            )
            .returning(IpdrDayFile.id)
        )
        day_file_id = (await self.session.execute(statement)).scalar_one()
        await self.session.execute(
            delete(IpdrDaySubject).where(IpdrDaySubject.day_file_id == day_file_id)
        )
        rows = [
            {"day_file_id": day_file_id, "kind": kind, "digest": digest}
            for kind, digest in sorted(set(subjects))
        ]
        # 3 bind parameters a row; stay far below PostgreSQL's 65,535.
        for i in range(0, len(rows), _SUBJECT_CHUNK):
            chunk = rows[i : i + _SUBJECT_CHUNK]
            await self.session.execute(pg_insert(IpdrDaySubject).values(chunk))
        return int(day_file_id)
