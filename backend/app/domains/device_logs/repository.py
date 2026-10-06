"""Device Logs data access. Reads the router/peer/location/organization
tables directly (read-only joins for attribution and display names); writes
only this domain's two tables."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import and_, func, insert, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.location.models import Location
from app.domains.organization.models import Organization
from app.domains.router.models import Router
from app.domains.wireguard.models import WireGuardPeer, WireGuardServer

from .models import DeviceLogEvent, RouterRemoteLogging


@dataclass(frozen=True)
class PeerOwner:
    router_id: uuid.UUID
    organization_id: uuid.UUID | None
    location_id: uuid.UUID | None


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

    async def insert_events(self, rows: list[dict[str, Any]]) -> None:
        if rows:
            await self.session.execute(insert(DeviceLogEvent), rows)
            await self.session.flush()

    # -- viewer ---------------------------------------------------------
    async def list_events(
        self, filters: EventFilters, *, limit: int
    ) -> list[dict[str, Any]]:
        conditions = [
            DeviceLogEvent.received_at >= filters.since,
            DeviceLogEvent.received_at <= filters.until,
        ]
        if filters.unattributed_only:
            conditions.append(DeviceLogEvent.router_id.is_(None))
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
            .where(DeviceLogEvent.router_id.in_(router_ids))
            .group_by(DeviceLogEvent.router_id)
        )
        return {rid: at for rid, at in (await self.session.execute(stmt)).all()}

    async def count_unattributed_since(self, since: datetime) -> int:
        stmt = select(func.count()).where(
            DeviceLogEvent.router_id.is_(None), DeviceLogEvent.received_at >= since
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
    ) -> list[tuple[RouterRemoteLogging, str, str | None, str | None]]:
        stmt = (
            select(
                RouterRemoteLogging,
                Router.name,
                Location.name,
                Organization.name,
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
