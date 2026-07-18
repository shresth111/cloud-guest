"""Data access layer for the Analytics domain (BE-012 Part 1).

Mirrors ``app.domains.monitoring.repository``'s shape: a ``Protocol``
describing the operations the service/aggregation layer needs
(``AnalyticsRepositoryProtocol``), and a concrete implementation
(``AnalyticsRepository``) that is mostly ``GenericRepository``-backed for
this domain's own ``AnalyticsSnapshot`` table, plus hand-written ``select``
statements for (a) ``AnalyticsSnapshot``'s own date-ranged/filtered history
query (a shape ``GenericRepository``'s equality-only filter support cannot
express) and (b) the cross-domain composition reads the aggregation
pipeline needs (organization/location listing, router status counts,
platform-wide guest counts).

## Reading other domains' tables directly -- composition, not duplication

``list_active_organization_ids``/``list_active_location_ids_for_organization``/
``count_routers_by_status``/``count_active_guest_sessions``/
``get_platform_guest_aggregate``/``count_platform_organizations``/
``count_platform_locations``/``organization_exists`` all query another
domain's *model* directly (read-only ``SELECT``s), never that domain's
service or repository layer. This is the exact same precedent
``app.domains.monitoring.repository``'s own module docstring already
established (reading ``Router``/``RadiusNasClient``/``WireGuardPeer``/
``RouterEvent`` directly for its own aggregate/dashboard signals) -- a
narrow, read-only, cross-domain lookup that does not warrant standing up
each domain's full service layer just to read/aggregate a few rows. No file
inside ``organization``/``location``/``router``/``guest`` is edited to make
this work.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Protocol

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PageParams, PaginationMeta, paginate
from app.domains.guest.constants import GuestSessionStatus
from app.domains.guest.models import GuestSession
from app.domains.location.enums import LocationStatus
from app.domains.location.models import Location
from app.domains.organization.enums import OrganizationStatus
from app.domains.organization.models import Organization
from app.domains.router.models import Router

from .models import AnalyticsSnapshot


class AnalyticsRepositoryProtocol(Protocol):
    # -- AnalyticsSnapshot CRUD/query ---------------------------------------
    async def create_snapshot(self, **fields: object) -> AnalyticsSnapshot: ...

    async def get_snapshot(
        self, snapshot_id: uuid.UUID
    ) -> AnalyticsSnapshot | None: ...

    async def get_latest_snapshot(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        snapshot_type: str,
    ) -> AnalyticsSnapshot | None: ...

    async def list_snapshots(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        snapshot_type: str | None,
        start: datetime | None,
        end: datetime | None,
        page: int,
        page_size: int,
    ) -> tuple[list[AnalyticsSnapshot], PaginationMeta]: ...

    # -- cross-domain composition reads (aggregation pipeline inputs) -------
    async def organization_exists(self, organization_id: uuid.UUID) -> bool: ...

    async def list_active_organization_ids(self) -> list[uuid.UUID]: ...

    async def list_active_location_ids_for_organization(
        self, organization_id: uuid.UUID
    ) -> list[uuid.UUID]: ...

    async def count_routers_by_status(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
    ) -> list[tuple[str, int]]: ...

    async def count_active_guest_sessions(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
    ) -> int: ...

    async def get_platform_guest_aggregate(
        self, *, start: datetime, end: datetime
    ) -> tuple[int, int]: ...

    async def count_platform_organizations(self) -> int: ...

    async def count_platform_locations(self) -> int: ...


class AnalyticsRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``AnalyticsRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.snapshots = GenericRepository(AnalyticsSnapshot, session)

    # -- AnalyticsSnapshot CRUD/query ---------------------------------------

    async def create_snapshot(self, **fields: object) -> AnalyticsSnapshot:
        return await self.snapshots.create(fields)

    async def get_snapshot(self, snapshot_id: uuid.UUID) -> AnalyticsSnapshot | None:
        return await self.snapshots.get_by_id(snapshot_id)

    async def get_latest_snapshot(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        snapshot_type: str,
    ) -> AnalyticsSnapshot | None:
        statement = (
            select(AnalyticsSnapshot)
            .where(
                AnalyticsSnapshot.is_deleted.is_(False),
                AnalyticsSnapshot.snapshot_type == snapshot_type,
                AnalyticsSnapshot.organization_id.is_(organization_id)
                if organization_id is None
                else AnalyticsSnapshot.organization_id == organization_id,
                AnalyticsSnapshot.location_id.is_(location_id)
                if location_id is None
                else AnalyticsSnapshot.location_id == location_id,
            )
            .order_by(AnalyticsSnapshot.period_start.desc())
            .limit(1)
        )
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()

    async def list_snapshots(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        snapshot_type: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[AnalyticsSnapshot], PaginationMeta]:
        conditions = [AnalyticsSnapshot.is_deleted.is_(False)]
        if organization_id is not None:
            conditions.append(AnalyticsSnapshot.organization_id == organization_id)
        if location_id is not None:
            conditions.append(AnalyticsSnapshot.location_id == location_id)
        if snapshot_type is not None:
            conditions.append(AnalyticsSnapshot.snapshot_type == snapshot_type)
        if start is not None:
            conditions.append(AnalyticsSnapshot.period_start >= start)
        if end is not None:
            conditions.append(AnalyticsSnapshot.period_end <= end)

        params = PageParams(page=page, page_size=page_size)
        count_statement = (
            select(func.count()).select_from(AnalyticsSnapshot).where(*conditions)
        )
        total_items = int((await self.session.execute(count_statement)).scalar_one())

        statement = (
            select(AnalyticsSnapshot)
            .where(*conditions)
            .order_by(AnalyticsSnapshot.period_start.desc())
        )
        result = await self.session.execute(paginate(statement, params))
        rows = list(result.scalars().all())
        return rows, PaginationMeta.from_total(params, total_items)

    # -- cross-domain composition reads --------------------------------------

    async def organization_exists(self, organization_id: uuid.UUID) -> bool:
        statement = (
            select(func.count())
            .select_from(Organization)
            .where(
                Organization.id == organization_id,
                Organization.is_deleted.is_(False),
            )
        )
        result = await self.session.execute(statement)
        return int(result.scalar_one()) > 0

    async def list_active_organization_ids(self) -> list[uuid.UUID]:
        statement = (
            select(Organization.id)
            .where(
                Organization.is_deleted.is_(False),
                Organization.status == OrganizationStatus.ACTIVE.value,
            )
            .order_by(Organization.id.asc())
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    async def list_active_location_ids_for_organization(
        self, organization_id: uuid.UUID
    ) -> list[uuid.UUID]:
        statement = (
            select(Location.id)
            .where(
                Location.organization_id == organization_id,
                Location.is_deleted.is_(False),
                Location.status == LocationStatus.ACTIVE.value,
            )
            .order_by(Location.id.asc())
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    async def count_routers_by_status(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
    ) -> list[tuple[str, int]]:
        """Real SQL ``GROUP BY`` -- never a Python-side loop over fetched
        rows. Mirrors ``app.domains.monitoring.repository
        .MonitoringRepository.count_routers_by_status``'s identical shape,
        extended with an optional ``location_id`` scope for this domain's
        own location-level snapshot."""
        statement = (
            select(Router.status, func.count())
            .where(Router.is_deleted.is_(False))
            .group_by(Router.status)
        )
        if organization_id is not None:
            statement = statement.where(Router.organization_id == organization_id)
        if location_id is not None:
            statement = statement.where(Router.location_id == location_id)
        result = await self.session.execute(statement)
        return [(row[0], int(row[1])) for row in result.all()]

    async def count_active_guest_sessions(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
    ) -> int:
        statement = (
            select(func.count())
            .select_from(GuestSession)
            .where(
                GuestSession.is_deleted.is_(False),
                GuestSession.status == GuestSessionStatus.ACTIVE.value,
            )
        )
        if organization_id is not None:
            statement = statement.where(GuestSession.organization_id == organization_id)
        if location_id is not None:
            statement = statement.where(GuestSession.location_id == location_id)
        result = await self.session.execute(statement)
        return int(result.scalar_one())

    async def get_platform_guest_aggregate(
        self, *, start: datetime, end: datetime
    ) -> tuple[int, int]:
        """Returns ``(session_count_total, unique_guest_count)`` across
        every organization for ``[start, end]`` -- the one platform-wide
        guest aggregate ``app.domains.guest.service.GuestAnalyticsService
        .get_summary`` cannot itself produce (its ``organization_id``
        parameter is mandatory, by design -- guest analytics are inherently
        tenant-scoped upstream), so this queries ``GuestSession`` directly,
        the same read-only composition this repository already establishes
        above."""
        statement = select(
            func.count(GuestSession.id),
            func.count(func.distinct(GuestSession.guest_id)),
        ).where(
            GuestSession.is_deleted.is_(False),
            GuestSession.started_at >= start,
            GuestSession.started_at <= end,
        )
        result = await self.session.execute(statement)
        total, unique_guests = result.one()
        return int(total or 0), int(unique_guests or 0)

    async def count_platform_organizations(self) -> int:
        statement = (
            select(func.count())
            .select_from(Organization)
            .where(Organization.is_deleted.is_(False))
        )
        result = await self.session.execute(statement)
        return int(result.scalar_one())

    async def count_platform_locations(self) -> int:
        statement = (
            select(func.count())
            .select_from(Location)
            .where(Location.is_deleted.is_(False))
        )
        result = await self.session.execute(statement)
        return int(result.scalar_one())


__all__ = ["AnalyticsRepositoryProtocol", "AnalyticsRepository"]
