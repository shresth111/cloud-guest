"""Data access layer for the Monitoring domain (BE-011 Part 1).

Mirrors ``app.domains.guest.repository``'s shape: a ``Protocol`` describing
the operations the service layer needs (``MonitoringRepositoryProtocol``),
and a concrete, mostly-``GenericRepository``-backed implementation
(``MonitoringRepository``), plus hand-written ``select`` statements for two
kinds of query ``GenericRepository``'s equality-filter support cannot
express: (a) the event-timeline's read-side aggregation across *other*
domains' own tables (``AuditLogEntry``, ``RouterEvent``), and (b) the
FreeRADIUS/WireGuard proxy-signal composition queries against ``guest``'s/
``wireguard``'s own tables.

## Reading other domains' tables directly -- composition, not duplication

``list_audit_log_events``/``list_router_events``/
``count_active_radius_nas_clients``/``get_latest_guest_accounting_activity``/
``list_wireguard_peers`` all import and query another domain's *model*
directly (read-only ``SELECT``s), never that domain's service or repository
layer. This is the same precedent
``app.domains.rbac.dependencies.CurrentOrganization``/``CurrentLocation``
already establish (querying ``Organization``/``Location`` directly via a
bare ``GenericRepository`` rather than going through
``OrganizationService``/``LocationService``) -- a narrow, read-only,
cross-domain lookup that doesn't warrant standing up each domain's full
service layer just to read a few rows for an aggregate/dashboard signal. No
file inside ``rbac``/``router_provisioning``/``guest``/``wireguard`` is
edited to make this work.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Protocol

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PaginationMeta
from app.domains.guest.models import GuestSession, RadiusNasClient
from app.domains.rbac.models import AuditLogEntry
from app.domains.router.models import Router
from app.domains.router_provisioning.models import RouterEvent
from app.domains.wireguard.models import WireGuardPeer

from .models import HealthCheck, HeartbeatLog, PlatformEvent, ServiceHealth


class MonitoringRepositoryProtocol(Protocol):
    # -- health checks -----------------------------------------------------
    async def ping_database(self) -> None: ...

    async def create_health_check(self, **fields: object) -> HealthCheck: ...

    async def list_health_checks(
        self, *, component: str, page: int, page_size: int
    ) -> tuple[list[HealthCheck], PaginationMeta]: ...

    # -- service health rollup ----------------------------------------------
    async def get_service_health(self, component: str) -> ServiceHealth | None: ...

    async def create_service_health(self, **fields: object) -> ServiceHealth: ...

    async def update_service_health(
        self, service_health: ServiceHealth, data: dict[str, object]
    ) -> ServiceHealth: ...

    async def list_service_health(self) -> list[ServiceHealth]: ...

    # -- heartbeats -----------------------------------------------------------
    async def create_heartbeat_log(self, **fields: object) -> HeartbeatLog: ...

    # -- platform events -----------------------------------------------------
    async def create_platform_event(self, **fields: object) -> PlatformEvent: ...

    async def list_platform_events(
        self,
        *,
        organization_id: uuid.UUID | None,
        categories: list[str] | None,
        severities: list[str] | None,
        start: datetime | None,
        end: datetime | None,
        limit: int,
    ) -> list[PlatformEvent]: ...

    # -- read-side composition for the unified event timeline ----------------
    async def list_audit_log_events(
        self,
        *,
        organization_id: uuid.UUID | None,
        start: datetime | None,
        end: datetime | None,
        limit: int,
    ) -> list[AuditLogEntry]: ...

    async def list_router_events(
        self,
        *,
        organization_id: uuid.UUID | None,
        start: datetime | None,
        end: datetime | None,
        limit: int,
    ) -> list[RouterEvent]: ...

    # -- FreeRADIUS proxy signal (composes with app.domains.guest) ------------
    async def count_active_radius_nas_clients(self) -> int: ...

    async def get_latest_guest_accounting_activity(self) -> datetime | None: ...

    # -- WireGuard proxy signal (composes with app.domains.wireguard) --------
    async def list_wireguard_peers(self) -> list[WireGuardPeer]: ...


class MonitoringRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``MonitoringRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.health_checks = GenericRepository(HealthCheck, session)
        self.service_health = GenericRepository(ServiceHealth, session)
        self.heartbeat_logs = GenericRepository(HeartbeatLog, session)
        self.platform_events = GenericRepository(PlatformEvent, session)

    # -- health checks -----------------------------------------------------

    async def ping_database(self) -> None:
        """A trivial, real round-trip to the actual database -- the
        Database health check's entire mechanism (see ``service.py``)."""
        await self.session.execute(select(1))

    async def create_health_check(self, **fields: object) -> HealthCheck:
        return await self.health_checks.create(fields)

    async def list_health_checks(
        self, *, component: str, page: int, page_size: int
    ) -> tuple[list[HealthCheck], PaginationMeta]:
        return await self.health_checks.paginate(
            page=page,
            page_size=page_size,
            filters={"component": component},
            sort_by="checked_at",
            sort_order=SortOrder.DESC,
        )

    # -- service health rollup ----------------------------------------------

    async def get_service_health(self, component: str) -> ServiceHealth | None:
        results = await self.service_health.get_all(
            filters={"component": component}, limit=1
        )
        return results[0] if results else None

    async def create_service_health(self, **fields: object) -> ServiceHealth:
        return await self.service_health.create(fields)

    async def update_service_health(
        self, service_health: ServiceHealth, data: dict[str, object]
    ) -> ServiceHealth:
        return await self.service_health.update(service_health, data)

    async def list_service_health(self) -> list[ServiceHealth]:
        return await self.service_health.get_all(
            sort_by="component", sort_order=SortOrder.ASC
        )

    # -- heartbeats -----------------------------------------------------------

    async def create_heartbeat_log(self, **fields: object) -> HeartbeatLog:
        return await self.heartbeat_logs.create(fields)

    # -- platform events -----------------------------------------------------

    async def create_platform_event(self, **fields: object) -> PlatformEvent:
        return await self.platform_events.create(fields)

    async def list_platform_events(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        categories: list[str] | None = None,
        severities: list[str] | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 100,
    ) -> list[PlatformEvent]:
        statement = select(PlatformEvent).where(PlatformEvent.is_deleted.is_(False))
        if organization_id is not None:
            statement = statement.where(
                PlatformEvent.organization_id == organization_id
            )
        if categories:
            statement = statement.where(PlatformEvent.category.in_(categories))
        if severities:
            statement = statement.where(PlatformEvent.severity.in_(severities))
        if start is not None:
            statement = statement.where(PlatformEvent.occurred_at >= start)
        if end is not None:
            statement = statement.where(PlatformEvent.occurred_at <= end)
        statement = statement.order_by(PlatformEvent.occurred_at.desc()).limit(limit)
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    # -- read-side composition for the unified event timeline ----------------

    async def list_audit_log_events(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 100,
    ) -> list[AuditLogEntry]:
        statement = select(AuditLogEntry).where(AuditLogEntry.is_deleted.is_(False))
        if organization_id is not None:
            statement = statement.where(
                AuditLogEntry.organization_id == organization_id
            )
        if start is not None:
            statement = statement.where(AuditLogEntry.created_at >= start)
        if end is not None:
            statement = statement.where(AuditLogEntry.created_at <= end)
        statement = statement.order_by(AuditLogEntry.created_at.desc()).limit(limit)
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    async def list_router_events(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 100,
    ) -> list[RouterEvent]:
        statement = select(RouterEvent).where(RouterEvent.is_deleted.is_(False))
        if organization_id is not None:
            # RouterEvent has no organization_id column of its own (see its
            # module docstring: router-scoped only) -- join through Router
            # to scope it, the same "join to the owning tenant row" pattern
            # app.domains.guest.repository's own analytics queries use.
            statement = statement.join(
                Router, Router.id == RouterEvent.router_id
            ).where(Router.organization_id == organization_id)
        if start is not None:
            statement = statement.where(RouterEvent.occurred_at >= start)
        if end is not None:
            statement = statement.where(RouterEvent.occurred_at <= end)
        statement = statement.order_by(RouterEvent.occurred_at.desc()).limit(limit)
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    # -- FreeRADIUS proxy signal (composes with app.domains.guest) ------------

    async def count_active_radius_nas_clients(self) -> int:
        statement = (
            select(func.count())
            .select_from(RadiusNasClient)
            .where(
                RadiusNasClient.is_active.is_(True),
                RadiusNasClient.is_deleted.is_(False),
            )
        )
        result = await self.session.execute(statement)
        return int(result.scalar_one())

    async def get_latest_guest_accounting_activity(self) -> datetime | None:
        statement = select(func.max(GuestSession.last_activity_at)).where(
            GuestSession.is_deleted.is_(False)
        )
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()

    # -- WireGuard proxy signal (composes with app.domains.wireguard) --------

    async def list_wireguard_peers(self) -> list[WireGuardPeer]:
        statement = select(WireGuardPeer).where(WireGuardPeer.is_deleted.is_(False))
        result = await self.session.execute(statement)
        return list(result.scalars().all())


__all__ = [
    "MonitoringRepositoryProtocol",
    "MonitoringRepository",
]
