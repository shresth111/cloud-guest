"""Data access layer for the Guest domain.

Mirrors ``app.domains.voucher.repository``'s shape: a ``Protocol``
describing the operations the service layer needs
(``GuestRepositoryProtocol``), and a concrete, ``GenericRepository``-backed
implementation (``GuestRepository``) wrapping six ``GenericRepository``
instances (one per table), plus hand-written ``select``/aggregate
statements for the queries ``GenericRepository``'s equality/IN-filter
support genuinely can't express: explicit ``IS NULL``-adjacent lookups
(most-recent-session-by-guest), the per-row-varying timeout comparison, and
every ``GuestAnalyticsService`` aggregate (``func.count``/``func.sum``/
``func.avg``, ``GROUP BY``) -- the exact kind of query that needs to scale
and must never be a Python-side loop over fetched rows.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.location.models import Location

from .constants import GuestSessionStatus
from .models import (
    Guest,
    GuestConsent,
    GuestDevice,
    GuestLoginHistory,
    GuestSession,
    RadiusNasClient,
)

# ============================================================================
# Analytics read-models (repository-layer return shapes -- service.py wraps
# these into its own public dataclasses)
# ============================================================================


@dataclass(frozen=True, slots=True)
class SessionAggregate:
    visitors: int
    unique_guests: int
    avg_duration_seconds: float | None
    total_bandwidth_bytes: int


@dataclass(frozen=True, slots=True)
class LocationSessionCount:
    location_id: uuid.UUID
    location_name: str
    session_count: int


@dataclass(frozen=True, slots=True)
class DeviceSessionCount:
    device_id: uuid.UUID
    mac_address: str
    session_count: int
    unique_guest_count: int


@dataclass(frozen=True, slots=True)
class AuthMethodOutcomeCounts:
    total_attempts: int
    successful_attempts: int


class GuestRepositoryProtocol(Protocol):
    # -- guests ----------------------------------------------------------------
    async def create_guest(self, **fields: object) -> Guest: ...

    async def get_guest_by_id(
        self, guest_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Guest | None: ...

    async def get_guest_by_identifier(
        self, organization_id: uuid.UUID, identifier: str
    ) -> Guest | None: ...

    async def update_guest(self, guest: Guest, data: dict[str, object]) -> Guest: ...

    async def list_guests(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        search: str | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[Guest], PaginationMeta]: ...

    # -- devices -----------------------------------------------------------------
    async def create_device(self, **fields: object) -> GuestDevice: ...

    async def get_device_by_id(self, device_id: uuid.UUID) -> GuestDevice | None: ...

    async def get_device_by_mac(self, mac_address: str) -> GuestDevice | None: ...

    async def update_device(
        self, device: GuestDevice, data: dict[str, object]
    ) -> GuestDevice: ...

    # -- sessions ------------------------------------------------------------------
    async def create_session(self, **fields: object) -> GuestSession: ...

    async def get_session_by_id(
        self, session_id: uuid.UUID, *, include_deleted: bool = False
    ) -> GuestSession | None: ...

    async def update_session(
        self, session: GuestSession, data: dict[str, object]
    ) -> GuestSession: ...

    async def list_sessions(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[GuestSession], PaginationMeta]: ...

    async def list_sessions_for_guest(
        self, guest_id: uuid.UUID, *, limit: int | None = None
    ) -> list[GuestSession]: ...

    async def get_latest_session_for_guest(
        self, guest_id: uuid.UUID
    ) -> GuestSession | None: ...

    async def get_latest_terminated_session_for_guest(
        self, guest_id: uuid.UUID
    ) -> GuestSession | None: ...

    async def count_active_sessions_for_guest(self, guest_id: uuid.UUID) -> int: ...

    async def list_timed_out_sessions(self, *, now: datetime) -> list[GuestSession]: ...

    # -- login history ---------------------------------------------------------
    async def create_login_history(self, **fields: object) -> GuestLoginHistory: ...

    # -- consents ----------------------------------------------------------------
    async def create_consent(self, **fields: object) -> GuestConsent: ...

    # -- RADIUS NAS clients --------------------------------------------------------
    async def create_nas_client(self, **fields: object) -> RadiusNasClient: ...

    async def get_nas_client_by_identifier(
        self, nas_identifier: str
    ) -> RadiusNasClient | None: ...

    async def get_nas_client_by_router(
        self, router_id: uuid.UUID
    ) -> RadiusNasClient | None: ...

    async def update_nas_client(
        self, nas_client: RadiusNasClient, data: dict[str, object]
    ) -> RadiusNasClient: ...

    # -- analytics -----------------------------------------------------------------
    async def get_session_aggregate(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> SessionAggregate: ...

    async def get_returning_guest_count(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> int: ...

    async def get_top_locations(
        self,
        *,
        organization_id: uuid.UUID,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> list[LocationSessionCount]: ...

    async def get_top_devices(
        self,
        *,
        organization_id: uuid.UUID,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> list[DeviceSessionCount]: ...

    async def get_login_history_outcome_counts(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
        auth_methods: Sequence[str],
    ) -> AuthMethodOutcomeCounts: ...

    async def get_session_auth_method_aggregate(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
        auth_method: str,
    ) -> SessionAggregate: ...


class GuestRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``GuestRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.guests = GenericRepository(Guest, session)
        self.devices = GenericRepository(GuestDevice, session)
        self.sessions = GenericRepository(GuestSession, session)
        self.login_history = GenericRepository(GuestLoginHistory, session)
        self.consents = GenericRepository(GuestConsent, session)
        self.nas_clients = GenericRepository(RadiusNasClient, session)

    # -- guests ----------------------------------------------------------------

    async def create_guest(self, **fields: object) -> Guest:
        return await self.guests.create(fields)

    async def get_guest_by_id(
        self, guest_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Guest | None:
        return await self.guests.get_by_id(guest_id, include_deleted=include_deleted)

    async def get_guest_by_identifier(
        self, organization_id: uuid.UUID, identifier: str
    ) -> Guest | None:
        results = await self.guests.get_all(
            filters={"organization_id": organization_id, "identifier": identifier},
            limit=1,
        )
        return results[0] if results else None

    async def update_guest(self, guest: Guest, data: dict[str, object]) -> Guest:
        return await self.guests.update(guest, data)

    async def list_guests(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        search: str | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[Guest], PaginationMeta]:
        if search:
            # GenericRepository.search has no pagination-meta return shape,
            # so a search query is a best-effort, capped list rather than a
            # paginated one -- acceptable for an admin free-text lookup.
            items = await self.guests.search(
                query=search,
                fields=["identifier", "display_name"],
                filters=filters,
                sort_by=sort_by,
                sort_order=sort_order,
                limit=page_size,
            )
            return items, PaginationMeta.from_total(
                PageParams(page=page, page_size=page_size), len(items)
            )
        return await self.guests.paginate(
            page=page,
            page_size=page_size,
            filters=filters,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    # -- devices -----------------------------------------------------------------

    async def create_device(self, **fields: object) -> GuestDevice:
        return await self.devices.create(fields)

    async def get_device_by_id(self, device_id: uuid.UUID) -> GuestDevice | None:
        return await self.devices.get_by_id(device_id)

    async def get_device_by_mac(self, mac_address: str) -> GuestDevice | None:
        results = await self.devices.get_all(
            filters={"mac_address": mac_address}, limit=1
        )
        return results[0] if results else None

    async def update_device(
        self, device: GuestDevice, data: dict[str, object]
    ) -> GuestDevice:
        return await self.devices.update(device, data)

    # -- sessions ------------------------------------------------------------------

    async def create_session(self, **fields: object) -> GuestSession:
        return await self.sessions.create(fields)

    async def get_session_by_id(
        self, session_id: uuid.UUID, *, include_deleted: bool = False
    ) -> GuestSession | None:
        return await self.sessions.get_by_id(
            session_id, include_deleted=include_deleted
        )

    async def update_session(
        self, session: GuestSession, data: dict[str, object]
    ) -> GuestSession:
        return await self.sessions.update(session, data)

    async def list_sessions(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[GuestSession], PaginationMeta]:
        return await self.sessions.paginate(
            page=page,
            page_size=page_size,
            filters=filters,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    async def list_sessions_for_guest(
        self, guest_id: uuid.UUID, *, limit: int | None = None
    ) -> list[GuestSession]:
        return await self.sessions.get_all(
            filters={"guest_id": guest_id},
            sort_by="started_at",
            sort_order=SortOrder.DESC,
            limit=limit,
        )

    async def get_latest_session_for_guest(
        self, guest_id: uuid.UUID
    ) -> GuestSession | None:
        results = await self.list_sessions_for_guest(guest_id, limit=1)
        return results[0] if results else None

    async def get_latest_terminated_session_for_guest(
        self, guest_id: uuid.UUID
    ) -> GuestSession | None:
        statement = (
            select(GuestSession)
            .where(
                GuestSession.guest_id == guest_id,
                GuestSession.status == GuestSessionStatus.TERMINATED.value,
                GuestSession.is_deleted.is_(False),
            )
            .order_by(GuestSession.ended_at.desc())
            .limit(1)
        )
        result = await self.session.execute(statement)
        return result.scalars().first()

    async def count_active_sessions_for_guest(self, guest_id: uuid.UUID) -> int:
        """Guest Session Engine (Phase 1): how many ``ACTIVE`` sessions
        ``guest_id`` currently holds -- backs
        ``GuestService._enforce_concurrent_session_limit``. A plain
        equality-filtered count ``GenericRepository.count`` already
        supports natively; no hand-written SQL needed, unlike
        ``get_batch_status_counts``'s grouped-count shape in
        ``app.domains.voucher.repository`` (that one needs a `GROUP BY`
        this single-status count does not)."""
        return await self.sessions.count(
            filters={
                "guest_id": guest_id,
                "status": GuestSessionStatus.ACTIVE.value,
            }
        )

    async def list_timed_out_sessions(self, *, now: datetime) -> list[GuestSession]:
        """Active sessions whose ``last_activity_at`` plus their own
        ``session_timeout_minutes`` has already passed ``now`` -- a
        per-row-varying comparison ``GenericRepository``'s equality-filter
        support cannot express, hence hand-written here. Uses Postgres's
        ``make_interval`` so the comparison happens entirely server-side
        (real SQL, not a Python-side scan) regardless of how many active
        sessions exist."""
        statement = select(GuestSession).where(
            GuestSession.status == GuestSessionStatus.ACTIVE.value,
            GuestSession.session_timeout_minutes.isnot(None),
            GuestSession.is_deleted.is_(False),
            GuestSession.last_activity_at
            + func.make_interval(0, 0, 0, 0, 0, GuestSession.session_timeout_minutes)
            < now,
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    # -- login history ---------------------------------------------------------

    async def create_login_history(self, **fields: object) -> GuestLoginHistory:
        return await self.login_history.create(fields)

    # -- consents ----------------------------------------------------------------

    async def create_consent(self, **fields: object) -> GuestConsent:
        return await self.consents.create(fields)

    # -- RADIUS NAS clients --------------------------------------------------------

    async def create_nas_client(self, **fields: object) -> RadiusNasClient:
        return await self.nas_clients.create(fields)

    async def get_nas_client_by_identifier(
        self, nas_identifier: str
    ) -> RadiusNasClient | None:
        results = await self.nas_clients.get_all(
            filters={"nas_identifier": nas_identifier}, limit=1
        )
        return results[0] if results else None

    async def get_nas_client_by_router(
        self, router_id: uuid.UUID
    ) -> RadiusNasClient | None:
        results = await self.nas_clients.get_all(
            filters={"router_id": router_id}, limit=1
        )
        return results[0] if results else None

    async def update_nas_client(
        self, nas_client: RadiusNasClient, data: dict[str, object]
    ) -> RadiusNasClient:
        return await self.nas_clients.update(nas_client, data)

    # -- analytics -----------------------------------------------------------------

    def _session_scope_clause(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> list[object]:
        clauses: list[object] = [
            GuestSession.organization_id == organization_id,
            GuestSession.started_at >= start,
            GuestSession.started_at <= end,
            GuestSession.is_deleted.is_(False),
        ]
        if location_id is not None:
            clauses.append(GuestSession.location_id == location_id)
        return clauses

    async def get_session_aggregate(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> SessionAggregate:
        duration_seconds = func.extract(
            "epoch",
            func.coalesce(GuestSession.ended_at, func.now()) - GuestSession.started_at,
        )
        statement = select(
            func.count(GuestSession.id),
            func.count(func.distinct(GuestSession.guest_id)),
            func.avg(duration_seconds),
            func.coalesce(
                func.sum(GuestSession.bytes_uploaded + GuestSession.bytes_downloaded),
                0,
            ),
        ).where(
            *self._session_scope_clause(
                organization_id=organization_id,
                location_id=location_id,
                start=start,
                end=end,
            )
        )
        result = await self.session.execute(statement)
        visitors, unique_guests, avg_duration, total_bandwidth = result.one()
        return SessionAggregate(
            visitors=int(visitors or 0),
            unique_guests=int(unique_guests or 0),
            avg_duration_seconds=float(avg_duration)
            if avg_duration is not None
            else None,
            total_bandwidth_bytes=int(total_bandwidth or 0),
        )

    async def get_returning_guest_count(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> int:
        statement = (
            select(func.count(func.distinct(GuestSession.guest_id)))
            .select_from(GuestSession)
            .join(Guest, Guest.id == GuestSession.guest_id)
            .where(
                *self._session_scope_clause(
                    organization_id=organization_id,
                    location_id=location_id,
                    start=start,
                    end=end,
                ),
                Guest.total_visit_count > 1,
            )
        )
        result = await self.session.execute(statement)
        return int(result.scalar_one() or 0)

    async def get_top_locations(
        self,
        *,
        organization_id: uuid.UUID,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> list[LocationSessionCount]:
        statement = (
            select(
                GuestSession.location_id,
                Location.name,
                func.count(GuestSession.id).label("session_count"),
            )
            .select_from(GuestSession)
            .join(Location, Location.id == GuestSession.location_id)
            .where(
                *self._session_scope_clause(
                    organization_id=organization_id,
                    location_id=None,
                    start=start,
                    end=end,
                )
            )
            .group_by(GuestSession.location_id, Location.name)
            .order_by(func.count(GuestSession.id).desc())
            .limit(limit)
        )
        result = await self.session.execute(statement)
        return [
            LocationSessionCount(
                location_id=location_id, location_name=name, session_count=int(count)
            )
            for location_id, name, count in result.all()
        ]

    async def get_top_devices(
        self,
        *,
        organization_id: uuid.UUID,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> list[DeviceSessionCount]:
        statement = (
            select(
                GuestSession.device_id,
                GuestDevice.mac_address,
                func.count(GuestSession.id).label("session_count"),
                func.count(func.distinct(GuestSession.guest_id)).label(
                    "unique_guest_count"
                ),
            )
            .select_from(GuestSession)
            .join(GuestDevice, GuestDevice.id == GuestSession.device_id)
            .where(
                *self._session_scope_clause(
                    organization_id=organization_id,
                    location_id=None,
                    start=start,
                    end=end,
                ),
                GuestSession.device_id.isnot(None),
            )
            .group_by(GuestSession.device_id, GuestDevice.mac_address)
            .order_by(func.count(GuestSession.id).desc())
            .limit(limit)
        )
        result = await self.session.execute(statement)
        return [
            DeviceSessionCount(
                device_id=row.device_id,
                mac_address=row.mac_address,
                session_count=int(row.session_count),
                unique_guest_count=int(row.unique_guest_count),
            )
            for row in result.all()
        ]

    async def get_login_history_outcome_counts(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
        auth_methods: Sequence[str],
    ) -> AuthMethodOutcomeCounts:
        clauses: list[object] = [
            GuestLoginHistory.organization_id == organization_id,
            GuestLoginHistory.attempted_at >= start,
            GuestLoginHistory.attempted_at <= end,
            GuestLoginHistory.auth_method.in_(list(auth_methods)),
            GuestLoginHistory.is_deleted.is_(False),
        ]
        if location_id is not None:
            clauses.append(GuestLoginHistory.location_id == location_id)
        statement = select(
            func.count(GuestLoginHistory.id),
            func.count(GuestLoginHistory.id).filter(
                GuestLoginHistory.success.is_(True)
            ),
        ).where(*clauses)
        result = await self.session.execute(statement)
        total, successful = result.one()
        return AuthMethodOutcomeCounts(
            total_attempts=int(total or 0), successful_attempts=int(successful or 0)
        )

    async def get_session_auth_method_aggregate(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
        auth_method: str,
    ) -> SessionAggregate:
        duration_seconds = func.extract(
            "epoch",
            func.coalesce(GuestSession.ended_at, func.now()) - GuestSession.started_at,
        )
        statement = select(
            func.count(GuestSession.id),
            func.count(func.distinct(GuestSession.guest_id)),
            func.avg(duration_seconds),
            func.coalesce(
                func.sum(GuestSession.bytes_uploaded + GuestSession.bytes_downloaded),
                0,
            ),
        ).where(
            *self._session_scope_clause(
                organization_id=organization_id,
                location_id=location_id,
                start=start,
                end=end,
            ),
            GuestSession.auth_method == auth_method,
        )
        result = await self.session.execute(statement)
        visitors, unique_guests, avg_duration, total_bandwidth = result.one()
        return SessionAggregate(
            visitors=int(visitors or 0),
            unique_guests=int(unique_guests or 0),
            avg_duration_seconds=float(avg_duration)
            if avg_duration is not None
            else None,
            total_bandwidth_bytes=int(total_bandwidth or 0),
        )


__all__ = [
    "GuestRepositoryProtocol",
    "GuestRepository",
    "SessionAggregate",
    "LocationSessionCount",
    "DeviceSessionCount",
    "AuthMethodOutcomeCounts",
]
