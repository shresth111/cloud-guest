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
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.constants import DEFAULT_SORT_FIELD, SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.location.models import Location
from app.domains.organization.models import Organization

from .constants import GuestSessionStatus
from .models import (
    Guest,
    GuestConsent,
    GuestDevice,
    GuestLoginHistory,
    GuestQuotaUsage,
    GuestSession,
    RadiusNasClient,
    RadiusNasCodeCounter,
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


@dataclass(frozen=True, slots=True)
class ActiveGuestOrgPair:
    """One distinct ``(guest_id, organization_id)`` pair drawn from
    currently ``ACTIVE`` ``GuestSession`` rows -- see
    ``GuestRepository.list_active_guest_org_pairs``'s own docstring."""

    guest_id: uuid.UUID
    organization_id: uuid.UUID


@dataclass(frozen=True, slots=True)
class QuotaUsageWithOrgTimezone:
    """A ``GuestQuotaUsage`` row paired with its own organization's
    ``timezone`` -- see ``GuestRepository
    .list_all_quota_usages_with_org_timezone``'s own docstring."""

    usage: GuestQuotaUsage
    organization_timezone: str


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

    async def count_devices_for_guest(self, guest_id: uuid.UUID) -> int: ...

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

    async def list_active_sessions_for_guest(
        self, guest_id: uuid.UUID
    ) -> list[GuestSession]: ...

    async def list_active_guest_org_pairs(self) -> list[ActiveGuestOrgPair]: ...

    # -- FUP quota usage ---------------------------------------------------------
    async def get_quota_usage(
        self, guest_id: uuid.UUID, period_type: str
    ) -> GuestQuotaUsage | None: ...

    async def create_quota_usage(self, **fields: object) -> GuestQuotaUsage: ...

    async def update_quota_usage(
        self, usage: GuestQuotaUsage, data: dict[str, object]
    ) -> GuestQuotaUsage: ...

    async def list_all_quota_usages_with_org_timezone(
        self,
    ) -> list[QuotaUsageWithOrgTimezone]: ...

    async def get_organization_timezone(self, organization_id: uuid.UUID) -> str: ...

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

    async def get_nas_client_by_id(
        self, nas_id: uuid.UUID, *, include_deleted: bool = False
    ) -> RadiusNasClient | None: ...

    async def update_nas_client(
        self, nas_client: RadiusNasClient, data: dict[str, object]
    ) -> RadiusNasClient: ...

    async def soft_delete_nas_client(
        self, nas_client: RadiusNasClient
    ) -> RadiusNasClient: ...

    async def list_nas_clients(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[RadiusNasClient], PaginationMeta]: ...

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

    async def list_login_history(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        guest_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
    ) -> tuple[list[GuestLoginHistory], PaginationMeta]: ...


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
        self.quota_usages = GenericRepository(GuestQuotaUsage, session)

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

    async def count_devices_for_guest(self, guest_id: uuid.UUID) -> int:
        """Guest Session Engine (Phase 1): how many distinct
        :class:`~.models.GuestDevice` rows currently belong to
        ``guest_id`` -- backs ``GuestService._enforce_device_limit``. A
        plain equality-filtered count, mirroring
        ``count_active_sessions_for_guest``'s identical shape."""
        return await self.devices.count(filters={"guest_id": guest_id})

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

    async def list_active_sessions_for_guest(
        self, guest_id: uuid.UUID
    ) -> list[GuestSession]:
        """Every currently ``ACTIVE`` session for ``guest_id`` -- backs
        ``tasks.run_fup_time_accrual_sweep``'s "disconnect every active
        session" step once a guest's cumulative time usage has just
        crossed a configured FUP limit."""
        return await self.sessions.get_all(
            filters={"guest_id": guest_id, "status": GuestSessionStatus.ACTIVE.value}
        )

    async def list_active_guest_org_pairs(self) -> list[ActiveGuestOrgPair]:
        """Every distinct ``(guest_id, organization_id)`` pair with at
        least one currently ``ACTIVE`` session -- backs
        ``tasks.run_fup_time_accrual_sweep``'s per-guest sweep loop.
        ``organization_id`` comes straight off ``GuestSession`` itself (see
        that model's own denormalization docstring) -- no join through
        ``guests`` needed at all."""
        statement = (
            select(GuestSession.guest_id, GuestSession.organization_id)
            .where(
                GuestSession.status == GuestSessionStatus.ACTIVE.value,
                GuestSession.is_deleted.is_(False),
            )
            .distinct()
        )
        result = await self.session.execute(statement)
        return [
            ActiveGuestOrgPair(guest_id=row[0], organization_id=row[1])
            for row in result.all()
        ]

    # -- FUP quota usage ---------------------------------------------------------

    async def get_quota_usage(
        self, guest_id: uuid.UUID, period_type: str
    ) -> GuestQuotaUsage | None:
        results = await self.quota_usages.get_all(
            filters={"guest_id": guest_id, "period_type": period_type}, limit=1
        )
        return results[0] if results else None

    async def create_quota_usage(self, **fields: object) -> GuestQuotaUsage:
        return await self.quota_usages.create(fields)

    async def update_quota_usage(
        self, usage: GuestQuotaUsage, data: dict[str, object]
    ) -> GuestQuotaUsage:
        return await self.quota_usages.update(usage, data)

    async def list_all_quota_usages_with_org_timezone(
        self,
    ) -> list[QuotaUsageWithOrgTimezone]:
        """Every non-deleted ``GuestQuotaUsage`` row, paired with its own
        organization's ``timezone`` in a single joined query -- backs
        ``tasks.run_quota_reset_sweep``'s proactive rollover walk, avoiding
        an N+1 organization lookup per row."""
        statement = select(GuestQuotaUsage, Organization.timezone).join(
            Organization, Organization.id == GuestQuotaUsage.organization_id
        )
        result = await self.session.execute(statement)
        return [
            QuotaUsageWithOrgTimezone(usage=row[0], organization_timezone=row[1])
            for row in result.all()
        ]

    async def get_organization_timezone(self, organization_id: uuid.UUID) -> str:
        """A single-column read of ``Organization.timezone`` -- used by the
        two request-triggered FUP call sites (login-time enforcement,
        ``record_usage``'s per-accounting-call bump) that only have an
        ``organization_id`` on hand, not a joined row. Falls back to
        ``"UTC"`` if the organization row is somehow missing (defensive;
        every caller's ``organization_id`` was already resolved via a real
        FK earlier in the same request) -- mirrors
        ``Organization.timezone``'s own ``default="UTC"``."""
        statement = select(Organization.timezone).where(
            Organization.id == organization_id
        )
        result = await self.session.execute(statement)
        timezone = result.scalar_one_or_none()
        return timezone or "UTC"

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

    async def get_nas_client_by_id(
        self, nas_id: uuid.UUID, *, include_deleted: bool = False
    ) -> RadiusNasClient | None:
        return await self.nas_clients.get_by_id(nas_id, include_deleted=include_deleted)

    async def update_nas_client(
        self, nas_client: RadiusNasClient, data: dict[str, object]
    ) -> RadiusNasClient:
        return await self.nas_clients.update(nas_client, data)

    async def soft_delete_nas_client(
        self, nas_client: RadiusNasClient
    ) -> RadiusNasClient:
        """GenericRepository.update() deliberately refuses to set
        is_deleted/deleted_at (see its `protected` fields) -- only this
        dedicated soft_delete() path actually flips them."""
        return await self.nas_clients.soft_delete(nas_client)

    async def list_nas_clients(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = DEFAULT_SORT_FIELD,
        sort_order: SortOrder = SortOrder.DESC,
    ) -> tuple[list[RadiusNasClient], PaginationMeta]:
        return await self.nas_clients.paginate(
            page=page,
            page_size=page_size,
            filters=filters,
            sort_by=sort_by,
            sort_order=sort_order,
        )

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

    async def list_login_history(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        guest_id: uuid.UUID | None = None,
        page: int,
        page_size: int,
    ) -> tuple[list[GuestLoginHistory], PaginationMeta]:
        """Real, paginated ``GuestLoginHistory`` read -- the tenant-scoped
        read source ``app.domains.controller_logs`` composes for its own
        "Authentication Logs" (guest side) category. Unlike
        ``app.domains.auth.LoginAttempt``, this table already carries
        ``organization_id``/``location_id``, so it is genuinely
        tenant-filterable."""
        filters: dict[str, object] = {}
        if organization_id is not None:
            filters["organization_id"] = organization_id
        if location_id is not None:
            filters["location_id"] = location_id
        if guest_id is not None:
            filters["guest_id"] = guest_id
        return await self.login_history.paginate(
            page=page,
            page_size=page_size,
            filters=filters or None,
            sort_by="attempted_at",
            sort_order=SortOrder.DESC,
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


class RadiusNasCodeCounterRepository:
    """Concrete, SQLAlchemy-backed implementation of
    ``nas_number_generator.NasCodeCounterRepositoryProtocol`` -- mirrors
    ``app.domains.location.repository.LocationCodeCounterRepository``
    exactly (see ``nas_number_generator.py``'s own module docstring for the
    full concurrency-safety write-up)."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def increment_and_get_next(self, counter_key: str) -> int:
        statement = (
            pg_insert(RadiusNasCodeCounter)
            .values(counter_key=counter_key, last_value=1)
            .on_conflict_do_update(
                index_elements=[RadiusNasCodeCounter.counter_key],
                set_={
                    "last_value": RadiusNasCodeCounter.last_value + 1,
                    "version": RadiusNasCodeCounter.version + 1,
                },
            )
            .returning(RadiusNasCodeCounter.last_value)
        )
        result = await self.session.execute(statement)
        await self.session.flush()
        return int(result.scalar_one())


__all__ = [
    "GuestRepositoryProtocol",
    "GuestRepository",
    "RadiusNasCodeCounterRepository",
    "SessionAggregate",
    "LocationSessionCount",
    "DeviceSessionCount",
    "AuthMethodOutcomeCounts",
]
