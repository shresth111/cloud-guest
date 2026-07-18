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
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from sqlalchemy import Integer, case, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PageParams, PaginationMeta, paginate
from app.domains.captive_portal.models import CaptivePortalConfig
from app.domains.guest.constants import GuestSessionStatus
from app.domains.guest.models import Guest, GuestLoginHistory, GuestSession
from app.domains.location.enums import LocationStatus
from app.domains.location.models import Location
from app.domains.monitoring.constants import AlertStatus
from app.domains.monitoring.models import Alert
from app.domains.organization.enums import OrganizationStatus
from app.domains.organization.models import Organization
from app.domains.otp.models import OtpRequest
from app.domains.router.models import Router
from app.domains.voucher.models import Voucher, VoucherBatch

from .models import AnalyticsSnapshot

# ============================================================================
# BE-012 Part 2: dashboard read-models
# ============================================================================


@dataclass(frozen=True, slots=True)
class OtpStatsRow:
    total_requests: int
    verified_count: int


@dataclass(frozen=True, slots=True)
class UserAgentBreakdown:
    """The result of classifying every non-``NULL``
    ``GuestSession.user_agent`` value within scope/window into device/
    browser/OS buckets via real SQL -- see
    ``AnalyticsRepository.get_user_agent_breakdown``'s own docstring for the
    exact classifier. ``sessions_total``/``sessions_with_user_agent`` are
    reported alongside the breakdown so a caller can honestly convey
    coverage (older sessions predating this column, or a guest device that
    omitted the header, are real ``NULL``s, never silently dropped without a
    trace)."""

    sessions_total: int
    sessions_with_user_agent: int
    by_os: list[tuple[str, int]]
    by_browser: list[tuple[str, int]]
    by_device_type: list[tuple[str, int]]


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

    # -- BE-012 Part 2: Super Admin Dashboard --------------------------------
    async def count_platform_guests_total(self) -> int: ...

    async def count_guest_sessions_total(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
    ) -> int: ...

    async def count_organizations_by_status(self) -> list[tuple[str, int]]: ...

    async def list_session_intervals(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> list[tuple[datetime, datetime | None]]: ...

    # -- BE-012 Part 2: Organization Dashboard --------------------------------
    async def get_auth_method_breakdown(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> list[tuple[str, bool, int]]: ...

    async def get_otp_stats(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> OtpStatsRow: ...

    async def get_voucher_status_counts(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
    ) -> dict[str, int]: ...

    async def count_captive_portal_configs(
        self, *, organization_id: uuid.UUID
    ) -> tuple[int, int]: ...

    async def get_open_alert_counts_by_severity(
        self, *, organization_id: uuid.UUID | None, since: datetime
    ) -> dict[str, int]: ...

    async def get_session_counts_by_hour(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> list[tuple[int, int]]: ...

    async def get_session_counts_by_day_of_week(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> list[tuple[int, int]]: ...

    # -- BE-012 Part 2: Location Dashboard -----------------------------------
    async def get_user_agent_breakdown(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID,
        start: datetime,
        end: datetime,
    ) -> UserAgentBreakdown: ...


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

    # ========================================================================
    # BE-012 Part 2: Super Admin Dashboard
    # ========================================================================

    async def count_platform_guests_total(self) -> int:
        """All-time, platform-wide distinct guest count -- a real ``COUNT``
        over ``Guest`` (one row per returning-guest identity, see
        ``app.domains.guest.models.Guest``'s own docstring), distinct from
        ``get_platform_guest_aggregate``'s *windowed* unique-guest count."""
        statement = (
            select(func.count()).select_from(Guest).where(Guest.is_deleted.is_(False))
        )
        result = await self.session.execute(statement)
        return int(result.scalar_one())

    async def count_guest_sessions_total(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
    ) -> int:
        statement = (
            select(func.count())
            .select_from(GuestSession)
            .where(GuestSession.is_deleted.is_(False))
        )
        if organization_id is not None:
            statement = statement.where(GuestSession.organization_id == organization_id)
        if location_id is not None:
            statement = statement.where(GuestSession.location_id == location_id)
        result = await self.session.execute(statement)
        return int(result.scalar_one())

    async def count_organizations_by_status(self) -> list[tuple[str, int]]:
        """Real SQL ``GROUP BY`` over ``Organization.status`` -- the
        honest, real-data mechanism behind "Trial Customers"/"Paid
        Customers" (see ``dashboard_service.py``'s own docstring for exactly
        how these two counts are derived from this, and why, given
        ``Organization.subscription_tier`` is not populated anywhere in this
        codebase's real data paths -- see that field's own module
        docstring)."""
        statement = (
            select(Organization.status, func.count())
            .where(Organization.is_deleted.is_(False))
            .group_by(Organization.status)
        )
        result = await self.session.execute(statement)
        return [(row[0], int(row[1])) for row in result.all()]

    async def list_session_intervals(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> list[tuple[datetime, datetime | None]]:
        """Fetches only the two datetime columns of every ``GuestSession``
        whose interval could possibly overlap ``[start, end]`` -- a real,
        bounded SQL filter (never every row ever created) feeding
        ``peak_concurrency.compute_peak_concurrent_sessions``'s pure sweep-
        line. See that module's own docstring for why the sweep itself is a
        Python function rather than a single SQL aggregate."""
        statement = select(GuestSession.started_at, GuestSession.ended_at).where(
            GuestSession.is_deleted.is_(False),
            GuestSession.started_at <= end,
            (GuestSession.ended_at.is_(None)) | (GuestSession.ended_at >= start),
        )
        if organization_id is not None:
            statement = statement.where(GuestSession.organization_id == organization_id)
        if location_id is not None:
            statement = statement.where(GuestSession.location_id == location_id)
        result = await self.session.execute(statement)
        return [(row[0], row[1]) for row in result.all()]

    # ========================================================================
    # BE-012 Part 2: Organization Dashboard
    # ========================================================================

    async def get_auth_method_breakdown(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> list[tuple[str, bool, int]]:
        """Real SQL ``GROUP BY (auth_method, success)`` over
        ``app.domains.guest.models.GuestLoginHistory`` -- the "Authentication
        Summary"/"Authentication Methods" bullet, composing with the same
        table ``app.domains.guest.service.GuestAnalyticsService
        .get_otp_success_rate`` already reads (never re-derived from
        ``otp_requests``/``vouchers`` directly)."""
        statement = (
            select(
                GuestLoginHistory.auth_method,
                GuestLoginHistory.success,
                func.count(),
            )
            .where(
                GuestLoginHistory.is_deleted.is_(False),
                GuestLoginHistory.organization_id == organization_id,
                GuestLoginHistory.attempted_at >= start,
                GuestLoginHistory.attempted_at <= end,
            )
            .group_by(GuestLoginHistory.auth_method, GuestLoginHistory.success)
        )
        if location_id is not None:
            statement = statement.where(GuestLoginHistory.location_id == location_id)
        result = await self.session.execute(statement)
        return [(row[0], bool(row[1]), int(row[2])) for row in result.all()]

    async def get_otp_stats(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> OtpStatsRow:
        """Real aggregate over ``app.domains.otp.models.OtpRequest`` directly
        (that domain has no organization-scoped stats method of its own to
        compose with -- see ``repository.py``'s module docstring for the
        established "read another domain's table directly for a narrow,
        read-only aggregate" precedent this follows). Scoped by
        ``OtpRequest.organization_id``/``location_id`` and ``created_at``
        (when the code was requested), not ``expires_at``."""
        statement = select(
            func.count(),
            func.count().filter(OtpRequest.is_consumed.is_(True)),
        ).where(
            OtpRequest.is_deleted.is_(False),
            OtpRequest.organization_id == organization_id,
            OtpRequest.created_at >= start,
            OtpRequest.created_at <= end,
        )
        if location_id is not None:
            statement = statement.where(OtpRequest.location_id == location_id)
        result = await self.session.execute(statement)
        total, verified = result.one()
        return OtpStatsRow(
            total_requests=int(total or 0), verified_count=int(verified or 0)
        )

    async def get_voucher_status_counts(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
    ) -> dict[str, int]:
        """A current-state snapshot (not time-windowed, mirroring
        ``app.domains.voucher.service.VoucherService.get_batch_stats``'s own
        non-windowed design -- a voucher's status is a live fact, not a
        per-day rollup) -- real ``GROUP BY`` over
        ``app.domains.voucher.models.Voucher`` joined to its owning
        ``VoucherBatch`` for organization/location scoping, since ``Voucher``
        itself carries no tenant columns of its own."""
        statement = (
            select(Voucher.status, func.count())
            .select_from(Voucher)
            .join(VoucherBatch, VoucherBatch.id == Voucher.batch_id)
            .where(
                Voucher.is_deleted.is_(False),
                VoucherBatch.organization_id == organization_id,
            )
            .group_by(Voucher.status)
        )
        if location_id is not None:
            statement = statement.where(VoucherBatch.location_id == location_id)
        result = await self.session.execute(statement)
        return {status_value: int(count) for status_value, count in result.all()}

    async def count_captive_portal_configs(
        self, *, organization_id: uuid.UUID
    ) -> tuple[int, int]:
        """Returns ``(active_count, total_count)`` -- see
        ``dashboard_service.py``'s own docstring for why "Captive Portal
        Usage" is defined as guest-login volume under the organization
        rather than a per-config view/impression count nothing in this
        codebase tracks; this real, direct count of configured portals is
        included alongside that for context."""
        total_statement = (
            select(func.count())
            .select_from(CaptivePortalConfig)
            .where(
                CaptivePortalConfig.is_deleted.is_(False),
                CaptivePortalConfig.organization_id == organization_id,
            )
        )
        total = int((await self.session.execute(total_statement)).scalar_one())
        active_statement = total_statement.where(
            CaptivePortalConfig.is_active.is_(True)
        )
        active = int((await self.session.execute(active_statement)).scalar_one())
        return active, total

    async def get_open_alert_counts_by_severity(
        self, *, organization_id: uuid.UUID | None, since: datetime
    ) -> dict[str, int]:
        """Real ``GROUP BY`` over ``app.domains.monitoring.models.Alert`` for
        currently-open (non-``RESOLVED``) alerts triggered on/after
        ``since`` -- the Organization Health Score's alert-severity input
        (see ``health_score.py``)."""
        statement = (
            select(Alert.severity, func.count())
            .where(
                Alert.is_deleted.is_(False),
                Alert.status != AlertStatus.RESOLVED.value,
                Alert.triggered_at >= since,
            )
            .group_by(Alert.severity)
        )
        if organization_id is not None:
            statement = statement.where(Alert.organization_id == organization_id)
        result = await self.session.execute(statement)
        return {severity: int(count) for severity, count in result.all()}

    async def get_session_counts_by_hour(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> list[tuple[int, int]]:
        """Real SQL ``GROUP BY EXTRACT(HOUR FROM started_at)`` -- "Peak
        Hours" (0-23, UTC, matching every other timestamp column in this
        codebase)."""
        hour = cast(func.extract("hour", GuestSession.started_at), Integer)
        statement = (
            select(hour, func.count())
            .where(
                GuestSession.is_deleted.is_(False),
                GuestSession.organization_id == organization_id,
                GuestSession.started_at >= start,
                GuestSession.started_at <= end,
            )
            .group_by(hour)
        )
        if location_id is not None:
            statement = statement.where(GuestSession.location_id == location_id)
        result = await self.session.execute(statement)
        return [(int(row[0]), int(row[1])) for row in result.all()]

    async def get_session_counts_by_day_of_week(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> list[tuple[int, int]]:
        """Real SQL ``GROUP BY EXTRACT(DOW FROM started_at)`` -- "Peak Days"
        (Postgres ``DOW``: ``0`` = Sunday .. ``6`` = Saturday, UTC)."""
        dow = cast(func.extract("dow", GuestSession.started_at), Integer)
        statement = (
            select(dow, func.count())
            .where(
                GuestSession.is_deleted.is_(False),
                GuestSession.organization_id == organization_id,
                GuestSession.started_at >= start,
                GuestSession.started_at <= end,
            )
            .group_by(dow)
        )
        if location_id is not None:
            statement = statement.where(GuestSession.location_id == location_id)
        result = await self.session.execute(statement)
        return [(int(row[0]), int(row[1])) for row in result.all()]

    # ========================================================================
    # BE-012 Part 2: Location Dashboard
    # ========================================================================

    async def get_user_agent_breakdown(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID,
        start: datetime,
        end: datetime,
    ) -> UserAgentBreakdown:
        """Classifies every non-``NULL`` ``GuestSession.user_agent`` in
        scope/window into OS/browser/device-type buckets via real SQL
        ``CASE``/regex matching (Postgres ``~*`` -- case-insensitive regex
        match), then ``GROUP BY``/``COUNT`` -- never a Python-side per-row
        parsing loop (see ``app.domains.guest.models.GuestSession
        .user_agent``'s docstring for why the raw string, not a pre-parsed
        column, is what is stored; this is where the parsing actually
        happens, at read time).

        **This is a small, honest heuristic classifier, not a
        specification-compliant User-Agent parser.** It recognizes the
        common, high-frequency patterns real browsers/OSes/devices send
        (checked most-specific-first, e.g. iPadOS/iPhone before generic
        Mobile, Edge/Opera before Chrome, since both Edge and Opera also
        include "Chrome" in their own UA strings) and buckets anything else
        as ``"Other"`` -- see ``docs/analytics/FLOW.md`` for the exact
        decision to write this by hand rather than add a
        ``user-agents``-style parsing dependency for this one, narrow
        analytics slice.
        """
        os_case = case(
            (GuestSession.user_agent.op("~*")("iPhone|iPad|iPod|iOS"), "iOS"),
            (GuestSession.user_agent.op("~*")("Android"), "Android"),
            (GuestSession.user_agent.op("~*")("Windows"), "Windows"),
            (
                GuestSession.user_agent.op("~*")("Macintosh|Mac OS X"),
                "macOS",
            ),
            (GuestSession.user_agent.op("~*")("Linux"), "Linux"),
            else_="Other",
        )
        browser_case = case(
            (GuestSession.user_agent.op("~*")("EdgiOS|Edge|Edg/"), "Edge"),
            (GuestSession.user_agent.op("~*")("OPR/|Opera"), "Opera"),
            (
                GuestSession.user_agent.op("~*")("CriOS|Chrome"),
                "Chrome",
            ),
            (
                GuestSession.user_agent.op("~*")("FxiOS|Firefox"),
                "Firefox",
            ),
            (
                GuestSession.user_agent.op("~*")("Safari")
                & ~GuestSession.user_agent.op("~*")("Chrome|CriOS|Chromium"),
                "Safari",
            ),
            else_="Other",
        )
        device_type_case = case(
            (GuestSession.user_agent.op("~*")("iPad|Tablet"), "Tablet"),
            (
                GuestSession.user_agent.op("~*")("Mobile|iPhone|Android"),
                "Mobile",
            ),
            else_="Desktop",
        )

        base_filters = [
            GuestSession.is_deleted.is_(False),
            GuestSession.organization_id == organization_id,
            GuestSession.location_id == location_id,
            GuestSession.started_at >= start,
            GuestSession.started_at <= end,
        ]

        total_statement = (
            select(func.count()).select_from(GuestSession).where(*base_filters)
        )
        sessions_total = int((await self.session.execute(total_statement)).scalar_one())

        with_ua_filters = [*base_filters, GuestSession.user_agent.is_not(None)]
        with_ua_statement = (
            select(func.count()).select_from(GuestSession).where(*with_ua_filters)
        )
        sessions_with_user_agent = int(
            (await self.session.execute(with_ua_statement)).scalar_one()
        )

        os_result = await self.session.execute(
            select(os_case, func.count()).where(*with_ua_filters).group_by(os_case)
        )
        browser_result = await self.session.execute(
            select(browser_case, func.count())
            .where(*with_ua_filters)
            .group_by(browser_case)
        )
        device_result = await self.session.execute(
            select(device_type_case, func.count())
            .where(*with_ua_filters)
            .group_by(device_type_case)
        )

        return UserAgentBreakdown(
            sessions_total=sessions_total,
            sessions_with_user_agent=sessions_with_user_agent,
            by_os=[(row[0], int(row[1])) for row in os_result.all()],
            by_browser=[(row[0], int(row[1])) for row in browser_result.all()],
            by_device_type=[(row[0], int(row[1])) for row in device_result.all()],
        )


__all__ = [
    "AnalyticsRepositoryProtocol",
    "AnalyticsRepository",
    "OtpStatsRow",
    "UserAgentBreakdown",
]
