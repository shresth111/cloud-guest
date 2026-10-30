"""Venue insights for the customer (venue-owner) dashboard.

Four read-only aggregates, each computed straight from rows this platform
already records -- nothing is estimated, sampled or back-filled:

* **Peak hours** -- ``guest_sessions.started_at`` bucketed by ISO weekday x
  hour in the venue's own timezone.
* **Guest mix** -- of the distinct guests with a session at this location in
  the window, how many had a session *at this location* before the window
  started ("returning") and how many did not ("new"). This is deliberately
  not ``Guest.total_visit_count > 1`` (what ``GET /analytics/guests`` uses):
  that counter is lifetime and organization-wide, so a guest first seen in
  the window who then came back twice is "returning" there. Repeat-visit
  rate is the share of the window's guests who came on two or more
  different local calendar days.
* **Login funnel** -- OTP codes requested -> verified (``otp_requests``) ->
  signed in (successful ``guest_login_history`` rows for an OTP method,
  written only after the guest session exists). Two stages are reported
  as unavailable, not guessed:

  - *Portal opened*: no table records a captive-portal page view.
  - *Internet confirmed*: the hotspot-gate dispatch that opens the network
    is fire-and-forget and its outcome is not stored, and per-session byte
    counters come only from RADIUS accounting, which bypassed (authorized-
    MAC) guests never produce -- so "0 bytes" would mislabel most of the
    fleet's working sessions as failures.

  The login-method split is ``guest_login_history`` grouped by
  ``auth_method``.
* **Location comparison** -- per location in the organization: distinct
  guests and sessions in the window, and router liveness *now* (the same
  ``compute_internet_availability`` rule every other screen uses). Uptime
  over the window is not offered: no per-router state history is kept that
  covers the whole fleet.

## Tenant scoping

Every method takes the organization id the permission check resolved
(``RequireOrganization``, never a caller-supplied id) and, for the
location-scoped ones, first proves the location belongs to that
organization (``get_location_context`` returns ``None`` otherwise, which
the service turns into a 404 indistinguishable from "no such location").
All SQL filters on both ids anyway. There is no ``organization_id=None``
code path: an "all organizations" caller is rejected by
``RequireOrganization`` before reaching here.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import (
    Date,
    and_,
    case,
    cast,
    distinct,
    exists,
    func,
    or_,
    select,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.guest.constants import GuestAuthMethod
from app.domains.guest.models import GuestLoginHistory, GuestSession
from app.domains.location.exceptions import LocationNotFoundError
from app.domains.location.models import Location
from app.domains.organization.models import Organization
from app.domains.otp.constants import OtpPurpose
from app.domains.otp.models import OtpRequest
from app.domains.router.enums import RouterStatus
from app.domains.router.fleet_scope import agent_managed_only
from app.domains.router.models import Router

from .exceptions import AnalyticsError
from .router_availability import compute_internet_availability
from .venue_insight_schemas import (
    FunnelStageUnavailable,
    GuestMixResponse,
    LocationComparisonItem,
    LocationComparisonResponse,
    LoginFunnelResponse,
    LoginMethodItem,
    PeakHourCell,
    PeakHoursResponse,
)

DEFAULT_WINDOW_DAYS = 28
MAX_WINDOW_DAYS = 92

OTP_AUTH_METHODS: tuple[str, ...] = (
    GuestAuthMethod.OTP_SMS.value,
    GuestAuthMethod.OTP_EMAIL.value,
    GuestAuthMethod.OTP_WHATSAPP.value,
)

PORTAL_OPENED_MESSAGE = (
    "Not recorded: the platform does not log captive-portal page views, so "
    "guests who opened the portal and left are not counted anywhere."
)
INTERNET_CONFIRMED_MESSAGE = (
    "Not recorded: whether the router actually let a signed-in guest onto "
    "the internet is not stored per session."
)


class InvalidInsightWindowError(AnalyticsError):
    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=422)


# ============================================================================
# Pure helpers
# ============================================================================


def resolve_window(
    start: datetime | None, end: datetime | None, *, now: datetime | None = None
) -> tuple[datetime, datetime]:
    """``[start, end)`` in UTC. Defaults to the trailing
    ``DEFAULT_WINDOW_DAYS``; rejects inverted or over-long windows. A naive
    datetime is read as UTC."""

    def _utc(value: datetime | None) -> datetime | None:
        if value is None or value.tzinfo is not None:
            return value
        return value.replace(tzinfo=UTC)

    start, end = _utc(start), _utc(end)
    resolved_end = end or (now or datetime.now(UTC))
    resolved_start = start or resolved_end - timedelta(days=DEFAULT_WINDOW_DAYS)
    if resolved_start >= resolved_end:
        raise InvalidInsightWindowError("start_date must be before end_date")
    if resolved_end - resolved_start > timedelta(days=MAX_WINDOW_DAYS):
        raise InvalidInsightWindowError(
            f"The window may be at most {MAX_WINDOW_DAYS} days"
        )
    return resolved_start, resolved_end


def resolve_timezone(location_tz: str | None, organization_tz: str | None) -> str:
    """The venue's IANA timezone. ``Location.timezone`` defaults to "UTC" on
    creation, so a location still on "UTC" defers to its organization's
    timezone when that is set to something else. Unknown names fall back
    to UTC rather than failing the request."""
    for candidate in (location_tz, organization_tz):
        if candidate and candidate != "UTC" and _is_valid_tz(candidate):
            return candidate
    return "UTC"


def _is_valid_tz(name: str) -> bool:
    try:
        ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        return False
    return True


def percent(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return round(numerator * 100.0 / denominator, 1)


# ============================================================================
# Repository
# ============================================================================


@dataclass(frozen=True)
class LocationContext:
    location_id: uuid.UUID
    timezone: str


@dataclass(frozen=True)
class GuestMixRow:
    unique_guests: int
    returning_guests: int
    multi_visit_guests: int
    sessions: int
    history_starts_at: datetime | None


@dataclass(frozen=True)
class OtpFunnelRow:
    codes_sent: int
    requested_identifiers: int
    verified_identifiers: int
    signed_in_identifiers: int


@dataclass(frozen=True)
class LoginMethodRow:
    auth_method: str
    successful: int
    failed: int
    guests: int


@dataclass(frozen=True)
class LocationActivityRow:
    location_id: uuid.UUID
    location_name: str
    guests: int
    sessions: int


@dataclass(frozen=True)
class RouterLivenessRow:
    location_id: uuid.UUID
    status: str
    last_seen_at: datetime | None


class VenueInsightsRepositoryProtocol(Protocol):
    async def get_location_context(
        self, *, organization_id: uuid.UUID, location_id: uuid.UUID
    ) -> LocationContext | None: ...

    async def get_peak_hour_cells(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID,
        timezone: str,
        start: datetime,
        end: datetime,
    ) -> list[tuple[int, int, int, int]]: ...

    async def get_guest_mix(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID,
        timezone: str,
        start: datetime,
        end: datetime,
    ) -> GuestMixRow: ...

    async def get_otp_funnel(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID,
        start: datetime,
        end: datetime,
    ) -> OtpFunnelRow: ...

    async def get_login_methods(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID,
        start: datetime,
        end: datetime,
    ) -> list[LoginMethodRow]: ...

    async def get_location_activity(
        self, *, organization_id: uuid.UUID, start: datetime, end: datetime
    ) -> list[LocationActivityRow]: ...

    async def get_router_liveness(
        self, *, organization_id: uuid.UUID
    ) -> list[RouterLivenessRow]: ...


class VenueInsightsRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    @staticmethod
    def _session_scope(
        organization_id: uuid.UUID,
        location_id: uuid.UUID,
        start: datetime,
        end: datetime,
    ) -> tuple:
        return (
            GuestSession.organization_id == organization_id,
            GuestSession.location_id == location_id,
            GuestSession.is_deleted.is_(False),
            GuestSession.started_at >= start,
            GuestSession.started_at < end,
        )

    async def get_location_context(
        self, *, organization_id: uuid.UUID, location_id: uuid.UUID
    ) -> LocationContext | None:
        statement = (
            select(Location.id, Location.timezone, Organization.timezone)
            .join(Organization, Organization.id == Location.organization_id)
            .where(
                Location.id == location_id,
                Location.organization_id == organization_id,
                Location.is_deleted.is_(False),
            )
        )
        row = (await self.session.execute(statement)).one_or_none()
        if row is None:
            return None
        return LocationContext(
            location_id=row[0], timezone=resolve_timezone(row[1], row[2])
        )

    async def get_peak_hour_cells(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID,
        timezone: str,
        start: datetime,
        end: datetime,
    ) -> list[tuple[int, int, int, int]]:
        local = func.timezone(timezone, GuestSession.started_at)
        weekday = func.extract("isodow", local)
        hour = func.extract("hour", local)
        statement = (
            select(
                weekday,
                hour,
                func.count(GuestSession.id),
                func.count(distinct(GuestSession.guest_id)),
            )
            .where(*self._session_scope(organization_id, location_id, start, end))
            .group_by(weekday, hour)
        )
        rows = (await self.session.execute(statement)).all()
        return [(int(d), int(h), int(s), int(g)) for d, h, s, g in rows]

    async def get_guest_mix(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID,
        timezone: str,
        start: datetime,
        end: datetime,
    ) -> GuestMixRow:
        local_day = cast(func.timezone(timezone, GuestSession.started_at), Date)
        per_guest = (
            select(
                GuestSession.guest_id.label("guest_id"),
                func.count(GuestSession.id).label("sessions"),
                func.count(distinct(local_day)).label("visit_days"),
            )
            .where(*self._session_scope(organization_id, location_id, start, end))
            .group_by(GuestSession.guest_id)
            .subquery()
        )
        earlier = GuestSession.__table__.alias("earlier")
        seen_before = exists(
            select(1).where(
                earlier.c.guest_id == per_guest.c.guest_id,
                earlier.c.organization_id == organization_id,
                earlier.c.location_id == location_id,
                earlier.c.is_deleted.is_(False),
                earlier.c.started_at < start,
            )
        )
        statement = select(
            func.count(per_guest.c.guest_id),
            func.coalesce(func.sum(case((seen_before, 1), else_=0)), 0),
            func.coalesce(func.sum(case((per_guest.c.visit_days >= 2, 1), else_=0)), 0),
            func.coalesce(func.sum(per_guest.c.sessions), 0),
        )
        unique, returning, multi, sessions = (
            await self.session.execute(statement)
        ).one()

        history_statement = select(func.min(GuestSession.started_at)).where(
            GuestSession.organization_id == organization_id,
            GuestSession.location_id == location_id,
            GuestSession.is_deleted.is_(False),
        )
        history_starts_at = (
            await self.session.execute(history_statement)
        ).scalar_one_or_none()
        return GuestMixRow(
            unique_guests=int(unique or 0),
            returning_guests=int(returning or 0),
            multi_visit_guests=int(multi or 0),
            sessions=int(sessions or 0),
            history_starts_at=history_starts_at,
        )

    async def get_otp_funnel(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID,
        start: datetime,
        end: datetime,
    ) -> OtpFunnelRow:
        # OtpRequest.organization_id is whatever the portal sent and may be
        # NULL; the location (already proven to belong to this organization)
        # is the tenant boundary here. A row naming a *different*
        # organization is still excluded.
        otp_statement = select(
            func.count(OtpRequest.id),
            func.count(distinct(OtpRequest.identifier)),
            func.count(distinct(OtpRequest.identifier)).filter(
                OtpRequest.verified_at.is_not(None)
            ),
        ).where(
            OtpRequest.location_id == location_id,
            or_(
                OtpRequest.organization_id == organization_id,
                OtpRequest.organization_id.is_(None),
            ),
            OtpRequest.purpose == OtpPurpose.GUEST_LOGIN.value,
            OtpRequest.is_deleted.is_(False),
            OtpRequest.created_at >= start,
            OtpRequest.created_at < end,
        )
        sent, requested, verified = (await self.session.execute(otp_statement)).one()

        signed_in_statement = select(
            func.count(distinct(GuestLoginHistory.identifier))
        ).where(
            GuestLoginHistory.organization_id == organization_id,
            GuestLoginHistory.location_id == location_id,
            GuestLoginHistory.is_deleted.is_(False),
            GuestLoginHistory.success.is_(True),
            GuestLoginHistory.auth_method.in_(OTP_AUTH_METHODS),
            GuestLoginHistory.attempted_at >= start,
            GuestLoginHistory.attempted_at < end,
        )
        signed_in = (await self.session.execute(signed_in_statement)).scalar_one()
        return OtpFunnelRow(
            codes_sent=int(sent or 0),
            requested_identifiers=int(requested or 0),
            verified_identifiers=int(verified or 0),
            signed_in_identifiers=int(signed_in or 0),
        )

    async def get_login_methods(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID,
        start: datetime,
        end: datetime,
    ) -> list[LoginMethodRow]:
        success = GuestLoginHistory.success.is_(True)
        statement = (
            select(
                GuestLoginHistory.auth_method,
                func.count(GuestLoginHistory.id).filter(success),
                func.count(GuestLoginHistory.id).filter(~success),
                func.count(distinct(GuestLoginHistory.identifier)).filter(success),
            )
            .where(
                GuestLoginHistory.organization_id == organization_id,
                GuestLoginHistory.location_id == location_id,
                GuestLoginHistory.is_deleted.is_(False),
                GuestLoginHistory.attempted_at >= start,
                GuestLoginHistory.attempted_at < end,
            )
            .group_by(GuestLoginHistory.auth_method)
        )
        rows = (await self.session.execute(statement)).all()
        return [
            LoginMethodRow(
                auth_method=str(method),
                successful=int(ok or 0),
                failed=int(bad or 0),
                guests=int(guests or 0),
            )
            for method, ok, bad, guests in rows
        ]

    async def get_location_activity(
        self, *, organization_id: uuid.UUID, start: datetime, end: datetime
    ) -> list[LocationActivityRow]:
        statement = (
            select(
                Location.id,
                Location.name,
                func.count(distinct(GuestSession.guest_id)),
                func.count(GuestSession.id),
            )
            .select_from(Location)
            .outerjoin(
                GuestSession,
                and_(
                    GuestSession.location_id == Location.id,
                    GuestSession.organization_id == organization_id,
                    GuestSession.is_deleted.is_(False),
                    GuestSession.started_at >= start,
                    GuestSession.started_at < end,
                ),
            )
            .where(
                Location.organization_id == organization_id,
                Location.is_deleted.is_(False),
            )
            .group_by(Location.id, Location.name)
        )
        rows = (await self.session.execute(statement)).all()
        return [
            LocationActivityRow(
                location_id=loc_id,
                location_name=name,
                guests=int(guests or 0),
                sessions=int(sessions or 0),
            )
            for loc_id, name, guests, sessions in rows
        ]

    async def get_router_liveness(
        self, *, organization_id: uuid.UUID
    ) -> list[RouterLivenessRow]:
        # Agent-managed rows only: `compute_internet_availability` judges a
        # router by heartbeat, and a controller-managed row (Omada, Aruba)
        # never heartbeats, so it would always read as offline. A venue
        # with only controller equipment comes back with zero routers here
        # and the card shows "status not reported", not "offline".
        statement = agent_managed_only(
            select(Router.location_id, Router.status, Router.last_seen_at).where(
                Router.organization_id == organization_id,
                Router.is_deleted.is_(False),
                Router.status != RouterStatus.DECOMMISSIONED.value,
            )
        )
        rows = (await self.session.execute(statement)).all()
        return [
            RouterLivenessRow(location_id=loc, status=str(status), last_seen_at=seen)
            for loc, status, seen in rows
        ]


# ============================================================================
# Service
# ============================================================================


class VenueInsightsService:
    def __init__(self, repository: VenueInsightsRepositoryProtocol) -> None:
        self.repository = repository

    async def _require_location(
        self, organization_id: uuid.UUID, location_id: uuid.UUID
    ) -> LocationContext:
        context = await self.repository.get_location_context(
            organization_id=organization_id, location_id=location_id
        )
        if context is None:
            # Same 404 for "does not exist" and "belongs to someone else":
            # the response must not reveal which.
            raise LocationNotFoundError(location_id)
        return context

    async def get_peak_hours(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID,
        start: datetime,
        end: datetime,
    ) -> PeakHoursResponse:
        context = await self._require_location(organization_id, location_id)
        rows = await self.repository.get_peak_hour_cells(
            organization_id=organization_id,
            location_id=location_id,
            timezone=context.timezone,
            start=start,
            end=end,
        )
        cells = sorted(
            (
                PeakHourCell(weekday=d, hour=h, sessions=s, guests=g)
                for d, h, s, g in rows
                if s > 0
            ),
            key=lambda c: (c.weekday, c.hour),
        )
        return PeakHoursResponse(
            location_id=location_id,
            timezone=context.timezone,
            window_start=start.isoformat(),
            window_end=end.isoformat(),
            total_sessions=sum(c.sessions for c in cells),
            cells=cells,
        )

    async def get_guest_mix(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID,
        start: datetime,
        end: datetime,
    ) -> GuestMixResponse:
        context = await self._require_location(organization_id, location_id)
        row = await self.repository.get_guest_mix(
            organization_id=organization_id,
            location_id=location_id,
            timezone=context.timezone,
            start=start,
            end=end,
        )
        returning = min(row.returning_guests, row.unique_guests)
        history = row.history_starts_at
        return GuestMixResponse(
            location_id=location_id,
            timezone=context.timezone,
            window_start=start.isoformat(),
            window_end=end.isoformat(),
            unique_guests=row.unique_guests,
            new_guests=row.unique_guests - returning,
            returning_guests=returning,
            sessions=row.sessions,
            multi_visit_guests=row.multi_visit_guests,
            repeat_visit_rate_percent=percent(
                row.multi_visit_guests, row.unique_guests
            ),
            history_starts_at=history.isoformat() if history else None,
            has_prior_history=history is not None and history < start,
        )

    async def get_login_funnel(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID,
        start: datetime,
        end: datetime,
    ) -> LoginFunnelResponse:
        await self._require_location(organization_id, location_id)
        otp = await self.repository.get_otp_funnel(
            organization_id=organization_id,
            location_id=location_id,
            start=start,
            end=end,
        )
        methods = await self.repository.get_login_methods(
            organization_id=organization_id,
            location_id=location_id,
            start=start,
            end=end,
        )
        return LoginFunnelResponse(
            location_id=location_id,
            window_start=start.isoformat(),
            window_end=end.isoformat(),
            otp_codes_sent=otp.codes_sent,
            otp_requested_guests=otp.requested_identifiers,
            otp_verified_guests=otp.verified_identifiers,
            otp_signed_in_guests=otp.signed_in_identifiers,
            portal_opened=FunnelStageUnavailable(message=PORTAL_OPENED_MESSAGE),
            internet_confirmed=FunnelStageUnavailable(
                message=INTERNET_CONFIRMED_MESSAGE
            ),
            methods=[
                LoginMethodItem(
                    auth_method=m.auth_method,
                    successful_logins=m.successful,
                    failed_logins=m.failed,
                    guests=m.guests,
                )
                for m in sorted(
                    methods, key=lambda m: (-m.successful, -m.failed, m.auth_method)
                )
            ],
        )

    async def get_location_comparison(
        self,
        *,
        organization_id: uuid.UUID,
        start: datetime,
        end: datetime,
        now: datetime | None = None,
    ) -> LocationComparisonResponse:
        activity = await self.repository.get_location_activity(
            organization_id=organization_id, start=start, end=end
        )
        routers = await self.repository.get_router_liveness(
            organization_id=organization_id
        )
        moment = now or datetime.now(UTC)
        totals: dict[uuid.UUID, list[int]] = {}
        last_seen: dict[uuid.UUID, datetime] = {}
        for router in routers:
            bucket = totals.setdefault(router.location_id, [0, 0])
            bucket[0] += 1
            if compute_internet_availability(
                status=router.status, last_seen_at=router.last_seen_at, now=moment
            ):
                bucket[1] += 1
            seen = router.last_seen_at
            if seen is not None and (
                router.location_id not in last_seen
                or seen > last_seen[router.location_id]
            ):
                last_seen[router.location_id] = seen
        items = [
            LocationComparisonItem(
                location_id=row.location_id,
                location_name=row.location_name,
                guests=row.guests,
                sessions=row.sessions,
                routers_total=totals.get(row.location_id, [0, 0])[0],
                routers_online=totals.get(row.location_id, [0, 0])[1],
                last_router_seen_at=(
                    last_seen[row.location_id].isoformat()
                    if row.location_id in last_seen
                    else None
                ),
            )
            for row in activity
        ]
        items.sort(key=lambda i: (-i.guests, -i.sessions, i.location_name.lower()))
        return LocationComparisonResponse(
            organization_id=organization_id,
            window_start=start.isoformat(),
            window_end=end.isoformat(),
            locations=items,
        )


__all__ = [
    "DEFAULT_WINDOW_DAYS",
    "MAX_WINDOW_DAYS",
    "InvalidInsightWindowError",
    "VenueInsightsRepository",
    "VenueInsightsRepositoryProtocol",
    "VenueInsightsService",
    "percent",
    "resolve_timezone",
    "resolve_window",
]
