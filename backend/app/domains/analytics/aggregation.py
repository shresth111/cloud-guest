"""Real aggregation logic for the Analytics domain (BE-012 Part 1).

Deliberately kept separate from ``tasks.py``'s thin Celery-task wrappers so
this module stays testable as plain async code, independent of Celery --
every function here is exercised in ``tests/unit/test_analytics.py`` against
small, hand-rolled fakes, with no Celery worker, broker, or real
Postgres/Redis involved.

Every function below computes one snapshot type's ``metrics`` dict (see
``models.AnalyticsSnapshot``'s docstring for the exact schema) via **real
SQL aggregate queries** reached through injected, narrow protocols -- never
a Python-side loop summing values out of a bulk-fetched list. Guest
counts/session counts are computed by **reusing**
``app.domains.guest.service.GuestAnalyticsService.get_summary`` directly
(its own real ``GROUP BY``/``COUNT``/``AVG``/``SUM`` aggregate queries, per
this part's "compose, don't duplicate" mandate) rather than re-deriving the
same numbers from a second, parallel query against ``GuestSession``. Router
counts and the platform-wide guest aggregate (which
``GuestAnalyticsService.get_summary`` cannot itself produce -- its
``organization_id`` parameter is mandatory) are computed via
``AnalyticsRepositoryProtocol``'s own real ``GROUP BY``/``COUNT`` queries
(``repository.py``).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Protocol

from app.domains.router.enums import RouterStatus

from .repository import AnalyticsRepositoryProtocol


class GuestSummaryLike(Protocol):
    """The structural shape this module reads off whatever
    ``GuestAnalyticsLookupProtocol.get_summary`` returns -- satisfied by the
    real ``app.domains.guest.service.GuestAnalyticsSummary`` without
    importing that class, mirroring
    ``app.domains.monitoring.service._VisitorSummaryProtocol``'s identical
    duck-typed composition discipline."""

    visitors: int
    unique_guests: int
    returning_guests: int
    average_session_duration_seconds: float | None
    total_bandwidth_bytes: int


class GuestAnalyticsLookupProtocol(Protocol):
    """The single method this module needs from the real
    ``app.domains.guest.service.GuestAnalyticsService`` -- reused directly,
    never reimplemented."""

    async def get_summary(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> GuestSummaryLike: ...


def _router_counts(rows: list[tuple[str, int]]) -> tuple[int, int, int]:
    """Reduces a ``[(status, count), ...]`` ``GROUP BY`` result (real SQL,
    from ``AnalyticsRepositoryProtocol.count_routers_by_status``) into
    ``(online, offline, total)`` -- the only "loop over already-aggregated
    rows" this module does, over at most a handful of distinct
    ``RouterStatus`` values, never over individual router rows."""
    counts = dict(rows)
    online = counts.get(RouterStatus.ONLINE.value, 0)
    offline = counts.get(RouterStatus.OFFLINE.value, 0)
    total = sum(counts.values())
    return online, offline, total


async def compute_org_daily_summary(
    *,
    organization_id: uuid.UUID,
    period_start: datetime,
    period_end: datetime,
    guest_analytics: GuestAnalyticsLookupProtocol,
    repository: AnalyticsRepositoryProtocol,
) -> dict[str, Any]:
    """``ORG_DAILY_SUMMARY``: guest counts (new/returning/unique), session
    counts (total/active), router counts (online/offline) for one
    organization over one window."""
    summary = await guest_analytics.get_summary(
        organization_id=organization_id,
        location_id=None,
        start=period_start,
        end=period_end,
    )
    active_sessions = await repository.count_active_guest_sessions(
        organization_id=organization_id, location_id=None
    )
    router_rows = await repository.count_routers_by_status(
        organization_id=organization_id, location_id=None
    )
    online, offline, total_routers = _router_counts(router_rows)

    return {
        "guest_count_unique": summary.unique_guests,
        "guest_count_new": max(summary.unique_guests - summary.returning_guests, 0),
        "guest_count_returning": summary.returning_guests,
        "session_count_total": summary.visitors,
        "session_count_active": active_sessions,
        "average_session_duration_seconds": summary.average_session_duration_seconds,
        "total_bandwidth_bytes": summary.total_bandwidth_bytes,
        "router_count_online": online,
        "router_count_offline": offline,
        "router_count_total": total_routers,
    }


async def compute_location_daily_summary(
    *,
    organization_id: uuid.UUID,
    location_id: uuid.UUID,
    period_start: datetime,
    period_end: datetime,
    guest_analytics: GuestAnalyticsLookupProtocol,
    repository: AnalyticsRepositoryProtocol,
) -> dict[str, Any]:
    """``LOCATION_DAILY_SUMMARY``: the same shape as
    ``compute_org_daily_summary``, scoped to one location within one
    organization."""
    summary = await guest_analytics.get_summary(
        organization_id=organization_id,
        location_id=location_id,
        start=period_start,
        end=period_end,
    )
    active_sessions = await repository.count_active_guest_sessions(
        organization_id=organization_id, location_id=location_id
    )
    router_rows = await repository.count_routers_by_status(
        organization_id=organization_id, location_id=location_id
    )
    online, offline, total_routers = _router_counts(router_rows)

    return {
        "guest_count_unique": summary.unique_guests,
        "guest_count_new": max(summary.unique_guests - summary.returning_guests, 0),
        "guest_count_returning": summary.returning_guests,
        "session_count_total": summary.visitors,
        "session_count_active": active_sessions,
        "average_session_duration_seconds": summary.average_session_duration_seconds,
        "total_bandwidth_bytes": summary.total_bandwidth_bytes,
        "router_count_online": online,
        "router_count_offline": offline,
        "router_count_total": total_routers,
    }


async def compute_platform_daily_summary(
    *,
    period_start: datetime,
    period_end: datetime,
    repository: AnalyticsRepositoryProtocol,
) -> dict[str, Any]:
    """``PLATFORM_DAILY_SUMMARY``: platform-wide totals -- total
    organizations, total locations, total routers online/offline, total
    guests today. The Super Admin dashboard's later consumer."""
    organization_count = await repository.count_platform_organizations()
    location_count = await repository.count_platform_locations()
    router_rows = await repository.count_routers_by_status(
        organization_id=None, location_id=None
    )
    online, offline, total_routers = _router_counts(router_rows)
    session_count, unique_guest_count = await repository.get_platform_guest_aggregate(
        start=period_start, end=period_end
    )

    return {
        "organization_count_total": organization_count,
        "location_count_total": location_count,
        "router_count_online": online,
        "router_count_offline": offline,
        "router_count_total": total_routers,
        "guest_count_unique_today": unique_guest_count,
        "session_count_total_today": session_count,
    }


__all__ = [
    "GuestSummaryLike",
    "GuestAnalyticsLookupProtocol",
    "compute_org_daily_summary",
    "compute_location_daily_summary",
    "compute_platform_daily_summary",
]
