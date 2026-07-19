"""BE-012 Part 2: Super Admin + Organization + Location Dashboard business
logic.

``DashboardService`` composes, never re-derives: every number here comes
from either (a) an already-computed ``AnalyticsSnapshot`` row (Part 1's
whole reason for existing), (b) ``app.domains.guest.service
.GuestAnalyticsService``'s existing real aggregate queries, or (c) a new,
narrow, read-only cross-domain aggregate added to this domain's own
``repository.py`` (following the exact "read another domain's table
directly for a narrow composition" precedent that module already
establishes for ``Organization``/``Location``/``Router``/``GuestSession``).
Live aggregation is used only where a snapshot genuinely does not cover what
is needed (e.g. "right now" active-session counts, peak-concurrency, and
anything scoped to a partial "today so far" window) -- see each method's own
docstring for exactly which source backs which figure.

Every endpoint enforces :class:`~.dashboard_scope.DashboardScope` as a real,
second check (see that module's own docstring for why this matters beyond
RBAC's header-driven permission dependency) before touching any data.

## Dashboard-view auditing

See ``dashboard_audit.py``'s own module docstring for the full volume-
tiering write-up. Every dashboard view is logged via the structured logger
unconditionally; a durable ``audit_log_entries`` row is written at most once
per ``(user, dashboard kind, scope)`` per
``constants.DASHBOARD_AUDIT_THROTTLE_MINUTES``.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Protocol

from redis.asyncio import Redis

from app.domains.organization.enums import OrganizationStatus
from app.domains.router.enums import RouterStatus

from .aggregation import GuestAnalyticsLookupProtocol
from .constants import (
    AUDIT_ACTION_DASHBOARD_LOCATION_VIEWED,
    AUDIT_ACTION_DASHBOARD_ORGANIZATION_VIEWED,
    AUDIT_ACTION_DASHBOARD_SUPER_ADMIN_VIEWED,
    DEFAULT_GROWTH_LOOKBACK_DAYS,
    HEALTH_SCORE_ALERT_LOOKBACK_DAYS,
    MONTHLY_WINDOW_DAYS,
    WEEKLY_WINDOW_DAYS,
    AnalyticsSnapshotType,
)
from .dashboard_aggregation import (
    build_auth_method_breakdown,
    compute_growth,
    device_breakdown_response,
    growth_direction_to_health_direction,
    sum_metric_across_snapshots,
)
from .dashboard_audit import DashboardAuditThrottle
from .dashboard_schemas import (
    CountryStatisticsResponse,
    GrowthPointResponse,
    HealthScoreResponse,
    LocationDashboardResponse,
    OrganizationDashboardResponse,
    OrganizationSummaryItem,
    PeakDayItem,
    PeakHourItem,
    RevenueMetricsResponse,
    SuperAdminDashboardResponse,
)
from .dashboard_scope import (
    DashboardScopeResolver,
    LocationLookupProtocol,
    OrganizationLookupProtocol,
)
from .health_score import compute_health_score
from .peak_concurrency import compute_peak_concurrent_sessions
from .repository import AnalyticsRepositoryProtocol

logger = logging.getLogger(__name__)


class AuditLogWriter(Protocol):
    """The minimal surface this service needs to write into RBAC's shared
    ``audit_log_entries`` table -- the same narrow, duck-typed protocol
    shape every other domain's service defines for itself."""

    async def create_audit_log_entry(self, **fields: object) -> object: ...


def _reduce_router_counts(rows: list[tuple[str, int]]) -> tuple[int, int, int]:
    counts = dict(rows)
    online = counts.get(RouterStatus.ONLINE.value, 0)
    offline = counts.get(RouterStatus.OFFLINE.value, 0)
    total = sum(counts.values())
    return online, offline, total


def _growth_response(
    metric: str, current: float, previous: float | None
) -> GrowthPointResponse:
    point = compute_growth(metric=metric, current=current, previous=previous)
    return GrowthPointResponse(
        metric=point.metric,
        current_value=point.current_value,
        previous_value=point.previous_value,
        delta=point.delta,
        delta_percent=point.delta_percent,
        direction=point.direction.value,
    )


class DashboardService:
    def __init__(
        self,
        repository: AnalyticsRepositoryProtocol,
        guest_analytics: GuestAnalyticsLookupProtocol,
        scope_resolver: DashboardScopeResolver,
        organization_lookup: OrganizationLookupProtocol,
        location_lookup: LocationLookupProtocol,
        redis: Redis,
        *,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.guest_analytics = guest_analytics
        self.scope_resolver = scope_resolver
        self.organization_lookup = organization_lookup
        self.location_lookup = location_lookup
        self.redis = redis
        self.audit_writer = audit_writer

    # ========================================================================
    # Super Admin Dashboard
    # ========================================================================

    async def get_super_admin_dashboard(
        self, user_id: uuid.UUID
    ) -> SuperAdminDashboardResponse:
        scope = await self.scope_resolver.resolve(user_id)
        scope.require_global()

        now = datetime.now(UTC)
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        month_start = today_start.replace(day=1)

        total_organizations = await self.repository.count_platform_organizations()
        total_locations = await self.repository.count_platform_locations()
        router_rows = await self.repository.count_routers_by_status(
            organization_id=None, location_id=None
        )
        routers_online, routers_offline, total_routers = _reduce_router_counts(
            router_rows
        )

        total_guests = await self.repository.count_platform_guests_total()
        _, todays_guest_count = await self.repository.get_platform_guest_aggregate(
            start=today_start, end=now
        )
        _, monthly_guest_count = await self.repository.get_platform_guest_aggregate(
            start=month_start, end=now
        )

        total_sessions = await self.repository.count_guest_sessions_total()
        active_sessions = await self.repository.count_active_guest_sessions(
            organization_id=None, location_id=None
        )

        intervals = await self.repository.list_session_intervals(
            organization_id=None, location_id=None, start=today_start, end=now
        )
        peak_concurrent = compute_peak_concurrent_sessions(
            intervals, window_start=today_start, window_end=now
        )

        growth = await self._compute_platform_growth(now)

        status_counts = dict(await self.repository.count_organizations_by_status())
        trial_customers = status_counts.get(OrganizationStatus.TRIAL.value, 0)
        paid_customers = sum(
            count
            for status_value, count in status_counts.items()
            if status_value
            not in (OrganizationStatus.TRIAL.value, OrganizationStatus.ARCHIVED.value)
        )

        await self._maybe_audit(
            user_id,
            action=AUDIT_ACTION_DASHBOARD_SUPER_ADMIN_VIEWED,
            dashboard_kind="super_admin",
            scope_key="global",
            organization_id=None,
            location_id=None,
            description="Super Admin dashboard viewed",
        )

        return SuperAdminDashboardResponse(
            total_organizations=total_organizations,
            total_locations=total_locations,
            total_routers=total_routers,
            routers_online=routers_online,
            routers_offline=routers_offline,
            total_guests=total_guests,
            todays_guests=todays_guest_count,
            monthly_guests=monthly_guest_count,
            total_sessions=total_sessions,
            active_sessions=active_sessions,
            peak_concurrent_sessions=peak_concurrent,
            peak_concurrent_sessions_window_start=today_start.isoformat(),
            peak_concurrent_sessions_window_end=now.isoformat(),
            organization_growth=growth["organization_growth"],
            location_growth=growth["location_growth"],
            router_growth=growth["router_growth"],
            guest_growth=growth["guest_growth"],
            network_growth=growth["network_growth"],
            trial_customers=trial_customers,
            paid_customers=paid_customers,
            revenue=RevenueMetricsResponse(),
        )

    async def _compute_platform_growth(
        self, now: datetime
    ) -> dict[str, GrowthPointResponse]:
        """Day-over-(``DEFAULT_GROWTH_LOOKBACK_DAYS``-days-ago) deltas
        derived entirely from ``PLATFORM_DAILY_SUMMARY`` snapshot history --
        see ``AnalyticsSnapshot``'s own docstring for that snapshot type's
        metrics shape."""
        current = await self.repository.get_latest_snapshot(
            organization_id=None,
            location_id=None,
            snapshot_type=AnalyticsSnapshotType.PLATFORM_DAILY_SUMMARY.value,
        )
        cutoff = (current.period_start if current else now) - timedelta(
            days=DEFAULT_GROWTH_LOOKBACK_DAYS
        )
        previous_rows, _ = await self.repository.list_snapshots(
            organization_id=None,
            location_id=None,
            snapshot_type=AnalyticsSnapshotType.PLATFORM_DAILY_SUMMARY.value,
            end=cutoff,
            page=1,
            page_size=1,
        )
        previous = previous_rows[0] if previous_rows else None

        current_metrics = current.metrics if current else {}
        previous_metrics = previous.metrics if previous else None

        def _value(metrics: dict[str, object] | None, *keys: str) -> float | None:
            if metrics is None:
                return None
            total = 0.0
            for key in keys:
                value = metrics.get(key, 0)
                if isinstance(value, int | float):
                    total += value
            return total

        return {
            "organization_growth": _growth_response(
                "organization_count_total",
                _value(current_metrics, "organization_count_total") or 0.0,
                _value(previous_metrics, "organization_count_total"),
            ),
            "location_growth": _growth_response(
                "location_count_total",
                _value(current_metrics, "location_count_total") or 0.0,
                _value(previous_metrics, "location_count_total"),
            ),
            "router_growth": _growth_response(
                "router_count_total",
                _value(current_metrics, "router_count_online", "router_count_offline")
                or 0.0,
                _value(previous_metrics, "router_count_online", "router_count_offline"),
            ),
            "guest_growth": _growth_response(
                "guest_count_unique_today",
                _value(current_metrics, "guest_count_unique_today") or 0.0,
                _value(previous_metrics, "guest_count_unique_today"),
            ),
            "network_growth": _growth_response(
                "session_count_total_today",
                _value(current_metrics, "session_count_total_today") or 0.0,
                _value(previous_metrics, "session_count_total_today"),
            ),
        }

    # ========================================================================
    # Organization Dashboard
    # ========================================================================

    async def get_organization_dashboard(
        self, user_id: uuid.UUID, organization_id: uuid.UUID
    ) -> OrganizationDashboardResponse:
        scope = await self.scope_resolver.resolve(user_id)
        scope.require_organization(organization_id)

        organization = await self.organization_lookup.get_organization(organization_id)
        children = (
            await self.organization_lookup.list_children(organization_id)
            if organization.is_msp()
            else []
        )
        target_organizations = [(organization_id, organization.name)] + [
            (child.id, child.name) for child in children
        ]

        summary_items: list[OrganizationSummaryItem] = []
        rollup_guest_unique = 0
        rollup_session_total = 0
        rollup_session_active = 0
        rollup_router_online = 0
        rollup_router_total = 0
        rollup_bandwidth = 0
        rollup_location_count = 0

        for org_id, org_name in target_organizations:
            snapshot = await self.repository.get_latest_snapshot(
                organization_id=org_id,
                location_id=None,
                snapshot_type=AnalyticsSnapshotType.ORG_DAILY_SUMMARY.value,
            )
            metrics = snapshot.metrics if snapshot else {}
            guest_unique = int(metrics.get("guest_count_unique", 0) or 0)
            session_total = int(metrics.get("session_count_total", 0) or 0)
            session_active = int(metrics.get("session_count_active", 0) or 0)
            router_online = int(metrics.get("router_count_online", 0) or 0)
            router_total = int(metrics.get("router_count_total", 0) or 0)
            bandwidth = int(metrics.get("total_bandwidth_bytes", 0) or 0)

            location_ids = (
                await self.repository.list_active_location_ids_for_organization(org_id)
            )

            summary_items.append(
                OrganizationSummaryItem(
                    organization_id=org_id,
                    organization_name=org_name,
                    guest_count_unique=guest_unique,
                    session_count_total=session_total,
                    session_count_active=session_active,
                    router_count_online=router_online,
                    router_count_total=router_total,
                    total_bandwidth_bytes=bandwidth,
                    snapshot_period_start=(
                        snapshot.period_start.isoformat() if snapshot else None
                    ),
                    snapshot_period_end=(
                        snapshot.period_end.isoformat() if snapshot else None
                    ),
                )
            )
            rollup_guest_unique += guest_unique
            rollup_session_total += session_total
            rollup_session_active += session_active
            rollup_router_online += router_online
            rollup_router_total += router_total
            rollup_bandwidth += bandwidth
            rollup_location_count += len(location_ids)

        # Sub-metrics below are scoped to the *primary* organization named by
        # the caller (the header-validated org they are a member of) -- see
        # this module's own docstring for why the MSP rollup applies to the
        # summary counts above, not to every one of these per-child (an
        # N-way fan-out of six separate aggregate queries per child
        # organization was judged not worth the cost for this part; an MSP
        # admin who wants a child's own detailed breakdown can drill into
        # that child directly once it is its own tenant with its own
        # membership).
        now = datetime.now(UTC)
        window_start = now - timedelta(days=MONTHLY_WINDOW_DAYS)

        auth_rows = await self.repository.get_auth_method_breakdown(
            organization_id=organization_id,
            location_id=None,
            start=window_start,
            end=now,
        )
        auth_methods = build_auth_method_breakdown(auth_rows)

        otp_stats = await self.repository.get_otp_stats(
            organization_id=organization_id,
            location_id=None,
            start=window_start,
            end=now,
        )
        otp_rate = (
            otp_stats.verified_count / otp_stats.total_requests
            if otp_stats.total_requests
            else 0.0
        )

        voucher_status_counts = await self.repository.get_voucher_status_counts(
            organization_id=organization_id, location_id=None
        )

        (
            active_configs,
            total_configs,
        ) = await self.repository.count_captive_portal_configs(
            organization_id=organization_id
        )
        captive_portal_login_volume = await self.repository.count_guest_sessions_total(
            organization_id=organization_id
        )

        summary = await self.guest_analytics.get_summary(
            organization_id=organization_id,
            location_id=None,
            start=window_start,
            end=now,
        )

        hour_rows = await self.repository.get_session_counts_by_hour(
            organization_id=organization_id,
            location_id=None,
            start=window_start,
            end=now,
        )
        peak_hour = max(hour_rows, key=lambda row: row[1])[0] if hour_rows else None
        day_rows = await self.repository.get_session_counts_by_day_of_week(
            organization_id=organization_id,
            location_id=None,
            start=window_start,
            end=now,
        )
        peak_day = max(day_rows, key=lambda row: row[1])[0] if day_rows else None

        traffic_trend = await self._compute_org_traffic_trend(organization_id, now)

        health_score = await self._compute_health_score(organization_id, now)

        await self._maybe_audit(
            user_id,
            action=AUDIT_ACTION_DASHBOARD_ORGANIZATION_VIEWED,
            dashboard_kind="organization",
            scope_key=str(organization_id),
            organization_id=organization_id,
            location_id=None,
            description=f"Organization dashboard viewed for {organization_id}",
        )

        return OrganizationDashboardResponse(
            organization_id=organization_id,
            is_msp_rollup=bool(children),
            organizations=summary_items,
            location_count=rollup_location_count,
            router_count=rollup_router_total,
            guest_count_unique=rollup_guest_unique,
            session_count_total=rollup_session_total,
            session_count_active=rollup_session_active,
            captive_portal_active_configs=active_configs,
            captive_portal_total_configs=total_configs,
            captive_portal_guest_login_volume=captive_portal_login_volume,
            auth_methods=auth_methods,
            otp_total_requests=otp_stats.total_requests,
            otp_verified_count=otp_stats.verified_count,
            otp_verification_rate=otp_rate,
            voucher_status_counts=voucher_status_counts,
            total_bandwidth_bytes=summary.total_bandwidth_bytes,
            average_session_duration_seconds=summary.average_session_duration_seconds,
            peak_hour_utc=peak_hour,
            peak_day_of_week_utc=peak_day,
            traffic_trend=traffic_trend,
            health_score=health_score,
        )

    async def _compute_org_traffic_trend(
        self, organization_id: uuid.UUID, now: datetime
    ) -> list[GrowthPointResponse]:
        """A real day-over-day bandwidth trend built entirely from
        ``ORG_DAILY_SUMMARY`` snapshot history (never re-querying raw
        ``GuestSession`` rows for a wider window)."""
        window_start = now - timedelta(days=WEEKLY_WINDOW_DAYS + 1)
        snapshots, _ = await self.repository.list_snapshots(
            organization_id=organization_id,
            location_id=None,
            snapshot_type=AnalyticsSnapshotType.ORG_DAILY_SUMMARY.value,
            start=window_start,
            end=now,
            page=1,
            page_size=WEEKLY_WINDOW_DAYS + 1,
        )
        ordered = sorted(snapshots, key=lambda snap: snap.period_start)
        points: list[GrowthPointResponse] = []
        previous_value: float | None = None
        for snapshot in ordered:
            current_value = float(snapshot.metrics.get("total_bandwidth_bytes", 0) or 0)
            points.append(
                _growth_response(
                    snapshot.period_start.date().isoformat(),
                    current_value,
                    previous_value,
                )
            )
            previous_value = current_value
        return points

    async def _compute_health_score(
        self, organization_id: uuid.UUID, now: datetime
    ) -> HealthScoreResponse:
        router_rows = await self.repository.count_routers_by_status(
            organization_id=organization_id, location_id=None
        )
        online, _, total = _reduce_router_counts(router_rows)

        since = now - timedelta(days=HEALTH_SCORE_ALERT_LOOKBACK_DAYS)
        alert_counts = await self.repository.get_open_alert_counts_by_severity(
            organization_id=organization_id, since=since
        )

        current = await self.repository.get_latest_snapshot(
            organization_id=organization_id,
            location_id=None,
            snapshot_type=AnalyticsSnapshotType.ORG_DAILY_SUMMARY.value,
        )
        cutoff = (current.period_start if current else now) - timedelta(
            days=DEFAULT_GROWTH_LOOKBACK_DAYS
        )
        previous_rows, _ = await self.repository.list_snapshots(
            organization_id=organization_id,
            location_id=None,
            snapshot_type=AnalyticsSnapshotType.ORG_DAILY_SUMMARY.value,
            end=cutoff,
            page=1,
            page_size=1,
        )
        previous = previous_rows[0] if previous_rows else None
        current_guests = (
            float(current.metrics.get("guest_count_unique", 0) or 0) if current else 0.0
        )
        previous_guests = (
            float(previous.metrics.get("guest_count_unique", 0) or 0)
            if previous
            else None
        )
        growth_point = compute_growth(
            metric="guest_count_unique",
            current=current_guests,
            previous=previous_guests,
        )
        growth_direction = growth_direction_to_health_direction(growth_point.direction)

        result = compute_health_score(
            router_online_count=online,
            router_total_count=total,
            open_alert_counts_by_severity=alert_counts,
            growth_direction=growth_direction,
        )
        return HealthScoreResponse(
            score=result.score,
            router_health_component=result.router_health_component,
            alert_health_component=result.alert_health_component,
            growth_health_component=result.growth_health_component,
            router_online_count=result.router_online_count,
            router_total_count=result.router_total_count,
            open_alert_penalty=result.open_alert_penalty,
            growth_direction=result.growth_direction.value,
        )

    # ========================================================================
    # Location Dashboard
    # ========================================================================

    async def get_location_dashboard(
        self, user_id: uuid.UUID, location_id: uuid.UUID
    ) -> LocationDashboardResponse:
        organization_id = await self.scope_resolver.resolve_location_organization_id(
            location_id
        )
        scope = await self.scope_resolver.resolve(user_id)
        scope.require_location(location_id, organization_id)

        now = datetime.now(UTC)
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start = today_start - timedelta(days=WEEKLY_WINDOW_DAYS - 1)
        month_start = today_start - timedelta(days=MONTHLY_WINDOW_DAYS - 1)

        daily_summary = await self.guest_analytics.get_summary(
            organization_id=organization_id,
            location_id=location_id,
            start=today_start,
            end=now,
        )
        daily_visitors = daily_summary.visitors

        # Weekly/monthly visitors: sum already-closed daily snapshots (never
        # re-querying raw GuestSession rows for the wider window), plus
        # today's own live, still-partial total -- see module docstring.
        weekly_snapshots, _ = await self.repository.list_snapshots(
            organization_id=organization_id,
            location_id=location_id,
            snapshot_type=AnalyticsSnapshotType.LOCATION_DAILY_SUMMARY.value,
            start=week_start,
            end=today_start,
            page=1,
            page_size=WEEKLY_WINDOW_DAYS + 1,
        )
        weekly_visitors = (
            int(
                sum_metric_across_snapshots(
                    [s.metrics for s in weekly_snapshots], "session_count_total"
                )
            )
            + daily_visitors
        )
        monthly_snapshots, _ = await self.repository.list_snapshots(
            organization_id=organization_id,
            location_id=location_id,
            snapshot_type=AnalyticsSnapshotType.LOCATION_DAILY_SUMMARY.value,
            start=month_start,
            end=today_start,
            page=1,
            page_size=MONTHLY_WINDOW_DAYS + 1,
        )
        monthly_visitors = (
            int(
                sum_metric_across_snapshots(
                    [s.metrics for s in monthly_snapshots], "session_count_total"
                )
            )
            + daily_visitors
        )

        monthly_summary = await self.guest_analytics.get_summary(
            organization_id=organization_id,
            location_id=location_id,
            start=month_start,
            end=now,
        )

        hour_rows = await self.repository.get_session_counts_by_hour(
            organization_id=organization_id,
            location_id=location_id,
            start=month_start,
            end=now,
        )
        peak_hours = sorted(hour_rows, key=lambda row: row[1], reverse=True)[:5]
        day_rows = await self.repository.get_session_counts_by_day_of_week(
            organization_id=organization_id,
            location_id=location_id,
            start=month_start,
            end=now,
        )
        peak_days = sorted(day_rows, key=lambda row: row[1], reverse=True)

        device_breakdown = await self.repository.get_user_agent_breakdown(
            organization_id=organization_id,
            location_id=location_id,
            start=month_start,
            end=now,
        )
        auth_rows = await self.repository.get_auth_method_breakdown(
            organization_id=organization_id,
            location_id=location_id,
            start=month_start,
            end=now,
        )

        average_session_bandwidth = (
            monthly_summary.total_bandwidth_bytes / monthly_summary.visitors
            if monthly_summary.visitors
            else None
        )

        await self._maybe_audit(
            user_id,
            action=AUDIT_ACTION_DASHBOARD_LOCATION_VIEWED,
            dashboard_kind="location",
            scope_key=str(location_id),
            organization_id=organization_id,
            location_id=location_id,
            description=f"Location dashboard viewed for {location_id}",
        )

        return LocationDashboardResponse(
            location_id=location_id,
            organization_id=organization_id,
            daily_visitors=daily_visitors,
            weekly_visitors=weekly_visitors,
            monthly_visitors=monthly_visitors,
            unique_guests=monthly_summary.unique_guests,
            returning_guests=monthly_summary.returning_guests,
            average_stay_seconds=monthly_summary.average_session_duration_seconds,
            peak_hours=[
                PeakHourItem(hour_utc=hour, session_count=count)
                for hour, count in peak_hours
            ],
            peak_days=[
                PeakDayItem(day_of_week_utc=day, session_count=count)
                for day, count in peak_days
            ],
            total_bandwidth_bytes=monthly_summary.total_bandwidth_bytes,
            average_session_bandwidth_bytes=average_session_bandwidth,
            average_session_duration_seconds=monthly_summary.average_session_duration_seconds,
            devices=device_breakdown_response(device_breakdown),
            auth_methods=build_auth_method_breakdown(auth_rows),
            country_statistics=CountryStatisticsResponse(),
        )

    # ========================================================================
    # Internal helpers
    # ========================================================================

    async def _maybe_audit(
        self,
        user_id: uuid.UUID,
        *,
        action: str,
        dashboard_kind: str,
        scope_key: str,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        description: str,
    ) -> None:
        logger.info(
            "dashboard_viewed",
            extra={
                "user_id": str(user_id),
                "dashboard_kind": dashboard_kind,
                "scope_key": scope_key,
            },
        )
        if self.audit_writer is None:
            return
        should_write = await DashboardAuditThrottle.should_write_audit_entry(
            self.redis,
            user_id=user_id,
            dashboard_kind=dashboard_kind,
            scope=scope_key,
        )
        if not should_write:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=user_id,
            action=action,
            entity_type="dashboard",
            entity_id=None,
            description=description,
            event_metadata={"dashboard_kind": dashboard_kind},
            organization_id=organization_id,
            location_id=location_id,
        )


__all__ = ["DashboardService", "AuditLogWriter"]
