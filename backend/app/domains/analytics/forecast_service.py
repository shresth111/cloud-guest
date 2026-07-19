"""BE-012 Part 4: Forecast Engine business logic --
``GET /analytics/forecast/bandwidth|capacity|router-failure-risk|
guest-growth|network-load``.

``ForecastService`` composes real ``AnalyticsSnapshot``/
``RouterHealthSnapshot``/``Alert`` history (via ``AnalyticsRepository`` --
every method used here already existed since Parts 1/3, or was added by this
part following the exact same real-SQL-query conventions) with
``forecast.py``'s pure, real linear-regression math -- this module's own job
is exclusively "fetch the real history, then hand it to the pure function,
then shape the result into a response"; no forecasting math lives here.

## Endpoint consolidation: five endpoints, not six

The module brief lists six forecast concepts (Bandwidth Forecast, Capacity
Prediction, Router Failure Prediction, Guest Growth Prediction, Network Load
Prediction, Traffic Forecast) but explicitly invites consolidating routes
where two concepts would be the same metric under a different name. **Traffic
Forecast and Bandwidth Forecast are folded into one endpoint**
(``GET /analytics/forecast/bandwidth``): this codebase has exactly one real,
per-day network-volume metric in ``AnalyticsSnapshot`` history
(``total_bandwidth_bytes``, summed from real ``GuestSession.bytes_uploaded``/
``bytes_downloaded`` -- see ``domain_analytics_service.py``'s own module
docstring) -- there is no separate "traffic" metric (packet count, request
count, ...) anywhere in this codebase's real data to forecast independently.
Network Load Prediction, by contrast, is kept as its own, genuinely distinct
endpoint (``session_count_total`` -- concurrent guest-session volume, a real,
different metric from total bytes moved) rather than folded into bandwidth,
since the two answer materially different operational questions ("how much
data" vs. "how many simultaneous guests").

## Scope: ORGANIZATION, mirroring Part 3's own domain analytics

Every forecast here is a per-organization operational concept (this
organization's own bandwidth/guest-count/session-count/router-count/router-
health trend), so every endpoint is gated exactly like Part 3's
``DomainAnalyticsService``: RBAC's
``RequirePermission("analytics.read", scope=ScopeType.ORGANIZATION)`` at the
route, plus this service's own ``DashboardScope.require_organization`` check
(the same ``DashboardScopeResolver`` every analytics endpoint in this domain
composes with). ``location_id`` is optional, narrowing history to one
location's own ``LOCATION_DAILY_SUMMARY`` snapshots (mirroring the identical
``organization_id``/``location_id`` dual-snapshot-type convention Part 2's
own dashboards already establish) -- except Router Failure Risk, which reads
per-router history directly (``RouterHealthSnapshot``/``Alert``), not
snapshot history, so its own ``location_id`` narrows
``list_routers_for_scope`` instead.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Protocol

from redis.asyncio import Redis

from app.core.config import Settings

from .constants import AUDIT_ACTION_FORECAST_VIEWED, AnalyticsSnapshotType
from .dashboard_audit import DashboardAuditThrottle
from .dashboard_scope import DashboardScopeResolver
from .forecast import (
    ForecastPoint,
    LinearForecastResult,
    ThresholdCrossingResult,
    assess_router_failure_risk,
    forecast_linear_series,
    project_upward_threshold_crossing,
)
from .forecast_schemas import (
    CapacityForecastResponse,
    HistoricalPointItem,
    LinearFitInfo,
    LinearForecastResponse,
    RouterFailureRiskItem,
    RouterFailureRiskResponse,
    RouterRiskSignalItem,
    ThresholdCrossingInfo,
)
from .repository import AnalyticsRepositoryProtocol
from .trends import TrendPoint, extract_metric_series


class AuditLogWriter(Protocol):
    async def create_audit_log_entry(self, **fields: object) -> object: ...


def _forecast_point_item(point: ForecastPoint) -> HistoricalPointItem:
    return HistoricalPointItem(
        date=point.timestamp.date().isoformat(), value=point.value
    )


def _forecast_response(
    result: LinearForecastResult, *, metric: str
) -> LinearForecastResponse:
    fit_info = (
        LinearFitInfo(
            slope_per_day=result.fit.slope,
            intercept=result.fit.intercept,
            r_squared=result.fit.r_squared,
            point_count=result.fit.point_count,
        )
        if result.fit is not None
        else None
    )
    return LinearForecastResponse(
        available=result.available,
        metric=metric,
        historical_points=[_forecast_point_item(p) for p in result.historical_points],
        projected_points=[_forecast_point_item(p) for p in result.projected_points],
        fit=fit_info,
        message=result.message,
    )


def _threshold_crossing_info(
    result: ThresholdCrossingResult,
    *,
    resource: str,
    threshold: float,
    current_value: float,
) -> ThresholdCrossingInfo:
    return ThresholdCrossingInfo(
        available=result.available,
        resource=resource,
        threshold=threshold,
        current_value=current_value,
        projected_crossing_date=(
            result.projected_crossing_date.isoformat()
            if result.projected_crossing_date
            else None
        ),
        days_until_crossing=result.days_until_crossing,
        message=result.message,
    )


class ForecastService:
    def __init__(
        self,
        repository: AnalyticsRepositoryProtocol,
        scope_resolver: DashboardScopeResolver,
        redis: Redis,
        settings: Settings,
        *,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.scope_resolver = scope_resolver
        self.redis = redis
        self.settings = settings
        self.audit_writer = audit_writer

    # ========================================================================
    # Bandwidth / Guest Growth / Network Load Forecast -- one shared
    # linear-trend-extrapolation implementation, three metric wrappers.
    # ========================================================================

    async def get_bandwidth_forecast(
        self,
        user_id: uuid.UUID,
        organization_id: uuid.UUID,
        *,
        location_id: uuid.UUID | None,
        forecast_days: int | None,
    ) -> LinearForecastResponse:
        """Bandwidth Forecast / Traffic Forecast (folded into one -- see
        module docstring): projects ``total_bandwidth_bytes`` forward."""
        return await self._linear_metric_forecast(
            user_id,
            organization_id,
            location_id=location_id,
            forecast_days=forecast_days,
            metric_key="total_bandwidth_bytes",
            audit_kind="forecast_bandwidth",
        )

    async def get_guest_growth_forecast(
        self,
        user_id: uuid.UUID,
        organization_id: uuid.UUID,
        *,
        location_id: uuid.UUID | None,
        forecast_days: int | None,
    ) -> LinearForecastResponse:
        return await self._linear_metric_forecast(
            user_id,
            organization_id,
            location_id=location_id,
            forecast_days=forecast_days,
            metric_key="guest_count_unique",
            audit_kind="forecast_guest_growth",
        )

    async def get_network_load_forecast(
        self,
        user_id: uuid.UUID,
        organization_id: uuid.UUID,
        *,
        location_id: uuid.UUID | None,
        forecast_days: int | None,
    ) -> LinearForecastResponse:
        return await self._linear_metric_forecast(
            user_id,
            organization_id,
            location_id=location_id,
            forecast_days=forecast_days,
            metric_key="session_count_total",
            audit_kind="forecast_network_load",
        )

    async def _linear_metric_forecast(
        self,
        user_id: uuid.UUID,
        organization_id: uuid.UUID,
        *,
        location_id: uuid.UUID | None,
        forecast_days: int | None,
        metric_key: str,
        audit_kind: str,
    ) -> LinearForecastResponse:
        scope = await self.scope_resolver.resolve(user_id)
        scope.require_organization(organization_id)

        now = datetime.now(UTC)
        snapshots = await self._fetch_daily_snapshot_history(
            organization_id=organization_id, location_id=location_id, now=now
        )
        series = extract_metric_series(snapshots, metric_key)
        result = forecast_linear_series(
            series,
            forecast_days=forecast_days
            or self.settings.analytics_forecast_default_days,
            min_points=self.settings.analytics_forecast_min_history_points,
        )

        await self._maybe_audit(
            user_id,
            dashboard_kind=audit_kind,
            scope_key=f"{organization_id}:{location_id}",
            organization_id=organization_id,
            location_id=location_id,
            description=f"{audit_kind} viewed for organization {organization_id}",
        )
        return _forecast_response(result, metric=metric_key)

    async def _fetch_daily_snapshot_history(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        now: datetime,
    ) -> list[object]:
        snapshot_type = (
            AnalyticsSnapshotType.LOCATION_DAILY_SUMMARY.value
            if location_id is not None
            else AnalyticsSnapshotType.ORG_DAILY_SUMMARY.value
        )
        history_days = self.settings.analytics_forecast_history_days
        start = now - timedelta(days=history_days)
        snapshots, _ = await self.repository.list_snapshots(
            organization_id=organization_id,
            location_id=location_id,
            snapshot_type=snapshot_type,
            start=start,
            end=now,
            page=1,
            page_size=history_days + 1,
        )
        return snapshots

    # ========================================================================
    # Capacity Prediction
    # ========================================================================

    async def get_capacity_forecast(
        self,
        user_id: uuid.UUID,
        organization_id: uuid.UUID,
        *,
        location_id: uuid.UUID | None,
    ) -> CapacityForecastResponse:
        """Projects when ``router_count_total`` will cross the configured
        capacity ceiling (``Settings.analytics_forecast_capacity_router_
        count_threshold`` -- an operator-set planning assumption, not
        derived data; see that setting's own docstring)."""
        scope = await self.scope_resolver.resolve(user_id)
        scope.require_organization(organization_id)

        now = datetime.now(UTC)
        snapshots = await self._fetch_daily_snapshot_history(
            organization_id=organization_id, location_id=location_id, now=now
        )
        series = extract_metric_series(snapshots, "router_count_total")
        result = forecast_linear_series(
            series,
            forecast_days=self.settings.analytics_forecast_default_days,
            min_points=self.settings.analytics_forecast_min_history_points,
        )

        threshold = float(
            self.settings.analytics_forecast_capacity_router_count_threshold
        )
        current_value = series[-1].value if series else 0.0
        if result.available and result.fit is not None:
            base_timestamp = series[0].timestamp
            last_x = (series[-1].timestamp - base_timestamp).total_seconds() / 86400.0
            crossing = project_upward_threshold_crossing(
                fit=result.fit,
                last_x=last_x,
                last_timestamp=series[-1].timestamp,
                current_value=current_value,
                threshold=threshold,
            )
        else:
            crossing = ThresholdCrossingResult(
                available=False,
                projected_crossing_date=None,
                days_until_crossing=None,
                message=(
                    result.message
                    or "Not enough historical data to project a threshold crossing."
                ),
            )

        await self._maybe_audit(
            user_id,
            dashboard_kind="forecast_capacity",
            scope_key=f"{organization_id}:{location_id}",
            organization_id=organization_id,
            location_id=location_id,
            description=f"forecast_capacity viewed for organization {organization_id}",
        )

        return CapacityForecastResponse(
            organization_id=organization_id,
            location_id=location_id,
            forecast=_forecast_response(result, metric="router_count_total"),
            threshold_crossing=_threshold_crossing_info(
                crossing,
                resource="router_count_total",
                threshold=threshold,
                current_value=current_value,
            ),
        )

    # ========================================================================
    # Router Failure Risk
    # ========================================================================

    async def get_router_failure_risk(
        self,
        user_id: uuid.UUID,
        organization_id: uuid.UUID,
        *,
        location_id: uuid.UUID | None,
    ) -> RouterFailureRiskResponse:
        scope = await self.scope_resolver.resolve(user_id)
        scope.require_organization(organization_id)

        now = datetime.now(UTC)
        health_lookback = timedelta(
            days=self.settings.analytics_forecast_router_health_lookback_days
        )
        alert_lookback = timedelta(
            days=self.settings.analytics_forecast_router_alert_lookback_days
        )

        routers = await self.repository.list_routers_for_scope(
            organization_id=organization_id, location_id=location_id
        )
        router_ids = [row.router_id for row in routers]
        health_history = await self.repository.get_router_health_snapshot_history(
            router_ids, start=now - health_lookback, end=now
        )
        alert_counts = await self.repository.get_alert_counts_by_router(
            router_ids, since=now - alert_lookback
        )

        items = []
        for router in routers:
            rows = health_history.get(router.router_id, [])
            cpu_points = [
                TrendPoint(timestamp=row.recorded_at, value=row.cpu_usage_percent)
                for row in rows
                if row.cpu_usage_percent is not None
            ]
            memory_points = [
                TrendPoint(timestamp=row.recorded_at, value=row.memory_usage_percent)
                for row in rows
                if row.memory_usage_percent is not None
            ]
            unhealthy_count = sum(1 for row in rows if row.health_status == "unhealthy")
            assessment = assess_router_failure_risk(
                router_id=router.router_id,
                router_name=router.router_name,
                cpu_history=cpu_points,
                memory_history=memory_points,
                unhealthy_snapshot_count=unhealthy_count,
                total_snapshot_count=len(rows),
                alert_count=alert_counts.get(router.router_id, 0),
                cpu_rising_slope_threshold=(
                    self.settings.analytics_forecast_router_cpu_rising_slope_threshold
                ),
                memory_rising_slope_threshold=(
                    self.settings.analytics_forecast_router_memory_rising_slope_threshold
                ),
                unhealthy_ratio_threshold=(
                    self.settings.analytics_forecast_router_unhealthy_ratio_threshold
                ),
                alert_count_threshold=(
                    self.settings.analytics_forecast_router_alert_count_threshold
                ),
                min_history_points=self.settings.analytics_forecast_min_history_points,
            )
            items.append(
                RouterFailureRiskItem(
                    router_id=router.router_id,
                    router_name=router.router_name,
                    location_id=router.location_id,
                    at_risk=assessment.at_risk,
                    signals=[
                        RouterRiskSignalItem(name=signal.name, detail=signal.detail)
                        for signal in assessment.signals
                    ],
                )
            )

        await self._maybe_audit(
            user_id,
            dashboard_kind="forecast_router_failure_risk",
            scope_key=f"{organization_id}:{location_id}",
            organization_id=organization_id,
            location_id=location_id,
            description=(
                f"forecast_router_failure_risk viewed for organization "
                f"{organization_id}"
            ),
        )

        return RouterFailureRiskResponse(
            organization_id=organization_id,
            location_id=location_id,
            window_start=(now - health_lookback).isoformat(),
            window_end=now.isoformat(),
            routers=items,
        )

    # ========================================================================
    # Internal helpers
    # ========================================================================

    async def _maybe_audit(
        self,
        user_id: uuid.UUID,
        *,
        dashboard_kind: str,
        scope_key: str,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        description: str,
    ) -> None:
        if self.audit_writer is None:
            return
        should_write = await DashboardAuditThrottle.should_write_audit_entry(
            self.redis, user_id=user_id, dashboard_kind=dashboard_kind, scope=scope_key
        )
        if not should_write:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=user_id,
            action=AUDIT_ACTION_FORECAST_VIEWED,
            entity_type="dashboard",
            entity_id=None,
            description=description,
            event_metadata={"dashboard_kind": dashboard_kind},
            organization_id=organization_id,
            location_id=location_id,
        )


__all__ = ["ForecastService", "AuditLogWriter"]
