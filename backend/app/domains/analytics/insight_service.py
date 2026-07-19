"""BE-012 Part 4: Insight Engine business logic --
``GET /analytics/insights/business``, ``GET /analytics/insights/operational``.

``InsightService`` is exclusively the "fetch real data, hand it to
``insights.py``'s pure rule functions, collect whatever fires" composition
layer -- no rule logic, no threshold comparison, and no text generation
lives here; see ``insights.py``'s own module docstring for the full rule
set and ``app.core.config.Settings`` for every threshold.

## Scope: GLOBAL for both endpoints

Both Business Insights and Operational Recommendations are, by design,
platform-wide sweeps (the module brief's own illustrative examples name
multiple organizations/locations at once: "3 organizations have had...",
"location A's guest volume dropped...") -- gated identically to Part 2's
Super Admin Dashboard and this part's own Business Analytics endpoint:
RBAC's ``RequirePermission("analytics.read", scope=ScopeType.GLOBAL)`` at
the route, plus this service's own ``DashboardScope.require_global()``
check.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Protocol

from redis.asyncio import Redis

from app.core.config import Settings
from app.domains.router.enums import RouterStatus

from .constants import (
    AUDIT_ACTION_BUSINESS_INSIGHTS_VIEWED,
    AUDIT_ACTION_OPERATIONAL_RECOMMENDATIONS_VIEWED,
    DEFAULT_GROWTH_LOOKBACK_DAYS,
    AnalyticsSnapshotType,
)
from .dashboard_audit import DashboardAuditThrottle
from .dashboard_scope import DashboardScopeResolver
from .insight_schemas import (
    BusinessInsightsResponse,
    InsightItem,
    OperationalRecommendationsResponse,
)
from .insights import (
    Insight,
    rule_customer_growth,
    rule_guest_growth,
    rule_location_guest_volume_drop,
    rule_offline_routers,
    rule_persistent_critical_alerts,
    rule_plan_distribution_coverage,
    rule_rising_router_cpu,
)
from .repository import AnalyticsRepositoryProtocol
from .trends import (
    compute_snapshot_metric_growth,
    count_trailing_consecutive_increases,
    growth_point_response,
)


class AuditLogWriter(Protocol):
    async def create_audit_log_entry(self, **fields: object) -> object: ...


def _to_item(insight: Insight) -> InsightItem:
    return InsightItem(
        rule=insight.rule, severity=insight.severity.value, message=insight.message
    )


class InsightService:
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
    # Business Insights
    # ========================================================================

    async def get_business_insights(
        self, user_id: uuid.UUID
    ) -> BusinessInsightsResponse:
        scope = await self.scope_resolver.resolve(user_id)
        scope.require_global()

        now = datetime.now(UTC)
        settings = self.settings
        insights: list[Insight] = []

        customer_growth = await compute_snapshot_metric_growth(
            self.repository,
            organization_id=None,
            location_id=None,
            snapshot_type=AnalyticsSnapshotType.PLATFORM_DAILY_SUMMARY.value,
            metric_key="organization_count_total",
            lookback_days=DEFAULT_GROWTH_LOOKBACK_DAYS,
            now=now,
        )
        insight = rule_customer_growth(
            delta_percent=customer_growth.delta_percent,
            direction=customer_growth.direction,
            significant_percent_threshold=(
                settings.analytics_insight_customer_growth_significant_percent
            ),
        )
        if insight is not None:
            insights.append(insight)

        guest_growth = await compute_snapshot_metric_growth(
            self.repository,
            organization_id=None,
            location_id=None,
            snapshot_type=AnalyticsSnapshotType.PLATFORM_DAILY_SUMMARY.value,
            metric_key="guest_count_unique_today",
            lookback_days=DEFAULT_GROWTH_LOOKBACK_DAYS,
            now=now,
        )
        insight = rule_guest_growth(
            delta_percent=guest_growth.delta_percent,
            direction=guest_growth.direction,
            significant_percent_threshold=(
                settings.analytics_insight_guest_growth_significant_percent
            ),
        )
        if insight is not None:
            insights.append(insight)

        tier_rows = await self.repository.count_organizations_by_subscription_tier()
        total = sum(count for _, count in tier_rows)
        unset = sum(count for tier, count in tier_rows if tier is None)
        populated = total - unset
        insight = rule_plan_distribution_coverage(
            populated_count=populated,
            total_count=total,
            min_coverage_percent_threshold=(
                settings.analytics_insight_plan_distribution_min_coverage_percent
            ),
        )
        if insight is not None:
            insights.append(insight)

        await self._maybe_audit(
            user_id,
            dashboard_kind="business_insights",
            action=AUDIT_ACTION_BUSINESS_INSIGHTS_VIEWED,
            description="Business insights viewed",
        )
        return BusinessInsightsResponse(
            generated_at=now.isoformat(), insights=[_to_item(i) for i in insights]
        )

    # ========================================================================
    # Operational Recommendations
    # ========================================================================

    async def get_operational_recommendations(
        self, user_id: uuid.UUID
    ) -> OperationalRecommendationsResponse:
        scope = await self.scope_resolver.resolve(user_id)
        scope.require_global()

        now = datetime.now(UTC)
        recommendations: list[Insight] = []

        recommendations.extend(await self._offline_router_recommendations(now))
        recommendations.extend(await self._location_volume_drop_recommendations(now))
        recommendations.extend(await self._rising_router_cpu_recommendations(now))
        recommendations.extend(
            await self._persistent_critical_alert_recommendations(now)
        )

        await self._maybe_audit(
            user_id,
            dashboard_kind="operational_recommendations",
            action=AUDIT_ACTION_OPERATIONAL_RECOMMENDATIONS_VIEWED,
            description="Operational recommendations viewed",
        )
        return OperationalRecommendationsResponse(
            generated_at=now.isoformat(),
            recommendations=[_to_item(i) for i in recommendations],
        )

    async def _offline_router_recommendations(self, now: datetime) -> list[Insight]:
        settings = self.settings
        routers = await self.repository.list_all_routers_with_organization()
        stale_cutoff = now - timedelta(
            hours=settings.analytics_insight_offline_router_hours_threshold
        )
        offline_by_org: dict[uuid.UUID, tuple[str, int]] = {}
        for router in routers:
            if router.status != RouterStatus.OFFLINE.value:
                continue
            offline_long_enough = (
                router.last_seen_at is None or router.last_seen_at < stale_cutoff
            )
            if not offline_long_enough:
                continue
            name, count = offline_by_org.get(
                router.organization_id, (router.organization_name, 0)
            )
            offline_by_org[router.organization_id] = (name, count + 1)

        results: list[Insight] = []
        for organization_id, (
            organization_name,
            offline_count,
        ) in offline_by_org.items():
            insight = rule_offline_routers(
                organization_id=organization_id,
                organization_name=organization_name,
                offline_count=offline_count,
                hours_threshold=settings.analytics_insight_offline_router_hours_threshold,
                count_threshold=settings.analytics_insight_offline_router_count_threshold,
                critical_count_threshold=(
                    settings.analytics_insight_offline_router_critical_count_threshold
                ),
            )
            if insight is not None:
                results.append(insight)
        return results

    async def _location_volume_drop_recommendations(
        self, now: datetime
    ) -> list[Insight]:
        settings = self.settings
        window_days = settings.analytics_insight_location_volume_lookback_days
        start = now - timedelta(days=window_days * 2)
        snapshots, _ = await self.repository.list_snapshots(
            organization_id=None,
            location_id=None,
            snapshot_type=AnalyticsSnapshotType.LOCATION_DAILY_SUMMARY.value,
            start=start,
            end=now,
            page=1,
            page_size=10_000,
        )
        by_location: dict[uuid.UUID, list[object]] = {}
        for snapshot in snapshots:
            if snapshot.location_id is not None:
                by_location.setdefault(snapshot.location_id, []).append(snapshot)

        location_names = await self.repository.get_location_names(
            list(by_location.keys())
        )

        results: list[Insight] = []
        for location_id, location_snapshots in by_location.items():
            ordered = sorted(location_snapshots, key=lambda snap: snap.period_start)
            current = ordered[-1]
            cutoff = current.period_start - timedelta(days=window_days)
            previous_candidates = [s for s in ordered if s.period_start <= cutoff]
            previous = previous_candidates[-1] if previous_candidates else None
            current_value = float(current.metrics.get("session_count_total", 0) or 0)
            previous_value = (
                float(previous.metrics.get("session_count_total", 0) or 0)
                if previous
                else None
            )
            growth = growth_point_response(
                "session_count_total", current_value, previous_value
            )
            insight = rule_location_guest_volume_drop(
                location_id=location_id,
                location_name=location_names.get(location_id, str(location_id)),
                delta_percent=growth.delta_percent,
                drop_percent_threshold=(
                    settings.analytics_insight_location_volume_drop_percent
                ),
            )
            if insight is not None:
                results.append(insight)
        return results

    async def _rising_router_cpu_recommendations(self, now: datetime) -> list[Insight]:
        settings = self.settings
        routers = await self.repository.list_all_routers_with_organization()
        router_ids = [router.router_id for router in routers]
        router_names = {router.router_id: router.router_name for router in routers}
        lookback = timedelta(days=settings.analytics_insight_router_cpu_lookback_days)
        history = await self.repository.get_router_health_snapshot_history(
            router_ids, start=now - lookback, end=now
        )

        results: list[Insight] = []
        for router_id, rows in history.items():
            cpu_values = [
                row.cpu_usage_percent
                for row in rows
                if row.cpu_usage_percent is not None
            ]
            if len(cpu_values) < 2:
                continue
            consecutive = count_trailing_consecutive_increases(cpu_values)
            first_index = len(cpu_values) - 1 - consecutive
            insight = rule_rising_router_cpu(
                router_id=router_id,
                router_name=router_names.get(router_id, str(router_id)),
                consecutive_rises=consecutive,
                consecutive_threshold=(
                    settings.analytics_insight_router_cpu_consecutive_threshold
                ),
                first_value=cpu_values[max(first_index, 0)],
                last_value=cpu_values[-1],
            )
            if insight is not None:
                results.append(insight)
        return results

    async def _persistent_critical_alert_recommendations(
        self, now: datetime
    ) -> list[Insight]:
        settings = self.settings
        age_cutoff = now - timedelta(
            hours=settings.analytics_insight_critical_alert_age_hours_threshold
        )
        org_alert_counts = (
            await self.repository.get_persistent_critical_alert_counts_by_organization(
                older_than=age_cutoff
            )
        )
        organization_names = await self.repository.get_organization_names(
            [organization_id for organization_id, _ in org_alert_counts]
        )

        results: list[Insight] = []
        for organization_id, count in org_alert_counts:
            insight = rule_persistent_critical_alerts(
                organization_id=organization_id,
                organization_name=organization_names.get(
                    organization_id, str(organization_id)
                ),
                count=count,
                count_threshold=settings.analytics_insight_critical_alert_count_threshold,
                age_hours_threshold=(
                    settings.analytics_insight_critical_alert_age_hours_threshold
                ),
            )
            if insight is not None:
                results.append(insight)
        return results

    # ========================================================================
    # Internal helpers
    # ========================================================================

    async def _maybe_audit(
        self, user_id: uuid.UUID, *, dashboard_kind: str, action: str, description: str
    ) -> None:
        if self.audit_writer is None:
            return
        should_write = await DashboardAuditThrottle.should_write_audit_entry(
            self.redis, user_id=user_id, dashboard_kind=dashboard_kind, scope="global"
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
            organization_id=None,
            location_id=None,
        )


__all__ = ["InsightService", "AuditLogWriter"]
