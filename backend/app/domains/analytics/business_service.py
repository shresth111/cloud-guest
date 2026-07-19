"""BE-012 Part 4: Business Analytics business logic
(``GET /analytics/business``).

Two figures are real: **Customer Growth** (a genuine trend, composed from
``AnalyticsSnapshot``'s existing ``PLATFORM_DAILY_SUMMARY.organization_count_
total`` history via ``trends.compute_snapshot_metric_growth`` -- Part 2's own
growth-computation machinery, never reimplemented) and **Plan Distribution**
(a real ``GROUP BY Organization.subscription_tier`` query,
``AnalyticsRepository.count_organizations_by_subscription_tier`` -- reporting
whatever the actual distribution is, even though ``subscription_tier`` is
known to be mostly unpopulated in practice, per Module 005's own documented
decision. This part does not skip the query just because the underlying
data happens to be unimpressive).

Revenue Trends / Subscription Trends / Churn Rate / Renewal Rate / License
Utilization are honest ``available: false`` placeholders -- see
``business_schemas.py``'s own module docstring for the exact shape/tone
mirroring Part 2's ``RevenueMetricsResponse``.

## Scope: GLOBAL, not organization-scoped

Every figure here (Customer Growth == platform-wide organization count,
Plan Distribution == platform-wide subscription_tier breakdown) is
inherently a platform-wide, cross-tenant concept -- there is no meaningful
"one organization's customer growth" (an organization does not have
customers of its own in this codebase's model; organizations themselves
*are* CloudGuest's customers). This endpoint is therefore gated exactly like
Part 2's own Super Admin Dashboard: RBAC's
``RequirePermission("analytics.read", scope=ScopeType.GLOBAL)`` at the
route, plus this service's own ``DashboardScope.require_global()`` check
(the same ``DashboardScopeResolver`` every other analytics endpoint in this
domain already composes with).
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Protocol

from redis.asyncio import Redis

from .business_schemas import (
    BusinessAnalyticsResponse,
    ChurnRateResponse,
    LicenseUtilizationResponse,
    PlanDistributionItem,
    PlanDistributionResponse,
    RenewalRateResponse,
    RevenueTrendsResponse,
    SubscriptionTrendsResponse,
)
from .constants import (
    AUDIT_ACTION_BUSINESS_ANALYTICS_VIEWED,
    DEFAULT_GROWTH_LOOKBACK_DAYS,
    AnalyticsSnapshotType,
)
from .dashboard_audit import DashboardAuditThrottle
from .dashboard_scope import DashboardScopeResolver
from .repository import AnalyticsRepositoryProtocol
from .trends import compute_snapshot_metric_growth

logger = logging.getLogger(__name__)


class AuditLogWriter(Protocol):
    async def create_audit_log_entry(self, **fields: object) -> object: ...


class BusinessAnalyticsService:
    def __init__(
        self,
        repository: AnalyticsRepositoryProtocol,
        scope_resolver: DashboardScopeResolver,
        redis: Redis,
        *,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.scope_resolver = scope_resolver
        self.redis = redis
        self.audit_writer = audit_writer

    async def get_business_analytics(
        self, user_id: uuid.UUID
    ) -> BusinessAnalyticsResponse:
        scope = await self.scope_resolver.resolve(user_id)
        scope.require_global()

        now = datetime.now(UTC)
        customer_growth = await compute_snapshot_metric_growth(
            self.repository,
            organization_id=None,
            location_id=None,
            snapshot_type=AnalyticsSnapshotType.PLATFORM_DAILY_SUMMARY.value,
            metric_key="organization_count_total",
            lookback_days=DEFAULT_GROWTH_LOOKBACK_DAYS,
            now=now,
        )
        plan_distribution = await self._compute_plan_distribution()

        await self._maybe_audit(user_id)

        return BusinessAnalyticsResponse(
            customer_growth=customer_growth,
            plan_distribution=plan_distribution,
            revenue_trends=RevenueTrendsResponse(),
            subscription_trends=SubscriptionTrendsResponse(),
            churn_rate=ChurnRateResponse(),
            renewal_rate=RenewalRateResponse(),
            license_utilization=LicenseUtilizationResponse(),
        )

    async def _compute_plan_distribution(self) -> PlanDistributionResponse:
        rows = await self.repository.count_organizations_by_subscription_tier()
        total = sum(count for _, count in rows)
        unset = sum(count for tier, count in rows if tier is None)
        populated = total - unset
        by_tier = [
            PlanDistributionItem(tier=(tier or "unset"), organization_count=count)
            for tier, count in sorted(
                rows, key=lambda row: (row[0] is None, row[0] or "")
            )
        ]
        message = None
        if total and not populated:
            message = (
                "No organization has a populated subscription_tier -- see "
                "Organization.subscription_tier's own module docstring: it "
                "is a lightweight, unpopulated label with no pricing/"
                "entitlement logic behind it."
            )
        return PlanDistributionResponse(
            total_organizations=total,
            populated_organizations=populated,
            unset_organizations=unset,
            by_tier=by_tier,
            message=message,
        )

    async def _maybe_audit(self, user_id: uuid.UUID) -> None:
        logger.info(
            "dashboard_viewed",
            extra={"user_id": str(user_id), "dashboard_kind": "business_analytics"},
        )
        if self.audit_writer is None:
            return
        should_write = await DashboardAuditThrottle.should_write_audit_entry(
            self.redis,
            user_id=user_id,
            dashboard_kind="business_analytics",
            scope="global",
        )
        if not should_write:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=user_id,
            action=AUDIT_ACTION_BUSINESS_ANALYTICS_VIEWED,
            entity_type="dashboard",
            entity_id=None,
            description="Business analytics viewed",
            event_metadata={"dashboard_kind": "business_analytics"},
            organization_id=None,
            location_id=None,
        )


__all__ = ["BusinessAnalyticsService", "AuditLogWriter"]
