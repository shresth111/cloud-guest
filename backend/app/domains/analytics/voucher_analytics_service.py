"""Voucher redemption analytics service (Phase 1 BhaiFi-parity #21) --
``GET /analytics/voucher-redemptions``.

## Scope: organization-scoped, no ``DashboardScopeResolver``

Unlike ``DomainAnalyticsService``/``BusinessAnalyticsService`` (which layer
RBAC's route-level ``RequirePermission(..., scope=...)`` gate underneath an
*additional*, independent ``DashboardScopeResolver`` check -- see
``dashboard_scope.py``'s own module docstring for why both layers matter for
those endpoints, chiefly MSP-parent-organizations viewing their children's
data), this service relies on RBAC's own route-level gate alone
(``RequirePermission("analytics.read", scope=ScopeType.ORGANIZATION)`` +
``RequireOrganization``, which already validates the caller holds an active
membership in the exact organization requested). **Honest scope
limitation:** an MSP parent organization's dashboard cannot see its
children's aggregated voucher-redemption figures through this endpoint the
way it can through ``/analytics/routers``/``/analytics/network`` --
composing ``DashboardScopeResolver`` here as well is a reasonable future
addition, not implemented in this first pass since no existing caller of
this endpoint has asked for MSP roll-up visibility into voucher redemption
specifically.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from .voucher_analytics import (
    VoucherRedemptionLookupProtocol,
    compute_voucher_redemption_analytics,
)
from .voucher_analytics_schemas import (
    VoucherRedemptionAnalyticsResponse,
    VoucherRedemptionByPlanResponse,
)


class VoucherAnalyticsService:
    def __init__(self, voucher_lookup: VoucherRedemptionLookupProtocol) -> None:
        self.voucher_lookup = voucher_lookup

    async def get_voucher_redemption_analytics(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> VoucherRedemptionAnalyticsResponse:
        analytics = await compute_voucher_redemption_analytics(
            organization_id=organization_id,
            location_id=location_id,
            start=start,
            end=end,
            voucher_lookup=self.voucher_lookup,
        )
        return VoucherRedemptionAnalyticsResponse(
            organization_id=organization_id,
            location_id=location_id,
            window_start=start.isoformat(),
            window_end=end.isoformat(),
            issued_count=analytics.issued_count,
            redeemed_count=analytics.redeemed_count,
            redemption_rate=analytics.redemption_rate,
            by_plan=[
                VoucherRedemptionByPlanResponse(
                    plan_id=str(row.plan_id) if row.plan_id else None,
                    redeemed_count=row.redeemed_count,
                )
                for row in analytics.by_plan
            ],
        )


__all__ = ["VoucherAnalyticsService"]
