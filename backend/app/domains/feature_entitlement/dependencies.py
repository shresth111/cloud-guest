from __future__ import annotations

from fastapi import Depends

from app.domains.billing.dependencies import (
    get_entitlement_checker,
    get_super_admin_billing_dashboard_service,
)
from app.domains.billing.service import (
    EntitlementChecker,
    SuperAdminBillingDashboardService,
)

from .service import FeatureEntitlementService


def get_feature_entitlement_service(
    billing_dashboard: SuperAdminBillingDashboardService = Depends(
        get_super_admin_billing_dashboard_service
    ),
    entitlement_checker: EntitlementChecker = Depends(get_entitlement_checker),
) -> FeatureEntitlementService:
    return FeatureEntitlementService(
        billing_dashboard=billing_dashboard,
        entitlement_checker=entitlement_checker,
    )
