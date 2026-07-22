from __future__ import annotations

from fastapi import Depends

from app.domains.billing.dependencies import get_super_admin_billing_dashboard_service
from app.domains.billing.service import SuperAdminBillingDashboardService

from .service import FeatureEntitlementService


def get_feature_entitlement_service(
    billing_dashboard: SuperAdminBillingDashboardService = Depends(get_super_admin_billing_dashboard_service),
) -> FeatureEntitlementService:
    return FeatureEntitlementService(billing_dashboard=billing_dashboard)
