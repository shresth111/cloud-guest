"""FastAPI dependencies for the Dashboard domain.

Composes existing analytics, monitoring, billing, and RBAC services into
a unified dashboard configuration — no new database tables or models.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.analytics.dependencies import get_dashboard_service as get_analytics_dashboard_service
from app.domains.analytics.dashboard_service import DashboardService as AnalyticsDashboardService
from app.domains.monitoring.dependencies import get_platform_dashboard_service
from app.domains.monitoring.service import PlatformDashboardService
from app.domains.billing.dependencies import get_super_admin_billing_dashboard_service
from app.domains.billing.service import SuperAdminBillingDashboardService
from app.domains.rbac.dependencies import get_rbac_service
from app.domains.rbac.service import RBACService
from app.domains.organization.dependencies import get_organization_service
from app.domains.organization.service import OrganizationService

from .service import DashboardService


def get_dashboard_service(
    analytics_dashboard: AnalyticsDashboardService = Depends(get_analytics_dashboard_service),
    platform_dashboard: PlatformDashboardService = Depends(get_platform_dashboard_service),
    billing_dashboard: SuperAdminBillingDashboardService = Depends(get_super_admin_billing_dashboard_service),
    rbac_service: RBACService = Depends(get_rbac_service),
    organization_service: OrganizationService = Depends(get_organization_service),
) -> DashboardService:
    return DashboardService(
        analytics_dashboard=analytics_dashboard,
        platform_dashboard=platform_dashboard,
        billing_dashboard=billing_dashboard,
        rbac_service=rbac_service,
        organization_service=organization_service,
    )
