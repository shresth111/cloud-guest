from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.billing.cache import EntitlementCache
from app.domains.billing.constants import PlanFeatureKey
from app.domains.billing.dependencies import (
    get_entitlement_cache,
    get_entitlement_checker,
    get_feature_override_repository,
    get_license_service,
    get_super_admin_billing_dashboard_service,
)
from app.domains.billing.repository import FeatureOverrideRepositoryProtocol
from app.domains.billing.service import (
    EntitlementChecker,
    LicenseService,
    SuperAdminBillingDashboardService,
)
from app.domains.marketing.repository import MarketingRepository
from app.domains.organization.dependencies import get_organization_service
from app.domains.organization.service import OrganizationService
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .addons import AddonService, SqlUserNameLookup
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


def get_addon_service(
    db: AsyncSession = Depends(get_db_session),
    organization_service: OrganizationService = Depends(get_organization_service),
    license_service: LicenseService = Depends(get_license_service),
    overrides: FeatureOverrideRepositoryProtocol = Depends(
        get_feature_override_repository
    ),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    entitlement_cache: EntitlementCache = Depends(get_entitlement_cache),
) -> AddonService:
    return AddonService(
        organizations=organization_service,
        plan_features=license_service,
        overrides=overrides,
        campaign_hooks={
            PlanFeatureKey.GUEST_MARKETING.value: MarketingRepository(db),
        },
        user_names=SqlUserNameLookup(db),
        audit_writer=audit_repository,
        entitlement_cache=entitlement_cache,
        committer=db,
    )
