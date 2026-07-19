"""FastAPI dependencies for the Billing domain.

Wires the repository/service layer, composing with
``app.domains.organization``'s existing ``OrganizationService`` (MSP
child-organization lookup for the ``ORGANIZATIONS`` usage metric, and the
new, additive ``sync_subscription_tier`` hook), ``app.domains.guest``'s
existing ``GuestAnalyticsService`` (guest/session/bandwidth aggregates), and
``app.domains.analytics``'s existing ``AnalyticsRepository`` (the
``count_active_guest_sessions`` real aggregate query) -- the same narrow,
duck-typed ``Protocol`` composition pattern every prior domain in this
codebase establishes (see ``app.domains.analytics.dependencies
.get_analytics_service`` for the closest existing precedent of one domain's
service composing another's this same way). No file inside
``organization``/``guest``/``analytics`` is edited to wire any of this,
other than ``OrganizationService``'s own new, additive
``sync_subscription_tier`` method (see ``models.py``'s module docstring).
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.analytics.dependencies import get_analytics_repository
from app.domains.analytics.repository import AnalyticsRepositoryProtocol
from app.domains.guest.dependencies import get_guest_analytics_service
from app.domains.guest.service import GuestAnalyticsService
from app.domains.organization.dependencies import get_organization_service
from app.domains.organization.service import OrganizationService
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .repository import (
    LicenseRepository,
    LicenseRepositoryProtocol,
    PlanRepository,
    PlanRepositoryProtocol,
    UsageRepository,
    UsageRepositoryProtocol,
)
from .service import LicenseService, PlanService, UsageService


def get_plan_repository(
    db: AsyncSession = Depends(get_db_session),
) -> PlanRepositoryProtocol:
    return PlanRepository(db)


def get_license_repository(
    db: AsyncSession = Depends(get_db_session),
) -> LicenseRepositoryProtocol:
    return LicenseRepository(db)


def get_usage_repository(
    db: AsyncSession = Depends(get_db_session),
) -> UsageRepositoryProtocol:
    return UsageRepository(db)


def get_plan_service(
    repository: PlanRepositoryProtocol = Depends(get_plan_repository),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> PlanService:
    return PlanService(repository, audit_writer=audit_repository)


def get_usage_service(
    repository: UsageRepositoryProtocol = Depends(get_usage_repository),
    plan_repository: PlanRepositoryProtocol = Depends(get_plan_repository),
    license_repository: LicenseRepositoryProtocol = Depends(get_license_repository),
    organization_service: OrganizationService = Depends(get_organization_service),
    guest_analytics_service: GuestAnalyticsService = Depends(
        get_guest_analytics_service
    ),
    analytics_repository: AnalyticsRepositoryProtocol = Depends(
        get_analytics_repository
    ),
) -> UsageService:
    return UsageService(
        repository,
        plan_repository,
        license_repository,
        organization_service,
        guest_analytics_service,
        analytics_repository,
    )


def get_license_service(
    repository: LicenseRepositoryProtocol = Depends(get_license_repository),
    plan_repository: PlanRepositoryProtocol = Depends(get_plan_repository),
    organization_service: OrganizationService = Depends(get_organization_service),
    usage_service: UsageService = Depends(get_usage_service),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> LicenseService:
    return LicenseService(
        repository,
        plan_repository,
        organization_sync=organization_service,
        usage_validator=usage_service,
        audit_writer=audit_repository,
    )


__all__ = [
    "get_plan_repository",
    "get_license_repository",
    "get_usage_repository",
    "get_plan_service",
    "get_license_service",
    "get_usage_service",
]
