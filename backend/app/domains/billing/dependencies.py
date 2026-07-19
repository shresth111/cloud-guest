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

from app.core.config import Settings, get_settings
from app.database.session import get_db_session
from app.domains.analytics.dependencies import get_analytics_repository
from app.domains.analytics.repository import AnalyticsRepositoryProtocol
from app.domains.guest.dependencies import get_guest_analytics_service
from app.domains.guest.service import GuestAnalyticsService
from app.domains.organization.dependencies import get_organization_service
from app.domains.organization.service import OrganizationService
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .renewal_service import (
    PaymentGatewayProtocol,
    RenewalService,
    UnconfiguredPaymentGateway,
)
from .repository import (
    CouponRepository,
    CouponRepositoryProtocol,
    LicenseRepository,
    LicenseRepositoryProtocol,
    PlanRepository,
    PlanRepositoryProtocol,
    SubscriptionRepository,
    SubscriptionRepositoryProtocol,
    UsageRepository,
    UsageRepositoryProtocol,
)
from .service import (
    CouponService,
    LicenseService,
    PlanService,
    SubscriptionService,
    UsageService,
)


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


def get_subscription_repository(
    db: AsyncSession = Depends(get_db_session),
) -> SubscriptionRepositoryProtocol:
    return SubscriptionRepository(db)


def get_coupon_repository(
    db: AsyncSession = Depends(get_db_session),
) -> CouponRepositoryProtocol:
    return CouponRepository(db)


def get_coupon_service(
    repository: CouponRepositoryProtocol = Depends(get_coupon_repository),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> CouponService:
    return CouponService(repository, audit_writer=audit_repository)


def get_subscription_service(
    repository: SubscriptionRepositoryProtocol = Depends(get_subscription_repository),
    plan_repository: PlanRepositoryProtocol = Depends(get_plan_repository),
    license_service: LicenseService = Depends(get_license_service),
    coupon_service: CouponService = Depends(get_coupon_service),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    settings: Settings = Depends(get_settings),
) -> SubscriptionService:
    return SubscriptionService(
        repository,
        plan_repository,
        license_service,
        coupon_service=coupon_service,
        trial_period_days=settings.subscription_trial_period_days,
        audit_writer=audit_repository,
    )


def get_payment_gateway() -> PaymentGatewayProtocol:
    """The exact seam BE-013 Part 3 overrides via dependency injection --
    see ``renewal_service``'s own module docstring for the full write-up.
    Part 3 replaces this function's body (or overrides it via FastAPI's
    ``app.dependency_overrides``) to return a real Stripe/Razorpay-backed
    ``PaymentGatewayProtocol`` implementation; nothing else in this module
    needs to change."""
    return UnconfiguredPaymentGateway()


def get_renewal_service(
    repository: SubscriptionRepositoryProtocol = Depends(get_subscription_repository),
    plan_repository: PlanRepositoryProtocol = Depends(get_plan_repository),
    license_service: LicenseService = Depends(get_license_service),
    organization_service: OrganizationService = Depends(get_organization_service),
    payment_gateway: PaymentGatewayProtocol = Depends(get_payment_gateway),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    settings: Settings = Depends(get_settings),
) -> RenewalService:
    return RenewalService(
        repository,
        plan_repository,
        license_service=license_service,
        organization_lookup=organization_service,
        payment_gateway=payment_gateway,
        audit_writer=audit_repository,
        grace_period_days=settings.subscription_renewal_grace_period_days,
        renewal_reminder_days_before=settings.subscription_renewal_reminder_days_before,
        expiry_reminder_days_before=settings.subscription_expiry_reminder_days_before,
    )


__all__ = [
    "get_plan_repository",
    "get_license_repository",
    "get_usage_repository",
    "get_plan_service",
    "get_license_service",
    "get_usage_service",
    "get_subscription_repository",
    "get_coupon_repository",
    "get_coupon_service",
    "get_subscription_service",
    "get_payment_gateway",
    "get_renewal_service",
]
