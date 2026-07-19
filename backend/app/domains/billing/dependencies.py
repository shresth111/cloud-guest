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
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.database.redis import get_redis_client
from app.database.session import get_db_session
from app.domains.analytics.dependencies import get_analytics_repository
from app.domains.analytics.repository import AnalyticsRepositoryProtocol
from app.domains.guest.dependencies import get_guest_analytics_service
from app.domains.guest.service import GuestAnalyticsService
from app.domains.organization.dependencies import get_organization_service
from app.domains.organization.service import OrganizationService
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .constants import PaymentProvider
from .payment_gateways import RazorpayPaymentGateway, StripePaymentGateway
from .renewal_service import PaymentGatewayProtocol, RenewalService
from .repository import (
    BillingProfileRepository,
    BillingProfileRepositoryProtocol,
    CouponRepository,
    CouponRepositoryProtocol,
    CreditDebitNoteRepository,
    CreditDebitNoteRepositoryProtocol,
    InvoiceRepository,
    InvoiceRepositoryProtocol,
    LicenseRepository,
    LicenseRepositoryProtocol,
    NumberCounterRepository,
    PaymentMethodRepository,
    PaymentMethodRepositoryProtocol,
    PaymentRepository,
    PaymentRepositoryProtocol,
    PlanRepository,
    PlanRepositoryProtocol,
    SubscriptionRepository,
    SubscriptionRepositoryProtocol,
    TaxRateRepository,
    TaxRateRepositoryProtocol,
    UsageRepository,
    UsageRepositoryProtocol,
)
from .service import (
    BillingProfileService,
    CouponService,
    InvoiceService,
    LicenseService,
    PaymentMethodService,
    PaymentService,
    PlanService,
    SubscriptionService,
    TaxRateService,
    UsageService,
)
from .webhooks import RedisWebhookEventDedup, WebhookEventDedupProtocol


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


def build_payment_gateway(
    *, db: AsyncSession, settings: Settings
) -> PaymentGatewayProtocol:
    """Plain, FastAPI-DI-framework-free constructor for the real gateway
    selection -- the actual "wire it in for real" logic BE-013 Part 3 adds,
    called both by the FastAPI dependency ``get_payment_gateway`` below
    *and* directly by ``tasks.py``'s Celery bridge (which already owns its
    own open ``AsyncSession`` and cannot resolve FastAPI's ``Depends(...)``
    outside the framework -- calling a function whose parameters merely
    *default* to ``Depends(...)`` works fine as long as every such
    parameter is passed explicitly, which this one always is).

    ## Provider-selection model: one platform-wide default, not per-org/plan

    A single ``Settings.payment_default_provider`` selects Stripe vs.
    Razorpay for the entire platform -- not a per-organization or per-plan
    choice. This was judged the simpler, equally defensible model for this
    part: neither ``Organization`` nor ``Plan`` (Part 1) carries any
    "preferred payment provider" column today, and inventing one now, with
    no real multi-provider deployment to justify it and no way to actually
    exercise a per-org routing decision against real credentials in this
    sandbox anyway, would be speculative scope beyond what Part 3 asks for.
    A future part could add a nullable ``Organization.preferred_payment_provider``
    (or similar) and this function would become the one place that reads
    it -- the seam is already isolated here for exactly that reason.

    Since no real API key is ever actually configured in this sandbox,
    both concrete gateways' own ``_is_configured`` guard means the
    platform's real, observed behavior is byte-for-byte unchanged from
    Part 2's ``UnconfiguredPaymentGateway`` in practice -- this function is
    the entire "wire it in for real" step Part 2 explicitly deferred.
    """
    payment_repository = PaymentRepository(db)
    payment_method_repository = PaymentMethodRepository(db)
    stripe_gateway = StripePaymentGateway(
        settings=settings,
        payment_repository=payment_repository,
        payment_method_repository=payment_method_repository,
    )
    razorpay_gateway = RazorpayPaymentGateway(
        settings=settings,
        payment_repository=payment_repository,
        payment_method_repository=payment_method_repository,
    )
    if settings.payment_default_provider == PaymentProvider.RAZORPAY.value:
        return razorpay_gateway
    return stripe_gateway


def get_payment_gateway(
    db: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings),
) -> PaymentGatewayProtocol:
    """The exact seam BE-013 Part 2 deferred, wired for real here -- see
    ``renewal_service``'s own module docstring for the seam's full
    write-up, and ``build_payment_gateway``'s own docstring immediately
    above for the provider-selection model and the "still-unconfigured-in-
    this-sandbox" honesty note."""
    return build_payment_gateway(db=db, settings=settings)


def get_payment_repository(
    db: AsyncSession = Depends(get_db_session),
) -> PaymentRepositoryProtocol:
    return PaymentRepository(db)


def get_payment_method_repository(
    db: AsyncSession = Depends(get_db_session),
) -> PaymentMethodRepositoryProtocol:
    return PaymentMethodRepository(db)


def get_payment_service(
    db: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> PaymentService:
    payment_repository = PaymentRepository(db)
    payment_method_repository = PaymentMethodRepository(db)
    stripe_gateway = StripePaymentGateway(
        settings=settings,
        payment_repository=payment_repository,
        payment_method_repository=payment_method_repository,
    )
    razorpay_gateway = RazorpayPaymentGateway(
        settings=settings,
        payment_repository=payment_repository,
        payment_method_repository=payment_method_repository,
    )
    return PaymentService(
        payment_repository,
        payment_method_repository,
        gateways={
            PaymentProvider.STRIPE.value: stripe_gateway,
            PaymentProvider.RAZORPAY.value: razorpay_gateway,
        },
        audit_writer=audit_repository,
    )


def get_payment_method_service(
    repository: PaymentMethodRepositoryProtocol = Depends(
        get_payment_method_repository
    ),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> PaymentMethodService:
    return PaymentMethodService(repository, audit_writer=audit_repository)


def get_webhook_event_dedup(
    redis: Redis = Depends(get_redis_client),
    settings: Settings = Depends(get_settings),
) -> WebhookEventDedupProtocol:
    return RedisWebhookEventDedup(
        redis, ttl_seconds=settings.payment_webhook_event_dedup_ttl_seconds
    )


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


# ============================================================================
# BE-013 Part 4: Invoice Engine + Tax/GST
# ============================================================================


def get_tax_rate_repository(
    db: AsyncSession = Depends(get_db_session),
) -> TaxRateRepositoryProtocol:
    return TaxRateRepository(db)


def get_tax_rate_service(
    repository: TaxRateRepositoryProtocol = Depends(get_tax_rate_repository),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> TaxRateService:
    return TaxRateService(repository, audit_writer=audit_repository)


def get_billing_profile_repository(
    db: AsyncSession = Depends(get_db_session),
) -> BillingProfileRepositoryProtocol:
    return BillingProfileRepository(db)


def get_billing_profile_service(
    repository: BillingProfileRepositoryProtocol = Depends(
        get_billing_profile_repository
    ),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> BillingProfileService:
    return BillingProfileService(repository, audit_writer=audit_repository)


def get_invoice_repository(
    db: AsyncSession = Depends(get_db_session),
) -> InvoiceRepositoryProtocol:
    return InvoiceRepository(db)


def get_credit_debit_note_repository(
    db: AsyncSession = Depends(get_db_session),
) -> CreditDebitNoteRepositoryProtocol:
    return CreditDebitNoteRepository(db)


def get_number_counter_repository(
    db: AsyncSession = Depends(get_db_session),
) -> NumberCounterRepository:
    return NumberCounterRepository(db)


def get_invoice_service(
    repository: InvoiceRepositoryProtocol = Depends(get_invoice_repository),
    subscription_repository: SubscriptionRepositoryProtocol = Depends(
        get_subscription_repository
    ),
    plan_repository: PlanRepositoryProtocol = Depends(get_plan_repository),
    billing_profile_repository: BillingProfileRepositoryProtocol = Depends(
        get_billing_profile_repository
    ),
    tax_rate_repository: TaxRateRepositoryProtocol = Depends(get_tax_rate_repository),
    number_counter_repository: NumberCounterRepository = Depends(
        get_number_counter_repository
    ),
    note_repository: CreditDebitNoteRepositoryProtocol = Depends(
        get_credit_debit_note_repository
    ),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    settings: Settings = Depends(get_settings),
) -> InvoiceService:
    return InvoiceService(
        repository,
        subscription_repository=subscription_repository,
        plan_repository=plan_repository,
        billing_profile_repository=billing_profile_repository,
        tax_rate_repository=tax_rate_repository,
        number_counter_repository=number_counter_repository,
        note_repository=note_repository,
        platform_gst_state=settings.platform_gst_state,
        platform_gst_country=settings.platform_gst_country,
        invoice_due_days=settings.invoice_due_days,
        audit_writer=audit_repository,
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
    "build_payment_gateway",
    "get_payment_gateway",
    "get_renewal_service",
    "get_payment_repository",
    "get_payment_method_repository",
    "get_payment_service",
    "get_payment_method_service",
    "get_webhook_event_dedup",
    "get_tax_rate_repository",
    "get_tax_rate_service",
    "get_billing_profile_repository",
    "get_billing_profile_service",
    "get_invoice_repository",
    "get_credit_debit_note_repository",
    "get_number_counter_repository",
    "get_invoice_service",
]
