"""Enumerations and small constants for the Billing domain.

Stored as plain ``String`` columns on the ORM models (``Plan.plan_type`` /
``Plan.billing_cycle`` / ``PlanFeature.feature_key`` /
``PlanFeature.feature_type`` / ``License.status`` /
``LicenseChangeLog.change_type`` / ``UsageMetric.metric_key``), never a
native PostgreSQL enum type -- the same reason every other domain in this
codebase documents (``app.domains.otp.constants``, ``app.domains.rbac.enums``,
``app.domains.voucher.constants``): adding a new value never requires an
``ALTER TYPE`` migration, only a new additive ``StrEnum`` member.

No new ``Settings`` fields. Like ``app.domains.voucher``, this module adds
no fields to ``app.core.config.Settings`` -- the default currency and every
usage-computation window are plain module-level constants here, not
per-environment tunables. Nothing in this Part's own scope needs
per-deployment tuning badly enough to justify touching ``app/core/config.py``
(a file outside this module's directory-rule boundary).
"""

from __future__ import annotations

from enum import StrEnum


class PlanType(StrEnum):
    """The commercial category of a :class:`~.models.Plan`.

    ``MSP`` exists as its own first-class value (not just a feature flag on
    another type) because the spec calls out MSP-specific plans explicitly
    -- an MSP-type organization (``app.domains.organization.enums
    .OrganizationType.MSP``) manages a portfolio of child organizations, and
    a plan built for that shape (e.g. ``MAX_ORGANIZATIONS`` > 1) is a
    genuinely distinct commercial product, not a variant of ``BUSINESS``/
    ``ENTERPRISE``. ``CUSTOM`` is for Super-Admin-created, negotiated,
    typically-private (``Plan.is_public = False``) one-off plans that don't
    fit any standard tier.
    """

    FREE_TRIAL = "free_trial"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"
    MSP = "msp"
    CUSTOM = "custom"


class BillingCycle(StrEnum):
    """How often a :class:`~.models.Plan` bills, if at all.

    ``NONE`` is a real, first-class member (not a nullable column) for
    trial/custom plans that do not bill on any fixed cadence at all (e.g. a
    ``FREE_TRIAL`` plan, or a bespoke MSP arrangement billed by a mechanism
    a later BE-013 part -- Payment/Invoice -- will define). Modeling this as
    an enum member rather than leaving ``billing_cycle`` nullable keeps every
    plan's billing cadence an explicit, queryable fact instead of an
    ambiguous ``NULL`` that could mean either "not yet decided" or
    "deliberately cycle-less".
    """

    MONTHLY = "monthly"
    YEARLY = "yearly"
    NONE = "none"


class PlanFeatureKey(StrEnum):
    """The closed, finite set of entitlements/limits a :class:`~.models.Plan`
    can carry -- exactly the list the spec enumerates, no more, no less."""

    MAX_ORGANIZATIONS = "max_organizations"
    MAX_LOCATIONS = "max_locations"
    MAX_ROUTERS = "max_routers"
    MAX_GUESTS = "max_guests"
    MAX_ADMIN_USERS = "max_admin_users"
    CAPTIVE_PORTAL_BUILDER = "captive_portal_builder"
    AI_FEATURES = "ai_features"
    ANALYTICS = "analytics"
    MONITORING = "monitoring"
    WHITE_LABEL = "white_label"
    API_ACCESS = "api_access"
    PMS_INTEGRATION = "pms_integration"
    SMS_QUOTA = "sms_quota"
    EMAIL_QUOTA = "email_quota"
    STORAGE_QUOTA_MB = "storage_quota_mb"
    SUPPORT_LEVEL = "support_level"


class PlanFeatureType(StrEnum):
    """The value-shape a :class:`~.models.PlanFeature` row carries -- see
    that model's docstring for exactly which typed column each type reads
    from (``limit_value`` / ``is_enabled`` / ``tier_value``)."""

    LIMIT = "limit"
    BOOLEAN = "boolean"
    TIER = "tier"


class SupportTier(StrEnum):
    """The closed set of legal ``PlanFeature.tier_value`` values for the
    ``SUPPORT_LEVEL`` feature key -- the one ``TIER``-shaped feature this
    spec names."""

    BASIC = "basic"
    PRIORITY = "priority"
    DEDICATED = "dedicated"


# Which PlanFeatureKey each feature key must be stored as -- a defensive,
# additive validation table (see validators.validate_feature_shape) so a
# caller can never create e.g. a BOOLEAN-shaped MAX_GUESTS row by mistake.
LIMIT_FEATURE_KEYS: frozenset[PlanFeatureKey] = frozenset(
    {
        PlanFeatureKey.MAX_ORGANIZATIONS,
        PlanFeatureKey.MAX_LOCATIONS,
        PlanFeatureKey.MAX_ROUTERS,
        PlanFeatureKey.MAX_GUESTS,
        PlanFeatureKey.MAX_ADMIN_USERS,
        PlanFeatureKey.SMS_QUOTA,
        PlanFeatureKey.EMAIL_QUOTA,
        PlanFeatureKey.STORAGE_QUOTA_MB,
    }
)
BOOLEAN_FEATURE_KEYS: frozenset[PlanFeatureKey] = frozenset(
    {
        PlanFeatureKey.CAPTIVE_PORTAL_BUILDER,
        PlanFeatureKey.AI_FEATURES,
        PlanFeatureKey.ANALYTICS,
        PlanFeatureKey.MONITORING,
        PlanFeatureKey.WHITE_LABEL,
        PlanFeatureKey.API_ACCESS,
        PlanFeatureKey.PMS_INTEGRATION,
    }
)
TIER_FEATURE_KEYS: frozenset[PlanFeatureKey] = frozenset({PlanFeatureKey.SUPPORT_LEVEL})

FEATURE_KEY_TYPE: dict[PlanFeatureKey, PlanFeatureType] = {
    **{key: PlanFeatureType.LIMIT for key in LIMIT_FEATURE_KEYS},
    **{key: PlanFeatureType.BOOLEAN for key in BOOLEAN_FEATURE_KEYS},
    **{key: PlanFeatureType.TIER for key in TIER_FEATURE_KEYS},
}


class LicenseStatus(StrEnum):
    """The full :class:`~.models.License` lifecycle -- see
    ``service.py``'s ``_LICENSE_TRANSITIONS`` for the exact, explicit
    transition graph this enum's members participate in (mirrors
    ``app.domains.router.enums.RouterStatus``/
    ``app.domains.voucher.constants.VoucherBatchStatus``'s identical
    "define every legal transition, reject everything else" rigor).

    * ``PENDING_ACTIVATION`` -- a license has just been assigned to an
      organization but has not yet been activated (e.g. awaiting a first
      payment in a later BE-013 part, or an admin's explicit go-ahead).
    * ``ACTIVE`` -- usable; the organization's real entitlements are
      whatever its ``Plan``'s ``PlanFeature`` rows say.
    * ``SUSPENDED`` -- temporarily unusable (e.g. a payment issue a later
      part will detect), but not yet expired/cancelled -- reversible via
      ``activate_license``.
    * ``EXPIRED`` -- ``expires_at`` has passed. Terminal from this module's
      own perspective (a later Renewal-engine part is what would create a
      path back to ``ACTIVE`` -- see ``docs/billing/FLOW.md`` §5 for why no
      such path is built here).
    * ``CANCELLED`` -- administratively terminated. Terminal.
    """

    PENDING_ACTIVATION = "pending_activation"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class LicenseChangeType(StrEnum):
    """What kind of change one :class:`~.models.LicenseChangeLog` row
    records."""

    ASSIGNED = "assigned"
    UPGRADED = "upgraded"
    DOWNGRADED = "downgraded"


# ============================================================================
# BE-013 Part 2: Subscription + Renewal + Coupon Engines
# ============================================================================


class SubscriptionStatus(StrEnum):
    """The full :class:`~.models.Subscription` lifecycle -- see
    ``service.py``'s ``_SUBSCRIPTION_TRANSITIONS`` for the exact, explicit
    transition graph (same rigor as ``LicenseStatus``'s own
    ``_LICENSE_TRANSITIONS``), and ``docs/billing/FLOW.md`` for the full
    write-up of every transition and the ``PAUSED``-vs-``CANCELLED``
    distinction below.

    * ``TRIALING`` -- a free-trial period is in progress (``Plan.plan_type
      == FREE_TRIAL``); ``trial_end``/``current_period_end`` mark when the
      trial converts (a real renewal attempt is made -- see
      ``renewal_service.RenewalService.process_renewal``).
    * ``ACTIVE`` -- usable and current on billing.
    * ``PAST_DUE`` -- the most recent renewal attempt failed (a real decline,
      or the ``PaymentGatewayProtocol`` seam not yet being configured); the
      organization's license is **not** immediately revoked -- a
      configurable grace period (``Settings
      .subscription_renewal_grace_period_days``) still applies before
      ``LicenseService.expire_license`` is finally called (see
      ``renewal_service.RenewalService.expire_lapsed_subscriptions``).
    * ``PAUSED`` -- billing is suspended but the organization's entitlements
      (``License``) are left completely untouched -- distinct from
      ``CANCELLED`` (see below). Reversible via ``resume_subscription``.
    * ``CANCELLED`` -- the organization chose to stop (immediately, or at
      the end of the current period via ``cancel_at_period_end``); the
      underlying ``License`` is suspended (reversible) at the moment
      cancellation takes effect, not hard-expired -- only the grace-period
      sweep above ever calls the terminal ``LicenseService.expire_license``.
      Reversible via ``reactivate_subscription`` *only* while the license
      has not since been expired by that sweep.

    **``PAUSED`` vs ``CANCELLED`` -- the real distinction implemented here:**
    pausing is a *billing* pause only -- no renewal attempts are made while
    ``PAUSED`` (excluded from ``renewal_service`` module's own renewable-
    status set), but the organization keeps using the product on its
    current plan's entitlements exactly as before (no ``License`` call at
    all). Cancelling is a *commercial* decision to stop -- the ``License``
    is suspended the moment cancellation takes effect (immediately, or when
    a scheduled ``cancel_at_period_end`` period elapses), which does revoke
    entitlements, just via the same reversible ``SUSPENDED`` state
    ``LicenseService`` already uses for a payment issue -- not the
    ``EXPIRED`` terminal state, which is reserved for a lapsed grace period
    with no active recovery in progress.
    """

    TRIALING = "trialing"
    ACTIVE = "active"
    PAST_DUE = "past_due"
    PAUSED = "paused"
    CANCELLED = "cancelled"


# Statuses ``renewal_service.RenewalService`` will attempt to renew --
# ``PAUSED``/``CANCELLED`` subscriptions are never billed. ``PAST_DUE`` is
# included so a retry attempt (this same sweep, next tick) can recover a
# subscription back to ``ACTIVE`` without a separate "retry" code path.
RENEWABLE_SUBSCRIPTION_STATUSES: frozenset[SubscriptionStatus] = frozenset(
    {
        SubscriptionStatus.TRIALING,
        SubscriptionStatus.ACTIVE,
        SubscriptionStatus.PAST_DUE,
    }
)

# Billing cycles a real, recurring renewal sweep applies to. ``NONE`` (a
# trial/custom/MSP-negotiated plan with no fixed cadence -- see
# ``BillingCycle``'s own docstring) is deliberately excluded: there is no
# "next period" to compute for a cycle-less plan, so such a subscription is
# never auto-renewed regardless of its own ``auto_renew`` flag.
CYCLIC_BILLING_CYCLES: frozenset[BillingCycle] = frozenset(
    {BillingCycle.MONTHLY, BillingCycle.YEARLY}
)


class DiscountType(StrEnum):
    """The shape of a :class:`~.models.Coupon`'s ``discount_value`` --
    ``PERCENTAGE`` (0-100, applied against the base charge amount) or
    ``FLAT`` (a currency amount in ``Coupon.currency``, clamped so it can
    never exceed -- and therefore never make negative -- the amount it is
    applied against; see ``validators.compute_discount_amount``)."""

    PERCENTAGE = "percentage"
    FLAT = "flat"


# Legal range for a PERCENTAGE-shaped Coupon.discount_value -- a percentage
# discount above 100% (i.e. "pay less than nothing") is never legal.
MAX_PERCENTAGE_DISCOUNT_VALUE = 100

# The Celery Beat task name and interval for
# ``tasks.run_subscription_renewal_sweep`` (registered in
# ``app.core.celery_app``'s ``beat_schedule``). Hourly -- the same
# granularity ``app.domains.analytics.report_tasks``' own scheduler sweep
# uses, and for the identical reasoning: this domain's own billing periods
# are day/month/year granularity (``BillingCycle``), so checking every 15
# minutes (like Analytics' near-real-time dashboard tick) would mean dozens
# of no-op sweeps for every one that actually finds a due subscription, for
# no freshness benefit any real billing workflow needs -- an hourly sweep
# still renews every subscription within an hour of its
# ``current_period_end``, processes grace-period expiries the same day the
# grace period lapses, and sends both reminder kinds well within their own
# multi-day windows.
TASK_RUN_SUBSCRIPTION_RENEWAL_SWEEP = (
    "app.domains.billing.tasks.run_subscription_renewal_sweep"
)
SUBSCRIPTION_RENEWAL_SWEEP_INTERVAL_SECONDS = 3600.0


class UsageMetricKey(StrEnum):
    """The closed, finite set of usage counters this module tracks --
    exactly the list the spec enumerates. See ``service.UsageService
    .record_current_usage``'s module docstring for exactly which existing
    domain's data backs each one (and the two honest placeholders, ``
    STORAGE_USAGE_MB``/``API_REQUESTS``, that have no real data source
    anywhere in this codebase yet)."""

    ORGANIZATIONS = "organizations"
    LOCATIONS = "locations"
    ROUTERS = "routers"
    ACTIVE_DEVICES = "active_devices"
    GUESTS = "guests"
    GUEST_SESSIONS = "guest_sessions"
    OTP_REQUESTS = "otp_requests"
    SMS_USAGE = "sms_usage"
    EMAIL_USAGE = "email_usage"
    STORAGE_USAGE_MB = "storage_usage_mb"
    API_REQUESTS = "api_requests"
    BANDWIDTH_USAGE_MB = "bandwidth_usage_mb"


# Which UsageMetricKey values have a corresponding LIMIT-shaped
# PlanFeatureKey to validate against -- see
# service.UsageService.validate_usage_against_license's module docstring.
# ACTIVE_DEVICES/GUEST_SESSIONS/API_REQUESTS/BANDWIDTH_USAGE_MB have no
# matching LIMIT feature in the spec's finite feature-key list, so they are
# tracked (recorded as UsageMetric rows) but never limit-checked -- an
# honest scope boundary, not an oversight.
USAGE_METRIC_TO_LIMIT_FEATURE: dict[UsageMetricKey, PlanFeatureKey] = {
    UsageMetricKey.ORGANIZATIONS: PlanFeatureKey.MAX_ORGANIZATIONS,
    UsageMetricKey.LOCATIONS: PlanFeatureKey.MAX_LOCATIONS,
    UsageMetricKey.ROUTERS: PlanFeatureKey.MAX_ROUTERS,
    UsageMetricKey.GUESTS: PlanFeatureKey.MAX_GUESTS,
    UsageMetricKey.SMS_USAGE: PlanFeatureKey.SMS_QUOTA,
    UsageMetricKey.EMAIL_USAGE: PlanFeatureKey.EMAIL_QUOTA,
    UsageMetricKey.STORAGE_USAGE_MB: PlanFeatureKey.STORAGE_QUOTA_MB,
}

# Default currency for a newly-created Plan when the caller does not name
# one. The spec's GST mention implies India/INR support must exist, but a
# platform-wide default of USD (this codebase's existing convention -- no
# other domain defaults to any other currency) is kept unless a caller opts
# into "INR" (or any other ISO 4217 code) explicitly per-plan.
DEFAULT_PLAN_CURRENCY = "USD"

# UsageMetric.value is stored as Decimal(18, 2) -- see models.py. Bandwidth
# is recorded in MB (not bytes) to match STORAGE_QUOTA_MB's own unit and
# every "*_MB" metric key name.
BYTES_PER_MB = 1024 * 1024

# ============================================================================
# BE-013 Part 3: Payment Service + Real Stripe/Razorpay Integration + Webhooks
# ============================================================================


class PaymentProvider(StrEnum):
    """The two real, supported payment gateways. See ``payment_gateways.py``
    for each provider's concrete ``renewal_service.PaymentGatewayProtocol``
    implementation, and ``dependencies.build_payment_gateway`` for how
    ``Settings.payment_default_provider`` selects between them."""

    STRIPE = "stripe"
    RAZORPAY = "razorpay"


class PaymentStatus(StrEnum):
    """The full :class:`~.models.Payment` lifecycle -- see ``service.py``'s
    ``_PAYMENT_TRANSITIONS`` for the exact, explicit transition graph (same
    "define every legal transition, reject everything else" rigor as
    ``LicenseStatus``/``SubscriptionStatus``).

    * ``PENDING`` -- a charge attempt has been recorded but the provider has
      not yet confirmed an outcome (e.g. an async Stripe confirmation still
      in flight, or a genuinely not-yet-attempted row).
    * ``SUCCEEDED`` -- the provider confirmed the charge captured.
    * ``FAILED`` -- the provider declined/errored, or the gateway was not
      configured (a real, honest terminal-for-this-attempt outcome --
      ``retry_failed_payment`` is the real, explicit path back out of this
      state, not an automatic retry).
    * ``REFUNDED`` -- ``refunded_amount == amount``.
    * ``PARTIALLY_REFUNDED`` -- ``0 < refunded_amount < amount``.
    """

    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    REFUNDED = "refunded"
    PARTIALLY_REFUNDED = "partially_refunded"


class PaymentMethodType(StrEnum):
    """The tokenized-reference shape a :class:`~.models.PaymentMethod`
    represents -- never raw card data, only a provider token (see that
    model's own docstring)."""

    CARD = "card"
    BANK_ACCOUNT = "bank_account"
    UPI = "upi"
    OTHER = "other"


# Real, well-known "zero-decimal currency" exception set both Stripe and
# Razorpay document identically: for every currency NOT in this set, both
# providers require amounts as an integer count of the currency's smallest
# unit (e.g. USD cents: $12.34 -> 1234); for a currency in this set, the
# smallest unit IS the whole unit (e.g. JPY has no sub-unit: JPY 1234 ->
# 1234, not 123400). See validators.to_minor_units.
ZERO_DECIMAL_CURRENCIES: frozenset[str] = frozenset(
    {
        "BIF",
        "CLP",
        "DJF",
        "GNF",
        "JPY",
        "KMF",
        "KRW",
        "MGA",
        "PYG",
        "RWF",
        "UGX",
        "VND",
        "VUV",
        "XAF",
        "XOF",
        "XPF",
    }
)

# Redis key prefix for the webhook event-id dedup set (webhooks.py's
# RedisWebhookEventDedup) -- see FLOW.md §24 for the full write-up of why a
# Redis-backed, TTL'd dedup set was chosen over a dedicated table.
WEBHOOK_EVENT_DEDUP_KEY_PREFIX = "billing:webhook_event"


__all__ = [
    "PlanType",
    "BillingCycle",
    "PlanFeatureKey",
    "PlanFeatureType",
    "SupportTier",
    "LIMIT_FEATURE_KEYS",
    "BOOLEAN_FEATURE_KEYS",
    "TIER_FEATURE_KEYS",
    "FEATURE_KEY_TYPE",
    "LicenseStatus",
    "LicenseChangeType",
    "SubscriptionStatus",
    "RENEWABLE_SUBSCRIPTION_STATUSES",
    "CYCLIC_BILLING_CYCLES",
    "DiscountType",
    "MAX_PERCENTAGE_DISCOUNT_VALUE",
    "TASK_RUN_SUBSCRIPTION_RENEWAL_SWEEP",
    "SUBSCRIPTION_RENEWAL_SWEEP_INTERVAL_SECONDS",
    "UsageMetricKey",
    "USAGE_METRIC_TO_LIMIT_FEATURE",
    "DEFAULT_PLAN_CURRENCY",
    "BYTES_PER_MB",
    "PaymentProvider",
    "PaymentStatus",
    "PaymentMethodType",
    "ZERO_DECIMAL_CURRENCIES",
    "WEBHOOK_EVENT_DEDUP_KEY_PREFIX",
]
