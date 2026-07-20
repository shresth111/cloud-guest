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
    can carry -- exactly the list the spec enumerates, no more, no less.

    Extended by Smart Location Provisioning (``app.domains.location
    .provisioning_service``) with the "Feature Access"/"Plan Limits" keys
    that part's own onboarding spec names and BE-013 Part 1 had not yet
    needed (``DASHBOARD`` through ``MULTI_LOCATION`` below, plus
    ``MAX_CONCURRENT_SESSIONS``/``MAX_STAFF_USERS``/``MAX_API_KEYS``) -- see
    ``docs/location/FLOW.md``'s "Feature Access / Plan Limits" section for
    the full reasoning on why this is an additive extension of billing's own
    existing, closed feature-key set rather than a second, parallel concept
    invented in the ``location`` domain."""

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

    # -- Smart Location Provisioning additions: plan limits (LIMIT-typed) --
    MAX_CONCURRENT_SESSIONS = "max_concurrent_sessions"
    MAX_STAFF_USERS = "max_staff_users"
    MAX_API_KEYS = "max_api_keys"

    # -- Smart Location Provisioning additions: feature access
    # (BOOLEAN-typed) --
    DASHBOARD = "dashboard"
    GUEST_WIFI = "guest_wifi"
    CAPTIVE_PORTAL = "captive_portal"
    FREERADIUS = "freeradius"
    WIREGUARD = "wireguard"
    REPORTS = "reports"
    ALERTS = "alerts"
    BILLING = "billing"
    VOUCHER_LOGIN = "voucher_login"
    QR_LOGIN = "qr_login"
    SOCIAL_LOGIN = "social_login"
    MOBILE_OTP = "mobile_otp"
    NOTIFICATION_CENTER = "notification_center"
    AUDIT_LOGS = "audit_logs"
    MULTI_ROUTER = "multi_router"
    MULTI_LOCATION = "multi_location"


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
        PlanFeatureKey.MAX_CONCURRENT_SESSIONS,
        PlanFeatureKey.MAX_STAFF_USERS,
        PlanFeatureKey.MAX_API_KEYS,
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
        PlanFeatureKey.DASHBOARD,
        PlanFeatureKey.GUEST_WIFI,
        PlanFeatureKey.CAPTIVE_PORTAL,
        PlanFeatureKey.FREERADIUS,
        PlanFeatureKey.WIREGUARD,
        PlanFeatureKey.REPORTS,
        PlanFeatureKey.ALERTS,
        PlanFeatureKey.BILLING,
        PlanFeatureKey.VOUCHER_LOGIN,
        PlanFeatureKey.QR_LOGIN,
        PlanFeatureKey.SOCIAL_LOGIN,
        PlanFeatureKey.MOBILE_OTP,
        PlanFeatureKey.NOTIFICATION_CENTER,
        PlanFeatureKey.AUDIT_LOGS,
        PlanFeatureKey.MULTI_ROUTER,
        PlanFeatureKey.MULTI_LOCATION,
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


# ============================================================================
# BE-013 Part 4: Invoice Engine + Tax/GST
# ============================================================================


class TaxType(StrEnum):
    """The closed set of tax regimes a :class:`~.models.TaxRate` row can
    represent. ``GST`` is the one this part implements the real CGST/SGST/
    IGST split for (see ``validators.compute_tax_breakdown``); ``VAT``/
    ``SALES_TAX`` get an honest flat-percentage computation (no split --
    neither regime has GST's own intra/inter-state CGST/SGST/IGST concept);
    ``NONE`` is a real, first-class "no tax applies" member, mirroring
    ``BillingCycle.NONE``'s identical "explicit member, never an ambiguous
    NULL" reasoning."""

    GST = "gst"
    VAT = "vat"
    SALES_TAX = "sales_tax"
    NONE = "none"


class InvoiceStatus(StrEnum):
    """The full :class:`~.models.Invoice` lifecycle -- see ``service.py``'s
    ``_INVOICE_TRANSITIONS`` for the exact, explicit transition graph (same
    "define every legal transition, reject everything else" rigor as
    ``LicenseStatus``/``SubscriptionStatus``/``PaymentStatus``).

    * ``DRAFT`` -- created but not yet issued to the customer. Reachable
      only via a future manual-invoice-creation flow (this part's own
      ``generate_invoice_for_subscription`` issues directly -- see that
      method's own docstring); kept as a real, legal member for that
      forward compatibility rather than invented dead.
    * ``ISSUED`` -- sent to the customer, awaiting payment.
    * ``PAID`` -- a real ``Payment`` has settled it in full (see
      ``service.InvoiceService.mark_invoice_paid``). Terminal from this
      service's own perspective -- correcting a paid invoice is done via a
      :class:`~.models.CreditDebitNote`, never a direct status change.
    * ``OVERDUE`` -- ``ISSUED`` past its ``due_date`` with no payment yet.
      Reversible back to ``PAID`` the moment a payment settles it.
    * ``CANCELLED`` -- a ``DRAFT`` invoice withdrawn before ever being sent
      (never reached a customer). Terminal.
    * ``VOID`` -- an already-``ISSUED``/``OVERDUE`` invoice formally
      voided after being sent (a real accounting reversal, the invoice
      number itself is never reused/reassigned). Terminal.
    """

    DRAFT = "draft"
    ISSUED = "issued"
    PAID = "paid"
    OVERDUE = "overdue"
    CANCELLED = "cancelled"
    VOID = "void"


class NoteType(StrEnum):
    """The discriminator for :class:`~.models.CreditDebitNote` -- one table,
    not two near-identical ones, since a credit note and a debit note share
    every column (``invoice_id``/``amount``/``reason``/``issued_at``/
    ``note_number``) and differ only in commercial direction (reduces vs.
    increases what the customer owes) and their own independent number
    sequence (see ``number_generator.py``)."""

    CREDIT = "credit"
    DEBIT = "debit"


# Invoice/credit-note/debit-note number-format prefixes -- see
# number_generator.py for the exact "INV-2026-00001"-shaped format and its
# real, DB-level-atomic concurrency mechanism. Credit and debit notes get
# their own, independent sequences (never the invoice sequence, and never
# each other's) -- a real, distinct accounting-document-type numbering
# convention.
INVOICE_NUMBER_PREFIX = "INV"
CREDIT_NOTE_NUMBER_PREFIX = "CN"
DEBIT_NOTE_NUMBER_PREFIX = "DN"

# Zero-padded digit width for the sequence portion of every generated
# number (e.g. "00001") -- 5 digits comfortably covers 99,999 documents of
# one type within a single calendar year before rolling over into 6 digits
# (never a hard ceiling -- Python's ``:0{width}d}`` format simply widens
# for a larger value; this is a cosmetic default, not an enforced limit).
NUMBER_SEQUENCE_DIGITS = 5

# The Celery Beat task name and interval for
# ``tasks.run_invoice_overdue_sweep`` (registered in
# ``app.core.celery_app``'s ``beat_schedule``) -- see
# ``Settings.invoice_overdue_sweep_interval_seconds``'s own docstring for
# the interval reasoning.
TASK_RUN_INVOICE_OVERDUE_SWEEP = "app.domains.billing.tasks.run_invoice_overdue_sweep"


# ============================================================================
# BE-013 Part 5: Super Admin + Customer Billing Dashboards
# ============================================================================

# Which PaymentStatus values represent money this platform actually
# captured (at least once) -- used by ``repository.BillingDashboardRepository``
# / ``service`` dashboard aggregates to compute "total revenue"/"lifetime
# revenue"/the monthly revenue trend as ``SUM(amount) - SUM(refunded_amount)``
# over exactly this status set. This is a deliberate generalization of the
# module brief's own "sum of Payment.amount where status=SUCCEEDED, minus
# refunded_amount" wording: once ANY refund (full or partial) is recorded
# against a Payment, ``PaymentService.refund_payment`` moves its ``status``
# to ``PARTIALLY_REFUNDED``/``REFUNDED`` -- it no longer reads ``SUCCEEDED``
# at all (see that method's own docstring). Reading the brief's formula
# completely literally (``status = SUCCEEDED`` only) would therefore make a
# partially-refunded payment's entire original amount vanish from "total
# revenue" the instant it is even partly refunded, rather than correctly
# netting down by only the refunded portion -- an undercounting bug, not a
# faithful implementation of the brief's own intent. Including
# ``PARTIALLY_REFUNDED``/``REFUNDED`` in the summed set (still subtracting
# ``refunded_amount`` from each) preserves the brief's intent ("real money
# captured, minus what was given back") while fixing that gap. ``PENDING``/
# ``FAILED`` never captured any money and are correctly excluded.
DASHBOARD_CAPTURED_PAYMENT_STATUSES: frozenset[PaymentStatus] = frozenset(
    {
        PaymentStatus.SUCCEEDED,
        PaymentStatus.PARTIALLY_REFUNDED,
        PaymentStatus.REFUNDED,
    }
)

# Default lookback window (in whole calendar months, inclusive of the
# current in-progress month) for the Super Admin Revenue Dashboard's
# month-by-month trend -- a reasonable default "recent history" view; the
# router accepts a caller-supplied ``months`` override within
# ``MIN_DASHBOARD_REVENUE_TREND_MONTHS``..``MAX_DASHBOARD_REVENUE_TREND_MONTHS``.
DEFAULT_DASHBOARD_REVENUE_TREND_MONTHS = 12
MIN_DASHBOARD_REVENUE_TREND_MONTHS = 1
MAX_DASHBOARD_REVENUE_TREND_MONTHS = 36

# How many of a customer's own most-recent Invoice/Payment rows the
# Customer Billing Dashboard ("me") surfaces -- a dashboard summary, not a
# full paginated history (that already exists at GET /invoices, GET
# /payments for a caller who wants the complete list).
CUSTOMER_DASHBOARD_RECENT_INVOICES_LIMIT = 10
CUSTOMER_DASHBOARD_RECENT_PAYMENTS_LIMIT = 10

# Dashboard-view audit throttling -- see ``service.py``'s own
# ``_should_write_dashboard_audit`` docstring for the full volume-tiering
# write-up (mirrors ``app.domains.analytics.dashboard_audit``'s identical
# reasoning and Redis SET-NX-EX idiom, re-implemented here rather than
# imported so this domain's own dashboard auditing has no runtime import-time
# coupling to another domain's module -- the same "each domain owns its own
# copy of this small idiom" precedent ``app.domains.otp``'s/
# ``app.domains.voucher``'s own independent rate limiters already establish
# for an structurally-identical Redis check-and-mark pattern).
BILLING_DASHBOARD_AUDIT_THROTTLE_MINUTES = 15
BILLING_DASHBOARD_AUDIT_THROTTLE_KEY_TEMPLATE = "billing:dashboard_audit_throttle:{key}"

# Plain, domain-local audit-action label strings -- not members of the
# shared ``app.domains.rbac.enums.AuditAction`` ``StrEnum`` (that enum lives
# outside this module's own directory-rule boundary, and
# ``AuditLogWriter.create_audit_log_entry``'s ``action`` field is a plain
# string column with no FK/enum constraint tying it to that shared type --
# see ``app.domains.analytics.constants``'s own identical
# ``AUDIT_ACTION_DASHBOARD_*`` precedent for a dashboard-view action that
# is real, audited, and yet deliberately not added to the shared enum).
AUDIT_ACTION_DASHBOARD_SUPER_ADMIN_VIEWED = "billing_dashboard_super_admin_viewed"
AUDIT_ACTION_DASHBOARD_CUSTOMER_VIEWED = "billing_dashboard_customer_viewed"
# Likewise for the new customer-initiated renewal-settings update -- no
# existing AuditAction member fits "toggled auto_renew" without being
# misleading (see docs/billing/FLOW.md's Part 5 section for the full
# write-up of this choice).
AUDIT_ACTION_SUBSCRIPTION_RENEWAL_SETTINGS_UPDATED = (
    "subscription_renewal_settings_updated"
)


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
    "TaxType",
    "InvoiceStatus",
    "NoteType",
    "INVOICE_NUMBER_PREFIX",
    "CREDIT_NOTE_NUMBER_PREFIX",
    "DEBIT_NOTE_NUMBER_PREFIX",
    "NUMBER_SEQUENCE_DIGITS",
    "TASK_RUN_INVOICE_OVERDUE_SWEEP",
    "DASHBOARD_CAPTURED_PAYMENT_STATUSES",
    "DEFAULT_DASHBOARD_REVENUE_TREND_MONTHS",
    "MIN_DASHBOARD_REVENUE_TREND_MONTHS",
    "MAX_DASHBOARD_REVENUE_TREND_MONTHS",
    "CUSTOMER_DASHBOARD_RECENT_INVOICES_LIMIT",
    "CUSTOMER_DASHBOARD_RECENT_PAYMENTS_LIMIT",
    "BILLING_DASHBOARD_AUDIT_THROTTLE_MINUTES",
    "BILLING_DASHBOARD_AUDIT_THROTTLE_KEY_TEMPLATE",
    "AUDIT_ACTION_DASHBOARD_SUPER_ADMIN_VIEWED",
    "AUDIT_ACTION_DASHBOARD_CUSTOMER_VIEWED",
    "AUDIT_ACTION_SUBSCRIPTION_RENEWAL_SETTINGS_UPDATED",
]
