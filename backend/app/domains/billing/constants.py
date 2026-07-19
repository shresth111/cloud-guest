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
    "UsageMetricKey",
    "USAGE_METRIC_TO_LIMIT_FEATURE",
    "DEFAULT_PLAN_CURRENCY",
    "BYTES_PER_MB",
]
