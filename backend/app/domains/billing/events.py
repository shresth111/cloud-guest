"""Lightweight, in-process domain events for the Billing module.

Plain, frozen dataclasses constructed by ``service.py`` methods and logged
synchronously by that same service -- mirrors ``app.domains.otp.events``/
``app.domains.wireguard.events``'s identical "simplest thing that could
work" posture: no event bus, no publish/subscribe registry, no async
dispatch, just a typed, self-documenting value object per notable lifecycle
moment. Not part of the public API surface -- nothing outside this module's
own ``service.py`` constructs or reads these.

Distinct from, and a strict subset of, what reaches RBAC's
``audit_log_entries`` -- every event here is logged; the license lifecycle
transitions (assign/activate/suspend/upgrade/downgrade/expire/cancel) are
also audited (see ``service.py``'s ``_audit`` calls), since they are exactly
the kind of moderate-volume, admin-attributable action every other domain's
own ``AuditAction`` additions already cover this same way.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class LicenseAssigned:
    license_id: uuid.UUID
    organization_id: uuid.UUID
    plan_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class LicenseActivated:
    license_id: uuid.UUID
    organization_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class LicenseSuspended:
    license_id: uuid.UUID
    organization_id: uuid.UUID
    reason: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class LicenseExpired:
    license_id: uuid.UUID
    organization_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class LicenseCancelled:
    license_id: uuid.UUID
    organization_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class LicenseUpgraded:
    license_id: uuid.UUID
    organization_id: uuid.UUID
    from_plan_id: uuid.UUID | None
    to_plan_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class LicenseDowngraded:
    license_id: uuid.UUID
    organization_id: uuid.UUID
    from_plan_id: uuid.UUID | None
    to_plan_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class UsageLimitExceeded:
    organization_id: uuid.UUID
    metric_key: str
    current_value: str
    limit_value: str
    occurred_at: datetime = field(default_factory=_now)


# ============================================================================
# BE-013 Part 2: Subscription + Renewal + Coupon
# ============================================================================


@dataclass(frozen=True, slots=True)
class SubscriptionCreated:
    subscription_id: uuid.UUID
    organization_id: uuid.UUID
    plan_id: uuid.UUID
    status: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class SubscriptionCancelled:
    subscription_id: uuid.UUID
    organization_id: uuid.UUID
    immediate: bool
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class SubscriptionReactivated:
    subscription_id: uuid.UUID
    organization_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class SubscriptionPaused:
    subscription_id: uuid.UUID
    organization_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class SubscriptionResumed:
    subscription_id: uuid.UUID
    organization_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class SubscriptionRenewed:
    subscription_id: uuid.UUID
    organization_id: uuid.UUID
    amount_charged: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class SubscriptionRenewalFailed:
    subscription_id: uuid.UUID
    organization_id: uuid.UUID
    reason: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class SubscriptionExpiredAfterGracePeriod:
    subscription_id: uuid.UUID
    organization_id: uuid.UUID
    license_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class CouponApplied:
    coupon_id: uuid.UUID
    organization_id: uuid.UUID
    subscription_id: uuid.UUID | None
    discount_amount: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class CouponValidationFailed:
    code: str
    organization_id: uuid.UUID
    reason: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class RenewalReminderSent:
    subscription_id: uuid.UUID
    organization_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class ExpiryReminderSent:
    subscription_id: uuid.UUID
    organization_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


# ============================================================================
# BE-013 Part 3: Payment Service + Real Stripe/Razorpay Integration + Webhooks
# ============================================================================


@dataclass(frozen=True, slots=True)
class PaymentSucceeded:
    payment_id: uuid.UUID
    organization_id: uuid.UUID
    provider: str
    amount: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class PaymentFailed:
    payment_id: uuid.UUID
    organization_id: uuid.UUID
    provider: str
    reason: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class PaymentRefunded:
    payment_id: uuid.UUID
    organization_id: uuid.UUID
    refunded_amount: str
    full: bool
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class PaymentRetried:
    payment_id: uuid.UUID
    organization_id: uuid.UUID
    succeeded: bool
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class PaymentMethodRegistered:
    payment_method_id: uuid.UUID
    organization_id: uuid.UUID
    provider: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class PaymentMethodRemoved:
    payment_method_id: uuid.UUID
    organization_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class WebhookProcessed:
    provider: str
    event_id: str
    event_type: str
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class WebhookSignatureInvalid:
    provider: str
    reason: str
    occurred_at: datetime = field(default_factory=_now)


__all__ = [
    "LicenseAssigned",
    "LicenseActivated",
    "LicenseSuspended",
    "LicenseExpired",
    "LicenseCancelled",
    "LicenseUpgraded",
    "LicenseDowngraded",
    "UsageLimitExceeded",
    "SubscriptionCreated",
    "SubscriptionCancelled",
    "SubscriptionReactivated",
    "SubscriptionPaused",
    "SubscriptionResumed",
    "SubscriptionRenewed",
    "SubscriptionRenewalFailed",
    "SubscriptionExpiredAfterGracePeriod",
    "CouponApplied",
    "CouponValidationFailed",
    "RenewalReminderSent",
    "ExpiryReminderSent",
    "PaymentSucceeded",
    "PaymentFailed",
    "PaymentRefunded",
    "PaymentRetried",
    "PaymentMethodRegistered",
    "PaymentMethodRemoved",
    "WebhookProcessed",
    "WebhookSignatureInvalid",
]
