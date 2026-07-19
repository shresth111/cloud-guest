"""Pure, side-effect-free validation for the Billing domain.

Mirrors ``app.domains.otp.validators``/``app.domains.wireguard.validators``'s
identical discipline: no I/O, just "is this a legal input" checks the
service layer can call before touching the database.
"""

from __future__ import annotations

import calendar
import uuid
from datetime import datetime
from decimal import ROUND_HALF_UP, Decimal

from .constants import (
    FEATURE_KEY_TYPE,
    MAX_PERCENTAGE_DISCOUNT_VALUE,
    ZERO_DECIMAL_CURRENCIES,
    BillingCycle,
    DiscountType,
    PlanFeatureKey,
    PlanFeatureType,
    SupportTier,
)
from .exceptions import InvalidDiscountValueError, InvalidPlanFeatureValueError


def normalize_slug(slug: str) -> str:
    return slug.strip().lower()


def expected_feature_type(feature_key: PlanFeatureKey) -> PlanFeatureType:
    """The one legal ``feature_type`` for a given ``feature_key`` -- see
    ``constants.FEATURE_KEY_TYPE``."""
    return FEATURE_KEY_TYPE[feature_key]


def validate_feature_value(
    *,
    feature_key: PlanFeatureKey,
    feature_type: PlanFeatureType,
    limit_value: Decimal | None,
    is_enabled: bool | None,
    tier_value: str | None,
) -> None:
    """Raises ``InvalidPlanFeatureValueError`` unless ``feature_type`` is the
    one legal type for ``feature_key`` (per
    ``constants.FEATURE_KEY_TYPE``) and exactly the matching typed column is
    populated -- see ``models.PlanFeature``'s docstring for why this module
    uses three typed columns rather than one JSONB blob."""
    required_type = expected_feature_type(feature_key)
    if feature_type != required_type:
        raise InvalidPlanFeatureValueError(
            f"Feature '{feature_key.value}' must use feature_type "
            f"'{required_type.value}', not '{feature_type.value}'"
        )

    if feature_type == PlanFeatureType.LIMIT:
        if limit_value is None:
            raise InvalidPlanFeatureValueError(
                f"Feature '{feature_key.value}' is LIMIT-typed and requires "
                "limit_value"
            )
        if limit_value < 0:
            raise InvalidPlanFeatureValueError("limit_value cannot be negative")
        if is_enabled is not None or tier_value is not None:
            raise InvalidPlanFeatureValueError(
                "LIMIT-typed features must not set is_enabled/tier_value"
            )
    elif feature_type == PlanFeatureType.BOOLEAN:
        if is_enabled is None:
            raise InvalidPlanFeatureValueError(
                f"Feature '{feature_key.value}' is BOOLEAN-typed and requires "
                "is_enabled"
            )
        if limit_value is not None or tier_value is not None:
            raise InvalidPlanFeatureValueError(
                "BOOLEAN-typed features must not set limit_value/tier_value"
            )
    else:  # TIER
        if tier_value is None:
            raise InvalidPlanFeatureValueError(
                f"Feature '{feature_key.value}' is TIER-typed and requires "
                "tier_value"
            )
        if tier_value not in {tier.value for tier in SupportTier}:
            raise InvalidPlanFeatureValueError(
                f"'{tier_value}' is not a legal tier_value "
                f"({', '.join(tier.value for tier in SupportTier)})"
            )
        if limit_value is not None or is_enabled is not None:
            raise InvalidPlanFeatureValueError(
                "TIER-typed features must not set limit_value/is_enabled"
            )


# ============================================================================
# BE-013 Part 2: Subscription + Renewal + Coupon
# ============================================================================


def normalize_coupon_code(code: str) -> str:
    """Coupon codes are stored uppercase-normalized -- case-insensitive
    entry at checkout (``"save20"``/``"SAVE20"``/``"Save20"`` are the same
    coupon), the same normalization discipline ``normalize_slug`` already
    applies to ``Plan.slug`` (lowercase there, uppercase here since a
    coupon code is conventionally displayed/typed in caps, e.g.
    "SAVE20")."""
    return code.strip().upper()


def validate_discount_value(
    *, discount_type: DiscountType, discount_value: Decimal
) -> None:
    """Raises ``InvalidDiscountValueError`` unless ``discount_value`` is in
    the legal range for ``discount_type`` -- a ``PERCENTAGE`` must be
    ``0 <= value <= 100`` (a discount above 100% is never legal -- see
    ``constants.MAX_PERCENTAGE_DISCOUNT_VALUE``); a ``FLAT`` amount must be
    non-negative (its own upper bound is enforced at apply-time by
    ``compute_discount_amount``'s clamp, not here, since a flat amount is
    legal at creation time regardless of which future base amount it will
    later be applied against)."""
    if discount_value < 0:
        raise InvalidDiscountValueError("discount_value cannot be negative")
    if (
        discount_type == DiscountType.PERCENTAGE
        and discount_value > MAX_PERCENTAGE_DISCOUNT_VALUE
    ):
        raise InvalidDiscountValueError(
            f"A PERCENTAGE discount_value cannot exceed "
            f"{MAX_PERCENTAGE_DISCOUNT_VALUE}"
        )


def compute_discount_amount(
    *, discount_type: DiscountType, discount_value: Decimal, base_amount: Decimal
) -> Decimal:
    """The real discount computation -- ``PERCENTAGE`` ->
    ``base_amount * discount_value / 100``; ``FLAT`` -> ``min(discount_value,
    base_amount)`` so a flat discount can never make the charge negative
    (a real, important correctness detail the spec calls out explicitly).
    Rounded to 2 decimal places (currency-precision), matching every other
    ``Numeric(12, 2)``/``Numeric(18, 2)`` money column in this domain."""
    if discount_type == DiscountType.PERCENTAGE:
        raw = base_amount * discount_value / Decimal(100)
    else:
        raw = min(discount_value, base_amount)
    return raw.quantize(Decimal("0.01"))


def add_billing_cycle(start: datetime, billing_cycle: str) -> datetime:
    """The next period boundary after ``start`` for ``billing_cycle`` --
    calendar-correct month/year addition (stdlib ``calendar`` only, no new
    dependency), clamping the day-of-month for e.g. "Jan 31 + 1 month"
    (which becomes Feb 28/29, never an invalid "Feb 31"). ``BillingCycle
    .NONE`` (no fixed cadence) returns ``start`` unchanged -- callers
    (``renewal_service``) never schedule a cycle-less subscription for
    auto-renewal in the first place (see
    ``constants.CYCLIC_BILLING_CYCLES``), so this is a defensive no-op, not
    a code path expected to be exercised in practice."""
    cycle = BillingCycle(billing_cycle)
    if cycle == BillingCycle.MONTHLY:
        return _add_months(start, 1)
    if cycle == BillingCycle.YEARLY:
        return _add_months(start, 12)
    return start


def _add_months(dt: datetime, months: int) -> datetime:
    month_index = dt.month - 1 + months
    year = dt.year + month_index // 12
    month = month_index % 12 + 1
    day = min(dt.day, calendar.monthrange(year, month)[1])
    return dt.replace(year=year, month=month, day=day)


# ============================================================================
# BE-013 Part 3: Payment Service + Real Stripe/Razorpay Integration + Webhooks
# ============================================================================


def to_minor_units(amount: Decimal, currency: str) -> int:
    """Real Stripe/Razorpay requirement: both providers' APIs take charge
    amounts as an integer count of the currency's smallest unit (e.g. USD
    cents -- ``$12.34`` -> ``1234``), **except** for a small, well-known
    "zero-decimal currency" set both providers document identically (e.g.
    JPY has no sub-unit: ``JPY 1234`` -> ``1234``, never ``123400``) -- see
    ``constants.ZERO_DECIMAL_CURRENCIES``. Rounds half-up on the rare input
    that has more than 2 (or 0, for a zero-decimal currency) decimal places
    -- this domain's own ``Numeric(12, 2)`` money columns never produce
    such an input in practice, this is a defensive backstop, not a code
    path expected to be exercised."""
    if currency.upper() in ZERO_DECIMAL_CURRENCIES:
        return int(amount.to_integral_value(rounding=ROUND_HALF_UP))
    return int((amount * 100).to_integral_value(rounding=ROUND_HALF_UP))


def derive_retry_idempotency_key(original_idempotency_key: str) -> str:
    """The wire-level idempotency key a gateway passes to Stripe on
    ``retry_failed_payment`` -- **deliberately a fresh, derived value, never
    a reuse of the original key** (see ``payment_gateways.py``'s own module
    docstring for the full per-provider write-up of why: Stripe caches a
    key's outcome, including a genuine decline, for a real window --
    resubmitting the *same* key for an intentional retry would just return
    the cached decline again, never actually attempting a new charge). The
    original ``Payment.idempotency_key`` column itself is never mutated by
    a retry -- it remains this row's own permanent identity; only the
    value handed to the provider's SDK call changes."""
    return f"{original_idempotency_key}:retry:{uuid.uuid4().hex[:12]}"


__all__ = [
    "normalize_slug",
    "expected_feature_type",
    "validate_feature_value",
    "normalize_coupon_code",
    "validate_discount_value",
    "compute_discount_amount",
    "add_billing_cycle",
    "to_minor_units",
    "derive_retry_idempotency_key",
]
