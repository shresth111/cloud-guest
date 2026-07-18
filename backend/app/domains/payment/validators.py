"""Validators for coupon redemption and payment checks."""

from datetime import UTC, datetime
from .exceptions import CouponExpiredError
from .models import Coupon


def validate_coupon_eligibility(coupon: Coupon) -> None:
    """Check if coupon can be redeemed."""
    if not coupon.active:
        raise CouponExpiredError(coupon.code)

    if coupon.expires_at and coupon.expires_at < datetime.now(UTC):
        raise CouponExpiredError(coupon.code)

    if coupon.max_redemptions is not None and coupon.redemptions_count >= coupon.max_redemptions:
        raise CouponExpiredError(coupon.code)
