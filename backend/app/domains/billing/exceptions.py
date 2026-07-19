"""Billing domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like every
other domain's exception hierarchy -- no route needs its own try/except
translation.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError


class BillingError(CloudGuestError):
    """Base exception for Billing domain errors."""

    def __init__(self, message: str, *, status_code: int) -> None:
        super().__init__(message, status_code=status_code)


# -- Plan ---------------------------------------------------------------------


class PlanNotFoundError(BillingError):
    def __init__(self, identifier: object) -> None:
        super().__init__(
            f"Plan not found: {identifier}", status_code=status.HTTP_404_NOT_FOUND
        )


class DuplicatePlanSlugError(BillingError):
    def __init__(self, slug: str) -> None:
        super().__init__(
            f"A plan with slug '{slug}' already exists",
            status_code=status.HTTP_409_CONFLICT,
        )


class PlanInactiveError(BillingError):
    """A caller attempted to assign/reference an inactive plan."""

    def __init__(self, plan_id: uuid.UUID) -> None:
        super().__init__(
            f"Plan {plan_id} is inactive and cannot be assigned",
            status_code=status.HTTP_409_CONFLICT,
        )


class InvalidPlanFeatureValueError(BillingError):
    """A ``PlanFeature`` row's populated column(s) do not match what its
    ``feature_type`` requires (see ``validators.validate_feature_value``)."""

    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=status.HTTP_400_BAD_REQUEST)


class DuplicatePlanFeatureError(BillingError):
    def __init__(self, plan_id: uuid.UUID, feature_key: str) -> None:
        super().__init__(
            f"Plan {plan_id} already has a feature row for '{feature_key}'",
            status_code=status.HTTP_409_CONFLICT,
        )


# -- License --------------------------------------------------------------------


class LicenseNotFoundError(BillingError):
    def __init__(self, identifier: object) -> None:
        super().__init__(
            f"License not found: {identifier}", status_code=status.HTTP_404_NOT_FOUND
        )


class DuplicateLicenseError(BillingError):
    """An organization already has a ``License`` row -- see
    ``models.License``'s docstring for the one-row-per-organization
    cardinality decision."""

    def __init__(self, organization_id: uuid.UUID) -> None:
        super().__init__(
            f"Organization {organization_id} already has a license -- use "
            "upgrade/downgrade to change its plan",
            status_code=status.HTTP_409_CONFLICT,
        )


class InvalidLicenseStatusTransitionError(BillingError):
    def __init__(self, current_status: str, target: str) -> None:
        super().__init__(
            f"Cannot transition a license from '{current_status}' to '{target}'",
            status_code=status.HTTP_409_CONFLICT,
        )


class LicenseNotActiveError(BillingError):
    """Raised by ``validate_license``-style checks -- the license exists but
    is not currently usable (not ``ACTIVE``, or ``ACTIVE`` but past
    ``expires_at``)."""

    def __init__(self, organization_id: uuid.UUID, reason: str) -> None:
        self.reason = reason
        super().__init__(
            f"Organization {organization_id}'s license is not usable: {reason}",
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
        )


class SamePlanError(BillingError):
    """An upgrade/downgrade was requested to the license's current plan."""

    def __init__(self, plan_id: uuid.UUID) -> None:
        super().__init__(
            f"License is already on plan {plan_id}",
            status_code=status.HTTP_409_CONFLICT,
        )


class DowngradeBelowUsageError(BillingError):
    """A downgrade was rejected because current real usage already exceeds
    at least one ``LIMIT`` feature on the target plan."""

    def __init__(self, exceeded_metric_keys: list[str]) -> None:
        self.exceeded_metric_keys = exceeded_metric_keys
        super().__init__(
            "Cannot downgrade: current usage exceeds the target plan's limits "
            f"for: {', '.join(exceeded_metric_keys)}",
            status_code=status.HTTP_409_CONFLICT,
        )


# -- Usage ------------------------------------------------------------------------


class UsageMetricNotFoundError(BillingError):
    def __init__(self, organization_id: uuid.UUID, metric_key: str) -> None:
        super().__init__(
            f"No recorded usage for organization {organization_id}, metric "
            f"'{metric_key}'",
            status_code=status.HTTP_404_NOT_FOUND,
        )


# -- Subscription (BE-013 Part 2) ------------------------------------------------


class SubscriptionNotFoundError(BillingError):
    def __init__(self, identifier: object) -> None:
        super().__init__(
            f"Subscription not found: {identifier}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class DuplicateSubscriptionError(BillingError):
    """An organization already has a ``Subscription`` row -- see
    ``models.Subscription``'s docstring for the one-row-per-organization
    cardinality decision."""

    def __init__(self, organization_id: uuid.UUID) -> None:
        super().__init__(
            f"Organization {organization_id} already has a subscription",
            status_code=status.HTTP_409_CONFLICT,
        )


class InvalidSubscriptionStatusTransitionError(BillingError):
    def __init__(self, current_status: str, target: str) -> None:
        super().__init__(
            f"Cannot transition a subscription from '{current_status}' to "
            f"'{target}'",
            status_code=status.HTTP_409_CONFLICT,
        )


class InvalidSubscriptionStatusForRenewalError(BillingError):
    """Raised by ``renewal_service.RenewalService.process_renewal`` when the
    subscription is not in a renewable status (``PAUSED``/``CANCELLED``)."""

    def __init__(self, current_status: str) -> None:
        super().__init__(
            f"Subscription in status '{current_status}' is not eligible for " "renewal",
            status_code=status.HTTP_409_CONFLICT,
        )


class SubscriptionReactivationNotAllowedError(BillingError):
    """Raised by ``SubscriptionService.reactivate_subscription`` when the
    underlying license has already been hard-expired (by
    ``renewal_service.RenewalService.expire_lapsed_subscriptions``) -- past
    that point, reactivation requires a fresh ``assign_license``, not a
    reversal of this subscription's own cancellation."""

    def __init__(self, subscription_id: uuid.UUID) -> None:
        super().__init__(
            f"Subscription {subscription_id} cannot be reactivated: its "
            "license has already expired",
            status_code=status.HTTP_409_CONFLICT,
        )


# -- Coupon (BE-013 Part 2) -------------------------------------------------------


class CouponNotFoundError(BillingError):
    def __init__(self, identifier: object) -> None:
        super().__init__(
            f"Coupon not found: {identifier}", status_code=status.HTTP_404_NOT_FOUND
        )


class DuplicateCouponCodeError(BillingError):
    def __init__(self, code: str) -> None:
        super().__init__(
            f"A coupon with code '{code}' already exists",
            status_code=status.HTTP_409_CONFLICT,
        )


class InvalidDiscountValueError(BillingError):
    """A ``Coupon.discount_value`` is out of the legal range for its
    ``discount_type`` (e.g. a ``PERCENTAGE`` above 100, or a negative
    value)."""

    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=status.HTTP_400_BAD_REQUEST)


class CouponInactiveError(BillingError):
    def __init__(self, code: str) -> None:
        super().__init__(
            f"Coupon '{code}' is not active", status_code=status.HTTP_409_CONFLICT
        )


class CouponNotYetValidError(BillingError):
    def __init__(self, code: str) -> None:
        super().__init__(
            f"Coupon '{code}' is not valid yet", status_code=status.HTTP_409_CONFLICT
        )


class CouponExpiredError(BillingError):
    def __init__(self, code: str) -> None:
        super().__init__(
            f"Coupon '{code}' has expired", status_code=status.HTTP_409_CONFLICT
        )


class CouponExhaustedError(BillingError):
    def __init__(self, code: str) -> None:
        super().__init__(
            f"Coupon '{code}' has reached its maximum number of uses",
            status_code=status.HTTP_409_CONFLICT,
        )


class CouponNotApplicableToOrganizationError(BillingError):
    def __init__(self, code: str, organization_id: uuid.UUID) -> None:
        super().__init__(
            f"Coupon '{code}' is not applicable to organization " f"{organization_id}",
            status_code=status.HTTP_409_CONFLICT,
        )


class CouponNotApplicableToPlanError(BillingError):
    def __init__(self, code: str, plan_id: uuid.UUID) -> None:
        super().__init__(
            f"Coupon '{code}' is not applicable to plan {plan_id}",
            status_code=status.HTTP_409_CONFLICT,
        )


# -- Renewal / Payment seam (BE-013 Part 2) --------------------------------------


class PaymentGatewayNotConfiguredError(BillingError):
    """Raised by ``renewal_service.UnconfiguredPaymentGateway`` -- the
    honest default ``PaymentGatewayProtocol`` implementation this part
    wires in -- whenever a real (non-zero) charge is attempted before Part 3
    (real Stripe/Razorpay SDK integration) has wired in a real
    implementation. Never raised for a zero-amount charge (a ``FREE_TRIAL``
    or otherwise-comped renewal), which genuinely needs no real payment and
    auto-succeeds instead. See ``renewal_service``'s own module docstring
    for the full seam write-up."""

    def __init__(
        self, *, organization_id: uuid.UUID, amount: object, currency: str
    ) -> None:
        super().__init__(
            f"No real payment gateway is configured -- cannot charge "
            f"organization {organization_id} {amount} {currency}. This is "
            "an honest placeholder pending BE-013 Part 3's real Stripe/"
            "Razorpay integration (see renewal_service.PaymentGatewayProtocol).",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )


__all__ = [
    "BillingError",
    "PlanNotFoundError",
    "DuplicatePlanSlugError",
    "PlanInactiveError",
    "InvalidPlanFeatureValueError",
    "DuplicatePlanFeatureError",
    "LicenseNotFoundError",
    "DuplicateLicenseError",
    "InvalidLicenseStatusTransitionError",
    "LicenseNotActiveError",
    "SamePlanError",
    "DowngradeBelowUsageError",
    "UsageMetricNotFoundError",
    "SubscriptionNotFoundError",
    "DuplicateSubscriptionError",
    "InvalidSubscriptionStatusTransitionError",
    "InvalidSubscriptionStatusForRenewalError",
    "SubscriptionReactivationNotAllowedError",
    "CouponNotFoundError",
    "DuplicateCouponCodeError",
    "InvalidDiscountValueError",
    "CouponInactiveError",
    "CouponNotYetValidError",
    "CouponExpiredError",
    "CouponExhaustedError",
    "CouponNotApplicableToOrganizationError",
    "CouponNotApplicableToPlanError",
    "PaymentGatewayNotConfiguredError",
]
