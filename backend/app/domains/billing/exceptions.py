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
]
