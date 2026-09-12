"""Feature-entitlement errors.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide handler with their own status codes, same as every other domain.
"""

from __future__ import annotations

from fastapi import status

from app.common.exceptions import CloudGuestError


class FeatureEntitlementError(CloudGuestError):
    """Base class for this domain."""


class PerCustomerFeatureOverrideNotSupportedError(FeatureEntitlementError):
    """A caller tried to set feature flags on one customer directly.

    Entitlements in this platform are a property of the customer's **plan**,
    not of the customer: ``EntitlementSnapshot`` is assembled from the
    organization's ``License`` and that license's ``Plan``'s ``PlanFeature``
    rows (``billing.service.LicenseService.get_entitlement_snapshot``), and
    there is no per-license or per-organization override table anywhere in
    the billing domain.

    This endpoint previously accepted the write, persisted nothing, and
    returned ``"Customer features updated"``. A super-admin toggling a
    customer's features saw success and nothing changed. Refusing loudly is
    the honest behaviour until a real override model exists; the working path
    today is to move the customer to a different plan, or to change the plan's
    own ``PlanFeature`` rows.
    """

    def __init__(self) -> None:
        super().__init__(
            "Per-customer feature overrides are not supported. Entitlements "
            "come from the customer's plan: change the organization's plan "
            "via the licenses API, or edit that plan's features. This "
            "endpoint previously reported success without saving anything.",
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
        )
