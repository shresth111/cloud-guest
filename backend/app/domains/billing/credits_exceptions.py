"""Errors raised by the prepaid-credits ledger (§13).

Every one carries ``data.error_code``, because 402 is shared with the add-on
lock (``feature_not_entitled``) and the FE switches on the code, not the
status (§5.0).
"""

from __future__ import annotations

import uuid

from fastapi import status

from .exceptions import BillingError


class InsufficientCreditsError(BillingError):
    """402 ``insufficient_credits`` -- a reserve, or a charge from available,
    that the wallet cannot cover. ``data`` carries the numbers the FE shows
    (§13.4 step 2); callers that know them (BE-12b's schedule path) add the
    pricing fields."""

    def __init__(
        self,
        *,
        needed_minor: int,
        available_minor: int,
        extra: dict[str, object] | None = None,
    ) -> None:
        data: dict[str, object] = {
            "error_code": "insufficient_credits",
            "needed_minor": needed_minor,
            "available_minor": available_minor,
            "shortfall_minor": max(0, needed_minor - available_minor),
        }
        if extra:
            data.update(extra)
        super().__init__(
            "Not enough marketing credits",
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            data=data,
        )


class AdjustmentExceedsAvailableError(BillingError):
    """409 -- a negative Master adjustment larger than ``available_minor``.
    Reserved credits are never reachable by an adjustment (§13.4)."""

    def __init__(self, *, amount_minor: int, available_minor: int) -> None:
        super().__init__(
            "A negative adjustment cannot exceed the available balance; "
            "reserved credits belong to in-flight campaigns",
            status_code=status.HTTP_409_CONFLICT,
            data={
                "error_code": "adjustment_exceeds_available",
                "amount_minor": amount_minor,
                "available_minor": available_minor,
            },
        )


class CreditReservationExceededError(BillingError):
    """409 -- a release or campaign debit larger than what is reserved. Only
    reachable through a caller bug (BE-12b's charge flow bounds every debit
    by its reservation), so it is loud rather than clamped."""

    def __init__(self, *, amount_minor: int, reserved_minor: int) -> None:
        super().__init__(
            "Cannot release or debit more than is reserved",
            status_code=status.HTTP_409_CONFLICT,
            data={
                "error_code": "credit_reservation_exceeded",
                "amount_minor": amount_minor,
                "reserved_minor": reserved_minor,
            },
        )


class IdempotencyKeyReusedError(BillingError):
    """422 ``validation_error`` -- an idempotency key already used for a
    *different* movement. A true retry (same type, same amounts) returns the
    original row instead; this is the case a retry cannot explain. Same code
    the marketing domain uses for its own key reuse (Backend deviation 7)."""

    def __init__(self, idempotency_key: str) -> None:
        super().__init__(
            "This idempotency_key was already used for a different credit entry",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            data={"error_code": "validation_error", "field": "idempotency_key"},
        )
        self.idempotency_key = idempotency_key


class BillingProfileMissingError(BillingError):
    """409 ``billing_profile_missing`` -- ``issue_invoice=true`` for an
    organization with no ``BillingProfile``. Master can still post the top-up
    without an invoice (§13.9)."""

    def __init__(self, organization_id: uuid.UUID) -> None:
        super().__init__(
            "This organization has no billing profile, so a GST invoice cannot "
            "be issued. Add one, or post the top-up without an invoice.",
            status_code=status.HTTP_409_CONFLICT,
            data={
                "error_code": "billing_profile_missing",
                "organization_id": str(organization_id),
            },
        )


class CreditsOrganizationNotFoundError(BillingError):
    def __init__(self, organization_id: uuid.UUID) -> None:
        super().__init__(
            f"Organization not found: {organization_id}",
            status_code=status.HTTP_404_NOT_FOUND,
            data={"error_code": "organization_not_found"},
        )


class CreditsCampaignNotFoundError(BillingError):
    """A refund attributed to a campaign that is not this organization's."""

    def __init__(self, campaign_id: uuid.UUID) -> None:
        super().__init__(
            f"Campaign not found: {campaign_id}",
            status_code=status.HTTP_404_NOT_FOUND,
            data={"error_code": "campaign_not_found"},
        )


__all__ = [
    "AdjustmentExceedsAvailableError",
    "BillingProfileMissingError",
    "CreditReservationExceededError",
    "CreditsCampaignNotFoundError",
    "CreditsOrganizationNotFoundError",
    "IdempotencyKeyReusedError",
    "InsufficientCreditsError",
]
