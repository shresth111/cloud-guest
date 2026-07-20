"""Voucher domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like every
other domain's exception hierarchy -- no route needs its own try/except
translation.

## Error specificity vs. information-leakage (same judgment call as OTP)

``VoucherService.validate_voucher``/``redeem_voucher`` raise a distinct
exception per failure reason (not found, batch not active, revoked,
exhausted, expired) rather than one collapsed "invalid voucher" error --
mirroring ``app.domains.otp.exceptions``'s identical reasoning: a voucher
code, like an OTP identifier, is not a persistent account being enumerated,
so a distinct error is better guest-facing UX ("this code has already been
fully used" vs. "this code has expired") with no meaningful new attack
surface. What must never leak is anything that narrows the brute-force
search space below what this module's own rate limiting
(``service.VoucherRedemptionRateLimiter``) already bounds -- no exception
here echoes another valid code, a redemption count beyond what the caller's
own request already implies, or any other voucher's state.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "VoucherError",
    "VoucherBatchNotFoundError",
    "CrossOrganizationVoucherBatchAccessError",
    "InvalidBatchStatusTransitionError",
    "VoucherBatchQuantityExceededError",
    "InvalidCodeLengthError",
    "VoucherCodeGenerationExhaustedError",
    "VoucherNotFoundError",
    "VoucherBatchNotActiveError",
    "VoucherRevokedError",
    "VoucherExhaustedError",
    "VoucherExpiredError",
    "VoucherRedemptionRateLimitExceededError",
    "VoucherPlanNotFoundError",
    "CrossOrganizationVoucherPlanAccessError",
    "VoucherSeriesNotFoundError",
    "CrossOrganizationVoucherSeriesAccessError",
]


class VoucherError(CloudGuestError):
    """Base exception for Voucher domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class VoucherBatchNotFoundError(VoucherError):
    def __init__(self, batch_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Voucher batch not found: {batch_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class CrossOrganizationVoucherBatchAccessError(VoucherError):
    """A caller acting within organization A attempted to read/mutate a
    voucher batch belonging to organization B -- mirrors
    ``app.domains.router.exceptions.CrossOrganizationRouterAccessError``."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a voucher batch belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class InvalidBatchStatusTransitionError(VoucherError):
    """Raised when a requested status change is not a legal edge in
    ``app.domains.voucher.constants.VOUCHER_BATCH_STATUS_TRANSITIONS``."""

    def __init__(self, current_status: str, requested_status: str) -> None:
        super().__init__(
            f"Cannot transition voucher batch from '{current_status}' to "
            f"'{requested_status}'",
            status_code=status.HTTP_409_CONFLICT,
        )


class VoucherBatchQuantityExceededError(VoucherError):
    """The requested quantity (generation or import) exceeds
    ``app.database.constants.MAX_BULK_CREATE_SIZE`` -- see
    ``service.py``'s module docstring for why this is rejected outright
    rather than chunked across multiple bulk inserts."""

    def __init__(self, requested: int, max_allowed: int) -> None:
        super().__init__(
            f"Requested quantity {requested} exceeds the maximum of "
            f"{max_allowed} per batch/import call",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class InvalidCodeLengthError(VoucherError):
    def __init__(self, code_length: int, minimum: int, maximum: int) -> None:
        super().__init__(
            f"code_length must be between {minimum} and {maximum}, got {code_length}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class VoucherCodeGenerationExhaustedError(VoucherError):
    """Could not generate enough unique codes for the requested quantity
    within ``constants.CODE_GENERATION_MAX_ROUNDS`` rounds -- a defensive
    backstop, not expected in practice for any sane
    quantity/code_length/code_prefix combination."""

    def __init__(self, requested: int, generated: int) -> None:
        super().__init__(
            f"Could not generate {requested} unique voucher codes (only "
            f"{generated} unique codes found) -- try a longer code_length",
            status_code=status.HTTP_409_CONFLICT,
        )


class VoucherNotFoundError(VoucherError):
    def __init__(self) -> None:
        super().__init__(
            "Voucher code not found", status_code=status.HTTP_404_NOT_FOUND
        )


class VoucherBatchNotActiveError(VoucherError):
    """The voucher's batch is not (or no longer) ``ACTIVE`` -- covers a
    batch still awaiting approval, or one that has expired/been revoked."""

    def __init__(self, batch_status: str) -> None:
        super().__init__(
            "This voucher's batch is not currently active and cannot be " "redeemed",
            status_code=status.HTTP_409_CONFLICT,
            data={"batch_status": batch_status},
        )


class VoucherRevokedError(VoucherError):
    def __init__(self) -> None:
        super().__init__(
            "This voucher has been revoked and can no longer be used",
            status_code=status.HTTP_410_GONE,
        )


class VoucherExhaustedError(VoucherError):
    """``use_count`` has already reached ``max_uses_per_voucher``."""

    def __init__(self) -> None:
        super().__init__(
            "This voucher has already been used the maximum number of times",
            status_code=status.HTTP_409_CONFLICT,
        )


class VoucherExpiredError(VoucherError):
    """Either the voucher's own post-redemption ``expires_at`` has passed,
    or its batch's ``batch_expires_at`` passed before the voucher was ever
    redeemed."""

    def __init__(self) -> None:
        super().__init__("This voucher has expired", status_code=status.HTTP_410_GONE)


class VoucherRedemptionRateLimitExceededError(VoucherError):
    """This source has attempted too many validate/redeem calls within the
    configured rolling window
    (``constants.DEFAULT_REDEMPTION_MAX_ATTEMPTS_PER_WINDOW``/
    ``DEFAULT_REDEMPTION_WINDOW_MINUTES``) -- protects against brute-forcing
    voucher codes by trying many at once from one source. See
    ``service.VoucherRedemptionRateLimiter``'s docstring."""

    def __init__(self, retry_after_seconds: int) -> None:
        self.retry_after_seconds = retry_after_seconds
        super().__init__(
            f"Too many voucher attempts. Try again in {retry_after_seconds} seconds.",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            data={"retry_after_seconds": retry_after_seconds},
        )


class VoucherPlanNotFoundError(VoucherError):
    def __init__(self, plan_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Voucher plan not found: {plan_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class CrossOrganizationVoucherPlanAccessError(VoucherError):
    """A caller acting within organization A attempted to read/mutate a
    voucher plan belonging to organization B -- mirrors
    ``CrossOrganizationVoucherBatchAccessError``. A platform-wide plan
    (``organization_id is None``) is never subject to this check -- any
    organization may read it, the identical
    ``app.domains.queue_management.models.QueueProfile.organization_id``
    nullable-means-shared posture this plan's own model docstring mirrors."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a voucher plan belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class VoucherSeriesNotFoundError(VoucherError):
    def __init__(self, series_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Voucher series not found: {series_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class CrossOrganizationVoucherSeriesAccessError(VoucherError):
    """A caller acting within organization A attempted to read/mutate a
    voucher series belonging to organization B -- mirrors
    ``CrossOrganizationVoucherBatchAccessError``. Unlike a plan, a series
    always has a real ``organization_id`` (never platform-wide -- see
    ``models.VoucherSeries``'s own docstring), so this check applies
    unconditionally."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a voucher series belonging to another organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )
