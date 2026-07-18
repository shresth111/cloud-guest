"""Pure, side-effect-free validation for the Voucher domain.

Mirrors ``app.domains.otp.validators``/``app.domains.router_provisioning
.validators``'s identical discipline: no I/O, just "is this a legal input
or transition" checks the service layer calls before touching the database
or Redis.
"""

from __future__ import annotations

from app.database.constants import MAX_BULK_CREATE_SIZE

from .constants import (
    MAX_CODE_LENGTH,
    MIN_CODE_LENGTH,
    VOUCHER_BATCH_STATUS_TRANSITIONS,
    VoucherBatchStatus,
)
from .exceptions import (
    InvalidBatchStatusTransitionError,
    InvalidCodeLengthError,
    VoucherBatchQuantityExceededError,
)


def validate_code_length(code_length: int) -> None:
    """Raises ``InvalidCodeLengthError`` if ``code_length`` falls outside
    ``[MIN_CODE_LENGTH, MAX_CODE_LENGTH]``."""
    if not (MIN_CODE_LENGTH <= code_length <= MAX_CODE_LENGTH):
        raise InvalidCodeLengthError(code_length, MIN_CODE_LENGTH, MAX_CODE_LENGTH)


def validate_quantity(quantity: int) -> None:
    """Raises ``VoucherBatchQuantityExceededError`` if ``quantity`` exceeds
    ``app.database.constants.MAX_BULK_CREATE_SIZE`` -- see
    ``exceptions.VoucherBatchQuantityExceededError``'s docstring for why
    this is rejected outright rather than chunked."""
    if quantity > MAX_BULK_CREATE_SIZE:
        raise VoucherBatchQuantityExceededError(quantity, MAX_BULK_CREATE_SIZE)


def validate_batch_status_transition(
    *, current: VoucherBatchStatus, target: VoucherBatchStatus
) -> None:
    """Consults the exhaustive ``VOUCHER_BATCH_STATUS_TRANSITIONS`` graph.

    Deliberately has no "same status is a no-op" shortcut -- e.g. attempting
    to revoke an already-``REVOKED`` batch must raise (that status has no
    outgoing edges at all, including to itself), mirroring
    ``app.domains.router.service.RouterService._validate_transition``'s
    identical discipline."""
    legal_targets = VOUCHER_BATCH_STATUS_TRANSITIONS.get(current, frozenset())
    if target not in legal_targets:
        raise InvalidBatchStatusTransitionError(current.value, target.value)


def normalize_redeemed_identifier(identifier: str) -> str:
    """Strips surrounding whitespace from a guest-presented identifier
    (phone/email/device-MAC) -- deliberately no channel-specific shape
    validation (unlike ``app.domains.otp.validators.validate_identifier``):
    this module has no delivery channel to protect (nothing is sent to this
    identifier), it is only recorded as free-form provenance for who
    redeemed the code, so over-validating it would reject a legitimate but
    unusual guest-supplied value for no protective benefit."""
    return identifier.strip()


__all__ = [
    "validate_code_length",
    "validate_quantity",
    "validate_batch_status_transition",
    "normalize_redeemed_identifier",
]
