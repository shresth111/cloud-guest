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


#: Separators a person inserts to make a code readable. Deleting these is
#: the *fallback* spelling, never the stored one -- see
#: :func:`voucher_code_lookup_candidates` for why that distinction is the
#: whole design here.
_CODE_SEPARATORS = str.maketrans("", "", " \t-‐‑‒–—_")


def normalize_voucher_code(code: str) -> str:
    """The one spelling a code is stored and compared as: trimmed and
    upper-cased.

    ## The defect this closes

    Generated codes come from :data:`VOUCHER_CODE_ALPHABET`, which is
    uppercase letters and digits and nothing else. The bulk-import path
    normalised with ``.strip().upper()``; redemption and validation did
    ``.strip()`` only, and the lookup is exact. So a guest typing their own
    code in lower case got "voucher not found" for a code sitting valid and
    unredeemed in the row beside it -- and whether they succeeded depended
    on which path had created the row. The two disagreeing is the bug; this
    function exists so there is one answer and every caller uses it.

    Upper-casing cannot turn one valid code into a different valid one:
    lower case appears in no code, generated or imported, so ``kfa7`` can
    only ever have meant ``KFA7``.

    It stops short of confusable-character folding, deliberately. The
    alphabet already excludes ``I``, ``O``, ``0`` and ``1`` so that no two
    symbols look alike -- see its own comment. A guest who types ``0`` has
    not mistyped ``O`` for it, because ``O`` is in no code either; they are
    simply wrong, and saying so is more use than guessing which excluded
    character they meant.
    """
    return code.strip().upper()


def voucher_code_lookup_candidates(code: str) -> tuple[str, ...]:
    """The spellings to try, in order, when looking a guest-typed code up.

    Always at least :func:`normalize_voucher_code`. A second candidate with
    separators removed is appended when it differs -- so ``KFA7-X2M9-QDT``
    finds the generated code ``KFA7X2M9QDT`` that a printed card invited the
    guest to group that way.

    ## Why separators are a fallback and not part of the stored form

    Because imported codes are not generated codes. ``import_codes`` exists
    for vouchers a venue had **pre-printed elsewhere**, and those carry
    whatever the printer put on them -- ``PRINT-001`` is a real shape in
    this module's own tests. Stripping separators before storing would
    silently rewrite a venue's own code, and stripping them before every
    lookup would then make that stored code unreachable. This was not
    reasoned out in advance: the first version of this fix did strip them
    everywhere, and those tests failed.

    Order matters for the same reason. The as-typed spelling is tried
    first, so a venue whose codes genuinely contain a hyphen matches
    exactly, and the separator-free attempt only ever runs on a miss. It can
    therefore introduce no ambiguity -- it cannot shadow a code, only reach
    one that was otherwise unreachable.
    """
    exact = normalize_voucher_code(code)
    stripped = exact.translate(_CODE_SEPARATORS)
    return (exact,) if stripped == exact else (exact, stripped)


__all__ = [
    "validate_code_length",
    "validate_quantity",
    "validate_batch_status_transition",
    "normalize_redeemed_identifier",
    "normalize_voucher_code",
    "voucher_code_lookup_candidates",
]
