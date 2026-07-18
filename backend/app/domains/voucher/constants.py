"""Enumerations and small constants for the Voucher domain.

Stored as plain ``String`` columns on the ORM models
(``VoucherBatch.status``/``Voucher.status``), never a native PostgreSQL enum
type -- the same reason every other domain in this codebase documents
(``app.domains.otp.constants``, ``app.domains.rbac.enums``,
``app.domains.router.enums``): adding a new status value never requires an
``ALTER TYPE`` migration, only a new additive ``StrEnum`` member.

**No new ``Settings`` fields.** Unlike ``app.domains.otp``, this module adds
no fields to ``app.core.config.Settings`` -- the module's own directory
boundary keeps ``app/core/config.py`` untouched, so every tunable knob
(rate-limit thresholds, the print-friendly code alphabet, code-generation
retry bounds) lives here instead, as plain module-level constants rather
than environment-configurable settings. This is a narrower knob surface than
OTP's, but nothing in this module's own scope needs per-environment tuning
badly enough to justify the boundary exception.
"""

from __future__ import annotations

from enum import StrEnum


class VoucherBatchStatus(StrEnum):
    """Lifecycle status of a :class:`~.models.VoucherBatch`.

    See ``docs/voucher/FLOW.md`` §2 for the full write-up of why
    ``APPROVED -> ACTIVE`` is folded into the same ``approve`` call rather
    than exposed as a separate HTTP activation step, and why ``create_batch``
    performs the ``DRAFT -> PENDING_APPROVAL`` submission automatically
    rather than exposing a dedicated "submit" endpoint.

    * ``DRAFT`` -- just created; not yet submitted for approval. Every batch
      passes through this state, even if only for the instant between its
      row being inserted and ``VoucherService.create_batch`` auto-submitting
      it (see module docstring above) -- so the full state is always present
      in the batch's own event/audit trail.
    * ``PENDING_APPROVAL`` -- submitted, awaiting a ``voucher.approve``
      holder's decision. No voucher in this batch is redeemable yet.
    * ``APPROVED`` -- approved, but see ``FLOW.md`` §2: this module has no
      separate activation endpoint, so a batch spends this state only for
      the duration of ``VoucherService._approve_and_activate``'s second
      internal update, never observable via a GET in between.
    * ``ACTIVE`` -- vouchers in this batch are redeemable (subject to their
      own per-voucher state and ``batch_expires_at``).
    * ``EXPIRED`` -- ``batch_expires_at`` has passed; every unredeemed
      voucher in the batch is now permanently invalid. Reached lazily (on
      the next read of an ``ACTIVE`` batch past its expiry), not by a
      background job -- mirrors ``app.domains.otp.models.OtpRequest
      .is_expired``'s identical "checked on read, not swept by a cron"
      posture.
    * ``REVOKED`` -- administratively cancelled at any point before
      ``EXPIRED``. Terminal, like ``EXPIRED``.
    """

    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


# The explicit, exhaustive legal-transition graph for VoucherBatch.status --
# any transition not listed here is rejected by
# ``validators.validate_batch_status_transition`` with
# ``InvalidBatchStatusTransitionError``. Mirrors
# ``app.domains.router.enums.ROUTER_STATUS_TRANSITIONS``'s identical
# dict-of-frozenset shape.
#
# ``DRAFT -> APPROVED`` is the one edge that exists purely for the
# ``voucher.manage``-holder fast path (see ``service.create_batch``): a
# sufficiently-privileged caller's batch skips the ``PENDING_APPROVAL``
# queue entirely. It is still routed through the same
# ``_approve_and_activate`` helper as a normal approval, so
# ``approved_by_user_id``/``approved_at`` are always populated identically
# regardless of which path reached ``APPROVED``.
VOUCHER_BATCH_STATUS_TRANSITIONS: dict[
    VoucherBatchStatus, frozenset[VoucherBatchStatus]
] = {
    VoucherBatchStatus.DRAFT: frozenset(
        {
            VoucherBatchStatus.PENDING_APPROVAL,
            VoucherBatchStatus.APPROVED,
            VoucherBatchStatus.REVOKED,
        }
    ),
    VoucherBatchStatus.PENDING_APPROVAL: frozenset(
        {VoucherBatchStatus.APPROVED, VoucherBatchStatus.REVOKED}
    ),
    VoucherBatchStatus.APPROVED: frozenset(
        {VoucherBatchStatus.ACTIVE, VoucherBatchStatus.REVOKED}
    ),
    VoucherBatchStatus.ACTIVE: frozenset(
        {VoucherBatchStatus.EXPIRED, VoucherBatchStatus.REVOKED}
    ),
    VoucherBatchStatus.EXPIRED: frozenset(),
    VoucherBatchStatus.REVOKED: frozenset(),
}


class VoucherStatus(StrEnum):
    """Lifecycle status of a single :class:`~.models.Voucher` code.

    * ``UNUSED`` -- generated/imported, never redeemed. The only state a
      voucher starts in.
    * ``ACTIVE`` -- redeemed at least once, with uses remaining
      (``use_count < batch.max_uses_per_voucher``) and, once
      ``batch.validity_minutes`` has elapsed since first redemption, still
      within its own ``expires_at``.
    * ``EXHAUSTED`` -- ``use_count`` has reached
      ``batch.max_uses_per_voucher``. For a single-use voucher
      (``max_uses_per_voucher == 1``, the default), this is reached directly
      from ``UNUSED`` on the very first redemption -- it never passes
      through ``ACTIVE`` at all.
    * ``EXPIRED`` -- its own post-redemption ``expires_at`` has passed (set
      at first redemption, see ``models.Voucher.expires_at``'s docstring for
      why this is computed then, not at generation time), reached lazily on
      the next redemption/validation attempt, mirroring
      ``VoucherBatchStatus.EXPIRED``'s identical "checked on read" posture.
    * ``REVOKED`` -- cascaded from its batch being revoked
      (``VoucherService.revoke_batch``) -- there is no standalone
      per-voucher revoke endpoint in this module's API surface, only the
      batch-level one.
    """

    UNUSED = "unused"
    ACTIVE = "active"
    EXHAUSTED = "exhausted"
    EXPIRED = "expired"
    REVOKED = "revoked"


# ============================================================================
# Code generation
# ============================================================================

# Print-friendly alphabet: uppercase letters + digits, deliberately excluding
# every character a person could misread off a printed card or misdictate
# over a phone call -- ``0``/``O``, ``1``/``I``/``L`` (both upper and lower
# on the "L" family are covered since everything is uppercase-only), plus
# lowercase entirely (a printed voucher shouldn't force a guest to reason
# about case). 22 letters (26 minus I/O... plus L is kept since there is no
# lowercase 'l' to confuse it with -- only 'I' is excluded on that front) +
# 8 digits (10 minus 0/1) = 30 total symbols. This is the same design intent
# as Crockford's Base32 alphabet, independently derived for this module
# rather than imported (Crockford's own alphabet also folds a checksum
# scheme this module has no use for).
VOUCHER_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

# Bounds on VoucherBatch.code_length -- validated by
# validators.validate_code_length. Below 4, the search space (30^length) is
# too small to responsibly hand out at any real quantity; above 20, a code
# stops being practically printable/readable.
MIN_CODE_LENGTH = 4
MAX_CODE_LENGTH = 20

# Bound on how many (in-memory-generate, then DB-existence-check) rounds
# VoucherService._generate_codes will attempt before giving up and raising
# VoucherCodeGenerationExhaustedError -- a defensive backstop against a
# pathological caller-supplied code_length/quantity combination (e.g.
# quantity larger than the alphabet's own combinatorial space at that
# length), never expected to be hit for any sane input.
CODE_GENERATION_MAX_ROUNDS = 10

# ============================================================================
# Guest-facing redemption rate limiting (Redis, mirrors
# app.domains.otp.constants.OTP_REQUEST_RATE_LIMIT_KEY_TEMPLATE /
# app.domains.otp.service.OtpRateLimiter's identical INCR+EXPIRE+TTL shape)
# ============================================================================

# Scoped by ``source`` (the presumed caller IP address, supplied by
# router.py from the request) rather than by the presented voucher code --
# see service.py's module docstring for why: the risk being defended against
# is one source trying many codes, not one code being tried by many sources.
VOUCHER_REDEMPTION_RATE_LIMIT_KEY_TEMPLATE = "voucher:redemption_attempts:{source}"

# How many validate+redeem attempts, combined, a single source may make
# within the window below before VoucherRedemptionRateLimitExceededError.
# Deliberately more generous than OTP's own request limiter (5/hour) --
# guessing a voucher code is a single-shot action per attempt (no follow-up
# round trip the way OTP's request->verify is), and a legitimate front-desk
# device validating a stack of printed vouchers in quick succession is a
# real, non-adversarial usage pattern this limit must not choke on.
DEFAULT_REDEMPTION_MAX_ATTEMPTS_PER_WINDOW = 30
DEFAULT_REDEMPTION_WINDOW_MINUTES = 1

# ============================================================================
# CSV export (stdlib csv, see service.py's module docstring for the
# transport decision)
# ============================================================================

CSV_EXPORT_HEADERS = (
    "code",
    "status",
    "use_count",
    "max_uses_per_voucher",
    "redeemed_at",
    "last_used_at",
    "expires_at",
    "redeemed_identifier",
)

__all__ = [
    "VoucherBatchStatus",
    "VOUCHER_BATCH_STATUS_TRANSITIONS",
    "VoucherStatus",
    "VOUCHER_CODE_ALPHABET",
    "MIN_CODE_LENGTH",
    "MAX_CODE_LENGTH",
    "CODE_GENERATION_MAX_ROUNDS",
    "VOUCHER_REDEMPTION_RATE_LIMIT_KEY_TEMPLATE",
    "DEFAULT_REDEMPTION_MAX_ATTEMPTS_PER_WINDOW",
    "DEFAULT_REDEMPTION_WINDOW_MINUTES",
    "CSV_EXPORT_HEADERS",
]
