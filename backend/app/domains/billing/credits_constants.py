"""Constants for prepaid credits: the wallet and its append-only ledger.

Contract: ``wyfy-specs/guest-marketing-campaigns.md`` §13 (BE-12a).

Units (§13.1): every amount is an integer in **minor units**, where
``MINOR_PER_CREDIT`` minor = 1 credit = ₹1.00 before GST. There are no floats
and no ``Decimal`` anywhere in the ledger path.

Credits never expire (founder decision). Nothing here has a validity window,
and no task ever writes an expiry entry.
"""

from __future__ import annotations

from enum import StrEnum

MINOR_PER_CREDIT = 100

# 100 credits (§13.2 ``low_balance_threshold_minor`` default).
DEFAULT_LOW_BALANCE_THRESHOLD_MINOR = 10_000

# A single Master entry larger than this is a typo, not a top-up
# (₹1 crore of credits). Keeps a fat-fingered amount from ever reaching the
# ledger, which cannot be edited afterwards.
MAX_ENTRY_AMOUNT_MINOR = 1_000_000_000
MAX_LOW_BALANCE_THRESHOLD_MINOR = 1_000_000_000


class CreditBucket(StrEnum):
    """Which wallet an entry belongs to. ``marketing`` is the only MVP value;
    the column exists so the ledger is not marketing-only (§13.2)."""

    MARKETING = "marketing"


class CreditEntryType(StrEnum):
    """§13.2's six entry types. The sign convention per type is enforced by
    ``credits_service.CreditWalletService``, not by callers."""

    TOPUP = "topup"
    RESERVE = "reserve"
    RELEASE = "release"
    DEBIT = "debit"
    REFUND = "refund"
    ADJUSTMENT = "adjustment"


# Entry types a Master operator may post by hand (§13.7 adjustments).
MASTER_ENTRY_TYPES: frozenset[CreditEntryType] = frozenset(
    {CreditEntryType.TOPUP, CreditEntryType.ADJUSTMENT, CreditEntryType.REFUND}
)

# Client-supplied idempotency keys are namespaced so they can never collide
# with a system key (``reserve:{campaign_id}:{n}``, ``debit:{recipient_id}``
# ...). The column is varchar(80); the prefix plus a 64-char client key fits.
MASTER_IDEMPOTENCY_PREFIX = "master:"
MAX_CLIENT_IDEMPOTENCY_KEY_LENGTH = 64
IDEMPOTENCY_KEY_MAX_LENGTH = 80

NOTE_MIN_LENGTH = 5
NOTE_MAX_LENGTH = 500
REFERENCE_MAX_LENGTH = 100

# Master GET /platform/organizations/{id}/credits: "last 20" (§13.7).
MASTER_RECENT_ENTRIES_LIMIT = 20

# Per-recipient debits are aggregated to one row per campaign per *IST* day
# in the default ledger view (§13.7). IST because that is the day a venue
# owner reads the statement in; campaigns only send inside quiet-hours-free
# daytime IST anyway.
LEDGER_AGGREGATION_TIMEZONE = "Asia/Kolkata"

# Nightly reconciliation (§13.2): 02:30 UTC (08:00 IST), after the 01:00
# invoice overdue sweep, well clear of campaign sending hours.
TASK_RECONCILE_CREDIT_WALLETS = "billing.reconcile_credit_wallets"
RECONCILE_CREDIT_WALLETS_HOUR_UTC = 2
RECONCILE_CREDIT_WALLETS_MINUTE_UTC = 30

__all__ = [
    "MINOR_PER_CREDIT",
    "DEFAULT_LOW_BALANCE_THRESHOLD_MINOR",
    "MAX_ENTRY_AMOUNT_MINOR",
    "MAX_LOW_BALANCE_THRESHOLD_MINOR",
    "CreditBucket",
    "CreditEntryType",
    "MASTER_ENTRY_TYPES",
    "MASTER_IDEMPOTENCY_PREFIX",
    "MAX_CLIENT_IDEMPOTENCY_KEY_LENGTH",
    "IDEMPOTENCY_KEY_MAX_LENGTH",
    "NOTE_MIN_LENGTH",
    "NOTE_MAX_LENGTH",
    "REFERENCE_MAX_LENGTH",
    "MASTER_RECENT_ENTRIES_LIMIT",
    "LEDGER_AGGREGATION_TIMEZONE",
    "TASK_RECONCILE_CREDIT_WALLETS",
    "RECONCILE_CREDIT_WALLETS_HOUR_UTC",
    "RECONCILE_CREDIT_WALLETS_MINUTE_UTC",
]
