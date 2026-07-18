"""Lightweight, in-process domain events for the Voucher module.

Plain, frozen dataclasses constructed by ``VoucherService`` methods and
logged synchronously by that same service -- mirrors
``app.domains.otp.events``/``app.domains.wireguard.events``'s identical
"simplest thing that could work" posture: no event bus, no publish/
subscribe registry, no async dispatch, just a typed, self-documenting value
object per notable lifecycle moment. Not part of the public API surface --
nothing outside this module's own ``service.py`` constructs or reads these.

Distinct from, and a strict subset of, what reaches RBAC's
``audit_log_entries`` -- see ``service.py``'s module docstring for this
module's own audit-volume judgment call (every event here is logged; only
some are also audited).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class VoucherBatchCreated:
    batch_id: uuid.UUID
    organization_id: uuid.UUID
    quantity: int
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class VoucherBatchSubmitted:
    batch_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class VoucherBatchApproved:
    batch_id: uuid.UUID
    approved_by_user_id: uuid.UUID | None
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class VoucherBatchActivated:
    batch_id: uuid.UUID
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class VoucherBatchRevoked:
    batch_id: uuid.UUID
    revoked_vouchers_count: int
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class VoucherCodesImported:
    batch_id: uuid.UUID
    imported_count: int
    rejected_count: int
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class VoucherRedeemed:
    voucher_id: uuid.UUID
    batch_id: uuid.UUID
    is_first_use: bool
    use_count: int
    occurred_at: datetime = field(default_factory=_now)


@dataclass(frozen=True, slots=True)
class VoucherRedemptionFailed:
    voucher_id: uuid.UUID | None
    reason: str
    occurred_at: datetime = field(default_factory=_now)


__all__ = [
    "VoucherBatchCreated",
    "VoucherBatchSubmitted",
    "VoucherBatchApproved",
    "VoucherBatchActivated",
    "VoucherBatchRevoked",
    "VoucherCodesImported",
    "VoucherRedeemed",
    "VoucherRedemptionFailed",
]
