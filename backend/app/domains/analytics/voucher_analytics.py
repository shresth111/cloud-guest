"""Voucher redemption analytics read-model (Phase 1 BhaiFi-parity #21) --
pure aggregation logic, mirroring ``aggregation.py``'s identical "narrow
Protocol + a plain compute function" shape.

## Composing ``voucher``'s own repository, not its service

Every other analytics composition in this domain reads through a domain's
own **service** (``GuestAnalyticsLookupProtocol`` -> ``GuestAnalyticsService``,
``WireGuardHealthProtocol`` -> ``WireGuardService``) so that domain's own
authorization/business logic runs first. This module is a deliberate
exception: ``VoucherRedemptionLookupProtocol`` is satisfied directly by the
real ``app.domains.voucher.repository.VoucherRepository`` (via that
module's own already-public ``get_voucher_repository`` dependency factory --
no file inside ``app.domains.voucher`` is edited to make this work). That is
a defensible choice specifically here, not a shortcut taken lightly: these
three methods are pure, read-only aggregate *counts* (issued/redeemed/
by-plan) with no state-mutating business rule to apply first, unlike e.g.
``VoucherService.redeem_voucher``'s real validation/rate-limiting/audit
side effects -- there is nothing this module would be bypassing by reading
the repository directly. See ``app.domains.voucher.repository``'s own
module docstring for the matching write-up on the query side.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol


class VoucherRedemptionLookupProtocol(Protocol):
    """The three read-only aggregate methods this module needs from the
    real ``VoucherRepository`` -- reused directly, never reimplemented."""

    async def count_vouchers_issued(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> int: ...

    async def count_vouchers_redeemed(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> int: ...

    async def get_redemption_counts_by_plan(
        self,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        start: datetime,
        end: datetime,
    ) -> list[tuple[uuid.UUID | None, int]]: ...


@dataclass(frozen=True, slots=True)
class VoucherRedemptionByPlan:
    plan_id: uuid.UUID | None
    redeemed_count: int


@dataclass(frozen=True, slots=True)
class VoucherRedemptionAnalytics:
    issued_count: int
    redeemed_count: int
    redemption_rate: float
    by_plan: list[VoucherRedemptionByPlan]


def compute_redemption_rate(*, issued_count: int, redeemed_count: int) -> float:
    """``0.0`` when nothing was issued in the window -- a guard against
    division by zero, not an implicit claim that a zero-issuance window
    somehow "fully redeemed" nothing."""
    if issued_count <= 0:
        return 0.0
    return round(redeemed_count / issued_count, 4)


async def compute_voucher_redemption_analytics(
    *,
    organization_id: uuid.UUID,
    location_id: uuid.UUID | None,
    start: datetime,
    end: datetime,
    voucher_lookup: VoucherRedemptionLookupProtocol,
) -> VoucherRedemptionAnalytics:
    issued_count = await voucher_lookup.count_vouchers_issued(
        organization_id=organization_id, location_id=location_id, start=start, end=end
    )
    redeemed_count = await voucher_lookup.count_vouchers_redeemed(
        organization_id=organization_id, location_id=location_id, start=start, end=end
    )
    by_plan_rows = await voucher_lookup.get_redemption_counts_by_plan(
        organization_id=organization_id, location_id=location_id, start=start, end=end
    )
    return VoucherRedemptionAnalytics(
        issued_count=issued_count,
        redeemed_count=redeemed_count,
        redemption_rate=compute_redemption_rate(
            issued_count=issued_count, redeemed_count=redeemed_count
        ),
        by_plan=[
            VoucherRedemptionByPlan(plan_id=plan_id, redeemed_count=count)
            for plan_id, count in by_plan_rows
        ],
    )


__all__ = [
    "VoucherRedemptionLookupProtocol",
    "VoucherRedemptionByPlan",
    "VoucherRedemptionAnalytics",
    "compute_redemption_rate",
    "compute_voucher_redemption_analytics",
]
