"""Pydantic response schema for ``GET /analytics/voucher-redemptions``
(Phase 1 BhaiFi-parity #21) -- follows this domain's own
``domain_analytics_schemas.py`` conventions (``ConfigDict``, explicit
fields, ``uuid`` values serialized to plain ``str`` in ``by_plan``, ISO
timestamp strings for the resolved window -- mirrors
``RouterAnalyticsResponse``'s own ``window_start``/``window_end`` shape)."""

from __future__ import annotations

import uuid

from pydantic import BaseModel


class VoucherRedemptionByPlanResponse(BaseModel):
    plan_id: str | None
    redeemed_count: int


class VoucherRedemptionAnalyticsResponse(BaseModel):
    organization_id: uuid.UUID
    location_id: uuid.UUID | None
    window_start: str
    window_end: str
    issued_count: int
    redeemed_count: int
    redemption_rate: float
    by_plan: list[VoucherRedemptionByPlanResponse]


class VoucherRedemptionEntryResponse(BaseModel):
    """One row of ``GET /analytics/voucher-redemptions/log`` -- the
    row-level counterpart to ``VoucherRedemptionByPlanResponse`` above
    (which only ever carries a plan_id, never a human-readable name,
    since a per-plan *count* has no single voucher/batch to name). Powers
    cloudguest-foundation's "Voucher Redemption Log"/"Most Redeemed
    Vouchers" reports (``UserReports.tsx``)."""

    id: uuid.UUID
    code: str
    batch_id: uuid.UUID
    batch_name: str
    plan_id: uuid.UUID | None
    plan_name: str | None
    use_count: int
    redeemed_at: str
    last_used_at: str | None
    redeemed_identifier: str | None


class VoucherRedemptionListResponse(BaseModel):
    items: list[VoucherRedemptionEntryResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


__all__ = [
    "VoucherRedemptionByPlanResponse",
    "VoucherRedemptionAnalyticsResponse",
    "VoucherRedemptionEntryResponse",
    "VoucherRedemptionListResponse",
]
