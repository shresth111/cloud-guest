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


__all__ = ["VoucherRedemptionByPlanResponse", "VoucherRedemptionAnalyticsResponse"]
