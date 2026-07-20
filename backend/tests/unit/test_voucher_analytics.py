"""Unit tests for the voucher redemption analytics read-model (Phase 1
BhaiFi-parity #21): the pure ``compute_redemption_rate``/
``compute_voucher_redemption_analytics`` functions in
``app.domains.analytics.voucher_analytics``, and
``VoucherAnalyticsService``'s response-shaping on top of them.

``VoucherRedemptionLookupProtocol`` is exercised against a small,
hand-rolled fake -- there is no live Postgres in this environment, mirroring
every other analytics Protocol-composition test in this codebase (e.g.
``test_analytics.py``'s own ``_FakeGuestAnalyticsService``).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.domains.analytics.voucher_analytics import (
    compute_redemption_rate,
    compute_voucher_redemption_analytics,
)
from app.domains.analytics.voucher_analytics_service import VoucherAnalyticsService


@dataclass
class FakeVoucherRedemptionLookup:
    """Stand-in for ``VoucherRedemptionLookupProtocol``."""

    issued_count: int = 0
    redeemed_count: int = 0
    by_plan: list[tuple[uuid.UUID | None, int]] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)

    async def count_vouchers_issued(self, **kwargs: object) -> int:
        self.calls.append("count_vouchers_issued")
        return self.issued_count

    async def count_vouchers_redeemed(self, **kwargs: object) -> int:
        self.calls.append("count_vouchers_redeemed")
        return self.redeemed_count

    async def get_redemption_counts_by_plan(
        self, **kwargs: object
    ) -> list[tuple[uuid.UUID | None, int]]:
        self.calls.append("get_redemption_counts_by_plan")
        return self.by_plan


class TestComputeRedemptionRate:
    def test_zero_issued_returns_zero_rather_than_dividing_by_zero(self) -> None:
        assert compute_redemption_rate(issued_count=0, redeemed_count=0) == 0.0

    def test_partial_redemption(self) -> None:
        assert compute_redemption_rate(issued_count=4, redeemed_count=1) == 0.25

    def test_full_redemption(self) -> None:
        assert compute_redemption_rate(issued_count=10, redeemed_count=10) == 1.0


class TestComputeVoucherRedemptionAnalytics:
    async def test_aggregates_all_three_lookups(self) -> None:
        plan_id = uuid.uuid4()
        lookup = FakeVoucherRedemptionLookup(
            issued_count=10, redeemed_count=4, by_plan=[(plan_id, 3), (None, 1)]
        )
        result = await compute_voucher_redemption_analytics(
            organization_id=uuid.uuid4(),
            location_id=None,
            start=datetime(2026, 1, 1, tzinfo=UTC),
            end=datetime(2026, 2, 1, tzinfo=UTC),
            voucher_lookup=lookup,
        )
        assert result.issued_count == 10
        assert result.redeemed_count == 4
        assert result.redemption_rate == 0.4
        assert len(result.by_plan) == 2
        assert result.by_plan[0].plan_id == plan_id
        assert result.by_plan[0].redeemed_count == 3
        assert result.by_plan[1].plan_id is None
        assert result.by_plan[1].redeemed_count == 1
        assert set(lookup.calls) == {
            "count_vouchers_issued",
            "count_vouchers_redeemed",
            "get_redemption_counts_by_plan",
        }

    async def test_empty_window_produces_zeroed_result(self) -> None:
        lookup = FakeVoucherRedemptionLookup()
        result = await compute_voucher_redemption_analytics(
            organization_id=uuid.uuid4(),
            location_id=None,
            start=datetime(2026, 1, 1, tzinfo=UTC),
            end=datetime(2026, 2, 1, tzinfo=UTC),
            voucher_lookup=lookup,
        )
        assert result.issued_count == 0
        assert result.redeemed_count == 0
        assert result.redemption_rate == 0.0
        assert result.by_plan == []


class TestVoucherAnalyticsService:
    async def test_get_voucher_redemption_analytics_shapes_the_response(self) -> None:
        plan_id = uuid.uuid4()
        lookup = FakeVoucherRedemptionLookup(
            issued_count=8, redeemed_count=2, by_plan=[(plan_id, 2)]
        )
        service = VoucherAnalyticsService(lookup)
        organization_id = uuid.uuid4()
        start = datetime(2026, 3, 1, tzinfo=UTC)
        end = datetime(2026, 4, 1, tzinfo=UTC)

        response = await service.get_voucher_redemption_analytics(
            organization_id=organization_id, location_id=None, start=start, end=end
        )
        assert response.organization_id == organization_id
        assert response.location_id is None
        assert response.window_start == start.isoformat()
        assert response.window_end == end.isoformat()
        assert response.issued_count == 8
        assert response.redeemed_count == 2
        assert response.redemption_rate == 0.25
        assert len(response.by_plan) == 1
        assert response.by_plan[0].plan_id == str(plan_id)
        assert response.by_plan[0].redeemed_count == 2

    async def test_none_plan_id_serializes_to_none_not_the_string_none(self) -> None:
        lookup = FakeVoucherRedemptionLookup(
            issued_count=1, redeemed_count=1, by_plan=[(None, 1)]
        )
        service = VoucherAnalyticsService(lookup)
        response = await service.get_voucher_redemption_analytics(
            organization_id=uuid.uuid4(),
            location_id=None,
            start=datetime(2026, 1, 1, tzinfo=UTC),
            end=datetime(2026, 2, 1, tzinfo=UTC),
        )
        assert response.by_plan[0].plan_id is None
