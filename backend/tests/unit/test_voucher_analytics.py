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

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.analytics.voucher_analytics import (
    compute_redemption_rate,
    compute_voucher_redemption_analytics,
    list_voucher_redemptions,
)
from app.domains.analytics.voucher_analytics_service import VoucherAnalyticsService
from app.domains.voucher.repository import VoucherRedemptionRow


@dataclass
class FakeVoucherRedemptionLookup:
    """Stand-in for ``VoucherRedemptionLookupProtocol``."""

    issued_count: int = 0
    redeemed_count: int = 0
    by_plan: list[tuple[uuid.UUID | None, int]] = field(default_factory=list)
    redemption_rows: list[VoucherRedemptionRow] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    last_order_by_use_count: bool | None = field(default=None, init=False)

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

    async def list_redeemed_vouchers(
        self, *, page: int, page_size: int, order_by_use_count: bool = False, **kwargs: object
    ) -> tuple[list[VoucherRedemptionRow], PaginationMeta]:
        self.calls.append("list_redeemed_vouchers")
        self.last_order_by_use_count = order_by_use_count
        meta = PaginationMeta.from_total(
            PageParams(page=page, page_size=page_size), len(self.redemption_rows)
        )
        return self.redemption_rows, meta


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


def _row(*, use_count: int = 1, plan_id: uuid.UUID | None = None) -> VoucherRedemptionRow:
    return VoucherRedemptionRow(
        id=uuid.uuid4(),
        code="ZW-1000",
        batch_id=uuid.uuid4(),
        batch_name="Front Desk",
        plan_id=plan_id,
        plan_name="1-Hour Premium" if plan_id else None,
        use_count=use_count,
        redeemed_at=datetime(2026, 3, 15, tzinfo=UTC),
        last_used_at=None,
        redeemed_identifier="+919812345678",
    )


class TestListVoucherRedemptions:
    """The pure module-level function -- a thin passthrough, but its
    ``order_by_use_count`` flag is the one thing worth asserting actually
    reaches the lookup (see the module docstring: 'recent' vs 'most_used'
    is the same repository method, just a different sort)."""

    async def test_passes_through_rows_and_meta(self) -> None:
        rows = [_row(), _row()]
        lookup = FakeVoucherRedemptionLookup(redemption_rows=rows)
        result_rows, meta = await list_voucher_redemptions(
            organization_id=uuid.uuid4(),
            location_id=None,
            start=datetime(2026, 3, 1, tzinfo=UTC),
            end=datetime(2026, 4, 1, tzinfo=UTC),
            page=1,
            page_size=25,
            order_by_use_count=False,
            voucher_lookup=lookup,
        )
        assert result_rows == rows
        assert meta.total_items == 2
        assert lookup.last_order_by_use_count is False

    async def test_order_by_use_count_flag_reaches_the_lookup(self) -> None:
        lookup = FakeVoucherRedemptionLookup(redemption_rows=[_row(use_count=9)])
        await list_voucher_redemptions(
            organization_id=uuid.uuid4(),
            location_id=None,
            start=datetime(2026, 3, 1, tzinfo=UTC),
            end=datetime(2026, 4, 1, tzinfo=UTC),
            page=1,
            page_size=10,
            order_by_use_count=True,
            voucher_lookup=lookup,
        )
        assert lookup.last_order_by_use_count is True


class TestVoucherAnalyticsServiceListRedemptions:
    async def test_shapes_rows_into_response_with_plan_and_batch_names(self) -> None:
        plan_id = uuid.uuid4()
        rows = [_row(plan_id=plan_id), _row(plan_id=None)]
        lookup = FakeVoucherRedemptionLookup(redemption_rows=rows)
        service = VoucherAnalyticsService(lookup)

        response = await service.list_voucher_redemptions(
            organization_id=uuid.uuid4(),
            location_id=None,
            start=datetime(2026, 3, 1, tzinfo=UTC),
            end=datetime(2026, 4, 1, tzinfo=UTC),
            page=1,
            page_size=25,
            order_by_use_count=False,
        )
        assert response.total_items == 2
        assert response.items[0].batch_name == "Front Desk"
        assert response.items[0].plan_id == plan_id
        assert response.items[0].plan_name == "1-Hour Premium"
        assert response.items[1].plan_id is None
        assert response.items[1].plan_name is None
        # Timestamps are serialized, not left as raw datetime objects.
        assert response.items[0].redeemed_at == rows[0].redeemed_at.isoformat()

    async def test_empty_result_is_a_real_empty_page_not_an_error(self) -> None:
        lookup = FakeVoucherRedemptionLookup(redemption_rows=[])
        service = VoucherAnalyticsService(lookup)
        response = await service.list_voucher_redemptions(
            organization_id=uuid.uuid4(),
            location_id=None,
            start=datetime(2026, 3, 1, tzinfo=UTC),
            end=datetime(2026, 4, 1, tzinfo=UTC),
            page=1,
            page_size=25,
            order_by_use_count=True,
        )
        assert response.items == []
        assert response.total_items == 0
        assert response.total_pages == 0
