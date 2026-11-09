"""``GET /voucher-batches`` by venue.

The customer Vouchers page passed no location, and the route took none, so
every venue showed every venue's batches; a caller holding only location
grants got the whole organization's list too. A batch with no location is
valid at every venue, so it stays in each venue's list.
"""

from __future__ import annotations

import uuid

import pytest

from app.database.utils.filters import AnyOfOrNull
from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.voucher.exceptions import CrossLocationVoucherBatchAccessError

from .test_voucher import _create_batch, make_service


def _matches(value: object, actual: object) -> bool:
    if isinstance(value, AnyOfOrNull):
        return actual is None or actual in value.values
    if isinstance(value, list | tuple | set):
        return actual in value
    return actual == value


async def _fixture_with_batches():
    fx = make_service()
    venue_a, venue_b = uuid.uuid4(), uuid.uuid4()
    batch_a = await _create_batch(fx)
    batch_b = await _create_batch(fx)
    batch_all = await _create_batch(fx)
    batch_a.location_id = venue_a
    batch_b.location_id = venue_b
    batch_all.location_id = None

    repo = fx.repository
    recorded: dict[str, object] = {}

    # The shared fake compares filters with ``==``; give it apply_filters'
    # IN / IN-OR-NULL meaning for these tests.
    async def list_batches(*, page, page_size, filters=None, **_):
        recorded.update(filters or {})
        items = [
            b
            for b in repo.batches.values()
            if all(_matches(v, getattr(b, k)) for k, v in (filters or {}).items())
        ]
        params = PageParams(page=page, page_size=page_size)
        return items, PaginationMeta.from_total(params, len(items))

    repo.list_batches = list_batches  # type: ignore[method-assign]
    return fx, venue_a, venue_b, batch_a, batch_b, batch_all, recorded


async def test_location_filter_returns_that_venue_and_organization_wide_batches():
    fx, venue_a, _b, batch_a, _bb, batch_all, _r = await _fixture_with_batches()

    batches, meta = await fx.service.list_batches(
        requesting_organization_id=fx.organization.id, location_id=venue_a
    )

    assert {b.id for b in batches} == {batch_a.id, batch_all.id}
    assert meta.total_items == 2


async def test_no_location_still_lists_the_whole_organization():
    fx, *_rest, recorded = await _fixture_with_batches()

    batches, _meta = await fx.service.list_batches(
        requesting_organization_id=fx.organization.id
    )

    assert len(batches) == 3
    assert "location_id" not in recorded


async def test_location_scoped_caller_only_sees_their_sites():
    fx, venue_a, _b, batch_a, _bb, batch_all, _r = await _fixture_with_batches()
    fx.service.caller_location_scope = frozenset({venue_a})

    batches, _meta = await fx.service.list_batches(
        requesting_organization_id=fx.organization.id
    )

    assert {b.id for b in batches} == {batch_a.id, batch_all.id}


async def test_location_scoped_caller_cannot_name_another_site():
    fx, venue_a, venue_b, *_rest = await _fixture_with_batches()
    fx.service.caller_location_scope = frozenset({venue_a})

    with pytest.raises(CrossLocationVoucherBatchAccessError):
        await fx.service.list_batches(
            requesting_organization_id=fx.organization.id, location_id=venue_b
        )


def test_route_accepts_location_id():
    from app.domains.voucher.router import router as voucher_router

    route = next(
        r
        for r in voucher_router.routes
        if getattr(r, "path", "") == "/voucher-batches" and "GET" in r.methods
    )
    assert "location_id" in {p.name for p in route.dependant.query_params}
