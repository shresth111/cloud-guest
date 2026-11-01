"""DASH-1 pure rules: one bucket per subscriber (buckets add up to total),
overlays on top, the drill-down filter equals the tile count, period bounds
with plain dates, and the route guards."""

from __future__ import annotations

import itertools
import uuid
from datetime import UTC, date, datetime, timedelta

import pytest

from app.domains.isp_partner import dashboard_logic as logic
from app.domains.isp_partner.dashboard_service import Filters, period_bounds

NOW = datetime(2026, 11, 1, 6, 0, tzinfo=UTC)
CHURN = timedelta(days=60)
STATES = (
    "permanently_blocked",
    "blocked",
    "frozen",
    "suspended",
    "scheduled",
    "disabled",
    "expired",
    "grace",
    "active",
    "some_future_state",
)


@pytest.mark.parametrize(
    ("state", "kyc", "valid_until", "want"),
    [
        ("permanently_blocked", False, None, "blocked"),
        ("blocked", True, None, "blocked"),
        ("frozen", True, None, "frozen"),
        ("suspended", True, None, "suspended"),
        ("scheduled", False, None, "pending"),
        ("active", True, NOW + timedelta(days=9), "pending"),
        ("grace", True, NOW + timedelta(days=9), "pending"),
        ("active", False, NOW + timedelta(days=9), "active"),
        ("grace", False, NOW + timedelta(days=1), "active"),
        ("expired", True, NOW - timedelta(days=5), "expired"),
        ("expired", False, NOW - timedelta(days=61), "churned"),
        ("expired", False, NOW - timedelta(days=60), "expired"),
        ("disabled", False, None, "other"),
        ("some_future_state", False, None, "other"),
    ],
)
def test_bucket_of(state, kyc, valid_until, want) -> None:  # noqa: ANN001
    got = logic.bucket_of(
        state, valid_until=valid_until, now=NOW, churn_after=CHURN, kyc_pending=kyc
    )
    assert got == want


def _rows():  # noqa: ANN202
    rows = []
    vus = (
        None,
        NOW + timedelta(days=3),
        NOW + timedelta(days=30),
        NOW - timedelta(days=90),
    )
    for state, kyc, vu, ptype, online, created in itertools.product(
        STATES,
        (False, True),
        vus,
        ("prepaid", "postpaid", None),
        (False, True),
        (NOW - timedelta(days=2), NOW - timedelta(days=20)),
    ):
        b = logic.bucket_of(
            state, valid_until=vu, now=NOW, churn_after=CHURN, kyc_pending=kyc
        )
        rows.append(
            {
                "bucket": b,
                "overlays": logic.overlays_of(
                    b,
                    valid_until=vu,
                    created_at=created,
                    package_type=ptype,
                    online=online,
                    now=NOW,
                    period_start=NOW - timedelta(days=7),
                    period_end=NOW + timedelta(days=1),
                ),
            }
        )
    return rows


def test_buckets_add_up_to_total() -> None:
    rows = _rows()
    t = logic.tally(rows)
    assert t["total"] == len(rows)
    assert sum(t[b] for b in logic.BUCKETS) == t["total"]
    assert set(t) == set(logic.TILE_KEYS)
    assert all(t[b] > 0 for b in logic.BUCKETS)  # every bucket is reachable


def test_drill_filter_equals_tile_for_every_key() -> None:
    rows = _rows()
    t = logic.tally(rows)
    for key in logic.TILE_KEYS:
        assert sum(1 for r in rows if logic.in_tile(key, r)) == t[key], key


def test_overlays() -> None:
    def ov(bucket, vu, ptype, created=None):  # noqa: ANN001, ANN202
        return logic.overlays_of(
            bucket,
            valid_until=vu,
            created_at=created,
            package_type=ptype,
            online=False,
            now=NOW,
            period_start=NOW - timedelta(days=1),
            period_end=NOW,
        )

    soon = NOW + timedelta(days=3)
    assert ov("active", soon, "prepaid") == {"expiring_7d"}
    assert ov("active", soon, None) == {"expiring_7d"}
    assert ov("active", soon, "postpaid") == {"scheduled_renewals"}
    assert ov("active", NOW + timedelta(days=8), "prepaid") == set()
    assert ov("pending", soon, "prepaid") == set()  # only active subscribers
    assert ov("active", None, "prepaid", NOW - timedelta(hours=2)) == {"new_in_period"}
    assert ov("active", None, "prepaid", NOW) == set()  # end exclusive


def test_definitions_cover_every_tile() -> None:
    assert set(logic.TILE_KEYS) <= set(logic.DEFINITIONS)
    assert "pending_leads" in logic.DEFINITIONS


def test_period_bounds_use_isp_local_days() -> None:
    now = datetime(2026, 11, 1, 20, 0, tzinfo=UTC)  # 01:30 on 2 Nov in IST
    d0, d1, start, end = period_bounds(
        Filters(period="today"), now=now, tz="Asia/Kolkata"
    )
    assert (d0, d1) == (date(2026, 11, 2), date(2026, 11, 2))
    assert start == datetime(2026, 11, 1, 18, 30, tzinfo=UTC)
    assert end - start == timedelta(days=1)
    d0, d1, *_ = period_bounds(Filters(period="7d"), now=now, tz="Asia/Kolkata")
    assert (d1 - d0).days == 6
    d0, d1, *_ = period_bounds(Filters(period="30d"), now=now, tz="Asia/Kolkata")
    assert (d1 - d0).days == 29


def test_period_bounds_custom_validation() -> None:
    from app.domains.isp_partner.exceptions import IspBadRequestError

    f = Filters(
        period="custom", date_from=date(2026, 10, 1), date_to=date(2026, 10, 31)
    )
    d0, d1, *_ = period_bounds(f, now=NOW, tz="Asia/Kolkata")
    assert (d0, d1) == (date(2026, 10, 1), date(2026, 10, 31))
    for bad in (
        Filters(period="custom"),
        Filters(
            period="custom", date_from=date(2026, 10, 2), date_to=date(2026, 10, 1)
        ),
        Filters(period="custom", date_from=date(2025, 1, 1), date_to=date(2026, 10, 1)),
    ):
        with pytest.raises(IspBadRequestError):
            period_bounds(bad, now=NOW, tz="Asia/Kolkata")


def test_routes_guarded_and_flag_gated() -> None:
    from app.domains.isp_partner.dashboard_router import (
        RequireDashboardEnabled,
        dashboard_router,
    )

    paths = set()
    for r in dashboard_router.routes:
        deps = {d.call for d in r.dependant.dependencies}
        names = {getattr(d, "__name__", type(d).__name__) for d in deps}
        assert RequireDashboardEnabled in deps
        assert {"RequireIspPartner", "RejectLocationRouterHeaders"} <= names
        paths.add(r.path)
    assert paths == {"/dashboard/subscribers", "/dashboard/subscribers/list"}


def test_unknown_tile_rejected_by_pattern() -> None:
    import re

    from app.domains.isp_partner.dashboard_router import _TILE_PATTERN

    assert re.match(_TILE_PATTERN, "pending")
    assert not re.match(_TILE_PATTERN, "pending_leads")
    assert not re.match(_TILE_PATTERN, f"x{uuid.uuid4()}")
