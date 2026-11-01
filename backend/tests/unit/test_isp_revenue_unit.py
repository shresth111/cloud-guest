"""REVENUE-HUB + CHURN-RISK: the pure rules (``revenue_logic``) and the route
contract (flag first, keys: aggregates on isp_billing.read, anything naming a
subscriber on isp_billing.export)."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

import pytest

from app.domains.isp_partner import revenue_logic as logic

NOW = datetime(2026, 11, 15, 6, 0, tzinfo=UTC)
TZ = "Asia/Kolkata"


def test_states_are_the_overview_buckets() -> None:
    """ACTIVE-ALIGN: the hub maps DASH-1 buckets, it never re-derives them."""
    from app.domains.isp_partner import dashboard_logic as dash

    w = timedelta(days=60)
    for b in ("active", "pending", "expired", "churned"):
        assert logic.state_of(b) == b
    for b in ("suspended", "frozen", "blocked", "other"):
        assert logic.state_of(b) == "other"
    assert set(dash.BUCKETS) >= {"active", "pending", "expired", "churned"}
    # KYC outstanding: the Overview says pending, so does the hub
    b = dash.bucket_of(
        "active", valid_until=None, now=NOW, churn_after=w, kyc_pending=True
    )
    assert logic.state_of(b) == "pending"
    b = dash.bucket_of("scheduled", valid_until=None, now=NOW, churn_after=w)
    assert logic.state_of(b) == "pending"
    old = NOW - timedelta(days=61)
    b = dash.bucket_of("expired", valid_until=old, now=NOW, churn_after=w)
    assert logic.state_of(b) == "churned"
    assert logic.churned_at("churned", old, w) == old + w
    assert logic.churned_at("expired", old, w) is None
    import inspect

    from app.domains.isp_partner import revenue_service

    src = inspect.getsource(revenue_service)
    assert "dash_logic.bucket_of(" in src and "kyc_pending_ids(" in src


def test_mrr_is_taxable_and_scaled_to_30_days() -> None:
    kw = {"gst_applied": True, "rate_bp": 1800}
    assert logic.monthly_paise(50000, 30, includes_gst=False, **kw) == 50000
    # Rs 1,180 incl. 18 % GST for 30 days -> Rs 1,000 taxable
    assert logic.monthly_paise(118000, 30, includes_gst=True, **kw) == 100000
    assert logic.monthly_paise(90000, 90, includes_gst=False, **kw) == 30000
    assert logic.monthly_paise(10000, 7, includes_gst=False, **kw) == 42857
    for price, days in ((0, 30), (None, 30), (50000, 0), (50000, None)):
        assert logic.monthly_paise(price, days, includes_gst=False, **kw) is None


def test_ageing_buckets_by_days_past_due() -> None:
    t = date(2026, 11, 15)
    cases = {
        t + timedelta(days=1): "not_due",
        t: "d0_30",
        t - timedelta(days=30): "d0_30",
        t - timedelta(days=31): "d31_60",
        t - timedelta(days=60): "d31_60",
        t - timedelta(days=61): "d61_90",
        t - timedelta(days=90): "d61_90",
        t - timedelta(days=91): "d90_plus",
    }
    for due, want in cases.items():
        assert logic.ageing_bucket(due, t) == want, due


def test_months_and_rates() -> None:
    assert logic.parse_month(None, date(2026, 11, 15)) == date(2026, 11, 1)
    assert logic.parse_month("2026-02", date(2026, 11, 15)) == date(2026, 2, 1)
    with pytest.raises(ValueError):
        logic.parse_month("2026-2", date(2026, 11, 15))
    assert logic.add_months(date(2026, 11, 1), 3) == date(2027, 2, 1)
    assert logic.add_months(date(2026, 1, 1), -1) == date(2025, 12, 1)
    s, e = logic.month_bounds(date(2026, 11, 1), TZ)
    assert s == datetime(2026, 10, 31, 18, 30, tzinfo=UTC)
    assert e == datetime(2026, 11, 30, 18, 30, tzinfo=UTC)
    assert logic.rate(1, 3) == 0.3333 and logic.rate(5, 0) is None
    start = datetime(2026, 11, 1, tzinfo=UTC)
    rows = [
        (start - timedelta(days=5), None),  # in base
        (start - timedelta(days=5), start - timedelta(days=1)),  # churned before
        (start - timedelta(days=5), start + timedelta(days=1)),  # churns in month
        (start + timedelta(days=1), None),  # created later
    ]
    assert logic.base_at(rows, start) == 2


def _codes(**kw) -> list[str]:  # noqa: ANN003
    f = logic.RiskFacts(**kw)
    return [r["code"] for r in logic.risk_reasons(f, now=NOW, tz=TZ)]


def test_each_risk_rule_fires_only_on_its_own_condition() -> None:
    created = NOW - timedelta(days=1)
    seen = NOW - timedelta(hours=1)
    base = {"created_at": created, "last_seen_at": seen}
    soon = NOW + timedelta(days=3)
    far = NOW + timedelta(days=20)
    assert _codes(state="active", valid_until=far, **base) == []
    assert _codes(state="active", valid_until=soon, **base) == ["expiring_no_payment"]
    paid = NOW - timedelta(days=10)
    assert _codes(state="active", valid_until=soon, last_payment_at=paid, **base) == []
    assert _codes(state="active", valid_until=far, late_invoices=1, **base) == []
    assert _codes(state="active", valid_until=far, late_invoices=2, **base) == [
        "late_payments"
    ]
    # tickets: None = not measured (Apps off) never fires
    assert _codes(state="active", valid_until=far, open_tickets=None, **base) == []
    assert _codes(state="active", valid_until=far, open_tickets=1, **base) == [
        "tickets"
    ]
    assert _codes(
        state="active", valid_until=far, open_tickets=0, recent_tickets=2, **base
    ) == ["tickets"]
    assert (
        _codes(
            state="active", valid_until=far, open_tickets=0, recent_tickets=1, **base
        )
        == []
    )
    assert _codes(state="active", valid_until=far, fup_hits=1, **base) == ["fup_hits"]
    stale = NOW - timedelta(days=8)
    assert _codes(
        state="active", valid_until=far, created_at=created, last_seen_at=stale
    ) == ["long_offline"]
    # never online: only once the subscriber is old enough
    assert _codes(state="active", valid_until=far, created_at=created) == []
    assert _codes(state="active", valid_until=far, created_at=stale) == ["long_offline"]
    ended = NOW - timedelta(days=4)
    assert _codes(state="expired", valid_until=ended, created_at=stale) == [
        "expired_recently"
    ]
    assert _codes(state="churned", valid_until=ended, created_at=stale) == []


def test_reasons_explain_themselves_and_score_adds_weights() -> None:
    f = logic.RiskFacts(
        state="active",
        valid_until=NOW + timedelta(days=2),
        created_at=NOW - timedelta(days=40),
        late_invoices=3,
        last_seen_at=NOW - timedelta(days=9),
    )
    rs = logic.risk_reasons(f, now=NOW, tz=TZ)
    assert [r["code"] for r in rs] == [
        "expiring_no_payment",
        "late_payments",
        "long_offline",
    ]
    assert "17 Nov 2026" in rs[0]["detail"] and "never" in rs[0]["detail"]
    assert "3 invoices" in rs[1]["detail"]
    assert "9 days ago" in rs[2]["detail"]
    assert logic.risk_score(rs) == 30 + 25 + 15
    assert set(logic.RISK_WEIGHTS) == set(logic.RISK_REASONS)
    for code in (*logic.RISK_REASONS, "mrr", "arpu", "churn_rate", "collection_rate"):
        assert logic.DEFINITIONS[code]


def test_routes_are_flag_gated_and_keyed() -> None:
    from app.domains.isp_partner.revenue_router import (
        RequireRevenueHubEnabled,
        revenue_router,
    )

    def keys(route) -> list[str]:  # noqa: ANN001
        # RequirePermission(key, scope=...) closes over the key (see guards test)
        out = []
        for d in route.dependant.dependencies:
            if getattr(d.call, "__qualname__", "").startswith("RequirePermission"):
                cells = [c.cell_contents for c in d.call.__closure__ or ()]
                out += [v for v in cells if isinstance(v, str) and "." in v]
        return out

    want = {
        "/revenue/probe": "isp_billing.read",
        "/revenue/summary": "isp_billing.read",
        "/revenue/churn-risk/summary": "isp_billing.read",
        "/revenue/list": "isp_billing.export",
        "/revenue/churn-risk": "isp_billing.export",
    }
    seen = {}
    for r in revenue_router.routes:
        assert r.methods == {"GET"}, r.path  # read-only
        deps = [d.call for d in r.dependant.dependencies]
        assert deps[0] is RequireRevenueHubEnabled, r.path  # flag first
        seen[r.path] = keys(r)
    assert set(seen) == set(want)
    for path, key in want.items():
        assert seen[path] == [key], (path, seen[path])
