"""COLLECTIONS-1 rules (no database): risk score, promise status, forecast,
and the route surface (flag, guard keys)."""

from __future__ import annotations

from datetime import date, timedelta

from app.domains.isp_partner import collections_logic as L

TODAY = date(2026, 11, 4)  # a Wednesday


def _facts(**kw) -> L.PartyFacts:
    base = {"days_overdue": 5, "overdue_invoices": 1, "days_since_last_payment": 10}
    base.update(kw)
    return L.PartyFacts(**base)


def test_age_points_and_bands() -> None:
    assert L.score(_facts(days_overdue=5), today=TODAY).score == 10
    assert L.score(_facts(days_overdue=20), today=TODAY).score == 20
    assert L.score(_facts(days_overdue=45), today=TODAY).score == 35
    r = L.score(_facts(days_overdue=61), today=TODAY)
    assert r.score == 50 and r.band == "high"
    assert L.band_for(24) == "low" and L.band_for(25) == "medium"


def test_every_reason_is_explained_and_adds_up() -> None:
    r = L.score(
        _facts(
            days_overdue=40,
            overdue_invoices=3,
            broken_promises_90d=1,
            late_payments_180d=2,
            days_since_last_payment=None,
        ),
        today=TODAY,
    )
    codes = [x.code for x in r.reasons]
    assert codes == [
        "age_31_60",
        "many_unpaid",
        "broken_promise",
        "pays_late",
        "no_recent_payment",
    ]
    assert r.score == min(100, sum(x.points for x in r.reasons)) == 90
    assert all(x.text for x in r.reasons)


def test_open_promise_lowers_the_score_and_is_capped_at_zero() -> None:
    r = L.score(_facts(open_promise_on=TODAY), today=TODAY)
    assert r.score == 0 and r.reasons[-1].code == "open_promise"
    # a promise date already passed does not lower it
    r = L.score(_facts(open_promise_on=TODAY - timedelta(days=1)), today=TODAY)
    assert r.score == 10


def test_ranking_band_then_amount() -> None:
    def item(band: str, amt: int) -> dict:
        return {
            "risk": {"band": band, "score": {"high": 60, "medium": 30, "low": 5}[band]},
            "overdue_paise": amt,
            "days_overdue": 1,
        }

    rows = [item("low", 900), item("high", 100), item("medium", 500), item("high", 300)]
    rows.sort(key=lambda i: L.sort_key(i, "priority"))
    assert [(r["risk"]["band"], r["overdue_paise"]) for r in rows] == [
        ("high", 300),
        ("high", 100),
        ("medium", 500),
        ("low", 900),
    ]
    rows.sort(key=lambda i: L.sort_key(i, "amount"))
    assert rows[0]["overdue_paise"] == 900


def test_promise_status() -> None:
    kw = {"promised_on": TODAY, "target_paise": 1000}
    assert (
        L.promise_status(stored="open", paid_by_deadline_paise=0, today=TODAY, **kw)
        == "open"
    )
    assert (
        L.promise_status(stored="open", paid_by_deadline_paise=1000, today=TODAY, **kw)
        == "kept"
    )
    late = TODAY + timedelta(days=1)
    assert (
        L.promise_status(stored="open", paid_by_deadline_paise=999, today=late, **kw)
        == "broken"
    )
    # a resolved promise never moves again
    assert (
        L.promise_status(
            stored="cancelled", paid_by_deadline_paise=5000, today=late, **kw
        )
        == "cancelled"
    )


def test_rates_fall_back_to_defaults_without_history() -> None:
    assert L.keep_rate(3, 2) == (L.DEFAULT_KEEP_RATE, False)
    assert L.keep_rate(8, 2) == (0.8, True)
    assert L.on_time_rate(5, 19) == (L.DEFAULT_ON_TIME_RATE, False)
    assert L.on_time_rate(15, 20) == (0.75, True)


def test_forecast_components() -> None:
    f = L.forecast(
        today=TODAY,
        collected_so_far_paise=10_000,
        promises_due=[1000, 3000],
        keep=(0.5, True),
        invoices_due=[2000],
        on_time=(0.5, False),
        overdue_by_band={"low": [4000], "high": [10_000]},
    )
    assert f["week_start"] == "2026-11-02" and f["week_end"] == "2026-11-08"
    comps = {c["key"]: c for c in f["components"]}
    assert comps["promises"]["expected_paise"] == 2000
    assert comps["promises"]["rate_measured"] is True
    assert comps["due_this_week"]["expected_paise"] == 1000
    assert comps["due_this_week"]["rate_measured"] is False
    assert comps["overdue_low"]["expected_paise"] == 1000
    assert comps["overdue_high"]["expected_paise"] == 300
    assert comps["overdue_medium"]["expected_paise"] == 0
    assert f["predicted_remaining_paise"] == 4300
    assert f["predicted_total_paise"] == 14_300


def test_routes_are_flagged_and_guarded() -> None:
    from app.domains.isp_partner.collections_config import RequireCollectionsEnabled
    from app.domains.isp_partner.collections_router import collections_router

    paths = {(sorted(r.methods)[0], r.path) for r in collections_router.routes}
    assert ("GET", "/collections/overdue") in paths
    assert ("POST", "/collections/cash") in paths
    assert ("POST", "/collections/handovers/{handover_id}/approve") in paths
    for r in collections_router.routes:
        calls = [d.dependency for d in r.dependencies]
        assert calls[0] is RequireCollectionsEnabled, r.path


def test_seed_grants_approve_to_owner_and_admin_only() -> None:
    from app.domains.isp_partner.rbac_roles import ROLES

    holders = {r.slug for r in ROLES if "isp_collections.approve" in r.permission_keys}
    assert holders == {"isp-owner", "isp-admin"}
    collectors = {
        r.slug for r in ROLES if "isp_collections.collect" in r.permission_keys
    }
    assert collectors == {
        "isp-owner",
        "isp-admin",
        "isp-technician",
        "isp-billing",
        "isp-franchisee",  # RAKESH-FS: collects cash in its own zones
    }
