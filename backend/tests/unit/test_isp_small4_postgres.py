# ruff: noqa: E501, PLR0915 -- scenario test
"""SMALL-4: MRR history (daily revenue snapshots) + DSO, on real PostgreSQL +
Redis (skipped unless ``ISP_TEST_PG_DSN``). Run with
``scripts/run_isp_pg_tests.py``. The test switches ISP_REVENUE_HUB_ENABLED
itself (env + cache_clear).

Covers: flag off -> the daily task writes no snapshot; on -> one row per ISP
per day, a second run the same day updates it (still one row); hand-computed
MRR / ARPU / active / billed / dues / 90-day sales / DSO (GST 18 %, intra);
the trend takes the LAST snapshot of a past month, falls back to the billed
value for a month without one, and shows today's snapshot for this month;
DSO drops after a payment; a package filter and a confined billing user
never read snapshots (live / proxy); ISP B's snapshot is its own.
"""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)


def _clear() -> None:
    from app.domains.isp_partner.revenue_router import get_revenue_settings

    get_revenue_settings.cache_clear()


async def test_mrr_history_and_dso(monkeypatch) -> None:  # noqa: ANN001, C901
    from datetime import date

    import httpx
    from sqlalchemy import func, select

    from app.database.session import SessionLocal
    from app.domains.isp_partner import revenue_logic as logic
    from app.domains.isp_partner.revenue_snapshot_models import IspRevenueSnapshot
    from app.domains.isp_partner.tasks import _billing_daily_async

    from .isp_small_pg_helpers import (
        Api,
        billing_setup,
        confine,
        customer,
        dispose,
        make_world,
        package,
        subscriber,
    )

    monkeypatch.setenv("ISP_REVENUE_HUB_ENABLED", "false")
    _clear()

    async def snaps(isp) -> list:  # noqa: ANN001
        async with SessionLocal() as s:
            return list(
                (
                    await s.execute(
                        select(IspRevenueSnapshot)
                        .where(IspRevenueSnapshot.isp_organization_id == isp)
                        .order_by(IspRevenueSnapshot.snapshot_date)
                    )
                ).scalars()
            )

    try:
        w = await make_world({"bill": "isp-billing"})
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=w.app), base_url="http://t"
        ) as c:
            api = Api(c, w)
            await billing_setup(api, "A")
            await billing_setup(api, "B")
            c1 = await customer(api, "A", "One")
            await customer(api, "A", "Two")
            pkg = await package(api, "A", price=100000)  # Rs 1,000 + GST, 30 days
            other_pkg = await package(api, "A", price=50000, name="Other")
            s1 = await subscriber(api, "A", c1, pkg, "m1")
            s2 = await subscriber(api, "A", c1, pkg, "m2")
            inv = {}
            for sid in (s1, s2):
                r = await api.post(f"/subscribers/{sid}/recharge", {"package_id": pkg})
                inv[sid] = r["invoice"]
            assert inv[s1]["total_paise"] == 118000

            # ---- flag off: the daily task writes no snapshot
            await _billing_daily_async()
            assert await snaps(w.isps["A"]) == []

            monkeypatch.setenv("ISP_REVENUE_HUB_ENABLED", "true")
            _clear()
            res = await _billing_daily_async()
            assert res["revenue_snapshots"] == 2, res  # A and B
            await _billing_daily_async()  # same day again: updated, not added
            rows = await snaps(w.isps["A"])
            assert len(rows) == 1, rows
            t = rows[0]
            assert (
                t.mrr_paise,
                t.arpu_paise,
                t.active,
                t.pending,
                t.churned,
                t.billed_month_paise,
                t.collected_month_paise,
                t.dues_paise,
                t.sales_90d_paise,
                float(t.dso_days),
            ) == (200000, 100000, 2, 0, 0, 200000, 0, 236000, 236000, 90.0)
            today = t.snapshot_date
            b_rows = await snaps(w.isps["B"])
            assert len(b_rows) == 1 and b_rows[0].mrr_paise == 0

            # ---- history: two snapshots two months ago (the later wins), none last month
            m0 = logic.month_start(today)
            m2 = logic.add_months(m0, -2)
            async with SessionLocal() as s:
                for d, mrr in ((5, 50000), (20, 80000)):
                    s.add(
                        IspRevenueSnapshot(
                            isp_organization_id=w.isps["A"],
                            snapshot_date=date(m2.year, m2.month, d),
                            mrr_paise=mrr,
                            arpu_paise=mrr,
                            active=1,
                            pending=0,
                            expired=0,
                            churned=0,
                            unpriced=0,
                            billed_month_paise=0,
                            collected_month_paise=0,
                            dues_paise=0,
                            sales_90d_paise=0,
                            dso_days=None,
                        )
                    )
                await s.commit()

            summ = await api.get("/revenue/summary", params={"months": 3})
            assert summ["mrr_history"]["snapshots_used"] is True
            tr = summ["trend"]
            assert [x["mrr_source"] for x in tr] == [
                "snapshot",
                "billed_proxy",
                "snapshot",
            ], tr
            assert tr[0]["mrr_paise"] == 80000 and tr[0]["snapshot_date"].endswith(
                "-20"
            )
            assert (
                tr[1]["mrr_paise"] == tr[1]["billed_paise"] == 0
                and tr[1]["arpu_paise"] is None
            )
            assert tr[2]["mrr_paise"] == 200000 and tr[2]["active"] == 2
            k = summ["kpis"]
            assert (k["dues_paise"], k["sales_90d_paise"], k["dso_days"]) == (
                236000,
                236000,
                90.0,
            )
            assert "dso" in summ["definitions"]

            # ---- a payment: dues halve, DSO 45.0
            await api.post(
                "/billing/payments",
                {
                    "subscriber_id": s1,
                    "invoice_id": inv[s1]["id"],
                    "amount_paise": 118000,
                    "mode": "cash",
                },
            )
            k = (await api.get("/revenue/summary"))["kpis"]
            assert (k["dues_paise"], k["dso_days"]) == (118000, 45.0)

            # ---- filtered / confined views never read the whole-ISP snapshots
            f = await api.get(
                "/revenue/summary", params={"months": 3, "package_id": other_pkg}
            )
            assert f["mrr_history"]["snapshots_used"] is False
            assert [x["mrr_source"] for x in f["trend"]] == [
                "billed_proxy",
                "billed_proxy",
                "live",
            ]
            assert f["trend"][2]["mrr_paise"] == 0 and f["kpis"]["dso_days"] is None
            await confine(w, "bill", [c1])
            cb = await api.get("/revenue/summary", params={"months": 3}, who="bill")
            assert cb["mrr_history"]["snapshots_used"] is False
            assert cb["trend"][0]["mrr_source"] == "billed_proxy"
            assert (
                cb["trend"][2]["mrr_source"] == "live"
                and cb["trend"][2]["mrr_paise"] == 200000
            )

            # ---- ISP B sees only its own
            sb = await api.get("/revenue/summary", params={"months": 3}, who="B")
            assert [x["mrr_source"] for x in sb["trend"]] == [
                "billed_proxy",
                "billed_proxy",
                "snapshot",
            ]
            assert sb["trend"][2]["mrr_paise"] == 0
            async with SessionLocal() as s:
                n = (
                    await s.execute(
                        select(func.count()).select_from(IspRevenueSnapshot)
                    )
                ).scalar_one()
                assert n == 4
    finally:
        _clear()
        await dispose()
