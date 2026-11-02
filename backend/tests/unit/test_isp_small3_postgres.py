# ruff: noqa: E501, PLR0915 -- scenario test
"""SMALL-3: win-back save-rate tracking (CHURN-RISK), plus the customer plan
PUT fix, on real PostgreSQL + Redis (skipped unless ``ISP_TEST_PG_DSN``).
Run with ``scripts/run_isp_pg_tests.py``. The test switches
ISP_REVENUE_HUB_ENABLED itself (env + cache_clear).

Covers: flag off -> 404 on both routes; record per action type, replay by
idempotency key returns the same row; ISP B and a confined billing user get
404 for a subscriber outside their scope; viewer 403 on record, 200 on the
rate; the 120 s pass hook marks a renewal and a payment inside the window
(earliest wins), ignores a renewal before the action, leaves an expired
window lost and an open one pending; a re-run marks nothing new; save rate
= 2 / 3; the confined user's rate counts only their customer.
Plan PUT: no billing_cycle on create -> monthly (was a 500); explicit null
-> 422 ISP_PLAN_FIELD_REQUIRED; create without amount -> 422; omitted on
update keeps the stored value.
"""

from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)


def _clear() -> None:
    from app.domains.isp_partner.revenue_router import get_revenue_settings

    get_revenue_settings.cache_clear()


async def test_winback_save_rate(monkeypatch) -> None:  # noqa: ANN001, C901
    from datetime import UTC, datetime, timedelta

    import httpx
    from sqlalchemy import select, update

    from app.database.session import SessionLocal
    from app.domains.isp_partner.winback_models import IspWinbackAction
    from app.domains.isp_partner.winback_service import run_winback_saves

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
    try:
        w = await make_world({"bill": "isp-billing", "view": "isp-viewer"})
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=w.app), base_url="http://t"
        ) as c:
            api = Api(c, w)
            await billing_setup(api, "A")
            await billing_setup(api, "B")
            c1 = await customer(api, "A", "One")
            c2 = await customer(api, "A", "Two")

            # ---- customer plan PUT fix
            r = await api.put(
                f"/billing/customers/{c1}/plan",
                {"plan_name": "Venue", "amount_paise": 0, "active": False},
            )
            assert r["billing_cycle"] == "monthly", r
            body = await api.put(
                f"/billing/customers/{c1}/plan", {"billing_cycle": None}, code=422
            )
            assert "ISP_PLAN_FIELD_REQUIRED" in str(body), body
            body = await api.put(
                f"/billing/customers/{c2}/plan", {"plan_name": "X"}, code=422
            )
            assert "amount_paise" in str(body), body
            r = await api.put(
                f"/billing/customers/{c1}/plan", {"billing_cycle": "yearly"}
            )
            r = await api.put(f"/billing/customers/{c1}/plan", {"notes": "kept"})
            assert r["billing_cycle"] == "yearly", r

            pkg = await package(api, "A", price=50000)
            s1 = await subscriber(api, "A", c1, pkg, "w1")  # renews
            s2 = await subscriber(api, "A", c1, pkg, "w2")  # pays
            s3 = await subscriber(api, "A", c1, pkg, "w3")  # lost (window over)
            s4 = await subscriber(api, "A", c1, pkg, "w4")  # pending (renewed before)
            s5 = await subscriber(api, "A", c2, pkg, "w5")  # other customer

            # ---- flag off
            act = {"subscriber_id": s1, "action": "offer_renew"}
            await api.post("/revenue/churn-risk/actions", act, code=404)
            await api.get("/revenue/churn-risk/save-rate", code=404)
            monkeypatch.setenv("ISP_REVENUE_HUB_ENABLED", "true")
            _clear()

            # s2 owes an invoice issued before the action; s4 renews before
            inv2 = await api.post(
                "/invoices",
                {
                    "bill_to": {"kind": "subscriber", "subscriber_id": s2},
                    "lines": [{"description": "Dues", "amount_paise": 10000}],
                },
            )
            await api.post(f"/subscribers/{s4}/recharge", {"package_id": pkg})

            key = f"wb-{w.tag}-1"
            a1 = await api.post(
                "/revenue/churn-risk/actions",
                {
                    **act,
                    "reasons": ["expired_recently", "bogus"],
                    "idempotency_key": key,
                },
                code=201,
            )
            again = await api.post(
                "/revenue/churn-risk/actions",
                {**act, "idempotency_key": key},
                code=200,
            )
            assert again["id"] == a1["id"]
            await api.post(
                "/revenue/churn-risk/actions",
                {"subscriber_id": s2, "action": "whatsapp_share"},
                code=201,
            )
            a3 = await api.post(
                "/revenue/churn-risk/actions",
                {"subscriber_id": s3, "action": "ticket", "ref_id": str(uuid.uuid4())},
                code=201,
            )
            await api.post(
                "/revenue/churn-risk/actions",
                {"subscriber_id": s4, "action": "offer_renew"},
                code=201,
            )
            await api.post(
                "/revenue/churn-risk/actions",
                {"subscriber_id": s5, "action": "ticket"},
                code=201,
            )
            async with SessionLocal() as s:
                row = await s.get(IspWinbackAction, uuid.UUID(a1["id"]))
                assert row.reasons == ["expired_recently"]  # unknown codes dropped
                long_ago = datetime.now(UTC) - timedelta(days=40)
                await s.execute(
                    update(IspWinbackAction)
                    .where(IspWinbackAction.id == uuid.UUID(a3["id"]))
                    .values(
                        acted_at=long_ago, window_ends_at=long_ago + timedelta(days=30)
                    )
                )
                await s.commit()

            # ---- scope: ISP B, confined billing user, viewer
            await api.post("/revenue/churn-risk/actions", act, who="B", code=404)
            await confine(w, "bill", [c1])
            await api.post(
                "/revenue/churn-risk/actions",
                {"subscriber_id": s5, "action": "ticket"},
                who="bill",
                code=404,
            )
            await api.post("/revenue/churn-risk/actions", act, who="view", code=403)
            assert (await api.get("/revenue/churn-risk/save-rate", who="view"))[
                "actions"
            ] == 5

            # ---- the subscriber renews / pays after the action
            await api.post(f"/subscribers/{s1}/recharge", {"package_id": pkg})
            await api.post(
                "/billing/payments",
                {
                    "subscriber_id": s2,
                    "invoice_id": inv2["id"],
                    "amount_paise": inv2["total_paise"],
                    "mode": "cash",
                },
            )
            res = await run_winback_saves()
            assert res["saved"] == 2, res
            assert (await run_winback_saves())["saved"] == 0  # idempotent
            async with SessionLocal() as s:
                rows = {
                    str(r.subscriber_id): r
                    for r in (
                        await s.execute(
                            select(IspWinbackAction).where(
                                IspWinbackAction.isp_organization_id == w.isps["A"]
                            )
                        )
                    ).scalars()
                }
            assert rows[s1].saved_via == "renewal" and rows[s2].saved_via == "payment"
            assert rows[s3].saved_at is None and rows[s4].saved_at is None

            sr = await api.get("/revenue/churn-risk/save-rate")
            # subscribers: s1 saved, s2 saved, s3 lost, s4 + s5 pending
            assert (sr["saved"], sr["lost"], sr["pending"]) == (2, 1, 2), sr
            assert sr["save_rate"] == round(2 / 3, 4)
            assert sr["by_action"]["offer_renew"]["saved"] == 1
            assert sr["by_action"]["ticket"]["lost"] == 1
            assert sr["saved_via_actions"] == {"renewal": 1, "payment": 1}
            # confined: only customer 1 (s5's pending action is not counted)
            sb = await api.get("/revenue/churn-risk/save-rate", who="bill")
            assert (sb["subscribers"], sb["pending"]) == (4, 1), sb
            # ISP B sees nothing of A
            b = await api.get("/revenue/churn-risk/save-rate", who="B")
            assert b["actions"] == 0 and b["save_rate"] is None
    finally:
        _clear()
        await dispose()
