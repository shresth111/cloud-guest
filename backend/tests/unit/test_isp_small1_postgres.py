# ruff: noqa: E501, PLR0915 -- scenario test
"""SMALL-1: discount code on DIR-2 bulk renew, on real PostgreSQL + Redis
(skipped unless ``ISP_TEST_PG_DSN``). Run with ``scripts/run_isp_pg_tests.py``.

The test switches ISP_DIR2 (monkeypatched settings) and
ISP_DISCOUNT_APPLY_ENABLED (env + cache_clear) itself. ISP A bills GST from
state 07 at 18 %.

Covers: discount flag off + code -> 422, nothing written; unknown code and
ISP B's code -> 422; the dry run shows the per-subscriber discount and skips
the subscriber whose package the code does not allow, the one under the
minimum and the one past the code's last use, writing nothing; apply renews
the quoted ones with the pre-tax discount (intra-state CGST+SGST and
inter-state IGST, GST-inclusive price), counts one use each and renews none
of the skipped; a retry with the same bulk_key adds no invoice and uses
nothing; a dry run with no code is unchanged.
"""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)


def _clear() -> None:
    from app.domains.isp_partner.discount_wire import get_discount_apply_settings

    get_discount_apply_settings.cache_clear()


async def test_bulk_renew_discount(monkeypatch) -> None:  # noqa: ANN001, C901
    import httpx
    from sqlalchemy import func, select

    from app.database.session import SessionLocal
    from app.domains.isp_partner import directory_bulk_router as dbr
    from app.domains.isp_partner.apps_models import IspDiscountCode
    from app.domains.isp_partner.billing_models import IspInvoice

    from .isp_small_pg_helpers import (
        Api,
        billing_setup,
        customer,
        dispose,
        make_world,
        package,
        subscriber,
    )

    monkeypatch.setattr(
        dbr, "get_dir2_settings", lambda: dbr.IspDir2Settings(enabled=True)
    )
    monkeypatch.setenv("ISP_APPS_ENABLED", "true")
    monkeypatch.setenv("ISP_DISCOUNT_APPLY_ENABLED", "false")
    _clear()
    try:
        w = await make_world()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=w.app), base_url="http://t"
        ) as c:
            api = Api(c, w)

            async def invoices(sid: str | None = None) -> int:
                async with SessionLocal() as s:
                    q = (
                        select(func.count())
                        .select_from(IspInvoice)
                        .where(
                            IspInvoice.isp_organization_id == w.isps["A"],
                            IspInvoice.doc_type == "invoice",
                        )
                    )
                    if sid:
                        q = q.where(IspInvoice.subscriber_id == sid)
                    return int((await s.execute(q)).scalar_one())

            async def used(code: str) -> int:
                async with SessionLocal() as s:
                    return (
                        await s.execute(
                            select(IspDiscountCode.used_count).where(
                                IspDiscountCode.isp_organization_id == w.isps["A"],
                                IspDiscountCode.code == code,
                            )
                        )
                    ).scalar_one()

            await billing_setup(api, "A")
            await billing_setup(api, "B")
            cust = await customer(api, "A", "Cafe")
            p_ex = await package(api, "A", price=100000)  # Rs 1,000 + GST
            p_in = await package(
                api, "A", price=118000, incl=True, name="Incl"
            )  # Rs 1,180 incl.
            p_cheap = await package(api, "A", price=20000, name="Cheap")
            s_wrong = await subscriber(
                api, "A", cust, p_cheap, "wr"
            )  # not in allow-list
            s_intra = await subscriber(api, "A", cust, p_ex, "in")
            s_inter = await subscriber(api, "A", cust, p_in, "it", state="27")
            s_over = await subscriber(api, "A", cust, p_ex, "ov")  # past last use
            ids = [s_wrong, s_intra, s_inter, s_over]
            await api.post(
                "/apps/discounts",
                {
                    "code": "BULK100",
                    "kind": "flat",
                    "value": 10000,
                    "max_uses": 2,
                    "package_ids": [p_ex, p_in],
                },
            )
            await api.post(
                "/apps/discounts",
                {
                    "code": "MIN",
                    "kind": "percent",
                    "value": 1000,
                    "min_amount_paise": 50000,
                },
            )
            await api.post(
                "/apps/discounts",
                {"code": "BONLY", "kind": "flat", "value": 100},
                who="B",
            )
            before = await invoices()

            # ---- flag off: refused, nothing written
            body = await api.post(
                "/subscriber-bulk/renew",
                {"subscriber_ids": ids, "discount_code": "BULK100"},
                code=422,
            )
            assert "ISP_DISCOUNT_APPLY_OFF" in str(body), body
            # without a code: unchanged dry run
            dry = await api.post("/subscriber-bulk/renew", {"subscriber_ids": ids})
            assert dry["eligible"] == 4 and "discount" not in dry, dry

            monkeypatch.setenv("ISP_DISCOUNT_APPLY_ENABLED", "true")
            _clear()

            # ---- whole-request 422s: unknown, another ISP's code
            for code in ("NOPE", "BONLY"):
                body = await api.post(
                    "/subscriber-bulk/renew",
                    {"subscriber_ids": ids, "discount_code": code},
                    code=422,
                )
                assert "ISP_DISCOUNT_INVALID" in str(body), body

            # ---- dry run: per-subscriber discount + skips, nothing written
            dry = await api.post(
                "/subscriber-bulk/renew",
                {"subscriber_ids": ids, "discount_code": "bulk100"},
            )
            skipped = {x["id"]: x["reason"] for x in dry["skipped"]}
            assert skipped == {
                s_wrong: "discount_not_for_package",
                s_over: "discount_used_up",
            }, dry
            assert dry["eligible"] == 2
            per = {q["id"]: q for q in dry["discount"]["per_subscriber"]}
            assert set(per) == {s_intra, s_inter}
            assert (
                per[s_intra]["taxable_before_paise"],
                per[s_intra]["discount_paise"],
                per[s_intra]["taxable_after_paise"],
            ) == (100000, 10000, 90000)
            # GST-inclusive Rs 1,180 -> taxable gross Rs 1,000
            assert per[s_inter]["taxable_before_paise"] == 100000
            assert dry["discount"]["total_discount_paise"] == 20000
            assert dry["discount"]["remaining_uses_before"] == 2
            assert await invoices() == before and await used("BULK100") == 0

            # minimum: Rs 200 cheap package is under the Rs 500 minimum
            dmin = await api.post(
                "/subscriber-bulk/renew",
                {"subscriber_ids": [s_wrong, s_intra], "discount_code": "MIN"},
            )
            assert {x["id"]: x["reason"] for x in dmin["skipped"]} == {
                s_wrong: "discount_below_minimum"
            }
            assert dmin["discount"]["per_subscriber"][0]["discount_paise"] == 10000

            # ---- apply
            body = {
                "subscriber_ids": ids,
                "discount_code": "BULK100",
                "dry_run": False,
                "bulk_key": f"sm1-{w.tag}",
            }
            res = await api.post("/subscriber-bulk/renew", body)
            assert res["applied"] == 2 and set(res["applied_ids"]) == {
                s_intra,
                s_inter,
            }, res
            assert not res["failed"], res
            assert await used("BULK100") == 2
            assert await invoices(s_wrong) == 0 and await invoices(s_over) == 0
            rows = {}
            async with SessionLocal() as s:
                for sid in (s_intra, s_inter):
                    rows[sid] = (
                        await s.execute(
                            select(IspInvoice).where(IspInvoice.subscriber_id == sid)
                        )
                    ).scalar_one()
            intra, inter = rows[s_intra], rows[s_inter]
            assert (
                intra.taxable_paise,
                intra.cgst_paise,
                intra.sgst_paise,
                intra.igst_paise,
                intra.total_paise,
            ) == (90000, 8100, 8100, 0, 106200)
            assert (
                inter.taxable_paise,
                inter.cgst_paise,
                inter.sgst_paise,
                inter.igst_paise,
                inter.total_paise,
            ) == (90000, 0, 0, 16200, 106200)
            d = await api.get(f"/invoices/{intra.id}")
            assert d["lines"][0]["discount_paise"] == 10000
            assert "BULK100" in d["lines"][0]["discount_label"]

            # ---- retry same bulk_key: replays, no invoice, no extra use
            n = await invoices()
            res2 = await api.post("/subscriber-bulk/renew", body)
            assert set(res2["applied_ids"]) == {s_intra, s_inter}, res2
            assert {x["id"] for x in res2["skipped"]} == {s_wrong, s_over}
            assert all(q["replay"] for q in res2["discount"]["per_subscriber"])
            assert await invoices() == n and await used("BULK100") == 2

            # ---- the code is now used up: a new batch skips everyone
            d2 = await api.post(
                "/subscriber-bulk/renew",
                {"subscriber_ids": [s_intra, s_over], "discount_code": "BULK100"},
            )
            assert {x["reason"] for x in d2["skipped"]} == {"discount_used_up"}

            # ---- ISP B: A's subscribers are not_found, A's code unknown
            rb = await api.post(
                "/subscriber-bulk/renew",
                {"subscriber_ids": [s_intra], "discount_code": "BONLY"},
                who="B",
            )
            assert rb["skipped"] == [{"id": s_intra, "reason": "not_found"}]
    finally:
        _clear()
        await dispose()
