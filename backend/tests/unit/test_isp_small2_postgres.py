# ruff: noqa: E501, PLR0915 -- scenario test
"""SMALL-2: discount codes on customer (venue) invoices, on real PostgreSQL +
Redis (skipped unless ``ISP_TEST_PG_DSN``). Run with
``scripts/run_isp_pg_tests.py``. The test switches ISP_APPS_ENABLED and
ISP_DISCOUNT_APPLY_ENABLED itself (env + cache_clear).

ISP A bills GST from state 07 at 18 %. Covers: flag off + code -> 422 and no
invoice; 1b one-line invoice intra-state (CGST+SGST); manual multi-line
invoice to an inter-state customer (IGST) with the flat discount split across
lines to the paisa; a GST-inclusive line; a GST-exempt customer (gst_applicable
false: no GST taken out before quoting, no GST added); a manual subscriber
bill with a code; unknown / package-limited / used-up codes -> 422 with no
invoice and no use; void gives the use back; confined billing user 404 on
another customer's invoice (with a code); ISP B 404 on A's customer and 422
for A's code; no code = unchanged totals.
"""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)


def _clear() -> None:
    from app.domains.isp_partner.apps_common import get_isp_apps_settings
    from app.domains.isp_partner.discount_wire import get_discount_apply_settings

    get_discount_apply_settings.cache_clear()
    get_isp_apps_settings.cache_clear()


def _tot(inv: dict) -> tuple:
    return (
        inv["taxable_paise"],
        inv["cgst_paise"],
        inv["sgst_paise"],
        inv["igst_paise"],
        inv["total_paise"],
    )


async def test_customer_invoice_discounts(monkeypatch) -> None:  # noqa: ANN001, C901
    import httpx
    from sqlalchemy import func, select

    from app.database.session import SessionLocal
    from app.domains.isp_partner.apps_models import (
        IspDiscountCode,
        IspDiscountRedemption,
    )
    from app.domains.isp_partner.billing_models import IspInvoice

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

    monkeypatch.setenv("ISP_APPS_ENABLED", "true")
    monkeypatch.setenv("ISP_DISCOUNT_APPLY_ENABLED", "false")
    _clear()
    try:
        w = await make_world({"bill": "isp-billing"})
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=w.app), base_url="http://t"
        ) as c:
            api = Api(c, w)

            async def n_inv() -> int:
                async with SessionLocal() as s:
                    return int(
                        (
                            await s.execute(
                                select(func.count())
                                .select_from(IspInvoice)
                                .where(IspInvoice.isp_organization_id == w.isps["A"])
                            )
                        ).scalar_one()
                    )

            async def used(code: str) -> tuple[int, int]:
                async with SessionLocal() as s:
                    d = (
                        await s.execute(
                            select(IspDiscountCode).where(
                                IspDiscountCode.isp_organization_id == w.isps["A"],
                                IspDiscountCode.code == code,
                            )
                        )
                    ).scalar_one()
                    live = (
                        await s.execute(
                            select(func.count())
                            .select_from(IspDiscountRedemption)
                            .where(
                                IspDiscountRedemption.discount_id == d.id,
                                IspDiscountRedemption.is_deleted.is_(False),
                            )
                        )
                    ).scalar_one()
                    return d.used_count, int(live)

            await billing_setup(api, "A")
            await billing_setup(api, "B")
            c_intra = await customer(api, "A", "Intra")
            c_inter = await customer(api, "A", "Inter")
            c_exempt = await customer(api, "A", "Exempt")
            await api.put(
                f"/billing/customers/{c_inter}/plan",
                {
                    "plan_name": "Venue",
                    "amount_paise": 0,
                    "billing_cycle": "monthly",
                    "place_of_supply_state_code": "27",
                },
            )
            await api.put(
                f"/billing/customers/{c_exempt}/plan",
                {
                    "plan_name": "Venue",
                    "amount_paise": 0,
                    "billing_cycle": "monthly",
                    "gst_applicable": False,
                },
            )
            pkg = await package(api, "A", price=50000)
            s_inter = await subscriber(api, "A", c_intra, pkg, "sx", state="27")
            await api.post(
                "/apps/discounts", {"code": "PCT10", "kind": "percent", "value": 1000}
            )
            await api.post(
                "/apps/discounts",
                {"code": "FLAT150", "kind": "flat", "value": 15000, "max_uses": 1},
            )
            await api.post(
                "/apps/discounts",
                {
                    "code": "PKGONLY",
                    "kind": "flat",
                    "value": 1000,
                    "package_ids": [pkg],
                },
            )
            one = {
                "isp_customer_id": c_intra,
                "description": "Venue rent",
                "amount_paise": 100000,
            }

            # ---- flag off: refused, nothing written; no code: unchanged
            n0 = await n_inv()
            body = await api.post(
                "/billing/invoices", {**one, "discount_code": "PCT10"}, code=422
            )
            assert "ISP_DISCOUNT_APPLY_OFF" in str(body), body
            assert await n_inv() == n0 and await used("PCT10") == (0, 0)
            plain = await api.post("/billing/invoices", one)
            assert _tot(plain) == (100000, 9000, 9000, 0, 118000), plain

            monkeypatch.setenv("ISP_DISCOUNT_APPLY_ENABLED", "true")
            _clear()

            # ---- 1b one-line, intra-state: 10 % off Rs 1,000 -> 900 + 81 + 81
            inv1 = await api.post(
                "/billing/invoices", {**one, "discount_code": "pct10"}
            )
            assert _tot(inv1) == (90000, 8100, 8100, 0, 106200), inv1
            d1 = await api.get(f"/invoices/{inv1['id']}")
            assert d1["lines"][0]["discount_paise"] == 10000
            assert "PCT10" in d1["lines"][0]["discount_label"]
            assert await used("PCT10") == (1, 1)

            # ---- manual, inter-state, two lines (one GST-inclusive): Rs 150 split by gross
            # gross: 60,000 + (70,800 incl -> 60,000) = 120,000; shares 7,500 / 7,500
            man = {
                "bill_to": {"kind": "customer", "isp_customer_id": c_inter},
                "lines": [
                    {"description": "Bandwidth", "amount_paise": 60000},
                    {
                        "description": "AP rent",
                        "amount_paise": 70800,
                        "price_includes_gst": True,
                    },
                ],
                "discount_code": "FLAT150",
            }
            inv2 = await api.post("/invoices", man)
            assert _tot(inv2) == (105000, 0, 0, 18900, 123900), inv2
            assert [ln["discount_paise"] for ln in inv2["lines"]] == [7500, 7500]
            assert sum(ln["taxable_paise"] for ln in inv2["lines"]) == 105000
            assert await used("FLAT150") == (1, 1)

            # ---- used up / unknown / package-limited: 422, nothing written
            n1 = await n_inv()
            for code, msg in (
                ("FLAT150", "used up"),
                ("NOPE", "Unknown discount code"),
                ("PKGONLY", "does not apply to this package"),
            ):
                body = await api.post(
                    "/invoices", {**man, "discount_code": code}, code=422
                )
                assert "ISP_DISCOUNT_INVALID" in str(body) and msg in str(body), body
            assert await n_inv() == n1 and await used("PKGONLY") == (0, 0)

            # ---- void gives the use back; the code works again
            await api.post(f"/billing/invoices/{inv2['id']}/void", {"reason": "wrong"})
            assert await used("FLAT150") == (0, 0)
            again = await api.post("/invoices", man)
            assert again["total_paise"] == 123900 and await used("FLAT150") == (1, 1)

            # ---- GST-exempt customer: Rs 1,180 incl. is all taxable gross, no GST
            ex = await api.post(
                "/invoices",
                {
                    "bill_to": {"kind": "customer", "isp_customer_id": c_exempt},
                    "lines": [
                        {
                            "description": "Rent",
                            "amount_paise": 118000,
                            "price_includes_gst": True,
                        }
                    ],
                    "discount_code": "PCT10",
                },
            )
            assert _tot(ex) == (106200, 0, 0, 0, 106200), ex

            # ---- manual subscriber bill with a code (state 27 -> IGST)
            sb = await api.post(
                "/invoices",
                {
                    "bill_to": {"kind": "subscriber", "subscriber_id": s_inter},
                    "lines": [{"description": "Extra", "amount_paise": 100000}],
                    "discount_code": "PCT10",
                },
            )
            assert _tot(sb) == (90000, 0, 0, 16200, 106200), sb
            async with SessionLocal() as s:
                r = (
                    await s.execute(
                        select(IspDiscountRedemption).where(
                            IspDiscountRedemption.invoice_id == sb["id"]
                        )
                    )
                ).scalar_one()
                assert str(r.subscriber_id) == s_inter
            assert await used("PCT10") == (3, 3)

            # ---- confined billing user: only c_intra
            await confine(w, "bill", [c_intra])
            await api.post(
                "/billing/invoices",
                {**one, "isp_customer_id": c_inter, "discount_code": "PCT10"},
                who="bill",
                code=404,
            )
            ok_b = await api.post(
                "/billing/invoices", {**one, "discount_code": "PCT10"}, who="bill"
            )
            assert ok_b["total_paise"] == 106200

            # ---- ISP B
            n2 = await n_inv()
            await api.post(
                "/billing/invoices",
                {**one, "discount_code": "PCT10"},
                who="B",
                code=404,
            )
            cb = await customer(api, "B", "Bcafe")
            body = await api.post(
                "/billing/invoices",
                {**one, "isp_customer_id": cb, "discount_code": "PCT10"},
                who="B",
                code=422,
            )
            assert "Unknown discount code" in str(body)
            assert await n_inv() == n2 and await used("PCT10") == (4, 4)
    finally:
        _clear()
        await dispose()
