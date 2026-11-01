# ruff: noqa: E501, PLR0915 -- scenario test
"""DISCOUNT-WIRE on real PostgreSQL + Redis (skipped unless ``ISP_TEST_PG_DSN``).
Run::

    CLOUDGUEST_DATABASE_URL=postgresql+asyncpg://postgres@localhost:55471/dw \\
    CLOUDGUEST_REDIS_URL=redis://localhost:56391/1 \\
    ISP_TEST_PG_DSN=1 ISP_PARTNER_ENABLED=true \\
    python -m pytest tests/unit/test_isp_discount_wire_postgres.py

The test switches ISP_DISCOUNT_APPLY_ENABLED, ISP_APPS_ENABLED,
ISP_QUEUED_RENEWAL_ENABLED and ISP_BILL2_ENABLED itself (env + cache_clear).

ISP A bills GST from state 07 at 18 %. Covers: flag off -> 422 and nothing
written; the pre-tax math intra-state (CGST+SGST) and inter-state (IGST),
including a GST-inclusive price; the line/PDF/GSTR-1 show the reduced taxable
value; recharge, 360 renew, queued renewal and onboarding all take a code;
unknown and used-up codes -> 422 with nothing written; replay with the same
idempotency key redeems once; two requests racing for a code's last use ->
exactly one wins; a revert (full credit note) and a queued-renewal cancel
give the use back; ISP B gets 404 on A's subscriber and discount and 422 for
A's code.
"""

from __future__ import annotations

import asyncio
import base64
import os
import re
import uuid
import zlib
from datetime import UTC, datetime
from decimal import Decimal

import pytest
from fastapi import Request

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)


def _clear() -> None:
    from app.domains.isp_partner.apps_common import get_isp_apps_settings
    from app.domains.isp_partner.bill2_config import get_bill2_settings
    from app.domains.isp_partner.discount_wire import get_discount_apply_settings
    from app.domains.isp_partner.queued_renewal_config import (
        get_queued_renewal_settings,
    )

    for fn in (
        get_isp_apps_settings,
        get_bill2_settings,
        get_discount_apply_settings,
        get_queued_renewal_settings,
    ):
        fn.cache_clear()


def _pdf_text(pdf: bytes) -> str:
    out = []
    for m in re.finditer(rb"<<(.*?)>>\s*stream\r?\n(.*?)endstream", pdf, re.S):
        header, raw = m.group(1), m.group(2)
        try:
            if b"ASCII85Decode" in header:
                data = raw.strip().removeprefix(b"<~").removesuffix(b"~>")
                raw = base64.a85decode(data)
            if b"FlateDecode" in header:
                raw = zlib.decompress(raw)
        except (ValueError, zlib.error):
            continue
        out.append(raw.decode("latin-1"))
    return "\n".join(out)


async def test_discount_codes_on_invoices(monkeypatch) -> None:  # noqa: ANN001, C901
    import httpx
    from sqlalchemy import func, select

    from app.database.session import SessionLocal, engine
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.isp_partner.apps_models import (
        IspDiscountCode,
        IspDiscountRedemption,
    )
    from app.domains.isp_partner.billing_models import IspInvoice
    from app.domains.isp_partner.models import IspPartnerProfile
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.organization.models import Organization, OrganizationMember
    from app.domains.rbac.dependencies import CurrentUser
    from app.domains.rbac.models import Role, UserRole
    from app.domains.rbac.repository import RBACRepository
    from app.domains.rbac.seed import seed_rbac
    from app.main import create_app

    for k in ("ISP_APPS_ENABLED", "ISP_QUEUED_RENEWAL_ENABLED", "ISP_BILL2_ENABLED"):
        monkeypatch.setenv(k, "true")
    monkeypatch.setenv("ISP_DISCOUNT_APPLY_ENABLED", "false")
    _clear()
    tag = uuid.uuid4().hex[:8]
    try:
        async with SessionLocal() as s:
            await seed_rbac(s)
            await seed_isp_partner_rbac(RBACRepository(s))
            await s.commit()
        users: dict[str, uuid.UUID] = {}
        orgs: dict[str, uuid.UUID] = {}
        async with SessionLocal() as s:
            plan = Plan(
                name=f"P {tag}",
                slug=f"pdw-{tag}",
                plan_type="standard",
                billing_cycle="monthly",
                base_price=Decimal("0"),
                currency="INR",
                is_active=True,
                is_public=False,
            )
            s.add(plan)
            role = (
                await s.execute(select(Role).where(Role.slug == "isp-owner"))
            ).scalar_one()
            for n in ("A", "B"):
                org = Organization(
                    name=f"Net {n} {tag}",
                    slug=f"dw{n.lower()}{tag}",
                    org_type="msp",
                    status="active",
                    contact_email=f"dw{n}{tag}@example.com",
                    timezone="Asia/Kolkata",
                    settings={},
                )
                u = User(
                    first_name=n,
                    last_name="O",
                    email=f"dwu{n}{tag}@example.com",
                    username=f"dwu{n}{tag}",
                    password_hash="x",
                    is_active=True,
                    is_verified=True,
                )
                s.add_all([org, u])
                await s.flush()
                s.add(
                    IspPartnerProfile(
                        organization_id=org.id, default_customer_plan_id=plan.id
                    )
                )
                s.add(
                    OrganizationMember(
                        organization_id=org.id, user_id=u.id, status="active"
                    )
                )
                s.add(
                    UserRole(
                        user_id=u.id,
                        role_id=role.id,
                        scope_type="organization",
                        organization_id=org.id,
                        granted_at=datetime.now(UTC),
                        is_active=True,
                    )
                )
                users[n], orgs[n] = u.id, org.id
            await s.commit()

        app = create_app()

        def _user(request: Request) -> AuthUser:
            org = request.headers.get("X-Organization-Id")
            return AuthUser(
                id=str(users["B"] if org == str(orgs["B"]) else users["A"]),
                email="o@example.com",
            )

        app.dependency_overrides[CurrentUser] = _user
        h = {"X-Organization-Id": str(orgs["A"])}
        hb = {"X-Organization-Id": str(orgs["B"])}
        api = "/api/v1/isp"

        async def n_invoices(org: uuid.UUID) -> int:
            async with SessionLocal() as s:
                return int(
                    (
                        await s.execute(
                            select(func.count())
                            .select_from(IspInvoice)
                            .where(IspInvoice.isp_organization_id == org)
                        )
                    ).scalar_one()
                )

        async def used(code: str) -> tuple[int, int]:
            """(used_count, live redemptions) of A's code."""
            async with SessionLocal() as s:
                d = (
                    await s.execute(
                        select(IspDiscountCode).where(
                            IspDiscountCode.isp_organization_id == orgs["A"],
                            IspDiscountCode.code == code,
                        )
                    )
                ).scalar_one()
                live = int(
                    (
                        await s.execute(
                            select(func.count())
                            .select_from(IspDiscountRedemption)
                            .where(
                                IspDiscountRedemption.discount_id == d.id,
                                IspDiscountRedemption.is_deleted.is_(False),
                            )
                        )
                    ).scalar_one()
                )
                return d.used_count, live

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t"
        ) as c:

            async def post(
                path: str, body: dict, code: int = 201, headers: dict | None = None
            ) -> dict:
                r = await c.post(f"{api}{path}", json=body, headers=headers or h)
                assert r.status_code == code, (path, r.status_code, r.text)
                return r.json()["data"] if code < 300 else r.json()

            for hh, st in ((h, "07"), (hb, "07")):
                r = await c.put(
                    f"{api}/billing/settings",
                    json={
                        "legal_name": "Net",
                        "state_code": st,
                        "gst_enabled": True,
                        "invoice_prefix": "DW",
                    },
                    headers=hh,
                )
                assert r.status_code == 200, r.text
            cust = (
                await post(
                    "/customers",
                    {"name": f"Cafe {tag}", "contact_email": f"c{tag}@example.com"},
                )
            )["id"]
            gid = (
                await post(
                    "/speed-groups",
                    {"name": "50M", "download_kbps": 51200, "upload_kbps": 51200},
                )
            )["id"]
            p_ex = (
                await post(
                    "/packages",
                    {
                        "speed_group_id": gid,
                        "type": "prepaid",
                        "validity_days": 30,
                        "price_paise": 100000,
                        "price_includes_gst": False,
                    },
                )
            )["id"]
            p_in = (
                await post(
                    "/packages",
                    {
                        "speed_group_id": gid,
                        "type": "prepaid",
                        "validity_days": 30,
                        "name": f"Incl {tag}",
                        "price_paise": 118000,
                        "price_includes_gst": True,
                    },
                )
            )["id"]

            async def sub(n: int, state: str, pkg: str) -> str:
                return (
                    await post(
                        "/subscribers",
                        {
                            "isp_customer_id": cust,
                            "identifier": f"dw{n}{tag}",
                            "package_id": pkg,
                            "first_name": f"D{n}",
                            "state_code": state,
                        },
                    )
                )["id"]

            intra, inter, s3, s4, s5, s6 = (
                await sub(1, "07", p_ex),
                await sub(2, "27", p_in),
                await sub(3, "07", p_ex),
                await sub(4, "07", p_ex),
                await sub(5, "07", p_ex),
                await sub(6, "07", p_ex),
            )
            await post(
                "/apps/discounts", {"code": "PCT10", "kind": "percent", "value": 1000}
            )
            await post(
                "/apps/discounts",
                {"code": "FLAT100", "kind": "flat", "value": 10000, "max_uses": 1},
            )
            await post(
                "/apps/discounts",
                {"code": "LAST", "kind": "flat", "value": 5000, "max_uses": 1},
            )
            await post(
                "/apps/discounts",
                {
                    "code": "ONLYIN",
                    "kind": "flat",
                    "value": 5000,
                    "package_ids": [p_in],
                },
            )

            # ---- flag off: refused, nothing written
            before = await n_invoices(orgs["A"])
            body = await post(
                f"/subscribers/{intra}/recharge",
                {"package_id": p_ex, "discount_code": "PCT10"},
                422,
            )
            assert "ISP_DISCOUNT_APPLY_OFF" in str(body), body
            assert await n_invoices(orgs["A"]) == before and await used("PCT10") == (
                0,
                0,
            )

            monkeypatch.setenv("ISP_DISCOUNT_APPLY_ENABLED", "true")
            _clear()

            # ---- intra-state: Rs 1,000 excl. GST, 10 % off -> taxable 900, CGST+SGST 81 each
            rc = await post(
                f"/subscribers/{intra}/recharge",
                {
                    "package_id": p_ex,
                    "discount_code": "pct10",
                    "idempotency_key": f"k-intra-{tag}",
                },
            )
            inv = rc["invoice"]
            assert (
                inv["taxable_paise"],
                inv["cgst_paise"],
                inv["sgst_paise"],
                inv["igst_paise"],
                inv["total_paise"],
            ) == (90000, 8100, 8100, 0, 106200), inv
            d = (await c.get(f"{api}/invoices/{inv['id']}", headers=h)).json()["data"]
            (line,) = d["lines"]
            assert (
                line["discount_paise"] == 10000 and "PCT10" in line["discount_label"]
            ), line
            assert (
                line["unit_amount_paise"] == 100000 and line["taxable_paise"] == 90000
            )
            assert await used("PCT10") == (1, 1)
            # replay with the same key: same invoice, still one use
            again = await post(
                f"/subscribers/{intra}/recharge",
                {
                    "package_id": p_ex,
                    "discount_code": "PCT10",
                    "idempotency_key": f"k-intra-{tag}",
                },
            )
            assert again["invoice"]["id"] == inv["id"] and await used("PCT10") == (1, 1)
            pdf = await c.get(f"{api}/invoices/{inv['id']}/pdf", headers=h)
            assert pdf.status_code == 200 and "Less Discount PCT10" in _pdf_text(
                pdf.content
            )

            # ---- inter-state, GST-inclusive Rs 1,180: taxable gross 1,000, 10 % off -> 900 + IGST 162
            inv2 = (
                await post(
                    f"/subscribers/{inter}/recharge",
                    {"package_id": p_in, "discount_code": "PCT10"},
                )
            )["invoice"]
            assert (
                inv2["taxable_paise"],
                inv2["cgst_paise"],
                inv2["sgst_paise"],
                inv2["igst_paise"],
                inv2["total_paise"],
            ) == (90000, 0, 0, 16200, 106200), inv2

            # ---- bad codes: 422, nothing written
            before = await n_invoices(orgs["A"])
            for code in ("NOPE", "ONLYIN"):  # unknown / wrong package
                body = await post(
                    f"/subscribers/{s3}/recharge",
                    {"package_id": p_ex, "discount_code": code},
                    422,
                )
                assert "ISP_DISCOUNT_INVALID" in str(body), body
            assert await n_invoices(orgs["A"]) == before

            # ---- 360 renew with a single-use code, then used up
            r1 = await post(f"/subscribers/{s3}/renew", {"discount_code": "FLAT100"})
            assert (
                r1["invoice"]["taxable_paise"] == 90000
                and r1["invoice"]["total_paise"] == 106200
            )
            assert await used("FLAT100") == (1, 1)
            before = await n_invoices(orgs["A"])
            body = await post(
                f"/subscribers/{s4}/renew", {"discount_code": "FLAT100"}, 422
            )
            assert "used up" in str(body) and await n_invoices(orgs["A"]) == before

            # ---- revert (full credit note) gives the use back; the code works again
            r = await c.post(
                f"{api}/subscribers/{s3}/revert",
                json={"reason": "wrong plan"},
                headers=h,
            )
            assert r.status_code == 200, r.text
            assert await used("FLAT100") == (0, 0)
            reds = (await c.get(f"{api}/apps/discounts", headers=h)).json()["data"]
            flat_id = next(x["id"] for x in reds["items"] if x["code"] == "FLAT100")
            assert (
                await c.get(f"{api}/apps/discounts/{flat_id}/redemptions", headers=h)
            ).json()["data"] == []
            await post(f"/subscribers/{s4}/renew", {"discount_code": "FLAT100"})
            assert await used("FLAT100") == (1, 1)

            # ---- last use, two requests at once: exactly one wins
            before = await n_invoices(orgs["A"])
            res = await asyncio.gather(
                c.post(
                    f"{api}/subscribers/{s5}/recharge",
                    json={"package_id": p_ex, "discount_code": "LAST"},
                    headers=h,
                ),
                c.post(
                    f"{api}/subscribers/{s6}/recharge",
                    json={"package_id": p_ex, "discount_code": "LAST"},
                    headers=h,
                ),
            )
            assert sorted(x.status_code for x in res) == [201, 422], [
                x.text for x in res
            ]
            assert (
                await used("LAST") == (1, 1)
                and await n_invoices(orgs["A"]) == before + 1
            )

            # ---- queued renewal takes a code; cancelling it gives the use back
            q = await post(
                f"/subscribers/{s6}/queued-renewals",
                {
                    "package_id": p_ex,
                    "idempotency_key": f"q-{tag}-0001",
                    "discount_code": "PCT10",
                },
            )
            assert q["queued"]["invoice"]["total_paise"] == 106200, q
            assert await used("PCT10") == (3, 3)
            await post(
                f"/subscribers/{s6}/queued-renewals/{q['queued']['id']}/cancel",
                {"reason": "changed mind"},
                200,
            )
            assert await used("PCT10") == (2, 2)

            # ---- onboarding: the first invoice takes a code
            ob = await post(
                "/onboarding",
                {
                    "subscriber": {
                        "isp_customer_id": cust,
                        "identifier": f"dwob{tag}",
                        "package_id": p_ex,
                        "first_name": "Ob",
                        "state_code": "07",
                    },
                    "billing": {"issue_invoice": True, "discount_code": "PCT10"},
                },
            )
            assert (
                ob["invoice"]["taxable_paise"] == 90000
                and ob["invoice"]["total_paise"] == 106200
            ), ob["invoice"]
            assert await used("PCT10") == (3, 3)
            before = await n_invoices(orgs["A"])
            r = await c.post(
                f"{api}/onboarding",
                json={
                    "subscriber": {
                        "isp_customer_id": cust,
                        "identifier": f"dwob2{tag}",
                        "package_id": p_ex,
                        "first_name": "Ob",
                        "state_code": "07",
                    },
                    "billing": {"issue_invoice": True, "discount_code": "NOPE"},
                },
                headers=h,
            )
            assert (
                r.status_code == 422 and await n_invoices(orgs["A"]) == before
            ), r.text

            # ---- GSTR-1 carries the reduced taxable values
            month = datetime.now(UTC).astimezone().strftime("%Y-%m")
            g = (
                await c.get(f"{api}/gst/gstr1?month={month}&format=json", headers=h)
            ).json()
            live = 0
            async with SessionLocal() as s:
                live = int(
                    (
                        await s.execute(
                            select(
                                func.coalesce(func.sum(IspInvoice.taxable_paise), 0)
                            ).where(
                                IspInvoice.isp_organization_id == orgs["A"],
                                IspInvoice.doc_type == "invoice",
                            )
                        )
                    ).scalar_one()
                )
                notes = int(
                    (
                        await s.execute(
                            select(
                                func.coalesce(func.sum(IspInvoice.taxable_paise), 0)
                            ).where(
                                IspInvoice.isp_organization_id == orgs["A"],
                                IspInvoice.doc_type == "credit_note",
                            )
                        )
                    ).scalar_one()
                )
            got = round(sum(r["Taxable Value"] for r in g["b2cs"]) * 100)
            assert got == live - notes, (got, live, notes)
            assert not any(r["Taxable Value"] == 1000.0 for r in g["b2cs"])

            # ---- ISP B: 404 on A's subscriber and discount, 422 for A's code
            await post(
                f"/subscribers/{intra}/recharge",
                {"package_id": p_ex, "discount_code": "PCT10"},
                404,
                headers=hb,
            )
            r = await c.get(f"{api}/apps/discounts/{flat_id}/redemptions", headers=hb)
            assert r.status_code == 404, r.text
            cb = (
                await post(
                    "/customers",
                    {"name": f"B {tag}", "contact_email": f"b{tag}@example.com"},
                    headers=hb,
                )
            )["id"]
            gb = (
                await post(
                    "/speed-groups",
                    {"name": "B", "download_kbps": 1024, "upload_kbps": 1024},
                    headers=hb,
                )
            )["id"]
            pb = (
                await post(
                    "/packages",
                    {
                        "speed_group_id": gb,
                        "type": "prepaid",
                        "validity_days": 30,
                        "price_paise": 50000,
                    },
                    headers=hb,
                )
            )["id"]
            sb = (
                await post(
                    "/subscribers",
                    {
                        "isp_customer_id": cb,
                        "identifier": f"dwb{tag}",
                        "package_id": pb,
                        "first_name": "B",
                    },
                    headers=hb,
                )
            )["id"]
            body = await post(
                f"/subscribers/{sb}/recharge",
                {"package_id": pb, "discount_code": "PCT10"},
                422,
                headers=hb,
            )
            assert "Unknown discount code" in str(body)
            assert await used("PCT10") == (3, 3)
    finally:
        _clear()
        await engine.dispose()
        from app.database.redis import redis_client

        await redis_client.connection_pool.disconnect()
