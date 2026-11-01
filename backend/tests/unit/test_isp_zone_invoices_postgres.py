# ruff: noqa: E501, PLR0915 -- scenario test
"""FINISH: a zone settlement becomes a real GST tax invoice, on real
PostgreSQL + Redis (skipped unless ``ISP_TEST_PG_DSN``). Run::

    CLOUDGUEST_DATABASE_URL=postgresql+asyncpg://postgres@localhost:55441/finish \\
    CLOUDGUEST_REDIS_URL=redis://localhost:56381/0 \\
    ISP_TEST_PG_DSN=1 ISP_PARTNER_ENABLED=true \\
    python -m pytest tests/unit/test_isp_zone_invoices_postgres.py

The ISP bills GST from state 07. Three zones get a Rs 1,180 monthly charge:
Z1 in 07 with a 07 GSTIN (intra-state, CGST+SGST, B2B), Z2 in 27 without a
GSTIN (inter-state, IGST, B2CS), Z3 whose zone state says 07 but whose GSTIN
is from 29 (the GSTIN state wins: IGST, B2B). Covers: settlement -> invoice
(ZS number kept on both sides), the GST split, GSTR-1 placement, the
invoice never shows in the invoice list / customer ledger, a pre-0188
settlement invoiced later (idempotent), and ISP B gets 404 everywhere.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, date, datetime
from decimal import Decimal

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)


def _gstin(state: str, pan: str) -> str:
    from app.domains.isp_partner.gst import _CHARS

    body = f"{state}{pan}1Z"
    total = 0
    for i, ch in enumerate(body):
        p = _CHARS.index(ch) * (2 if i % 2 else 1)
        total += p // 36 + p % 36
    return body + _CHARS[(36 - total % 36) % 36]


async def test_zone_settlement_is_a_gst_tax_invoice() -> None:
    import httpx
    from sqlalchemy import select

    from app.database.session import SessionLocal, engine
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.isp_partner.bill2_config import get_bill2_settings
    from app.domains.isp_partner.billing_models import IspInvoice
    from app.domains.isp_partner.finance_config import get_finance_settings
    from app.domains.isp_partner.franchise_models import IspZoneSettlement
    from app.domains.isp_partner.franchise_service import get_franchise_settings
    from app.domains.isp_partner.gst import gstin_valid
    from app.domains.isp_partner.models import IspPartnerProfile
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.isp_partner.zones_config import get_zones_settings
    from app.domains.organization.models import Organization, OrganizationMember
    from app.domains.rbac.dependencies import CurrentUser
    from app.domains.rbac.models import Role, UserRole
    from app.domains.rbac.repository import RBACRepository
    from app.domains.rbac.seed import seed_rbac
    from app.main import create_app

    flags = (
        "ISP_FRANCHISE_ENABLED",
        "ISP_ZONE_LEDGER_ENABLED",
        "ISP_BILL2_ENABLED",
    )

    def clear() -> None:
        get_franchise_settings.cache_clear()
        get_finance_settings.cache_clear()
        get_bill2_settings.cache_clear()
        get_zones_settings.cache_clear()

    g07, g29 = _gstin("07", "AAACZ1234A"), _gstin("29", "AAACZ5678B")
    assert gstin_valid(g07) and gstin_valid(g29)
    tag = uuid.uuid4().hex[:8]
    os.environ.pop("ISP_ZONES_ENABLED", None)
    try:
        async with SessionLocal() as s:
            await seed_rbac(s)
            await seed_isp_partner_rbac(RBACRepository(s))
            await s.commit()
        users, isps = {}, {}
        async with SessionLocal() as s:
            plan = Plan(
                name=f"P {tag}",
                slug=f"pzi-{tag}",
                plan_type="standard",
                billing_cycle="monthly",
                base_price=Decimal("0"),
                currency="INR",
                is_active=True,
                is_public=False,
            )
            s.add(plan)
            owner = (
                await s.execute(select(Role).where(Role.slug == "isp-owner"))
            ).scalar_one()
            for n in ("A", "B"):
                org = Organization(
                    name=f"ZI {n} {tag}",
                    slug=f"zinet{n.lower()}{tag}",
                    org_type="msp",
                    status="active",
                    contact_email=f"zi{n}{tag}@example.com",
                    timezone="Asia/Kolkata",
                    settings={},
                )
                user = User(
                    first_name=n,
                    last_name="T",
                    email=f"zio{n.lower()}{tag}@example.com",
                    username=f"zio{n.lower()}{tag}",
                    password_hash="x",
                    is_active=True,
                    is_verified=True,
                )
                s.add_all([org, user])
                await s.flush()
                s.add(
                    IspPartnerProfile(
                        organization_id=org.id, default_customer_plan_id=plan.id
                    )
                )
                s.add_all(
                    [
                        OrganizationMember(
                            organization_id=org.id, user_id=user.id, status="active"
                        ),
                        UserRole(
                            user_id=user.id,
                            role_id=owner.id,
                            scope_type="organization",
                            organization_id=org.id,
                            granted_at=datetime.now(UTC),
                            is_active=True,
                        ),
                    ]
                )
                users[n], isps[n] = user.id, org.id
            await s.commit()

        for k in flags:
            os.environ[k] = "true"
        clear()
        app = create_app()
        state = {"user": users["A"]}
        app.dependency_overrides[CurrentUser] = lambda: AuthUser(
            id=str(state["user"]), email="o@example.com"
        )
        ha = {"X-Organization-Id": str(isps["A"])}
        hb = {"X-Organization-Id": str(isps["B"])}
        api = "/api/v1/isp"
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t"
        ) as c:

            async def call(method, path, body=None, h=ha, ok=(200, 201)):  # noqa: ANN001, ANN202
                r = await c.request(method, f"{api}{path}", json=body, headers=h)
                assert r.status_code in ok, (path, r.status_code, r.text)
                return r.json().get("data")

            await call(
                "PUT",
                "/billing/settings",
                {
                    "legal_name": "ZI Net Pvt Ltd",
                    "state_code": "07",
                    "gst_enabled": True,
                    "invoice_prefix": "ZIA",
                },
            )
            cust = (
                await call(
                    "POST",
                    "/customers",
                    {"name": f"cust {tag}", "contact_email": f"cust{tag}@e.com"},
                )
            )["id"]
            customer_inv = await call(
                "POST",
                "/billing/invoices",
                {
                    "isp_customer_id": cust,
                    "description": "Bandwidth",
                    "amount_paise": 10000,
                },
            )

            zones = {}
            for key, zstate, gstin in (
                ("Z1", "07", g07),
                ("Z2", "27", None),
                ("Z3", "07", g29),
            ):
                z = (
                    await call(
                        "POST", "/zones", {"name": f"{key} {tag}", "state_code": zstate}
                    )
                )["id"]
                prof = {"address": f"{key} road", "pincode": "110001"}
                if gstin:
                    prof["gstin"] = gstin
                await call("PUT", f"/finance/zones/{z}/profile", prof)
                await call(
                    "POST",
                    f"/franchise/zones/{z}/charges",
                    {
                        "name": "Backhaul",
                        "amount_paise": 118000,
                        "day_of_month": 1,
                        "starts_on": "2026-01-01",
                    },
                )
                zones[key] = z
            assert (await call("POST", "/franchise/charges/run", {}))["charges"] == 3
            today = datetime.now(UTC).date().isoformat()

            # settlement -> invoice ------------------------------------------------
            st = {}
            for key, z in zones.items():
                st[key] = await call(
                    "POST",
                    f"/franchise/zones/{z}/settlements",
                    {"date_from": "2026-01-01", "date_to": today},
                )
                assert st[key]["number"].startswith("ZS/")
                assert st[key]["billed_paise"] == 118000
                assert st[key]["invoice"] is not None, st[key]
            i1, i2, i3 = (st[k]["invoice"] for k in ("Z1", "Z2", "Z3"))
            assert i1["number"].startswith("ZIA/")
            # intra-state: Rs 1,180 incl. 18% -> 1,000 + 90 + 90
            assert (
                i1["taxable_paise"],
                i1["cgst_paise"],
                i1["sgst_paise"],
                i1["igst_paise"],
            ) == (100000, 9000, 9000, 0)
            assert i1["place_of_supply_state_code"] == "07" and i1["buyer_gstin"] == g07
            # inter-state by zone state
            assert (i2["taxable_paise"], i2["cgst_paise"], i2["igst_paise"]) == (
                100000,
                0,
                18000,
            )
            assert (
                i2["place_of_supply_state_code"] == "27" and i2["buyer_gstin"] is None
            )
            # GSTIN state beats the zone's state code
            assert (
                i3["place_of_supply_state_code"] == "29" and i3["igst_paise"] == 18000
            )
            # the settlement shows the invoice's split
            assert st["Z3"]["igst_paise"] == 18000 and st["Z3"]["cgst_paise"] == 0

            async with SessionLocal() as s:
                rows = {
                    r.number: r
                    for r in (
                        await s.execute(
                            select(IspInvoice).where(
                                IspInvoice.isp_organization_id == isps["A"],
                                IspInvoice.bill_to_kind == "zone",
                            )
                        )
                    ).scalars()
                }
            assert set(rows) == {i1["number"], i2["number"], i3["number"]}
            r1 = rows[i1["number"]]
            assert r1.customer_organization_id is None and r1.subscriber_id is None
            assert str(r1.zone_id) == zones["Z1"] and r1.invoice_kind == "settlement"
            assert st["Z1"]["number"] in r1.description  # ZS kept for audit
            assert r1.seller_state_code == "07"

            # detail + PDF for the ISP owner -----------------------------------------
            d = await call("GET", f"/invoices/{i1['id']}")
            assert d["bill_to_kind"] == "zone" and d["customer"] is None
            assert d["isp_customer_id"] is None and d["total_paise"] == 118000
            r = await c.get(f"{api}/invoices/{i1['id']}/pdf", headers=ha)
            assert r.status_code == 200 and r.content[:4] == b"%PDF"

            # never in the invoice list / customer ledger / dues ---------------------
            listed = await call("GET", "/invoices?page_size=100")
            nums = {i["number"] for i in listed["items"]}
            assert customer_inv["number"] in nums
            assert not nums & set(rows)
            led = await call("GET", f"/billing/customers/{cust}/ledger")
            assert set(rows).isdisjoint(str(led))
            billing = await call("GET", "/billing/invoices?page_size=100")
            assert set(rows).isdisjoint(str(billing))

            # GSTR-1 placement -------------------------------------------------------
            month = today[:7]
            r = await c.get(f"{api}/gst/gstr1?month={month}&format=json", headers=ha)
            assert r.status_code == 200, r.text
            g = r.json()
            b2b = {x["Invoice Number"]: x for x in g["b2b"]}
            assert i1["number"] in b2b and i3["number"] in b2b
            assert b2b[i1["number"]]["GSTIN/UIN of Recipient"] == g07
            assert b2b[i3["number"]]["Place Of Supply"].startswith("29")
            assert i2["number"] not in b2b
            b2cs_pos = {x["Place Of Supply"] for x in g["b2cs"]}
            assert any(p.startswith("27") for p in b2cs_pos)

            # a pre-0188 settlement, invoiced later (idempotent) ----------------------
            async with SessionLocal() as s:
                old = IspZoneSettlement(
                    isp_organization_id=isps["A"],
                    zone_id=uuid.UUID(zones["Z2"]),
                    number=f"ZS/26-27/{9000 + int(tag[:2], 16)}",
                    seq=9000,
                    fy="26-27",
                    period_from=date(2026, 4, 1),
                    period_to=date(2026, 4, 30),
                    opening_paise=0,
                    debits_paise=59000,
                    credits_paise=0,
                    closing_paise=-59000,
                    billed_paise=59000,
                    taxable_paise=50000,
                    cgst_paise=4500,
                    sgst_paise=4500,
                    igst_paise=0,
                    lines=[],
                    snapshot={"zone_name": "Z2"},
                )
                s.add(old)
                await s.commit()
                old_id, old_no = old.id, old.number
            listed = await call("GET", f"/franchise/zones/{zones['Z2']}/settlements")
            assert next(x for x in listed if x["id"] == str(old_id))["invoice"] is None
            got = await call("POST", f"/franchise/settlements/{old_id}/invoice", {})
            again = await call("POST", f"/franchise/settlements/{old_id}/invoice", {})
            assert got["invoice"]["number"] == again["invoice"]["number"]
            assert got["number"] == old_no  # the ZS number is unchanged
            assert got["invoice"]["igst_paise"] == 9000  # 27 vs 07: inter-state
            async with SessionLocal() as s:
                kept = await s.get(IspZoneSettlement, old_id)
                assert kept.cgst_paise == 4500  # stored audit figures untouched
                assert kept.snapshot["invoice_number"] == got["invoice"]["number"]

            # ISP B: 404 on all of it ------------------------------------------------
            state["user"] = users["B"]
            for method, path in (
                ("GET", f"/invoices/{i1['id']}"),
                ("GET", f"/invoices/{i1['id']}/pdf"),
                ("POST", f"/franchise/settlements/{old_id}/invoice"),
            ):
                r = await c.request(method, f"{api}{path}", json={}, headers=hb)
                assert r.status_code == 404, (path, r.text)
            assert {
                i["number"] for i in (await call("GET", "/invoices", h=hb))["items"]
            }.isdisjoint(rows)
    finally:
        for k in flags:
            os.environ.pop(k, None)
        clear()
        await engine.dispose()
