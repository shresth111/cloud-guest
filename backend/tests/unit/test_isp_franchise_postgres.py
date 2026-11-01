"""FRANCHISE-2 on real PostgreSQL + Redis (skipped unless ``ISP_TEST_PG_DSN``
is set; CI has neither). Fresh scratch DB at head. Real JAZE-1 renew/revert
and JAZE-4 ledger.

Covers: no plan = no debit; percent and wholesale debits; idempotent per
invoice; revert reverses; below the credit limit never blocks with the
enforce flag off, and blocks (rolled back, 409) with it on; auto-debit flag
off; revenue drill-down; recurring charges once per month; settlements
(numbering, GST split, PDF); min-balance state; another ISP 404; flag off.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from decimal import Decimal

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)


async def test_franchise_end_to_end() -> None:  # noqa: PLR0915
    import httpx
    from sqlalchemy import func, select

    from app.database.session import SessionLocal, engine
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.isp_partner.billing_models import IspInvoice
    from app.domains.isp_partner.finance_config import get_finance_settings
    from app.domains.isp_partner.franchise_models import (
        IspZoneAutoDebit,
        IspZoneSharePlan,
    )
    from app.domains.isp_partner.franchise_service import get_franchise_settings
    from app.domains.isp_partner.models import IspPartnerProfile
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.isp_partner.zones_config import get_zones_settings

    def clear() -> None:
        get_franchise_settings.cache_clear()
        get_finance_settings.cache_clear()

    from app.domains.organization.models import Organization, OrganizationMember
    from app.domains.rbac.dependencies import CurrentUser
    from app.domains.rbac.models import Role, UserRole
    from app.domains.rbac.repository import RBACRepository
    from app.domains.rbac.seed import seed_rbac
    from app.main import create_app

    tag = uuid.uuid4().hex[:8]
    os.environ.pop("ISP_ZONES_ENABLED", None)
    get_zones_settings.cache_clear()
    try:
        async with SessionLocal() as s:
            await seed_rbac(s)
            await seed_isp_partner_rbac(RBACRepository(s))
            await s.commit()
        users, isps = {}, {}
        async with SessionLocal() as s:
            plan = Plan(
                name=f"P {tag}",
                slug=f"z1-{tag}",
                plan_type="standard",
                billing_cycle="monthly",
                base_price=Decimal("0"),
                currency="INR",
                is_active=True,
                is_public=False,
            )
            s.add(plan)
            roles = {
                r.slug: r
                for r in (
                    await s.execute(
                        select(Role).where(
                            Role.slug.in_(("isp-owner", "isp-technician"))
                        )
                    )
                ).scalars()
            }

            def person(n: str) -> User:
                return User(
                    first_name=n,
                    last_name="Z",
                    email=f"z1{n.lower()}{tag}@example.com",
                    username=f"z1{n.lower()}{tag}",
                    password_hash="x",
                    is_active=True,
                    is_verified=True,
                )

            def grant(user: User, org: Organization, slug: str) -> list:
                return [
                    OrganizationMember(
                        organization_id=org.id, user_id=user.id, status="active"
                    ),
                    UserRole(
                        user_id=user.id,
                        role_id=roles[slug].id,
                        scope_type="organization",
                        organization_id=org.id,
                        granted_at=datetime.now(UTC),
                        is_active=True,
                    ),
                ]

            for n in ("A", "B"):
                org = Organization(
                    name=f"Zn {n} {tag}",
                    slug=f"z1net{n.lower()}{tag}",
                    org_type="msp",
                    status="active",
                    contact_email=f"z{n}{tag}@example.com",
                    timezone="Asia/Kolkata",
                    settings={},
                )
                user = person(n)
                s.add_all([org, user])
                await s.flush()
                s.add(
                    IspPartnerProfile(
                        organization_id=org.id, default_customer_plan_id=plan.id
                    )
                )
                s.add_all(grant(user, org, "isp-owner"))
                users[n], isps[n] = user.id, org.id
                if n == "A":
                    tech = person("Tech")
                    s.add(tech)
                    await s.flush()
                    s.add_all(grant(tech, org, "isp-technician"))
                    users["T"] = tech.id
            await s.commit()

        app = create_app()
        state = {"user": users["A"]}
        app.dependency_overrides[CurrentUser] = lambda: AuthUser(
            id=str(state["user"]), email="o@example.com"
        )
        ha = {"X-Organization-Id": str(isps["A"])}
        hb = {"X-Organization-Id": str(isps["B"])}
        api = "/api/v1/isp"

        def as_(who: str) -> None:
            state["user"] = users[who]

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t"
        ) as c:

            async def call(method: str, path: str, body=None, h=ha, ok=(200, 201)):  # noqa: ANN001, ANN202
                r = await c.request(method, f"{api}{path}", json=body, headers=h)
                assert r.status_code in ok, (method, path, r.status_code, r.text)
                return r.json().get("data")

            async def ids(path: str, h=ha) -> set[str]:  # noqa: ANN001
                data = await call("GET", path, h=h)
                items = data["items"] if isinstance(data, dict) else data
                return {i["id"] for i in items}

            # setup --------------------
            flags = (
                "ISP_FRANCHISE_ENABLED",
                "ISP_ZONE_AUTODEBIT_ENABLED",
                "ISP_ZONE_LEDGER_ENABLED",
            )
            for k in flags:
                os.environ[k] = "true"
            os.environ.pop("ISP_ZONE_ENFORCE_CREDIT", None)
            clear()
            await call(
                "PUT",
                "/billing/settings",
                {
                    "legal_name": "Net A Pvt Ltd",
                    "state_code": "07",
                    "gst_enabled": True,
                    "invoice_prefix": "FRA",
                },
            )
            z1 = (
                await call("POST", "/zones", {"name": f"Z1 {tag}", "state_code": "07"})
            )["id"]
            z2 = (await call("POST", "/zones", {"name": f"Z2 {tag}"}))["id"]
            await call(
                "PUT",
                f"/finance/zones/{z1}/profile",
                {"revenue_share_bp": 3000, "min_balance_paise": 20000},
            )
            await call(
                "POST",
                f"/finance/zones/{z1}/entries",
                {
                    "entry_kind": "add",
                    "amount_paise": 50000,
                    "mode": "upi",
                    "reference": "UTR1",
                },
            )
            c1 = (
                await call(
                    "POST",
                    "/customers",
                    {"name": f"c1 {tag}", "contact_email": f"c1{tag}@e.com"},
                )
            )["id"]
            g = (
                await call(
                    "POST",
                    "/speed-groups",
                    {"name": "20M", "download_kbps": 20480, "upload_kbps": 20480},
                )
            )["id"]
            pkg = (
                await call(
                    "POST",
                    "/packages",
                    {"speed_group_id": g, "type": "prepaid", "price_paise": 50000},
                )
            )["id"]

            async def subscriber(ident: str, zone: str) -> str:
                sid = (
                    await call(
                        "POST",
                        "/subscribers",
                        {"isp_customer_id": c1, "identifier": ident, "package_id": pkg},
                    )
                )["id"]
                await call("PATCH", f"/subscribers/{sid}", {"zone_id": zone})
                return sid

            s1 = await subscriber(f"a{tag}", z1)
            s2 = await subscriber(f"b{tag}", z2)

            async def wallet(zone: str) -> dict:
                items = (await call("GET", "/franchise/zones"))["items"]
                return next(i for i in items if i["zone_id"] == zone)

            async def renew(sid: str, key: str, ok=(201,)):  # noqa: ANN001, ANN202
                r = await c.post(
                    f"{api}/subscribers/{sid}/renew",
                    json={"idempotency_key": key},
                    headers=ha,
                )
                assert r.status_code in ok, r.text
                return r.json()["data"]

            async def autodebits(zone: str) -> list:
                async with SessionLocal() as s:
                    return list(
                        (
                            await s.execute(
                                select(IspZoneAutoDebit)
                                .where(IspZoneAutoDebit.zone_id == uuid.UUID(zone))
                                .order_by(IspZoneAutoDebit.created_at)
                            )
                        ).scalars()
                    )

            # no share plan -> never debited --------------------------------------
            await renew(s1, f"k0-{tag}")
            assert (await wallet(z1))["balance_paise"] == 50000
            assert await autodebits(z1) == []

            # percent plan: ISP keeps 70 % --------------------
            await call("PUT", f"/franchise/zones/{z1}/share", {"mode": "percent"})
            inv = (await renew(s1, f"k1-{tag}"))["invoice"]
            debit = inv["total_paise"] * 7000 // 10000
            w = await wallet(z1)
            assert w["balance_paise"] == 50000 - debit
            assert w["auto_debited_paise"] == debit
            # the same request again: same invoice, no second debit
            again = (await renew(s1, f"k1-{tag}"))["invoice"]
            assert again["id"] == inv["id"]
            assert len(await autodebits(z1)) == 1
            led = await call("GET", f"/finance/zones/{z1}")
            assert led["entries"][0]["reference"] == inv["number"]
            assert led["entries"][0]["amount_paise"] == -debit

            # revert -> credit note -> reversal ------------------------------------
            r = await c.post(
                f"{api}/subscribers/{s1}/revert", json={"reason": "wrong"}, headers=ha
            )
            assert r.status_code == 200, r.text
            w = await wallet(z1)
            assert w["balance_paise"] == 50000 and w["auto_reversed_paise"] == debit
            kinds = [a.kind for a in await autodebits(z1)]
            assert kinds == ["debit", "reversal"]

            # wholesale plan --------------------
            await call(
                "PUT",
                f"/franchise/zones/{z1}/share",
                {"mode": "wholesale", "wholesale_paise": 10000},
            )
            await renew(s1, f"k2-{tag}")
            assert (await wallet(z1))["balance_paise"] == 40000

            # a big wholesale debit goes below the credit limit: never blocks -----
            await call(
                "PUT",
                f"/franchise/zones/{z1}/share",
                {"mode": "wholesale", "wholesale_paise": 100000},
            )
            await renew(s1, f"k3-{tag}")
            w = await wallet(z1)
            assert w["balance_paise"] == -60000
            assert w["standing"] == "unpaid" and w["below_minimum"] is True

            # enforce on: the renewal is refused, nothing is written ---------------
            os.environ["ISP_ZONE_ENFORCE_CREDIT"] = "true"
            clear()
            before = len(await autodebits(z1))
            r = await c.post(
                f"{api}/subscribers/{s1}/renew",
                json={"idempotency_key": f"k4-{tag}"},
                headers=ha,
            )
            assert r.status_code == 409, r.text
            assert r.json()["data"]["code"] == "ISP_ZONE_CREDIT_EXCEEDED"
            assert len(await autodebits(z1)) == before
            async with SessionLocal() as s:
                n = (
                    await s.execute(
                        select(func.count()).where(
                            IspInvoice.subscriber_id == uuid.UUID(s1),
                            IspInvoice.doc_type == "invoice",
                        )
                    )
                ).scalar_one()
            assert n == 4  # k0, k1, k2, k3 -- k4 was rolled back
            os.environ.pop("ISP_ZONE_ENFORCE_CREDIT")
            clear()

            # auto-debit flag off: no debit -------------------------------------------
            os.environ.pop("ISP_ZONE_AUTODEBIT_ENABLED")
            clear()
            await renew(s1, f"k5-{tag}")
            assert (await wallet(z1))["balance_paise"] == -60000
            os.environ["ISP_ZONE_AUTODEBIT_ENABLED"] = "true"
            clear()

            # zone without a plan stays untouched --------------------
            await renew(s2, f"m1-{tag}")
            assert await autodebits(z2) == []

            # revenue drill-down -------------------------------------------------------
            from datetime import date as _d

            today = _d.today().isoformat()
            rev = await call(
                "GET",
                f"/franchise/zones/{z1}/revenue?date_from={today}&date_to={today}",
            )
            assert rev["mode"] == "wholesale" and rev["revenue_share_bp"] == 3000
            nums = [i["number"] for i in rev["items"]]
            # the reverted invoice was cancelled by the revert: not revenue
            assert inv["number"] not in nums and len(rev["items"]) == 4
            assert rev["totals"]["auto_net_paise"] == 110000

            # recurring charges --------------------
            ch = await call(
                "POST",
                f"/franchise/zones/{z1}/charges",
                {
                    "name": "Pole rent",
                    "amount_paise": 5000,
                    "day_of_month": 1,
                    "starts_on": "2026-01-01",
                },
            )
            out = await call("POST", "/franchise/charges/run", {})
            assert out["charges"] == 1
            assert (await call("POST", "/franchise/charges/run", {}))["charges"] == 0
            assert (await wallet(z1))["balance_paise"] == -65000
            await call("PATCH", f"/franchise/charges/{ch['id']}", {"active": False})

            # settlement --------------------
            st = await call(
                "POST",
                f"/franchise/zones/{z1}/settlements",
                {"date_from": today, "date_to": today},
            )
            assert st["number"].startswith("ZS/")
            assert st["billed_paise"] == 110000 + 5000
            assert st["opening_paise"] == 0 and st["closing_paise"] == -65000
            assert st["cgst_paise"] + st["sgst_paise"] + st["taxable_paise"] == 115000
            assert st["igst_paise"] == 0  # same state
            r = await c.get(f"{api}/franchise/settlements/{st['id']}/pdf", headers=ha)
            assert r.status_code == 200 and r.content[:4] == b"%PDF"
            st2 = await call(
                "POST",
                f"/franchise/zones/{z1}/settlements",
                {"date_from": today, "date_to": today},
            )
            assert st2["number"] != st["number"]

            # min-balance alert bookkeeping (Telegram not configured: none sent) --
            async with SessionLocal() as s:
                plan = (
                    await s.execute(
                        select(IspZoneSharePlan).where(
                            IspZoneSharePlan.zone_id == uuid.UUID(z1)
                        )
                    )
                ).scalar_one()
            assert plan.below_min_since is not None and plan.alerted_at is None

            # another ISP sees none of it --------------------
            as_("B")
            for method, path in (
                ("PUT", f"/franchise/zones/{z1}/share"),
                (
                    "GET",
                    f"/franchise/zones/{z1}/revenue?date_from={today}&date_to={today}",
                ),
                ("GET", f"/franchise/settlements/{st['id']}/pdf"),
            ):
                r = await c.request(
                    method, f"{api}{path}", json={"mode": "percent"}, headers=hb
                )
                assert r.status_code == 404, (path, r.text)
            assert (await call("GET", "/franchise/zones", h=hb))["items"] == []
            as_("A")

            # flag off -> 404 --------------------
            os.environ.pop("ISP_FRANCHISE_ENABLED")
            clear()
            r = await c.get(f"{api}/franchise/zones", headers=ha)
            assert r.status_code == 404
    finally:
        for k in (
            "ISP_FRANCHISE_ENABLED",
            "ISP_ZONE_AUTODEBIT_ENABLED",
            "ISP_ZONE_LEDGER_ENABLED",
            "ISP_ZONE_ENFORCE_CREDIT",
        ):
            os.environ.pop(k, None)
        clear()
        await engine.dispose()
