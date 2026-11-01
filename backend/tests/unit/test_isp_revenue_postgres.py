# ruff: noqa: E501, PLR0915, PLR0912 -- scenario test
"""REVENUE-HUB + CHURN-RISK on real PostgreSQL + Redis (skipped unless
``ISP_TEST_PG_DSN``). Run::

    CLOUDGUEST_DATABASE_URL=postgresql+asyncpg://postgres@localhost:55471/rev \\
    CLOUDGUEST_REDIS_URL=redis://localhost:56391/1 \\
    ISP_TEST_PG_DSN=1 ISP_PARTNER_ENABLED=true \\
    python -m pytest tests/unit/test_isp_revenue_postgres.py

Flags are switched by the test (env + cache_clear): ISP_REVENUE_HUB_ENABLED,
ISP_APPS_ENABLED (tickets), ISP_ZONES_ENABLED (scope_zone_id) and
ISP_ZONE_LEDGER_ENABLED (wallet balances).

One ISP (GST 18 %, intra-state), customers C1 (no zone) and C2 (zone Z2),
packages P1 (Rs 500 / 30 days) and P2 (Rs 1,200 / 90 days), six subscribers:
s1 active (Z1, two overdue invoices + an open ticket), s2 active (Z2, 360
override Rs 900, paid renewal, an FUP throttle, created 30 days ago and never
online), s3 expired 10 days ago (C2 -> Z2), s4 churned (expired 100 days ago),
s5 blocked (Z1), s6 active with no package (expires in 3 days, never paid).

Checks every KPI against hand-computed numbers, that each tile's list total is
the tile, the hub filters, ZONE-1 scope_zone_id, a confined billing user, the
viewer (aggregates yes, lists 403, no names in the aggregate body), ISP B (0
and 404 on A's zone/package), flag off (404 everywhere) and the churn-risk
reasons, order, scores and counts.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from zoneinfo import ZoneInfo

import pytest
from fastapi import Request

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)

_TZ = ZoneInfo("Asia/Kolkata")


def _clear() -> None:
    from app.domains.isp_partner.apps_common import get_isp_apps_settings
    from app.domains.isp_partner.finance_config import get_finance_settings
    from app.domains.isp_partner.revenue_router import get_revenue_settings
    from app.domains.isp_partner.zones_config import get_zones_settings

    for fn in (
        get_isp_apps_settings,
        get_finance_settings,
        get_revenue_settings,
        get_zones_settings,
    ):
        fn.cache_clear()


async def test_revenue_hub_and_churn_risk(monkeypatch) -> None:  # noqa: ANN001, C901
    import httpx
    from sqlalchemy import select, update

    from app.database.session import SessionLocal, engine
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.isp_partner.billing_models import IspInvoice
    from app.domains.isp_partner.enforcement_models import IspEnforcementEvent
    from app.domains.isp_partner.finance_models import IspZoneLedgerEntry
    from app.domains.isp_partner.models import (
        IspCustomerProfile,
        IspPartnerProfile,
        IspStaffCustomerScope,
    )
    from app.domains.isp_partner.plans_models import IspSubscriber
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.organization.models import Organization, OrganizationMember
    from app.domains.rbac.dependencies import CurrentUser
    from app.domains.rbac.models import Role, UserRole
    from app.domains.rbac.repository import RBACRepository
    from app.domains.rbac.seed import seed_rbac
    from app.main import create_app

    for k in ("ISP_APPS_ENABLED", "ISP_ZONES_ENABLED", "ISP_ZONE_LEDGER_ENABLED"):
        monkeypatch.setenv(k, "true")
    monkeypatch.setenv("ISP_REVENUE_HUB_ENABLED", "false")
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
                slug=f"prv-{tag}",
                plan_type="standard",
                billing_cycle="monthly",
                base_price=Decimal("0"),
                currency="INR",
                is_active=True,
                is_public=False,
            )
            s.add(plan)
            for isp_key, role_names in (
                ("A", ("owner", "billing", "viewer")),
                ("B", ("owner",)),
            ):
                org = Organization(
                    name=f"Net {isp_key} {tag}",
                    slug=f"rv{isp_key.lower()}{tag}",
                    org_type="msp",
                    status="active",
                    contact_email=f"rv{isp_key}{tag}@example.com",
                    timezone="Asia/Kolkata",
                    settings={},
                )
                s.add(org)
                await s.flush()
                s.add(
                    IspPartnerProfile(
                        organization_id=org.id, default_customer_plan_id=plan.id
                    )
                )
                orgs[isp_key] = org.id
                for name in role_names:
                    role = (
                        await s.execute(select(Role).where(Role.slug == f"isp-{name}"))
                    ).scalar_one()
                    u = User(
                        first_name=name,
                        last_name="R",
                        email=f"rv{isp_key}{name}{tag}@example.com",
                        username=f"rv{isp_key}{name}{tag}",
                        password_hash="x",
                        is_active=True,
                        is_verified=True,
                    )
                    s.add(u)
                    await s.flush()
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
                    users[f"{isp_key}{name}"] = u.id
            await s.commit()

        app = create_app()
        state = {"user": users["Aowner"]}

        def _user(request: Request) -> AuthUser:  # noqa: ARG001
            return AuthUser(id=str(state["user"]), email="o@example.com")

        app.dependency_overrides[CurrentUser] = _user
        h = {"X-Organization-Id": str(orgs["A"])}
        hb = {"X-Organization-Id": str(orgs["B"])}
        now = datetime.now(UTC)
        today = now.astimezone(_TZ).date()

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t"
        ) as c:

            async def post(path: str, body: dict, code: int = 201) -> dict:
                r = await c.post(f"/api/v1/isp{path}", json=body, headers=h)
                assert r.status_code == code, (path, r.text)
                return r.json()["data"]

            r = await c.put(
                "/api/v1/isp/billing/settings",
                json={
                    "legal_name": "Net A",
                    "state_code": "07",
                    "gst_enabled": True,
                    "invoice_prefix": "RV",
                },
                headers=h,
            )
            assert r.status_code == 200, r.text
            z1 = (await post("/zones", {"name": f"Z1 {tag}"}))["id"]
            z2 = (await post("/zones", {"name": f"Z2 {tag}"}))["id"]
            c1 = (
                await post(
                    "/customers",
                    {"name": f"C1 {tag}", "contact_email": f"c1{tag}@example.com"},
                )
            )["id"]
            c2 = (
                await post(
                    "/customers",
                    {"name": f"C2 {tag}", "contact_email": f"c2{tag}@example.com"},
                )
            )["id"]
            gid = (
                await post(
                    "/speed-groups",
                    {"name": "20M", "download_kbps": 20480, "upload_kbps": 20480},
                )
            )["id"]
            p1 = (
                await post(
                    "/packages",
                    {
                        "speed_group_id": gid,
                        "type": "prepaid",
                        "validity_days": 30,
                        "price_paise": 50000,
                        "price_includes_gst": False,
                    },
                )
            )["id"]
            p2 = (
                await post(
                    "/packages",
                    {
                        "speed_group_id": gid,
                        "type": "prepaid",
                        "validity_days": 90,
                        "price_paise": 120000,
                        "price_includes_gst": False,
                    },
                )
            )["id"]

            async def sub(n: int, cust: str, pkg: str | None, zone: str | None) -> str:
                body = {
                    "isp_customer_id": cust,
                    "identifier": f"rv{n}{tag}",
                    "first_name": f"Rv{n}{tag}",
                    "state_code": "07",
                    "phone": f"98100{n:05d}",
                }
                if pkg:
                    body["package_id"] = pkg
                if zone:
                    body["zone_id"] = zone
                return (await post("/subscribers", body))["id"]

            s1 = await sub(1, c1, p1, z1)
            s2 = await sub(2, c1, p2, z2)
            s3 = await sub(3, c2, p1, None)
            s4 = await sub(4, c2, p1, None)
            s5 = await sub(5, c1, p1, z1)
            s6 = await sub(6, c1, p1, None)  # package removed below (no package)
            # s2 renews at its override price (360), paid; s1 recharged twice, unpaid
            await c.put(
                f"/api/v1/isp/subscribers/{s2}/profile",
                json={"override_price_paise": 90000},
                headers=h,
            )
            inv3 = (
                await post(
                    f"/subscribers/{s2}/renew",
                    {"paid_now": True, "payment": {"mode": "cash"}},
                )
            )["invoice"]
            inv1 = (await post(f"/subscribers/{s1}/recharge", {"package_id": p1}))[
                "invoice"
            ]
            inv2 = (await post(f"/subscribers/{s1}/recharge", {"package_id": p1}))[
                "invoice"
            ]
            assert inv3["total_paise"] == 106200 and inv3["balance_paise"] == 0, inv3
            await post(
                f"/subscribers/{s5}/block",
                {"kind": "temporary", "reason": "test block"},
                200,
            )
            await post(
                "/apps/tickets",
                {"isp_customer_id": c1, "subscriber_id": s1, "subject": "Slow speed"},
            )

        async with SessionLocal() as s:
            await s.execute(
                update(IspCustomerProfile)
                .where(IspCustomerProfile.customer_organization_id == uuid.UUID(c2))
                .values(zone_id=uuid.UUID(z2))
            )
            await s.execute(
                update(IspInvoice)
                .where(IspInvoice.id == uuid.UUID(inv1["id"]))
                .values(due_date=today - timedelta(days=45))
            )
            await s.execute(
                update(IspInvoice)
                .where(IspInvoice.id == uuid.UUID(inv2["id"]))
                .values(due_date=today - timedelta(days=5))
            )
            await s.execute(
                update(IspSubscriber)
                .where(IspSubscriber.id == uuid.UUID(s3))
                .values(valid_until=now - timedelta(days=10), status="expired")
            )
            await s.execute(
                update(IspSubscriber)
                .where(IspSubscriber.id == uuid.UUID(s4))
                .values(
                    valid_until=now - timedelta(days=100),
                    status="expired",
                    created_at=now - timedelta(days=200),
                )
            )
            await s.execute(
                update(IspSubscriber)
                .where(IspSubscriber.id == uuid.UUID(s2))
                .values(created_at=now - timedelta(days=30))
            )
            await s.execute(
                update(IspSubscriber)
                .where(IspSubscriber.id == uuid.UUID(s6))
                .values(
                    valid_until=now + timedelta(days=3),
                    status="active",
                    package_id=None,
                )
            )
            s.add(
                IspEnforcementEvent(
                    isp_organization_id=orgs["A"],
                    subscriber_id=uuid.UUID(s2),
                    kind="fup_throttle",
                    detail="test",
                    occurred_at=now - timedelta(days=2),
                )
            )
            s.add(
                IspZoneLedgerEntry(
                    isp_organization_id=orgs["A"],
                    zone_id=uuid.UUID(z1),
                    entry_kind="add",
                    amount_paise=10000,
                    balance_after_paise=10000,
                    occurred_at=now,
                )
            )
            s.add(
                IspStaffCustomerScope(
                    isp_organization_id=orgs["A"],
                    user_id=users["Abilling"],
                    customer_organization_id=uuid.UUID(c2),
                )
            )
            await s.commit()

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t"
        ) as c:

            async def get(
                path: str,
                params: dict | None = None,
                headers: dict | None = None,
                code: int = 200,
            ) -> dict:
                r = await c.get(
                    f"/api/v1/isp{path}", params=params or {}, headers=headers or h
                )
                assert r.status_code == code, (path, params, r.status_code, r.text)
                return r.json().get("data") if code == 200 else r.json()

            routes = (
                "/revenue/probe",
                "/revenue/summary",
                "/revenue/list?metric=active",
                "/revenue/churn-risk",
                "/revenue/churn-risk/summary",
            )
            # ---- flag off: every route 404
            for p in routes:
                body = await get(p, code=404)
                assert "ISP_REVENUE_HUB_DISABLED" in str(body), body
            monkeypatch.setenv("ISP_REVENUE_HUB_ENABLED", "true")
            _clear()
            assert (await get("/revenue/probe"))["enabled"] is True

            # ---- owner: every KPI
            d = await get("/revenue/summary")
            k = d["kpis"]
            assert (
                k["active"],
                k["expired"],
                k["churned"],
                k["other"],
                k["total"],
            ) == (3, 1, 1, 1, 6), k
            assert (
                k["mrr_paise"] == 80000
                and k["unpriced"] == 1
                and k["arpu_paise"] == 26666
            ), k
            assert k["billed_paise"] == 190000 and k["net_billed_paise"] == 224200, k
            assert k["collected_paise"] == 106200 and k["collection_rate"] == round(
                106200 / 224200, 4
            ), k
            assert k["new"] == 4 and k["dues_paise"] == 118000, k
            ag = d["ageing"]
            assert ag["d31_60"] == {"invoices": 1, "amount_paise": 59000}, ag
            assert ag["d0_30"] == {"invoices": 1, "amount_paise": 59000}, ag
            assert sum(v["amount_paise"] for v in ag.values()) == k["dues_paise"]
            lost_month = (now - timedelta(days=40)).astimezone(_TZ).date()
            lm = f"{lost_month.year:04d}-{lost_month.month:02d}"
            (row,) = [t for t in d["trend"] if t["month"] == lm]
            assert (row["lost"], row["base_at_start"], row["churn_rate"]) == (
                1,
                1,
                1.0,
            ), row
            assert sum(t["lost"] for t in d["trend"]) == 1
            zones = {z["zone_id"]: z for z in d["zones"]}
            assert [z["zone_id"] for z in d["zones"]] == [z1, z2, None], d["zones"]
            assert (
                zones[z1]["active"],
                zones[z1]["mrr_paise"],
                zones[z1]["billed_paise"],
                zones[z1]["dues_paise"],
            ) == (1, 50000, 100000, 118000)
            assert (
                zones[z2]["active"],
                zones[z2]["churned"],
                zones[z2]["mrr_paise"],
                zones[z2]["collected_paise"],
            ) == (1, 1, 30000, 106200)
            assert (
                zones[z2]["collection_rate"] == 1.0
                and zones[z1]["collection_rate"] == 0.0
            )
            assert (
                zones[z1]["wallet_balance_paise"] == 10000
                and zones[z2]["wallet_balance_paise"] == 0
            )
            assert zones[None]["active"] == 1 and zones[None]["mrr_paise"] == 0
            pk = {p["package_id"]: p for p in d["packages"]}
            assert (
                pk[p1]["mrr_paise"] == 50000
                and pk[p2]["mrr_paise"] == 30000
                and pk[None]["unpriced"] == 1
            )
            assert pk[p1]["mrr_share"] == 0.625

            # ---- every tile opens exactly its list
            month = f"{today.year:04d}-{today.month:02d}"
            tiles = {
                "active": k["active"],
                "expired": k["expired"],
                "churned": k["churned"],
                "other": k["other"],
                "unpriced": k["unpriced"],
                "new": k["new"],
                "dues_d31_60": 1,
                "dues_d0_30": 1,
                "dues_not_due": ag["not_due"]["invoices"],
                "dues_d61_90": 0,
                "dues_d90_plus": 0,
                "uncollected": 2,
            }
            for metric, n in tiles.items():
                lst = await get("/revenue/list", {"metric": metric, "month": month})
                assert lst["total"] == n, (metric, lst["total"], n)
            lost = await get("/revenue/list", {"metric": "lost", "month": lm})
            assert lost["total"] == 1 and lost["items"][0]["id"] == s4
            act = await get("/revenue/list", {"metric": "active"})
            assert [i["id"] for i in act["items"]] == [
                s1,
                s2,
                s6,
            ]  # by MRR, highest first
            assert (
                act["items"][1]["mrr_paise"] == 30000
                and act["items"][0]["zone_name"] == f"Z1 {tag}"
            )
            dues = await get("/revenue/list", {"metric": "dues_d31_60"})
            assert (
                dues["kind"] == "invoices"
                and dues["items"][0]["number"] == inv1["number"]
            )
            assert dues["items"][0]["days_past_due"] == 45

            # ---- hub filters
            k1 = (await get("/revenue/summary", {"zone_id": z1}))["kpis"]
            assert (k1["active"], k1["mrr_paise"], k1["billed_paise"], k1["other"]) == (
                1,
                50000,
                100000,
                1,
            ), k1
            kn = (await get("/revenue/summary", {"no_zone": "true"}))["kpis"]
            assert (kn["active"], kn["mrr_paise"], kn["total"]) == (1, 0, 1), kn
            kp = (await get("/revenue/summary", {"package_id": p2}))["kpis"]
            assert (kp["active"], kp["billed_paise"], kp["total"]) == (1, 90000, 1), kp
            assert (await get("/revenue/list", {"metric": "active", "zone_id": z1}))[
                "total"
            ] == 1
            await get("/revenue/summary", {"zone_id": z1, "no_zone": "true"}, code=422)
            await get("/revenue/summary", {"month": "2099-01"}, code=422)

            # ---- ZONE-1 scope_zone_id narrows everything (ORM criteria on aggregates too)
            kz = (await get("/revenue/summary", {"scope_zone_id": z2}))["kpis"]
            assert (
                kz["active"],
                kz["expired"],
                kz["churned"],
                kz["mrr_paise"],
                kz["billed_paise"],
            ) == (1, 1, 1, 30000, 90000), kz
            assert (
                await get("/revenue/list", {"metric": "active", "scope_zone_id": z2})
            )["total"] == 1

            # ---- churn risk (owner)
            cr = await get("/revenue/churn-risk")
            ids = [i["id"] for i in cr["items"]]
            assert ids == [s1, s3, s6, s2], [
                (i["id"], i["score"], [x["code"] for x in i["reasons"]])
                for i in cr["items"]
            ]
            reasons = {
                i["id"]: sorted(x["code"] for x in i["reasons"]) for i in cr["items"]
            }
            assert reasons == {
                s1: ["late_payments", "tickets"],
                s3: ["expired_recently"],
                s6: ["expiring_no_payment"],
                s2: ["fup_hits", "long_offline"],
            }, reasons
            assert [i["score"] for i in cr["items"]] == [45, 40, 30, 25]
            assert all(x["detail"] for i in cr["items"] for x in i["reasons"])
            assert cr["items"][0]["open_invoice"]["id"] == inv2["id"]
            assert cr["tickets_measured"] is True
            cs = await get("/revenue/churn-risk/summary")
            assert cs["at_risk"] == 4 and cs["mrr_at_risk_paise"] == 80000, cs
            assert all(v == 1 for v in cs["by_reason"].values()), cs
            for code, n in cs["by_reason"].items():
                assert (await get("/revenue/churn-risk", {"reason": code}))[
                    "total"
                ] == n

            # ---- confined billing user (C2 only)
            state["user"] = users["Abilling"]
            kc = (await get("/revenue/summary"))["kpis"]
            assert (
                kc["active"],
                kc["expired"],
                kc["churned"],
                kc["mrr_paise"],
                kc["billed_paise"],
                kc["total"],
            ) == (0, 1, 1, 0, 0, 2), kc
            zc = (await get("/revenue/summary"))["zones"]
            assert all(z["wallet_balance_paise"] is None for z in zc), zc
            assert [i["id"] for i in (await get("/revenue/churn-risk"))["items"]] == [
                s3
            ]
            assert (await get("/revenue/list", {"metric": "active"}))["total"] == 0

            # ---- viewer: aggregates only, no names, lists 403
            state["user"] = users["Aviewer"]
            r = await c.get("/api/v1/isp/revenue/summary", headers=h)
            assert (
                r.status_code == 200
                and f"rv1{tag}" not in r.text
                and f"Rv1{tag}" not in r.text
                and "98100" not in r.text
            )
            assert (
                await c.get("/api/v1/isp/revenue/churn-risk/summary", headers=h)
            ).status_code == 200
            assert (
                await c.get("/api/v1/isp/revenue/list?metric=active", headers=h)
            ).status_code == 403
            assert (
                await c.get("/api/v1/isp/revenue/churn-risk", headers=h)
            ).status_code == 403

            # ---- ISP B sees nothing of A
            state["user"] = users["Bowner"]
            kb = (await get("/revenue/summary", headers=hb))["kpis"]
            assert (
                kb["total"] == 0 and kb["billed_paise"] == 0 and kb["dues_paise"] == 0
            )
            await get("/revenue/summary", {"zone_id": z1}, headers=hb, code=404)
            await get("/revenue/summary", {"package_id": p1}, headers=hb, code=404)
            await get(
                "/revenue/list",
                {"metric": "active", "zone_id": z1},
                headers=hb,
                code=404,
            )
            assert (await get("/revenue/churn-risk", headers=hb))["total"] == 0
            # A's zone in scope_zone_id from B -> ZONE-1 404
            await get("/revenue/summary", {"scope_zone_id": z1}, headers=hb, code=404)
            _ = (s5, date)
    finally:
        _clear()
        await engine.dispose()
        from app.database.redis import redis_client

        await redis_client.connection_pool.disconnect()
