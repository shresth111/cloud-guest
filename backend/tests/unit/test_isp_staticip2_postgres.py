# ruff: noqa: E501, PLR0915 -- scenario test
"""STATICIP-2 on real PostgreSQL + Redis (skipped unless ``ISP_TEST_PG_DSN``).

A subscriber lease billed for past months shows in the ledger with its
invoices; filters + CSV work; release ends the lease, removes the live
JAZE-2 binding (the IP is free again) and no further month is billed;
ISP B sees nothing and cannot release A's lease (404).
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

import pytest
from fastapi import Request

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)


async def test_staticip2_end_to_end(monkeypatch) -> None:  # noqa: ANN001
    import httpx
    from sqlalchemy import select

    from app.database.session import SessionLocal, engine
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.isp_partner import finance_config, staticip_router
    from app.domains.isp_partner.enforcement_models import IspSubscriberIpBinding
    from app.domains.isp_partner.models import IspPartnerProfile
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.organization.models import Organization, OrganizationMember
    from app.domains.rbac.dependencies import CurrentUser
    from app.domains.rbac.models import Role, UserRole
    from app.domains.rbac.repository import RBACRepository
    from app.domains.rbac.seed import seed_rbac
    from app.main import create_app

    fin = finance_config.IspFinanceSettings(
        finance_extras_enabled=True,
        zone_ledger_enabled=False,
        whatsapp_automation_enabled=False,
        telegram_alerts_enabled=False,
        pay_link_base_url="https://network-staging.wyfyguest.com",
    )
    monkeypatch.setattr(finance_config, "get_finance_settings", lambda: fin)
    flag = {"on": False}
    monkeypatch.setattr(
        staticip_router,
        "get_staticip2_settings",
        lambda: staticip_router.IspStaticIp2Settings(enabled=flag["on"]),
    )
    tag = uuid.uuid4().hex[:8]
    try:
        async with SessionLocal() as s:
            await seed_rbac(s)
            await seed_isp_partner_rbac(RBACRepository(s))
            await s.commit()
        users, isps = {}, {}
        async with SessionLocal() as s:
            plan = Plan(
                name=f"P {tag}",
                slug=f"ps2-{tag}",
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
                    slug=f"s2{n.lower()}{tag}",
                    org_type="msp",
                    status="active",
                    contact_email=f"{n}{tag}@example.com",
                    timezone="Asia/Kolkata",
                    settings={},
                )
                user = User(
                    first_name=n,
                    last_name="O",
                    email=f"s2{n}{tag}@example.com",
                    username=f"s2{n}{tag}",
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
                s.add(
                    OrganizationMember(
                        organization_id=org.id, user_id=user.id, status="active"
                    )
                )
                s.add(
                    UserRole(
                        user_id=user.id,
                        role_id=role.id,
                        scope_type="organization",
                        organization_id=org.id,
                        granted_at=datetime.now(UTC),
                        is_active=True,
                    )
                )
                users[n], isps[n] = user.id, org.id
            await s.commit()

        app = create_app()

        def _user(request: Request) -> AuthUser:
            org = request.headers.get("X-Organization-Id")
            return AuthUser(
                id=str(users["B"] if org == str(isps["B"]) else users["A"]),
                email="o@example.com",
            )

        app.dependency_overrides[CurrentUser] = _user
        ha = {"X-Organization-Id": str(isps["A"])}
        hb = {"X-Organization-Id": str(isps["B"])}
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t"
        ) as c:
            assert (
                await c.put(
                    "/api/v1/isp/billing/settings",
                    json={
                        "legal_name": "Net A",
                        "state_code": "07",
                        "gst_enabled": True,
                        "invoice_prefix": "NS2",
                    },
                    headers=ha,
                )
            ).status_code == 200
            cust = (
                await c.post(
                    "/api/v1/isp/customers",
                    json={
                        "name": f"Cafe {tag}",
                        "contact_email": f"c{tag}@example.com",
                    },
                    headers=ha,
                )
            ).json()["data"]["id"]
            loc = (
                await c.post(
                    f"/api/v1/isp/customers/{cust}/locations",
                    json={
                        "name": "Main",
                        "address_line1": "1",
                        "city": "c",
                        "state_province": "s",
                        "postal_code": "1",
                    },
                    headers=ha,
                )
            ).json()["data"]["id"]
            gid = (
                await c.post(
                    "/api/v1/isp/speed-groups",
                    json={
                        "name": "10 Mbps",
                        "download_kbps": 10240,
                        "upload_kbps": 10240,
                    },
                    headers=ha,
                )
            ).json()["data"]["id"]
            pkg = (
                await c.post(
                    "/api/v1/isp/packages",
                    json={
                        "speed_group_id": gid,
                        "type": "prepaid",
                        "price_paise": 40000,
                    },
                    headers=ha,
                )
            ).json()["data"]["id"]
            zone = (
                await c.post(
                    "/api/v1/isp/zones", json={"name": f"East {tag}"}, headers=ha
                )
            ).json()["data"]["id"]
            sub = (
                await c.post(
                    "/api/v1/isp/subscribers",
                    json={
                        "isp_customer_id": cust,
                        "identifier": f"sip{tag}",
                        "package_id": pkg,
                        "first_name": "Ravi",
                        "state_code": "07",
                        "zone_id": zone,
                    },
                    headers=ha,
                )
            ).json()["data"]

            # flag off: the whole surface is 404
            assert (
                await c.get("/api/v1/isp/static-ips/ledger", headers=ha)
            ).status_code == 404
            flag["on"] = True

            since = (date.today().replace(day=1) - timedelta(days=40)).replace(day=1)
            r = await c.post(
                "/api/v1/isp/finance/static-ip-leases",
                json={
                    "subscriber_id": sub["id"],
                    "ip_address": "203.0.113.77",
                    "monthly_amount_paise": 50000,
                    "active_since": since.isoformat(),
                },
                headers=ha,
            )
            assert r.status_code == 201, r.text
            lease = r.json()["data"]["id"]
            billed = (
                await c.post(
                    "/api/v1/isp/finance/static-ip-leases/bill", json={}, headers=ha
                )
            ).json()["data"]["invoices_issued"]
            assert billed >= 2
            async with SessionLocal() as s:
                b = IspSubscriberIpBinding(
                    isp_organization_id=isps["A"],
                    customer_organization_id=uuid.UUID(cust),
                    subscriber_id=uuid.UUID(sub["id"]),
                    location_id=uuid.UUID(loc),
                    ip="203.0.113.77",
                )
                s.add(b)
                await s.commit()
                binding_id = b.id

            led = (await c.get("/api/v1/isp/static-ips/ledger", headers=ha)).json()[
                "data"
            ]
            assert led["total"] == 1 and led["summary"] == {
                "active": 1,
                "ended": 0,
                "monthly_paise": 50000,
            }
            row = led["items"][0]
            assert (
                row["invoices"] == billed
                and row["subscriber_identifier"] == f"sip{tag}"
            )
            assert (
                row["zone_id"] == zone and row["due_paise"] == row["billed_paise"] > 0
            )
            assert (
                await c.get(
                    f"/api/v1/isp/static-ips/ledger?zone_id={uuid.uuid4()}", headers=ha
                )
            ).json()["data"]["total"] == 0
            assert (
                await c.get("/api/v1/isp/static-ips/ledger?search=113.77", headers=ha)
            ).json()["data"]["total"] == 1
            assert (
                await c.get("/api/v1/isp/static-ips/ledger?status=ended", headers=ha)
            ).json()["data"]["total"] == 0
            csv = await c.get("/api/v1/isp/static-ips/ledger/export.csv", headers=ha)
            assert (
                csv.status_code == 200
                and "203.0.113.77" in csv.text
                and csv.text.startswith("IP,Status")
            )
            invs = (
                await c.get(
                    f"/api/v1/isp/static-ips/leases/{lease}/invoices", headers=ha
                )
            ).json()["data"]
            assert invs["total"] == billed

            # isolation before release
            assert (await c.get("/api/v1/isp/static-ips/ledger", headers=hb)).json()[
                "data"
            ]["total"] == 0
            assert (
                await c.post(
                    f"/api/v1/isp/static-ips/leases/{lease}/release",
                    json={},
                    headers=hb,
                )
            ).status_code == 404
            assert (
                await c.get(
                    f"/api/v1/isp/static-ips/leases/{lease}/invoices", headers=hb
                )
            ).status_code == 404

            # release: lease ended, binding gone, IP free, no more billing
            r = await c.post(
                f"/api/v1/isp/static-ips/leases/{lease}/release",
                json={"reason": "moved"},
                headers=ha,
            )
            assert r.status_code == 200, r.text
            d = r.json()["data"]
            assert d["lease"]["status"] == "ended" and d["released_binding_ids"] == [
                str(binding_id)
            ]
            assert d["ip_back_in_pool"] is True and d["warnings"] == []
            async with SessionLocal() as s:
                assert (
                    await s.get(IspSubscriberIpBinding, binding_id)
                ).is_deleted is True
            again = (
                await c.post(
                    "/api/v1/isp/finance/static-ip-leases/bill", json={}, headers=ha
                )
            ).json()["data"]["invoices_issued"]
            assert again == 0
            r2 = await c.post(
                f"/api/v1/isp/static-ips/leases/{lease}/release", json={}, headers=ha
            )
            assert (
                r2.status_code == 200
                and r2.json()["data"]["released_binding_ids"] == []
            )
            led = (await c.get("/api/v1/isp/static-ips/ledger", headers=ha)).json()[
                "data"
            ]
            assert led["summary"]["active"] == 0 and led["summary"]["ended"] == 1
            # the same IP can be leased again now
            r = await c.post(
                "/api/v1/isp/finance/static-ip-leases",
                json={
                    "subscriber_id": sub["id"],
                    "ip_address": "203.0.113.77",
                    "monthly_amount_paise": 50000,
                },
                headers=ha,
            )
            assert r.status_code == 201, r.text
    finally:
        await engine.dispose()
        from app.database.redis import redis_client

        await redis_client.connection_pool.disconnect()
