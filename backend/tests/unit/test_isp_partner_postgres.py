# ruff: noqa: E501 -- snapshot strings and SQL are kept verbatim
"""End-to-end on a real PostgreSQL + Redis (skipped unless
``ISP_TEST_PG_DSN`` is set -- CI has neither). Run locally against a scratch
database migrated to head::

    CLOUDGUEST_DATABASE_URL=postgresql+asyncpg://postgres@localhost:55432/ispmig \\
    CLOUDGUEST_REDIS_URL=redis://localhost:56379/0 \\
    ISP_TEST_PG_DSN=1 ISP_PARTNER_ENABLED=true TR069_ENABLED=true \\
    python -m pytest tests/unit/test_isp_partner_postgres.py

Covers what fakes cannot: the RBAC seed on real rows (pre-existing grants
identical), users/members/user_roles counts unchanged across customer and
location creation, the child's subscription passing the licence gate, the
default portal config, report numbers against hand-written SQL, a fresh ISP
reporting zeros, TR-069 sync assignment rules, and NetLogs partition pruning.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)


async def _scalar(session, sql, **params):
    from sqlalchemy import text

    return (await session.execute(text(sql), params)).scalar()


async def _grants(session, *, isp: bool):
    from sqlalchemy import text

    op = "LIKE" if isp else "NOT LIKE"
    rows = await session.execute(
        text(
            f"""select r.slug, p.key from role_permissions rp
            join roles r on r.id = rp.role_id join permissions p on p.id = rp.permission_id
            where rp.is_deleted = false and r.slug {op} 'isp-%' order by 1, 2"""
        )
    )
    return [tuple(r) for r in rows.all()]


async def test_isp_partner_end_to_end() -> None:  # noqa: PLR0915 -- one scenario
    import httpx
    from fastapi import Depends, FastAPI

    from app.database.session import SessionLocal, engine
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.dependencies import RequireActiveLicenseForWrites
    from app.domains.billing.models import Plan
    from app.domains.guest.models import Guest, GuestSession
    from app.domains.isp_partner.models import IspPartnerProfile
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.organization.models import Organization, OrganizationMember
    from app.domains.rbac.dependencies import CurrentUser
    from app.domains.rbac.models import Role, UserRole
    from app.domains.rbac.repository import RBACRepository
    from app.domains.rbac.seed import seed_rbac
    from app.main import create_app

    tag = uuid.uuid4().hex[:8]
    try:
        # ---- 1. RBAC seeding on real rows ---------------------------------
        async with SessionLocal() as s:
            await seed_rbac(s)
            await s.commit()
        async with SessionLocal() as s:
            before = await _grants(s, isp=False)
            assert before, "rbac seed produced no grants"
            await seed_isp_partner_rbac(RBACRepository(s))
            await s.commit()
        async with SessionLocal() as s:
            assert await _grants(s, isp=False) == before
            isp_rows = await _grants(s, isp=True)
            assert {slug for slug, _ in isp_rows} == {
                "isp-owner",
                "isp-admin",
                "isp-noc",
                "isp-technician",
                "isp-viewer",
                "isp-billing",
            }
            assert all(
                key.split(".")[0]
                in {
                    "isp_partner",
                    "isp_logs",
                    "isp_ipdr",
                    "tr069",
                    "isp_billing",
                    "isp_invoices",
                    "isp_zones",
                    "isp_plans",
                    "isp_coupons",
                    "isp_subscribers",
                }
                for _, key in isp_rows
            )
            again = await seed_isp_partner_rbac(RBACRepository(s))
            assert again.roles_created == again.role_permissions_created == 0
            await seed_rbac(s)  # the existing seeder afterwards
            await s.commit()
        async with SessionLocal() as s:
            assert await _grants(s, isp=True) == isp_rows
            assert await _grants(s, isp=False) == before

        # ---- 2. an ISP with one owner ---------------------------------------
        async with SessionLocal() as s:
            plan = Plan(
                name=f"ISP plan {tag}",
                slug=f"isp-plan-{tag}",
                plan_type="standard",
                billing_cycle="monthly",
                base_price=Decimal("0"),
                currency="INR",
                is_active=True,
                is_public=False,
            )
            s.add(plan)
            isp = Organization(
                name=f"Airlink {tag}",
                slug=f"airlink-{tag}",
                org_type="msp",
                status="active",
                contact_email=f"ops-{tag}@example.com",
                timezone="Asia/Kolkata",
                settings={},
            )
            empty_isp = Organization(
                name=f"Empty {tag}",
                slug=f"empty-{tag}",
                org_type="msp",
                status="active",
                contact_email=f"e-{tag}@example.com",
                timezone="Asia/Kolkata",
                settings={},
            )
            owner = User(
                first_name="Ravi",
                last_name="Kumar",
                email=f"ravi-{tag}@example.com",
                username=f"ravi-{tag}",
                password_hash="x",
                is_active=True,
                is_verified=True,
            )
            s.add_all([isp, empty_isp, owner])
            await s.flush()
            for org in (isp, empty_isp):
                s.add(
                    IspPartnerProfile(
                        organization_id=org.id, default_customer_plan_id=plan.id
                    )
                )
                s.add(
                    OrganizationMember(
                        organization_id=org.id, user_id=owner.id, status="active"
                    )
                )
            from sqlalchemy import select

            role = (
                await s.execute(select(Role).where(Role.slug == "isp-owner"))
            ).scalar_one()
            for org in (isp, empty_isp):
                s.add(
                    UserRole(
                        user_id=owner.id,
                        role_id=role.id,
                        scope_type="organization",
                        organization_id=org.id,
                        granted_at=datetime.now(UTC),
                        is_active=True,
                    )
                )
            await s.commit()
            isp_id, empty_id, owner_id = isp.id, empty_isp.id, owner.id

        app = create_app()
        app.dependency_overrides[CurrentUser] = lambda: AuthUser(
            id=str(owner_id), email=f"ravi-{tag}@example.com"
        )
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            h = {"X-Organization-Id": str(isp_id)}
            me = await c.get("/api/v1/isp/me", headers=h)
            assert me.status_code == 200, me.text
            assert "isp_partner.assign" in me.json()["data"]["permissions"]

            # ---- 3. customers + locations, no users/members/roles created ---
            async with SessionLocal() as s:
                counts_before = [
                    await _scalar(s, f"select count(*) from {t}")
                    for t in ("users", "organization_members", "user_roles")
                ]
            customers = []
            for name in ("Cafe X", "Hostel Y"):
                r = await c.post(
                    "/api/v1/isp/customers",
                    json={
                        "name": f"{name} {tag}",
                        "contact_email": f"c-{tag}@example.com",
                    },
                    headers=h,
                )
                assert r.status_code == 201, r.text
                customers.append(r.json()["data"])
            locations = []
            for cust in customers:
                r = await c.post(
                    f"/api/v1/isp/customers/{cust['id']}/locations",
                    json={
                        "name": "Main",
                        "address_line1": "1 Road",
                        "city": "Noida",
                        "state_province": "UP",
                        "postal_code": "201301",
                    },
                    headers=h,
                )
                assert r.status_code == 201, r.text
                locations.append(r.json()["data"])
            async with SessionLocal() as s:
                counts_after = [
                    await _scalar(s, f"select count(*) from {t}")
                    for t in ("users", "organization_members", "user_roles")
                ]
                assert counts_after == counts_before
                for cust in customers:
                    row = await _scalar(
                        s,
                        "select org_type || ':' || parent_organization_id from organizations where id = :i",
                        i=uuid.UUID(cust["id"]),
                    )
                    assert row == f"standard:{isp_id}"
                    assert (
                        await _scalar(
                            s,
                            "select count(*) from subscriptions where organization_id = :i and status = 'active'",
                            i=uuid.UUID(cust["id"]),
                        )
                        == 1
                    )
                for loc in locations:
                    assert (
                        await _scalar(
                            s,
                            "select count(*) from captive_portal_configs where location_id = :i and is_active",
                            i=uuid.UUID(loc["id"]),
                        )
                        == 1
                    )

            # the child passes the existing licence gate for writes
            from app.common.exceptions import register_exception_handlers

            probe = FastAPI()
            register_exception_handlers(probe)

            @probe.post(
                "/probe", dependencies=[Depends(RequireActiveLicenseForWrites())]
            )
            async def _probe() -> dict:
                return {"ok": True}

            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=probe), base_url="http://p"
            ) as pc:
                ok = await pc.post(
                    "/probe", headers={"X-Organization-Id": customers[0]["id"]}
                )
                assert ok.status_code == 200, ok.text
                lapsed = await pc.post(
                    "/probe", headers={"X-Organization-Id": str(empty_id)}
                )
                assert lapsed.status_code == 402

            # ---- 4. routers + sessions over 3 days, reports vs SQL ------------
            routers = []
            for i, loc in enumerate(locations):
                r = await c.post(
                    f"/api/v1/isp/locations/{loc['id']}/routers",
                    json={
                        "name": f"hEX {i}",
                        "serial_number": f"SN{tag}{i}",
                        "mac_address": f"E4:8D:8C:{tag[:2]}:{tag[2:4]}:0{i}",
                        "model": "RB750Gr3",
                    },
                    headers=h,
                )
                assert r.status_code == 201, r.text
                routers.append(r.json()["data"])
            day0 = datetime.now(UTC).replace(
                hour=6, minute=0, second=0, microsecond=0
            ) - timedelta(days=3)
            async with SessionLocal() as s:
                for ci, cust in enumerate(customers):
                    org_id = uuid.UUID(cust["id"])
                    loc_id = uuid.UUID(locations[ci]["id"])
                    rtr_id = uuid.UUID(routers[ci]["id"])
                    guests = []
                    for g in range(2 + ci):
                        guest = Guest(
                            organization_id=org_id,
                            location_id=loc_id,
                            identifier=f"+9190000{ci}{g:04d}",
                            first_seen_at=day0,
                            last_seen_at=day0,
                        )
                        s.add(guest)
                        guests.append(guest)
                    await s.flush()
                    for d in range(3):
                        for gi, guest in enumerate(guests):
                            start = day0 + timedelta(days=d, hours=gi)
                            s.add(
                                GuestSession(
                                    guest_id=guest.id,
                                    router_id=rtr_id,
                                    location_id=loc_id,
                                    organization_id=org_id,
                                    auth_method="otp_sms",
                                    status="disconnected",
                                    started_at=start,
                                    ended_at=start + timedelta(minutes=30 + 10 * gi),
                                    last_activity_at=start,
                                    bytes_uploaded=1000 * (d + 1),
                                    bytes_downloaded=5000 * (gi + 1),
                                )
                            )
                await s.commit()
            since = (day0 - timedelta(hours=1)).isoformat()
            until = datetime.now(UTC).isoformat()
            rep = await c.get(
                "/api/v1/isp/reports/summary",
                params={"since": since, "until": until},
                headers=h,
            )
            assert rep.status_code == 200, rep.text
            data = rep.json()["data"]
            async with SessionLocal() as s:
                ids = [uuid.UUID(x["id"]) for x in customers]
                from sqlalchemy import bindparam, text

                q = text(
                    """select count(*), count(distinct guest_id),
                    sum(bytes_uploaded), sum(bytes_downloaded),
                    avg(extract(epoch from ended_at - started_at)) / 60
                    from guest_sessions where organization_id in :ids
                    and started_at >= :s and started_at < :u"""
                ).bindparams(bindparam("ids", expanding=True))
                logins, uniq, up, down, avg_min = (
                    await s.execute(
                        q,
                        {
                            "ids": ids,
                            "s": datetime.fromisoformat(since),
                            "u": datetime.fromisoformat(until),
                        },
                    )
                ).one()
            assert data["guest_activity"]["logins"] == logins == 15
            assert data["guest_activity"]["unique_guests"] == uniq == 5
            assert data["guest_activity"]["avg_session_minutes"] == round(
                float(avg_min), 1
            )
            usage = {u["isp_customer_id"]: u for u in data["usage_by_customer"]}
            assert sum(u["bytes_total"] for u in usage.values()) == up + down
            assert (
                usage[customers[0]["id"]]["logins"] == 6
                and usage[customers[1]["id"]]["logins"] == 9
            )
            assert sum(d["logins"] for d in data["guest_activity"]["by_day"]) == 15
            assert all(
                r["availability_percentage"] is None
                for r in data["portfolio"]["router_availability"]
            )
            assert data["portfolio"]["customers"]["active"] == 2
            too_long = await c.get(
                "/api/v1/isp/reports/summary",
                params={"since": (datetime.now(UTC) - timedelta(days=93)).isoformat()},
                headers=h,
            )
            assert too_long.status_code == 422
            assert too_long.json()["data"]["code"] == "ISP_RANGE_TOO_LONG"
            for fmt, section in (("csv", "usage_by_customer"), ("pdf", "all")):
                ex = await c.get(
                    "/api/v1/isp/reports/export",
                    params={
                        "format": fmt,
                        "section": section,
                        "since": since,
                        "until": until,
                    },
                    headers=h,
                )
                assert ex.status_code == 200, ex.text
                assert ex.headers["content-disposition"].startswith(
                    'attachment; filename="isp-report-'
                )
            # a fresh ISP with no customers: zeros, never platform totals
            empty = await c.get(
                "/api/v1/isp/reports/summary",
                headers={"X-Organization-Id": str(empty_id)},
            )
            ed = empty.json()["data"]
            assert ed["guest_activity"]["logins"] == 0 and ed["usage_by_customer"] == []
            assert ed["portfolio"]["routers"] == {
                "online": 0,
                "offline": 0,
                "pending": 0,
            }
            ov = await c.get(
                "/api/v1/isp/overview", headers={"X-Organization-Id": str(empty_id)}
            )
            assert (
                ov.status_code == 200 and ov.json()["data"]["customers"]["total"] == 0
            )

            # ---- 5. guests are masked ------------------------------------------
            g = await c.get(
                f"/api/v1/isp/customers/{customers[0]['id']}/guests", headers=h
            )
            item = g.json()["data"]["items"][0]
            assert (
                item["phone_masked"].startswith("X")
                and "90000" not in item["phone_masked"][:5]
            )

            # ---- 6. TR-069 credentials + sync ------------------------------------
            acs = await c.get("/api/v1/isp/tr069/acs", headers=h)
            assert acs.status_code == 200, acs.text
            isp_user = acs.json()["data"]["username"]
            on = await c.put(
                f"/api/v1/isp/tr069/customers/{customers[0]['id']}",
                json={"enabled": True},
                headers=h,
            )
            cust_user = on.json()["data"]["username"]
            script = await c.get(
                f"/api/v1/isp/tr069/routers/{routers[0]['id']}/script", headers=h
            )
            assert script.status_code == 200 and cust_user in script.text
            assert script.headers["cache-control"] == "no-store"

            from app.domains.tr069.sync import Tr069SyncService

            def doc(genie_id, username):
                return {
                    "_id": genie_id,
                    "_lastInform": datetime.now(UTC).isoformat(),
                    "Device": {
                        "ManagementServer": {"Username": {"_value": username}},
                        "DeviceInfo": {"ModelName": {"_value": "RB750Gr3"}},
                        "WiFi": {
                            "AccessPoint": {
                                "1": {"Security": {"KeyPassphrase": {"_value": "leak"}}}
                            }
                        },
                    },
                }

            class Nbi:
                def __init__(self, docs):
                    self.docs = docs

                async def query_devices(self, query, projection=None):
                    names = {v for clause in query["$or"] for v in clause.values()}
                    return [
                        d
                        for d in self.docs
                        if d["Device"]["ManagementServer"]["Username"]["_value"]
                        in names
                    ]

                async def add_tag(self, *a):
                    return None

                async def get_tasks(self, q):
                    return []

                async def get_faults(self, q):
                    return []

            nbi = Nbi(
                [
                    doc(f"A-{tag}", cust_user),
                    doc(f"B-{tag}", isp_user),
                    doc(f"C-{tag}", "isp-someoneelse"),
                ]
            )
            async with SessionLocal() as s:
                await Tr069SyncService(s, nbi).sync_isp(isp_id)
                await s.commit()
            devices = await c.get("/api/v1/isp/tr069/devices", headers=h)
            items = {
                d["genieacs_device_id"]: d for d in devices.json()["data"]["items"]
            }
            assert set(items) == {f"A-{tag}", f"B-{tag}"}
            assert items[f"A-{tag}"]["isp_customer_id"] == customers[0]["id"]
            assert items[f"B-{tag}"]["isp_customer_id"] is None
            async with SessionLocal() as s:
                assert "leak" not in str(
                    await _scalar(
                        s,
                        "select params_cache::text from tr069_devices where genieacs_device_id = :g",
                        g=f"A-{tag}",
                    )
                )
            # manual assignment survives the next sync
            cpe = items[f"B-{tag}"]["id"]
            pa = await c.patch(
                f"/api/v1/isp/tr069/devices/{cpe}",
                json={"isp_customer_id": customers[1]["id"]},
                headers=h,
            )
            assert pa.status_code == 200, pa.text
            async with SessionLocal() as s:
                await Tr069SyncService(s, nbi).sync_isp(isp_id)
                await s.commit()
            again = await c.get(f"/api/v1/isp/tr069/devices/{cpe}", headers=h)
            assert again.json()["data"]["isp_customer_id"] == customers[1]["id"]
            # disabling the customer blocks tasks with 409, keeps inventory
            off = await c.put(
                f"/api/v1/isp/tr069/customers/{customers[0]['id']}",
                json={"enabled": False},
                headers=h,
            )
            assert off.json()["data"]["password"] is None
            a_id = items[f"A-{tag}"]["id"]
            blocked = await c.post(
                f"/api/v1/isp/tr069/devices/{a_id}/reboot", headers=h
            )
            assert blocked.status_code == 409
            assert blocked.json()["data"]["code"] == "TR069_DISABLED_FOR_CUSTOMER"
            assert (
                await c.get(f"/api/v1/isp/tr069/devices/{a_id}", headers=h)
            ).status_code == 200

            # ---- 7. suspend: org suspended, guest WiFi untouched -----------------
            sus = await c.post(
                f"/api/v1/isp/customers/{customers[1]['id']}/suspend",
                json={"reason": "test"},
                headers=h,
            )
            assert (
                sus.status_code == 200 and sus.json()["data"]["status"] == "suspended"
            )
            async with SessionLocal() as s:
                assert (
                    await _scalar(
                        s,
                        "select count(*) from captive_portal_configs where organization_id = :i and is_active",
                        i=uuid.UUID(customers[1]["id"]),
                    )
                    == 1
                )
            act = await c.post(
                f"/api/v1/isp/customers/{customers[1]['id']}/activate", headers=h
            )
            assert act.json()["data"]["status"] == "active"

            # ---- 8. NetLogs: partition pruning for a 24 h window -----------------
            from sqlalchemy import select as sa_select

            from app.domains.device_logs.models import DeviceLogEvent
            from app.domains.device_logs.repository import CustomerFilters
            from app.domains.isp_partner.logs_repository import isp_conditions

            now = datetime.now(UTC)
            f = CustomerFilters(
                organization_id=ids[0], since=now - timedelta(hours=24), until=now
            )
            stmt = (
                sa_select(DeviceLogEvent.id)
                .where(*isp_conditions(f, ids))
                .order_by(DeviceLogEvent.received_at.desc(), DeviceLogEvent.id.desc())
                .limit(101)
            )
            async with SessionLocal() as s:
                compiled = stmt.compile(compile_kwargs={"literal_binds": True})
                plan_rows = (
                    (
                        await s.execute(
                            __import__("sqlalchemy").text(f"EXPLAIN {compiled}")
                        )
                    )
                    .scalars()
                    .all()
                )
            plan_text = "\n".join(plan_rows)
            print("\nEXPLAIN (24h window):\n" + plan_text)
            scanned = {
                p
                for p in ("p202610", "p202611", "p202612", "p202701", "default")
                if f"device_log_events_{p}" in plan_text
            }
            assert len(scanned) <= 2, plan_text
    finally:
        await engine.dispose()
        # the app-global redis client pools sockets bound to this test's loop
        from app.database.redis import redis_client

        await redis_client.connection_pool.disconnect()
