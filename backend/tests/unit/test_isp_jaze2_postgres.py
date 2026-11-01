"""JAZE-2 end to end on real PostgreSQL + Redis (skipped unless
``ISP_TEST_PG_DSN`` is set; CI has neither). Run against a scratch DB at head::

    CLOUDGUEST_DATABASE_URL=postgresql+asyncpg://postgres@localhost:55442/isp \\
    CLOUDGUEST_REDIS_URL=redis://localhost:56382/0 \\
    ISP_TEST_PG_DSN=1 ISP_PARTNER_ENABLED=true \\
    ISP_PARTNER_ENFORCEMENT_ENABLED=true ISP_PARTNER_ENFORCEMENT_LIVE_MODE=reauth \\
    python -m pytest tests/unit/test_isp_jaze2_postgres.py

Covers: policy PUT/GET + validation, the sweep throttling at the FUP limit and
ending live sessions (reauth), MAC auto-bind + reject, concurrency, the X1
override returning the fallback rate, FUP status/top-up/reset, MAC clear,
static-IP next-free/pin/conflict, router sessions list, TR-069 tiles, and
cross-ISP isolation (ISP B gets 404 on every A id).
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

GB = 1024**3


async def test_jaze2_end_to_end() -> None:  # noqa: PLR0915
    import httpx
    from sqlalchemy import select

    from app.database.session import SessionLocal, engine
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.dhcp.models import DhcpPool
    from app.domains.guest.models import Guest, GuestDevice, GuestSession
    from app.domains.isp_partner.config import get_isp_partner_settings
    from app.domains.isp_partner.enforcement import effective_rate_override
    from app.domains.isp_partner.enforcement_sweep import run_sweep
    from app.domains.isp_partner.models import IspPartnerProfile
    from app.domains.isp_partner.plans_models import IspSubscriber
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.organization.models import Organization, OrganizationMember
    from app.domains.rbac.dependencies import CurrentUser
    from app.domains.rbac.models import Role, UserRole
    from app.domains.rbac.repository import RBACRepository
    from app.domains.rbac.seed import seed_rbac
    from app.main import create_app

    get_isp_partner_settings.cache_clear()
    assert get_isp_partner_settings().enforcement_enabled
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
                slug=f"j2-{tag}",
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
                    name=f"J2 {n} {tag}",
                    slug=f"j2{n.lower()}{tag}",
                    org_type="msp",
                    status="active",
                    contact_email=f"j2{n}{tag}@example.com",
                    timezone="Asia/Kolkata",
                    settings={},
                )
                user = User(
                    first_name=n,
                    last_name="O",
                    email=f"j2{n}{tag}@example.com",
                    username=f"j2{n}{tag}",
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
        state = {"user": users["A"]}
        app.dependency_overrides[CurrentUser] = lambda: AuthUser(
            id=str(state["user"]), email="o@example.com"
        )
        ha = {"X-Organization-Id": str(isps["A"])}
        hb = {"X-Organization-Id": str(isps["B"])}
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t"
        ) as c:

            async def post(path, body, h=ha):  # noqa: ANN001, ANN202
                r = await c.post(f"/api/v1/isp{path}", json=body, headers=h)
                assert r.status_code in (200, 201), (path, r.text)
                return r.json()["data"]

            cust = (
                await post(
                    "/customers",
                    {"name": f"Cafe {tag}", "contact_email": f"c{tag}@example.com"},
                )
            )["id"]
            loc = (
                await post(
                    f"/customers/{cust}/locations",
                    {
                        "name": "Main",
                        "address_line1": "1",
                        "city": "c",
                        "state_province": "s",
                        "postal_code": "1",
                    },
                )
            )["id"]
            rtr = (
                await post(
                    f"/locations/{loc}/routers",
                    {
                        "name": "hEX",
                        "serial_number": f"SN{tag}",
                        "mac_address": "02:00:"
                        + ":".join(tag[i : i + 2] for i in (0, 2, 4, 6)),
                        "model": "hEX",
                    },
                )
            )["id"]
            g100 = (
                await post(
                    "/speed-groups",
                    {"name": "100M", "download_kbps": 102400, "upload_kbps": 102400},
                )
            )["id"]
            g2 = (
                await post(
                    "/speed-groups",
                    {"name": "2M", "download_kbps": 2048, "upload_kbps": 2048},
                )
            )["id"]
            g200 = (
                await post(
                    "/speed-groups",
                    {"name": "200M", "download_kbps": 204800, "upload_kbps": 204800},
                )
            )["id"]
            pkg = (
                await post(
                    "/packages",
                    {"speed_group_id": g100, "type": "prepaid", "price_paise": 50000},
                )
            )["id"]
            sub = (
                await post(
                    "/subscribers",
                    {
                        "isp_customer_id": cust,
                        "identifier": f"user{tag}",
                        "package_id": pkg,
                    },
                )
            )["id"]

            # policy validation + save -------------------------------------
            r = await c.put(
                f"/api/v1/isp/packages/{pkg}/policy",
                json={"fup_fallback_speed_group_id": g2},
                headers=ha,
            )
            assert r.status_code == 422, r.text
            r = await c.put(
                f"/api/v1/isp/packages/{pkg}/policy",
                json={"boost_speed_group_id": g200},
                headers=ha,
            )
            assert r.status_code == 422, r.text
            r = await c.put(
                f"/api/v1/isp/packages/{pkg}/policy",
                json={
                    "fup_limit_mb": 1024,
                    "fup_reset": "month",
                    "fup_fallback_speed_group_id": g2,
                    "mac_bind_count": 1,
                    "max_simultaneous": 1,
                },
                headers=ha,
            )
            assert r.status_code == 200, r.text
            pol = (
                await c.get(f"/api/v1/isp/packages/{pkg}/policy", headers=ha)
            ).json()["data"]
            assert pol["configured"] and pol["fup_limit_mb"] == 1024
            assert pol["fup_fallback_speed_group_name"] == "2M"

            # isolation -----------------------------------------------------
            for path in (
                f"/packages/{pkg}/policy",
                f"/subscribers/{sub}/fup",
                f"/subscribers/{sub}/mac-bindings",
                f"/subscribers/{sub}/ip-bindings",
                f"/subscribers/{sub}/enforcement-events",
                f"/locations/{loc}/ip-pools",
                f"/routers/{rtr}/sessions/active",
                f"/routers/{rtr}/health/history",
            ):
                state["user"] = users["B"]
                r = await c.get(f"/api/v1/isp{path}", headers=hb)
                state["user"] = users["A"]
                assert r.status_code == 404, (path, r.status_code, r.text)

            # guest + two live sessions, 1.2 GB used this month ------------
            now = datetime.now(UTC)
            async with SessionLocal() as s:
                guest = Guest(
                    organization_id=uuid.UUID(cust),
                    location_id=uuid.UUID(loc),
                    identifier=f"user{tag}",
                    first_seen_at=now,
                    last_seen_at=now,
                )
                s.add(guest)
                await s.flush()
                d1 = GuestDevice(
                    guest_id=guest.id,
                    mac_address=f"AA:00:00:00:{tag[:2]}:01",
                    first_seen_at=now,
                    last_seen_at=now,
                )
                d2 = GuestDevice(
                    guest_id=guest.id,
                    mac_address=f"AA:00:00:00:{tag[:2]}:02",
                    first_seen_at=now,
                    last_seen_at=now,
                )
                s.add_all([d1, d2])
                await s.flush()
                sess = []
                for i, d in enumerate((d1, d2)):
                    gs = GuestSession(
                        guest_id=guest.id,
                        device_id=d.id,
                        router_id=uuid.UUID(rtr),
                        location_id=uuid.UUID(loc),
                        organization_id=uuid.UUID(cust),
                        auth_method="voucher",
                        status="active",
                        started_at=now - timedelta(minutes=30 - i * 10),
                        last_activity_at=now,
                        ip_address=f"10.5.50.{10 + i}",
                        bytes_downloaded=int(0.6 * GB),
                        bytes_uploaded=10,
                    )
                    s.add(gs)
                    sess.append(gs)
                row = await s.get(IspSubscriber, uuid.UUID(sub))
                row.guest_id = guest.id
                await s.commit()
                s1, s2 = sess[0].id, sess[1].id

            ended: list[tuple[uuid.UUID, str]] = []

            async def disconnect(session_id, organization_id, reason):  # noqa: ANN001, ANN202
                assert str(organization_id) == cust
                ended.append((session_id, reason))

            async with SessionLocal() as s:
                summary = await run_sweep(s, disconnect=disconnect, live_mode="reauth")
                await s.commit()
            assert summary["throttled"] == 1 and summary["errors"] == 0, summary
            assert summary["bound"] == 1
            # s1 kept + bound; s2 ended for MAC (one verdict per session); s1
            # then re-authorized because the throttle flipped.
            assert (s2, "mac_reject") in ended and (s1, "reauth") in ended, ended

            fup = (
                await c.get(f"/api/v1/isp/subscribers/{sub}/fup", headers=ha)
            ).json()["data"]
            assert fup["throttled"] and fup["used_bytes"] >= int(1.2 * GB)
            assert fup["fallback_speed_group"]["name"] == "2M"

            async with SessionLocal() as s:
                srow = await s.get(IspSubscriber, uuid.UUID(sub))
                over, rate = await effective_rate_override(
                    s,
                    package_id=uuid.UUID(pkg),
                    subscriber=srow,
                    organization_id=uuid.UUID(cust),
                )
            assert over and rate == "2048k/2048k"

            macs = (
                await c.get(f"/api/v1/isp/subscribers/{sub}/mac-bindings", headers=ha)
            ).json()["data"]
            assert [m["source"] for m in macs] == ["auto"]
            r = await c.delete(
                f"/api/v1/isp/subscribers/{sub}/mac-bindings/{macs[0]['id']}",
                headers=ha,
            )
            assert r.status_code == 200

            fup = await post(f"/subscribers/{sub}/fup/topup", {"mb": 1024})
            assert fup["topup_bytes"] == 1024 * 1024 * 1024
            fup = await post(f"/subscribers/{sub}/fup/reset", {})
            assert fup["throttled"] is False

            ev = (
                await c.get(
                    f"/api/v1/isp/subscribers/{sub}/enforcement-events", headers=ha
                )
            ).json()["data"]
            kinds = {e["kind"] for e in ev}
            assert {
                "fup_throttle",
                "mac_bound",
                "mac_reject",
                "reauth",
                "fup_topup",
                "fup_reset",
            } <= kinds, kinds

            # sessions list masks nothing ISP-entered, shows circuit --------
            act = (
                await c.get(f"/api/v1/isp/routers/{rtr}/sessions/active", headers=ha)
            ).json()["data"]["sessions"]
            assert {a["subscriber_id"] for a in act} == {sub}

            # static IP -----------------------------------------------------
            async with SessionLocal() as s:
                pool = DhcpPool(
                    router_id=uuid.UUID(rtr),
                    organization_id=uuid.UUID(cust),
                    location_id=uuid.UUID(loc),
                    name="lan",
                    address_range_start="10.5.50.1",
                    address_range_end="10.5.50.3",
                    gateway_ip_address="10.5.50.1",
                )
                s.add(pool)
                await s.commit()
                pool_id = str(pool.id)
            nf = (
                await c.get(
                    f"/api/v1/isp/locations/{loc}/ip-pools/{pool_id}/next-free",
                    headers=ha,
                )
            ).json()["data"]
            assert nf["ip"] == "10.5.50.2"
            b1 = await post(
                f"/subscribers/{sub}/ip-bindings",
                {
                    "isp_location_id": loc,
                    "pool_id": pool_id,
                    "mac": "aa-bb-cc-dd-ee-ff",
                },
            )
            assert b1["ip"] == "10.5.50.2" and b1["mac"] == "AA:BB:CC:DD:EE:FF"
            r = await c.post(
                f"/api/v1/isp/subscribers/{sub}/ip-bindings",
                json={"isp_location_id": loc, "pool_id": pool_id, "ip": "10.5.50.2"},
                headers=ha,
            )
            assert r.status_code == 409, r.text
            r = await c.post(
                f"/api/v1/isp/subscribers/{sub}/ip-bindings",
                json={"isp_location_id": loc, "pool_id": pool_id, "ip": "10.5.50.9"},
                headers=ha,
            )
            assert r.status_code == 422, r.text
            await post(
                f"/subscribers/{sub}/ip-bindings",
                {"isp_location_id": loc, "pool_id": pool_id},
            )
            r = await c.get(
                f"/api/v1/isp/locations/{loc}/ip-pools/{pool_id}/next-free", headers=ha
            )
            assert (
                r.status_code == 409
                and r.json()["data"]["code"] == "ISP_IP_POOL_EXHAUSTED"
            )
            pools = (
                await c.get(f"/api/v1/isp/locations/{loc}/ip-pools", headers=ha)
            ).json()["data"]
            assert pools[0]["pinned"] == 2 and pools[0]["size"] == 3

            # router health: no credentials yet -> honest not_set_up ---------
            live = (
                await c.get(f"/api/v1/isp/routers/{rtr}/health/live", headers=ha)
            ).json()["data"]
            assert live["reachable"] is False and live["reason"] == "not_set_up"
            tiles = (await c.get("/api/v1/isp/tr069/summary", headers=ha)).json()[
                "data"
            ]
            assert tiles["total"] == 0

            # Subscriber 360 auth slots (JAZE-1 calls this from view_360) -----
            from app.domains.isp_partner.enforcement import auth_slots

            async with SessionLocal() as s:
                slots = await auth_slots(s, uuid.UUID(sub))
            assert slots["mac_bound"] is False  # the auto MAC was cleared above
            assert slots["static_ip"] == "10.5.50.2"
            assert slots["static_ips"] == ["10.5.50.2", "10.5.50.3"]
    finally:
        await engine.dispose()
