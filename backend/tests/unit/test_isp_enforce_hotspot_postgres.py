"""ENFORCE-2 on real PostgreSQL + Redis (skipped unless ``ISP_TEST_PG_DSN``
is set; CI has neither). Fresh scratch DB at head. Drives the REAL hotspot
``POST /api/v1/radius/authorize`` (NAS-authenticated, the full DI the
FreeRADIUS rlm_rest call gets) with the JAZE-2 hotspot gate registered.

MANDATORY zero-impact proof: a regular Wyfy tenant's guest, and a guest of an
ISP customer who is NOT a subscriber, get a byte-identical reply with
``ISP_PARTNER_ENFORCEMENT_ENABLED`` on and off.

Then, for an ISP subscriber with the flag on: MAC auto-bind + refusal (same
reject shape as the old authorize, refusal event de-duplicated), Idle- and
Session-Timeout only shortened, concurrency (counting a live PPPoE session),
IP restriction (no static IP / wrong IP / right IP), hard timeout already
spent; and flag off again = old behaviour.
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


async def test_enforce_hotspot_end_to_end() -> None:  # noqa: PLR0915
    import json

    import httpx
    from sqlalchemy import select, update

    from app.database.session import SessionLocal, engine
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.dhcp.models import DhcpPool
    from app.domains.guest.models import Guest, GuestSession, RadiusNasClient
    from app.domains.isp_partner.config import get_isp_partner_settings
    from app.domains.isp_partner.enforcement_hotspot import jaze2_hotspot_gate
    from app.domains.isp_partner.hotspot_hooks import (
        clear_hotspot_gates,
        register_hotspot_gate,
    )
    from app.domains.isp_partner.models import IspPartnerProfile
    from app.domains.isp_partner.plans_models import IspSubscriber
    from app.domains.isp_partner.pppoe_config import get_isp_pppoe_settings
    from app.domains.isp_partner.pppoe_models import IspPppoeCredential, IspPppoeSession
    from app.domains.isp_partner.rate_limit import _isp_customer_cache
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.isp_partner.zones_config import get_zones_settings
    from app.domains.location.models import Location
    from app.domains.router.crypto import encrypt_secret
    from app.domains.router.models import Router

    def clear() -> None:
        get_isp_partner_settings.cache_clear()
        get_isp_pppoe_settings.cache_clear()

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

            # setup ----------------------------------------------------------------
            os.environ["ISP_PPPOE_ENABLED"] = "true"
            os.environ.pop("ISP_PARTNER_ENFORCEMENT_ENABLED", None)
            clear()
            clear_hotspot_gates()
            register_hotspot_gate(jaze2_hotspot_gate)
            _isp_customer_cache.clear()
            cust = (
                await call(
                    "POST",
                    "/customers",
                    {"name": f"e2 {tag}", "contact_email": f"e2{tag}@e.com"},
                )
            )["id"]
            loc = (
                await call(
                    "POST",
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
            hexmac = ":".join(tag[i : i + 2] for i in (0, 2, 4, 6)).upper()
            rtr = (
                await call(
                    "POST",
                    f"/locations/{loc}/routers",
                    {
                        "name": "hEX",
                        "serial_number": f"SN{tag}",
                        "mac_address": "02:00:" + hexmac,
                        "model": "hEX",
                    },
                )
            )["id"]
            g20 = (
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
                    {"speed_group_id": g20, "type": "prepaid", "price_paise": 50000},
                )
            )["id"]
            sid = (
                await call(
                    "POST",
                    "/subscribers",
                    {
                        "isp_customer_id": cust,
                        "identifier": f"s{tag}",
                        "package_id": pkg,
                    },
                )
            )["id"]

            now = datetime.now(UTC)
            async with SessionLocal() as s:
                reg = Organization(
                    name=f"Reg {tag}",
                    slug=f"reg{tag}",
                    org_type="standard",
                    status="active",
                    contact_email=f"reg{tag}@e.com",
                    timezone="Asia/Kolkata",
                    settings={},
                )
                s.add(reg)
                await s.flush()
                rloc = Location(
                    organization_id=reg.id,
                    name="Cafe",
                    slug=f"cafe{tag}",
                    address_line1="1",
                    city="c",
                    state_province="s",
                    postal_code="1",
                    country="IN",
                    settings={},
                )
                s.add(rloc)
                await s.flush()
                rrtr = Router(
                    location_id=rloc.id,
                    organization_id=reg.id,
                    name="cafe",
                    serial_number=f"RSN{tag}",
                    mac_address="06:00:" + hexmac,
                    model="hAP",
                    settings={},
                )
                s.add(rrtr)
                await s.flush()
                for rid, oid, lid, ident in (
                    (uuid.UUID(rtr), uuid.UUID(cust), uuid.UUID(loc), f"nas-i{tag}"),
                    (rrtr.id, reg.id, rloc.id, f"nas-r{tag}"),
                ):
                    s.add(
                        RadiusNasClient(
                            router_id=rid,
                            organization_id=oid,
                            location_id=lid,
                            nas_identifier=ident,
                            shared_secret_encrypted=encrypt_secret("s3cret"),
                        )
                    )

                def guest(org_id, ident):  # noqa: ANN001, ANN202
                    return Guest(
                        organization_id=org_id,
                        identifier=ident,
                        display_name="Test",  # OTP sessions need a name
                        first_seen_at=now,
                        last_seen_at=now,
                    )

                g_isp = guest(uuid.UUID(cust), f"isp{tag}@e.com")
                g_np = guest(uuid.UUID(cust), f"np{tag}@e.com")  # not a subscriber
                g_reg = guest(reg.id, f"reg{tag}@e.com")
                s.add_all([g_isp, g_np, g_reg])
                await s.flush()
                await s.execute(
                    update(IspSubscriber)
                    .where(IspSubscriber.id == uuid.UUID(sid))
                    .values(guest_id=g_isp.id)
                )

                def gsess(g, router_id, org_id, loc_id, **kw):  # noqa: ANN001, ANN003, ANN202
                    return GuestSession(
                        guest_id=g.id,
                        router_id=router_id,
                        location_id=loc_id,
                        organization_id=org_id,
                        auth_method="otp_sms",
                        status="active",
                        started_at=now,
                        last_activity_at=now,
                        bytes_uploaded=0,
                        bytes_downloaded=0,
                        **kw,
                    )

                s_isp = gsess(
                    g_isp,
                    uuid.UUID(rtr),
                    uuid.UUID(cust),
                    uuid.UUID(loc),
                    session_timeout_minutes=120,
                    idle_timeout_minutes=30,
                    ip_address="10.5.60.50",
                )
                # no Session-Timeout (it counts down) so replies compare exactly
                s_np = gsess(
                    g_np,
                    uuid.UUID(rtr),
                    uuid.UUID(cust),
                    uuid.UUID(loc),
                    idle_timeout_minutes=30,
                )
                s_reg = gsess(g_reg, rrtr.id, reg.id, rloc.id, idle_timeout_minutes=30)
                s.add_all([s_isp, s_np, s_reg])
                await s.commit()
                s_isp_id = s_isp.id

            m1 = "AA:E2:" + hexmac
            m2 = "AB:E2:" + hexmac
            m_np = "AC:E2:" + hexmac
            m_reg = "AD:E2:" + hexmac

            async def auth(who: str, user: str, mac: str | None) -> dict:
                r = await c.post(
                    "/api/v1/radius/authorize",
                    json={"username": user, "calling_station_id": mac},
                    headers={
                        "X-RADIUS-NAS-Identifier": f"nas-{who}{tag}",
                        "X-RADIUS-Shared-Secret": "s3cret",
                    },
                )
                assert r.status_code == 200, r.text
                return r.json()

            async def policy(**kw) -> None:  # noqa: ANN003
                await call("PUT", f"/packages/{pkg}/policy", kw)

            async def events() -> list[str]:
                ev = await call(
                    "GET", f"/subscribers/{sid}/enforcement-events?limit=200"
                )
                return [e["kind"] for e in ev]

            def flag(on: bool) -> None:
                if on:
                    os.environ["ISP_PARTNER_ENFORCEMENT_ENABLED"] = "true"
                else:
                    os.environ.pop("ISP_PARTNER_ENFORCEMENT_ENABLED", None)
                clear()

            await policy(
                mac_bind_count=1,
                idle_timeout_s=600,
                hard_timeout_s=3600,
                max_simultaneous=1,
            )

            # flag OFF: baseline -------------------------------------------------
            reg_off = await auth("r", f"reg{tag}@e.com", m_reg)
            np_off = await auth("i", f"np{tag}@e.com", m_np)
            isp_off = await auth("i", f"isp{tag}@e.com", m1)
            assert reg_off["control:Auth-Type"] == "Accept", reg_off
            assert np_off["control:Auth-Type"] == "Accept", np_off
            assert isp_off["control:Auth-Type"] == "Accept", isp_off
            assert isp_off["Idle-Timeout"] == 1800
            assert isp_off["Session-Timeout"] > 3600
            assert (await auth("i", f"isp{tag}@e.com", m2))[
                "control:Auth-Type"
            ] == "Accept"
            old_reject = await auth("i", f"nobody{tag}@e.com", m2)
            assert old_reject == {"control:Auth-Type": "Reject"}, old_reject
            assert await events() == []

            # flag ON: MANDATORY byte-identical for everyone who is not a subscriber
            flag(True)
            for _ in range(2):  # cold, then warm X1 org cache
                reg_on = await auth("r", f"reg{tag}@e.com", m_reg)
                np_on = await auth("i", f"np{tag}@e.com", m_np)
                assert json.dumps(reg_on, sort_keys=True) == json.dumps(
                    reg_off, sort_keys=True
                )
                assert json.dumps(np_on, sort_keys=True) == json.dumps(
                    np_off, sort_keys=True
                )
            assert await auth("i", f"nobody{tag}@e.com", m2) == old_reject

            # MAC auto-bind + refusal, timeouts only shorten ----------------------
            # m2 was adopted as the session's device while the flag was off; the
            # NAS-asserted Calling-Station-Id is what the rule reads.
            r = await auth("i", f"isp{tag}@e.com", m1)
            assert r["control:Auth-Type"] == "Accept", r
            assert r["Idle-Timeout"] == 600  # min(1800, 600)
            assert 3500 < r["Session-Timeout"] <= 3600  # min(7200 left, 3600 hard)
            macs = await call("GET", f"/subscribers/{sid}/mac-bindings")
            assert [x["mac"] for x in macs] == [m1] and macs[0]["source"] == "auto"
            r = await auth("i", f"isp{tag}@e.com", m2)
            assert r == old_reject, r  # the very same reject shape
            r = await auth("i", f"isp{tag}@e.com", m2)
            assert r == old_reject
            ev = await events()
            assert ev.count("mac_bound") == 1 and ev.count("mac_reject") == 1, ev

            # concurrency: a live PPPoE session of the same subscriber counts ----
            await policy(max_simultaneous=1)  # MAC rules off, timeouts off
            r = await auth("i", f"isp{tag}@e.com", m2)
            assert r["control:Auth-Type"] == "Accept" and r["Idle-Timeout"] == 1800, r
            await call(
                "PUT",
                f"/subscribers/{sid}/pppoe",
                {"username": f"pp{tag}", "password": "Secret-12345"},
            )
            async with SessionLocal() as s:
                cred = (
                    await s.execute(
                        select(IspPppoeCredential).where(
                            IspPppoeCredential.subscriber_id == uuid.UUID(sid)
                        )
                    )
                ).scalar_one()
                nas_id = (
                    await s.execute(
                        select(RadiusNasClient.id).where(
                            RadiusNasClient.nas_identifier == f"nas-i{tag}"
                        )
                    )
                ).scalar_one()
                s.add(
                    IspPppoeSession(
                        isp_organization_id=isps["A"],
                        customer_organization_id=uuid.UUID(cust),
                        location_id=uuid.UUID(loc),
                        router_id=uuid.UUID(rtr),
                        nas_client_id=nas_id,
                        subscriber_id=uuid.UUID(sid),
                        credential_id=cred.id,
                        username=f"pp{tag}",
                        acct_session_id=f"h1{tag}",
                        calling_station_id="EE:00:00:00:00:01",
                        started_at=now,
                        last_update_at=now,
                        status="active",
                        bytes_uploaded=0,
                        bytes_downloaded=0,
                    )
                )
                await s.commit()
            assert await auth("i", f"isp{tag}@e.com", m2) == old_reject
            assert "concurrency" in await events()
            await policy(max_simultaneous=2)
            assert (await auth("i", f"isp{tag}@e.com", m2))[
                "control:Auth-Type"
            ] == "Accept"

            # IP restriction ------------------------------------------------------
            await policy(ip_restriction=True)
            assert await auth("i", f"isp{tag}@e.com", m2) == old_reject  # none bound
            async with SessionLocal() as s:
                pool = DhcpPool(
                    router_id=uuid.UUID(rtr),
                    organization_id=uuid.UUID(cust),
                    location_id=uuid.UUID(loc),
                    name="lan",
                    address_range_start="10.5.60.1",
                    address_range_end="10.5.60.9",
                    gateway_ip_address="10.5.60.1",
                )
                s.add(pool)
                await s.commit()
                pool_id = pool.id
            b = await call(
                "POST",
                f"/subscribers/{sid}/ip-bindings",
                {"isp_location_id": loc, "pool_id": str(pool_id)},
            )
            # session IP 10.5.60.50 is not the bound one
            assert await auth("i", f"isp{tag}@e.com", m2) == old_reject
            async with SessionLocal() as s:
                await s.execute(
                    update(GuestSession)
                    .where(GuestSession.id == s_isp_id)
                    .values(ip_address=b["ip"])
                )
                await s.commit()
            r = await auth("i", f"isp{tag}@e.com", m2)
            assert r["control:Auth-Type"] == "Accept", r
            assert (await events()).count("ip_reject") == 2

            # hard timeout already spent ------------------------------------------
            async with SessionLocal() as s:
                await s.execute(
                    update(GuestSession)
                    .where(GuestSession.id == s_isp_id)
                    .values(started_at=now - timedelta(minutes=10))
                )
                await s.commit()
            await policy(hard_timeout_s=300)
            assert await auth("i", f"isp{tag}@e.com", m2) == old_reject
            assert "hard_timeout" in await events()
            await policy(hard_timeout_s=3600)
            r = await auth("i", f"isp{tag}@e.com", m2)
            assert 2900 < r["Session-Timeout"] <= 3000, r  # 3600 - 600 elapsed

            # flag OFF again: old behaviour for the subscriber too ------------------
            flag(False)
            await policy(mac_bind_count=1, max_simultaneous=1, hard_timeout_s=300)
            r = await auth("i", f"isp{tag}@e.com", m2)
            assert r["control:Auth-Type"] == "Accept" and r["Idle-Timeout"] == 1800, r
            assert r["Session-Timeout"] > 3600
    finally:
        for k in ("ISP_PPPOE_ENABLED", "ISP_PARTNER_ENFORCEMENT_ENABLED"):
            os.environ.pop(k, None)
        clear()
        await engine.dispose()
