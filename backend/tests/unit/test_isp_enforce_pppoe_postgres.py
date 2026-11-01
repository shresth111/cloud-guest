"""ENFORCE-1 on real PostgreSQL + Redis (skipped unless ``ISP_TEST_PG_DSN``
is set; CI has neither). Fresh scratch DB at head. Drives the real JAZE-6
``IspPppoeService.authorize`` with the JAZE-2 hooks registered.

Covers: flag off = JAZE-6 reply unchanged; MAC auto-bind + refusal;
Session-/Idle-Timeout; queue priority encoding; concurrency (own device
reconnect allowed); IP restriction (refuse without a static IP, pin with
one); boost window; FUP over PPPoE bytes -> throttle -> fallback rate, live
PPPoE re-authorized, no double count; enforcement events; a non-ISP NAS and
the hotspot X1 path for a regular tenant are identical with the flag on.
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


async def test_enforce_pppoe_end_to_end() -> None:  # noqa: PLR0915
    import json
    from types import SimpleNamespace
    from zoneinfo import ZoneInfo

    import httpx
    from sqlalchemy import select

    from app.database.session import SessionLocal, engine
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.dhcp.models import DhcpPool
    from app.domains.guest.models import RadiusNasClient
    from app.domains.isp_partner.config import get_isp_partner_settings
    from app.domains.isp_partner.enforcement_pppoe import (
        jaze2_pppoe_gate,
        jaze2_pppoe_rate,
    )
    from app.domains.isp_partner.enforcement_sweep import run_sweep
    from app.domains.isp_partner.models import IspPartnerProfile
    from app.domains.isp_partner.pppoe_config import get_isp_pppoe_settings
    from app.domains.isp_partner.pppoe_hooks import (
        register_pppoe_gate,
        register_pppoe_rate_resolver,
    )
    from app.domains.isp_partner.pppoe_models import IspPppoeCredential, IspPppoeSession
    from app.domains.isp_partner.pppoe_service import IspPppoeService
    from app.domains.isp_partner.rate_limit import (
        IspRateLimitLookup,
        _isp_customer_cache,
    )
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.isp_partner.zones_config import get_zones_settings
    from app.domains.router.crypto import encrypt_secret

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
            for k in ("ISP_PPPOE_ENABLED",):
                os.environ[k] = "true"
            os.environ.pop("ISP_PARTNER_ENFORCEMENT_ENABLED", None)
            clear()
            register_pppoe_gate(jaze2_pppoe_gate)
            register_pppoe_rate_resolver(jaze2_pppoe_rate)
            cust = (
                await call(
                    "POST",
                    "/customers",
                    {"name": f"e1 {tag}", "contact_email": f"e1{tag}@e.com"},
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
            rtr = (
                await call(
                    "POST",
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

            async def group(name: str, kbps: int) -> str:
                return (
                    await call(
                        "POST",
                        "/speed-groups",
                        {"name": name, "download_kbps": kbps, "upload_kbps": kbps},
                    )
                )["id"]

            g20, g2, g100 = (
                await group("20M", 20480),
                await group("2M", 2048),
                await group("100M", 102400),
            )
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
                        "identifier": f"p{tag}",
                        "package_id": pkg,
                    },
                )
            )["id"]
            await call(
                "PUT",
                f"/subscribers/{sid}/pppoe",
                {"username": f"pp{tag}", "password": "Secret-12345"},
            )
            # a regular Wyfy tenant (not an ISP customer) with its own NAS
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
                nas = RadiusNasClient(
                    router_id=uuid.UUID(rtr),
                    organization_id=uuid.UUID(cust),
                    location_id=uuid.UUID(loc),
                    nas_identifier=f"nas-{tag}",
                    shared_secret_encrypted=encrypt_secret("s"),
                )
                s.add(nas)
                await s.commit()
                nas_id, reg_id = nas.id, reg.id

            uname = f"pp{tag}"
            m1, m2 = "AA:00:00:00:00:01", "AA:00:00:00:00:02"

            async def auth(mac: str, nas_override=None) -> dict:  # noqa: ANN001
                async with SessionLocal() as s:
                    n = nas_override or await s.get(RadiusNasClient, nas_id)
                    out = await IspPppoeService(session=s).authorize(
                        nas_client=n, username=uname, calling_station_id=mac
                    )
                    await s.commit()
                    return out

            async def policy(**kw) -> None:  # noqa: ANN003
                await call("PUT", f"/packages/{pkg}/policy", kw)

            async def events() -> list[str]:
                ev = await call(
                    "GET", f"/subscribers/{sid}/enforcement-events?limit=200"
                )
                return [e["kind"] for e in ev]

            # flag OFF: rules stored, Authorize exactly as JAZE-6 alone ----------
            await policy(
                mac_bind_count=1,
                idle_timeout_s=600,
                hard_timeout_s=3600,
                max_simultaneous=1,
                queue_priority=3,
            )
            base = await auth(m1)
            assert "reply:Idle-Timeout" not in base
            assert base["reply:Mikrotik-Rate-Limit"] == "20480k/20480k"
            assert (await auth(m2))["reply:Mikrotik-Rate-Limit"] == "20480k/20480k"
            assert await events() == []

            os.environ["ISP_PARTNER_ENFORCEMENT_ENABLED"] = "true"
            clear()

            # MAC bind + restriction, timeouts, priority --------------------------
            r = await auth(m1)
            assert r["reply:Idle-Timeout"] == 600 and r["reply:Session-Timeout"] == 3600
            assert r["reply:Mikrotik-Rate-Limit"] == "20480k/20480k 0k/0k 0k/0k 0/0 3"
            macs = await call("GET", f"/subscribers/{sid}/mac-bindings")
            assert [x["mac"] for x in macs] == [m1] and macs[0]["source"] == "auto"
            r = await auth(m2)
            assert r == {
                "control:Auth-Type": "Reject",
                "reply:Reply-Message": "wyfy:mac_not_bound",
            } or (r.get("control:Auth-Type") == "Reject"), r
            assert {"mac_bound", "mac_reject"} <= set(await events())

            # concurrency: same device reconnecting is fine; another live one is not
            async with SessionLocal() as s:
                cred = (
                    await s.execute(
                        select(IspPppoeCredential).where(
                            IspPppoeCredential.subscriber_id == uuid.UUID(sid)
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
                        username=uname,
                        acct_session_id=f"a1{tag}",
                        calling_station_id=m1,
                        started_at=datetime.now(UTC) - timedelta(minutes=5),
                        last_update_at=datetime.now(UTC),
                        status="active",
                        bytes_uploaded=0,
                        bytes_downloaded=0,
                    )
                )
                await s.commit()
            assert "control:Cleartext-Password" in await auth(m1)  # its own device
            await policy(max_simultaneous=1)  # MAC rules off now
            r = await auth(m2)
            assert r.get("control:Auth-Type") == "Reject", r
            assert "concurrency" in await events()
            await policy(max_simultaneous=2)
            assert "control:Cleartext-Password" in await auth(m2)

            # IP restriction -------------------------------------------------------
            await policy(ip_restriction=True)
            r = await auth(m1)
            assert r.get("control:Auth-Type") == "Reject", r
            assert "ip_reject" in await events()
            async with SessionLocal() as s:
                s.add(
                    DhcpPool(
                        router_id=uuid.UUID(rtr),
                        organization_id=uuid.UUID(cust),
                        location_id=uuid.UUID(loc),
                        name="lan",
                        address_range_start="10.5.60.1",
                        address_range_end="10.5.60.9",
                        gateway_ip_address="10.5.60.1",
                    )
                )
                await s.commit()
                pool_id = (
                    await s.execute(
                        select(DhcpPool.id).where(
                            DhcpPool.name == "lan", DhcpPool.router_id == uuid.UUID(rtr)
                        )
                    )
                ).scalar_one()
            b = await call(
                "POST",
                f"/subscribers/{sid}/ip-bindings",
                {"isp_location_id": loc, "pool_id": str(pool_id)},
            )
            r = await auth(m1)
            assert r["reply:Framed-IP-Address"] == b["ip"], r

            # FUP fallback, boost window ------------------------------------------
            now = datetime.now(UTC)
            ist = now.astimezone(ZoneInfo("Asia/Kolkata"))
            m_now = ist.hour * 60 + ist.minute
            await policy(
                fup_limit_mb=1,
                fup_reset="month",
                fup_fallback_speed_group_id=g2,
                boost_speed_group_id=g100,
                boost_start_minute=(m_now - 30) % 1440,
                boost_end_minute=(m_now + 30) % 1440,
            )
            assert (await auth(m1))["reply:Mikrotik-Rate-Limit"] == "102400k/102400k"
            # the sweep counts PPPoE bytes; over 1 MB -> throttled -> fallback
            async with SessionLocal() as s:
                row = (
                    await s.execute(
                        select(IspPppoeSession).where(
                            IspPppoeSession.acct_session_id == f"a1{tag}"
                        )
                    )
                ).scalar_one()
                row.bytes_downloaded = 3 * 1024 * 1024
                await s.commit()
            kicked: list[str] = []

            async def hot(*_a, **_k):  # noqa: ANN002, ANN003, ANN202
                return None

            async def pk(row):  # noqa: ANN001, ANN202
                kicked.append(row.acct_session_id)
                return {"ended": True}

            async with SessionLocal() as s:
                summary = await run_sweep(
                    s, disconnect=hot, live_mode="reauth", pppoe_kick=pk
                )
                await s.commit()
            assert summary["throttled"] == 1, summary
            assert kicked == [f"a1{tag}"]  # live PPPoE re-authorized on the flip
            fup = await call("GET", f"/subscribers/{sid}/fup")
            assert fup["throttled"] and fup["used_bytes"] >= 3 * 1024 * 1024
            assert (await auth(m1))["reply:Mikrotik-Rate-Limit"] == "2048k/2048k"
            # sweep again: totals, not increments -> no double count
            async with SessionLocal() as s:
                await run_sweep(s, disconnect=hot, live_mode="reauth", pppoe_kick=pk)
                await s.commit()
            fup2 = await call("GET", f"/subscribers/{sid}/fup")
            assert fup2["used_bytes"] == fup["used_bytes"]

            # a non-ISP NAS: identical with the flag on or off ---------------------
            fake = SimpleNamespace(
                id=uuid.uuid4(),
                organization_id=reg_id,
                location_id=None,
                router_id=None,
            )
            on = await auth(m1, fake)
            os.environ.pop("ISP_PARTNER_ENFORCEMENT_ENABLED")
            clear()
            off = await auth(m1, fake)
            assert json.dumps(on, sort_keys=True) == json.dumps(off, sort_keys=True)
            assert on.get("control:Auth-Type") == "Reject"

            # hotspot X1 for a regular tenant: the inner reply, byte for byte ------
            class Inner:
                def __init__(self, s):  # noqa: ANN001
                    self.repository = SimpleNamespace(session=s)

                async def rate_limit_reply_for_authorize(self, session_id, **kw):  # noqa: ANN001, ANN003, ANN201
                    return "10240k/10240k"

            outs = []
            for flag in (False, True):
                if flag:
                    os.environ["ISP_PARTNER_ENFORCEMENT_ENABLED"] = "true"
                else:
                    os.environ.pop("ISP_PARTNER_ENFORCEMENT_ENABLED", None)
                clear()
                _isp_customer_cache.clear()
                async with SessionLocal() as s:
                    outs.append(
                        await IspRateLimitLookup(
                            Inner(s)
                        ).rate_limit_reply_for_authorize(
                            uuid.uuid4(), organization_id=reg_id
                        )
                    )
            assert outs == ["10240k/10240k", "10240k/10240k"]
    finally:
        for k in ("ISP_PPPOE_ENABLED", "ISP_PARTNER_ENFORCEMENT_ENABLED"):
            os.environ.pop(k, None)
        clear()
        await engine.dispose()
