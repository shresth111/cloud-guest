"""ENFORCE-4 (BE review F5) on real PostgreSQL (skipped unless
``ISP_TEST_PG_DSN``). RouterOS restarts its Acct-Session-Id counter after a
reboot: a Start reusing a closed session's id must open a NEW row (the old
one is kept for IPDR), late Stop/interim retransmits still land on the
session that just closed, and the new live session counts for concurrency.
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


async def test_enforce4_pppoe_session_id_reuse() -> None:  # noqa: PLR0915
    import httpx
    from sqlalchemy import select

    from app.database.session import SessionLocal, engine
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.guest.models import RadiusNasClient
    from app.domains.isp_partner.config import get_isp_partner_settings
    from app.domains.isp_partner.enforcement_pppoe import (
        jaze2_pppoe_gate,
        jaze2_pppoe_rate,
    )
    from app.domains.isp_partner.models import IspPartnerProfile
    from app.domains.isp_partner.pppoe_config import get_isp_pppoe_settings
    from app.domains.isp_partner.pppoe_hooks import (
        register_pppoe_gate,
        register_pppoe_rate_resolver,
    )
    from app.domains.isp_partner.pppoe_models import IspPppoeSession
    from app.domains.isp_partner.pppoe_service import IspPppoeService
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.isp_partner.zones_config import get_zones_settings
    from app.domains.router.crypto import encrypt_secret
    from app.domains.wireguard.models import WireGuardPeer, WireGuardServer

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

            os.environ["ISP_PPPOE_ENABLED"] = "true"
            os.environ.pop("ISP_PARTNER_ENFORCEMENT_ENABLED", None)
            clear()
            register_pppoe_gate(jaze2_pppoe_gate)
            register_pppoe_rate_resolver(jaze2_pppoe_rate)
            cust = (
                await call(
                    "POST",
                    "/customers",
                    {"name": f"e3 {tag}", "contact_email": f"e3{tag}@e.com"},
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
            async with SessionLocal() as s:
                srv = WireGuardServer(
                    name=f"hub {tag}",
                    endpoint_host="203.0.113.1",
                    endpoint_port=51820,
                    public_key=f"srv{tag}".ljust(44, "A"),
                    private_key_encrypted=encrypt_secret("k"),
                    tunnel_network_cidr="10.66.0.0/24",
                )
                s.add(srv)
                await s.flush()
                s.add(
                    WireGuardPeer(
                        router_id=uuid.UUID(rtr),
                        server_id=srv.id,
                        tunnel_ip_address="10.66.0.50",
                        public_key=f"peer{tag}".ljust(44, "A"),
                        private_key_encrypted=encrypt_secret("k"),
                        status="active",
                    )
                )
                nas = RadiusNasClient(
                    router_id=uuid.UUID(rtr),
                    organization_id=uuid.UUID(cust),
                    location_id=uuid.UUID(loc),
                    nas_identifier=f"nas-{tag}",
                    shared_secret_encrypted=encrypt_secret("s3cret"),
                )
                s.add(nas)
                await s.commit()
                nas_id = nas.id

            from sqlalchemy.exc import IntegrityError

            g = (
                await call(
                    "POST",
                    "/speed-groups",
                    {"name": "1M", "download_kbps": 1024, "upload_kbps": 1024},
                )
            )["id"]
            pkg = (
                await call(
                    "POST",
                    "/packages",
                    {"speed_group_id": g, "type": "prepaid", "price_paise": 100},
                )
            )["id"]
            sid = (
                await call(
                    "POST",
                    "/subscribers",
                    {
                        "isp_customer_id": cust,
                        "identifier": f"r{tag}",
                        "package_id": pkg,
                    },
                )
            )["id"]
            await call(
                "PUT",
                f"/subscribers/{sid}/pppoe",
                {"username": f"r{tag}", "password": "Secret-12345"},
            )
            clock = {"t": datetime.now(UTC)}

            async def acct(status: str, **kw) -> dict:  # noqa: ANN003
                async with SessionLocal() as s:
                    svc = IspPppoeService(session=s)
                    svc._clock = lambda: clock["t"]
                    n = await s.get(RadiusNasClient, nas_id)
                    out = await svc.accounting(
                        nas_client=n,
                        payload={
                            "status_type": status,
                            "username": f"r{tag}",
                            "session_id": "81000001",
                            "calling_station_id": "AA:E4:00:00:00:01",
                            **kw,
                        },
                    )
                    await s.commit()
                    return out

            async def rows() -> list:
                async with SessionLocal() as s:
                    return list(
                        (
                            await s.execute(
                                select(IspPppoeSession)
                                .where(IspPppoeSession.nas_client_id == nas_id)
                                .order_by(IspPppoeSession.started_at)
                            )
                        ).scalars()
                    )

            def tick(seconds: int) -> None:
                clock["t"] = clock["t"] + timedelta(seconds=seconds)

            r1 = await acct("start")
            tick(60)
            await acct("interim-update", bytes_downloaded_total=1000)
            tick(5)
            await acct("accounting-on")  # router rebooted
            closed_at = (await rows())[0].stopped_at
            tick(10)  # its Stop arrives late
            await acct("stop", bytes_downloaded_total=2000, disconnect_reason="lost")
            [old] = await rows()
            assert old.status == "closed" and old.stopped_at == closed_at
            assert old.bytes_downloaded == 2000 and old.terminate_cause == "lost"

            tick(120)  # the counter restarted: the same id, a new session
            r2 = await acct("start")
            assert r2["status"] == "active" and r2["session_id"] != r1["session_id"]
            tick(60)
            await acct("interim-update", bytes_downloaded_total=500)
            old, new = await rows()
            assert (old.status, old.bytes_downloaded) == ("closed", 2000)
            assert (new.status, new.bytes_downloaded) == ("active", 500)
            assert new.started_at > old.stopped_at

            # the live session is visible to the concurrency gate
            os.environ["ISP_PARTNER_ENFORCEMENT_ENABLED"] = "true"
            clear()
            await call("PUT", f"/packages/{pkg}/policy", {"max_simultaneous": 1})
            async with SessionLocal() as s:
                out = await IspPppoeService(session=s).authorize(
                    nas_client=await s.get(RadiusNasClient, nas_id),
                    username=f"r{tag}",
                    calling_station_id="AA:E4:00:00:00:02",
                )
                await s.rollback()
            assert out.get("reply:Reply-Message") == "wyfy:concurrency", out
            os.environ.pop("ISP_PARTNER_ENFORCEMENT_ENABLED")
            clear()

            tick(30)
            await acct("stop", bytes_downloaded_total=900)
            tick(200)  # a Stop long after: not a retransmit -> its own row
            await acct("start")
            a, b, c = await rows()
            assert [x.status for x in (a, b, c)] == ["closed", "closed", "active"]
            assert b.bytes_downloaded == 900

            # only one OPEN row per id: the partial unique index holds
            async with SessionLocal() as s:
                s.add(
                    IspPppoeSession(
                        isp_organization_id=c.isp_organization_id,
                        customer_organization_id=c.customer_organization_id,
                        nas_client_id=nas_id,
                        username=c.username,
                        acct_session_id="81000001",
                        started_at=clock["t"],
                        last_update_at=clock["t"],
                        status="active",
                    )
                )
                try:
                    await s.commit()
                    raise AssertionError("two open rows for one id")
                except IntegrityError:
                    await s.rollback()
    finally:
        for k in ("ISP_PPPOE_ENABLED", "ISP_PARTNER_ENFORCEMENT_ENABLED"):
            os.environ.pop(k, None)
        clear()
        await engine.dispose()
