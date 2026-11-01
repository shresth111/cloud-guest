"""ENFORCE-3 on real PostgreSQL + Redis (skipped unless ``ISP_TEST_PG_DSN``
is set; CI has neither).

- Partner enrolment fills ``routers.management_ip_address`` from the tunnel
  peer only while it is empty.
- The PPPoE script keeps ``only-one=yes`` byte-identical with the flag off,
  and with the flag on unless the ISP sells a package allowing more than one
  device; then ``only-one=no`` (the only changed token).
- With ``only-one=no`` the PPPoE gate enforces the device limit: the
  package's ``max_simultaneous``, and 1 for a package without one.
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


async def test_enforce3_end_to_end() -> None:  # noqa: PLR0915
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
    from app.domains.isp_partner.pppoe_models import IspPppoeCredential, IspPppoeSession
    from app.domains.isp_partner.pppoe_service import IspPppoeService
    from app.domains.isp_partner.router import _fill_management_ip
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.isp_partner.zones_config import get_zones_settings
    from app.domains.router.crypto import encrypt_secret
    from app.domains.router.models import Router
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

            # 1. management IP from the tunnel peer, only while empty ------------
            async with SessionLocal() as s:
                await _fill_management_ip(s, uuid.UUID(rtr))
                await s.commit()
            async with SessionLocal() as s:
                r = await s.get(Router, uuid.UUID(rtr))
                assert r.management_ip_address == "10.66.0.50"
                r.management_ip_address = "10.66.0.99"  # the heartbeat said so
                await s.commit()
            async with SessionLocal() as s:
                await _fill_management_ip(s, uuid.UUID(rtr))
                await s.commit()
            async with SessionLocal() as s:
                assert (
                    await s.get(Router, uuid.UUID(rtr))
                ).management_ip_address == "10.66.0.99"

            # 2. PPPoE script only-one -----------------------------------------
            async def group(name: str) -> str:
                return (
                    await call(
                        "POST",
                        "/speed-groups",
                        {"name": name, "download_kbps": 1024, "upload_kbps": 1024},
                    )
                )["id"]

            g = await group("1M")
            g2 = await group("2M")
            pkg_a = (
                await call(
                    "POST",
                    "/packages",
                    {"speed_group_id": g, "type": "prepaid", "price_paise": 100},
                )
            )["id"]
            pkg_b = (
                await call(
                    "POST",
                    "/packages",
                    {"speed_group_id": g2, "type": "prepaid", "price_paise": 200},
                )
            )["id"]

            async def script() -> str:
                r = await c.get(
                    f"{api}/pppoe/routers/{rtr}/script?interface=ether2", headers=ha
                )
                assert r.status_code == 200, r.text
                return r.text

            off = await script()
            assert " only-one=yes " in off
            os.environ["ISP_PARTNER_ENFORCEMENT_ENABLED"] = "true"
            clear()
            assert await script() == off  # no multi-device package yet
            await call("PUT", f"/packages/{pkg_b}/policy", {"max_simultaneous": 2})
            multi = await script()
            assert multi == off.replace(" only-one=yes ", " only-one=no ", 1)
            assert multi.count("only-one=") == 1
            os.environ.pop("ISP_PARTNER_ENFORCEMENT_ENABLED")
            clear()
            assert await script() == off  # flag off: byte-identical again

            # 3. the gate enforces the limit when only-one=no -------------------
            os.environ["ISP_PARTNER_ENFORCEMENT_ENABLED"] = "true"
            clear()

            async def subscriber(ident: str, pkg: str) -> tuple[str, str]:
                sid = (
                    await call(
                        "POST",
                        "/subscribers",
                        {
                            "isp_customer_id": cust,
                            "identifier": ident,
                            "package_id": pkg,
                        },
                    )
                )["id"]
                await call(
                    "PUT",
                    f"/subscribers/{sid}/pppoe",
                    {"username": ident, "password": "Secret-12345"},
                )
                return sid, ident

            async def live(sid: str, uname: str, mac: str, n: int) -> None:
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
                            acct_session_id=f"{uname}-{n}",
                            calling_station_id=mac,
                            started_at=datetime.now(UTC),
                            last_update_at=datetime.now(UTC),
                            status="active",
                            bytes_uploaded=0,
                            bytes_downloaded=0,
                        )
                    )
                    await s.commit()

            async def auth(uname: str, mac: str) -> dict:
                async with SessionLocal() as s:
                    n = await s.get(RadiusNasClient, nas_id)
                    out = await IspPppoeService(session=s).authorize(
                        nas_client=n, username=uname, calling_station_id=mac
                    )
                    await s.commit()
                    return out

            m1, m2, m3 = "AA:E3:00:00:00:01", "AA:E3:00:00:00:02", "AA:E3:00:00:00:03"
            sa, ua = await subscriber(f"a{tag}", pkg_a)  # no device limit
            await live(sa, ua, m1, 1)
            assert "control:Cleartext-Password" in await auth(ua, m1)  # own device
            r = await auth(ua, m2)
            assert r.get("reply:Reply-Message") == "wyfy:concurrency", r
            sb, ub = await subscriber(f"b{tag}", pkg_b)  # limit 2
            await live(sb, ub, m1, 1)
            assert "control:Cleartext-Password" in await auth(ub, m2)
            await live(sb, ub, m2, 2)
            r = await auth(ub, m3)
            assert r.get("reply:Reply-Message") == "wyfy:concurrency", r
            # flag off: no gate at all (the router's only-one=yes is back)
            os.environ.pop("ISP_PARTNER_ENFORCEMENT_ENABLED")
            clear()
            assert "control:Cleartext-Password" in await auth(ua, m2)
    finally:
        for k in ("ISP_PPPOE_ENABLED", "ISP_PARTNER_ENFORCEMENT_ENABLED"):
            os.environ.pop(k, None)
        clear()
        await engine.dispose()
