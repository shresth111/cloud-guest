"""DASH-1 on real PostgreSQL + Redis (skipped unless ``ISP_TEST_PG_DSN`` is
set; CI has neither). Run against a FRESH scratch DB at head::

    CLOUDGUEST_DATABASE_URL=postgresql+asyncpg://postgres@localhost:55442/isp \
    CLOUDGUEST_REDIS_URL=redis://localhost:56382/0 \
    ISP_TEST_PG_DSN=1 ISP_PARTNER_ENABLED=true \
    python -m pytest tests/unit/test_isp_dashboard_postgres.py

One subscriber per state; every tile equals its drill-down list (also under
each filter and zone), the buckets add up to total, plain-date periods, the
ZONE-1 scope, a confined technician, and another ISP.
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


async def test_dashboard_end_to_end() -> None:  # noqa: PLR0915
    import httpx
    from sqlalchemy import select

    from app.database.session import SessionLocal, engine
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.guest.models import Guest, GuestDevice, GuestSession
    from app.domains.isp_partner.billing_models import IspCustomerServiceState
    from app.domains.isp_partner.compliance_models import IspSubscriberKyc
    from app.domains.isp_partner.dashboard_logic import TILE_KEYS
    from app.domains.isp_partner.dashboard_router import get_dashboard_settings
    from app.domains.isp_partner.models import IspPartnerProfile, IspStaffCustomerScope
    from app.domains.isp_partner.plans_models import IspSubscriber
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.isp_partner.subscriber360_models import IspSubscriberProfile
    from app.domains.isp_partner.zones_config import get_zones_settings
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

            async def dash_b() -> dict:
                return await call("GET", "/dashboard/subscribers", h=hb)

            async def ids(path: str, h=ha) -> set[str]:  # noqa: ANN001
                data = await call("GET", path, h=h)
                items = data["items"] if isinstance(data, dict) else data
                return {i["id"] for i in items}

            # setup: zones, customers, packages ---------------------------------
            os.environ["ISP_ZONES_ENABLED"] = "true"
            get_zones_settings.cache_clear()
            zn = (await call("POST", "/zones/tree", {"name": f"North {tag}"}))["id"]
            zso = (await call("POST", "/zones/tree", {"name": f"South {tag}"}))["id"]

            async def customer(name: str, zone: str | None) -> str:
                body = {"name": f"{name} {tag}", "contact_email": f"{name}{tag}@e.com"}
                cid = (await call("POST", "/customers", body))["id"]
                if zone:
                    await call("PATCH", f"/customers/{cid}", {"zone_id": zone})
                return cid

            c1 = await customer("d1", zn)
            c2 = await customer("d2", zso)
            loc = (
                await call(
                    "POST",
                    f"/customers/{c1}/locations",
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
            g = (
                await call(
                    "POST",
                    "/speed-groups",
                    {"name": "10M", "download_kbps": 10240, "upload_kbps": 10240},
                )
            )["id"]
            pre = (
                await call(
                    "POST",
                    "/packages",
                    {"speed_group_id": g, "type": "prepaid", "price_paise": 10000},
                )
            )["id"]
            post_ = (
                await call(
                    "POST",
                    "/packages",
                    {"speed_group_id": g, "type": "postpaid", "price_paise": 20000},
                )
            )["id"]

            subs: dict[str, str] = {}

            async def sub(key: str, cust: str, pkg: str) -> None:
                subs[key] = (
                    await call(
                        "POST",
                        "/subscribers",
                        {
                            "isp_customer_id": cust,
                            "identifier": f"{key}{tag}",
                            "package_id": pkg,
                        },
                    )
                )["id"]

            for k in (
                "active",
                "expiring",
                "renewal",
                "expired",
                "churned",
                "disabled",
                "blocked",
                "frozen",
                "scheduled",
                "kyc",
                "online",
            ):
                await sub(k, c1, post_ if k == "renewal" else pre)
            await sub("suspended", c2, pre)
            await sub("south_active", c2, pre)
            await call("POST", f"/subscribers/{subs['disabled']}/disable", {})

            now = datetime.now(UTC)
            async with SessionLocal() as s:

                def row(k):  # noqa: ANN001, ANN202
                    return s.get(IspSubscriber, uuid.UUID(subs[k]))

                for k, vu in (
                    ("active", now + timedelta(days=30)),
                    ("expiring", now + timedelta(days=3)),
                    ("renewal", now + timedelta(days=3)),
                    ("expired", now - timedelta(days=5)),
                    ("churned", now - timedelta(days=100)),
                    ("kyc", now + timedelta(days=30)),
                    ("online", now + timedelta(days=30)),
                    ("south_active", now + timedelta(days=30)),
                    ("suspended", now + timedelta(days=30)),
                ):
                    (await row(k)).valid_until = vu
                    if k == "active":
                        (await row(k)).created_at = now - timedelta(days=40)

                def prof(k, **kw):  # noqa: ANN001, ANN003, ANN202
                    return IspSubscriberProfile(
                        isp_organization_id=isps["A"],
                        subscriber_id=uuid.UUID(subs[k]),
                        connection_type="fiber" if k == "kyc" else None,
                        **kw,
                    )

                s.add_all(
                    [
                        prof("blocked", block_kind="temporary", blocked_at=now),
                        prof("frozen", frozen_at=now),
                        prof("scheduled", activation_at=now + timedelta(days=2)),
                        prof("kyc"),
                    ]
                )
                s.add(
                    IspSubscriberKyc(
                        isp_organization_id=isps["A"],
                        subscriber_id=uuid.UUID(subs["kyc"]),
                    )
                )
                s.add(
                    IspCustomerServiceState(
                        isp_organization_id=isps["A"],
                        customer_organization_id=uuid.UUID(c2),
                        state="suspended",
                        requested_at=now,
                    )
                )
                guest = Guest(
                    organization_id=uuid.UUID(c1),
                    location_id=uuid.UUID(loc),
                    identifier=f"online{tag}",
                    first_seen_at=now,
                    last_seen_at=now,
                )
                s.add(guest)
                await s.flush()
                dev = GuestDevice(
                    guest_id=guest.id,
                    mac_address="AA:00:00:00:" + tag[:2] + ":09",
                    first_seen_at=now,
                    last_seen_at=now,
                )
                s.add(dev)
                await s.flush()
                s.add(
                    GuestSession(
                        guest_id=guest.id,
                        device_id=dev.id,
                        router_id=uuid.UUID(rtr),
                        location_id=uuid.UUID(loc),
                        organization_id=uuid.UUID(c1),
                        auth_method="voucher",
                        status="active",
                        started_at=now - timedelta(minutes=5),
                        last_activity_at=now,
                    )
                )
                (await row("online")).guest_id = guest.id
                await s.commit()

            # flag off -> 404 ------------------------------------------------------
            r = await c.get(f"{api}/dashboard/subscribers", headers=ha)
            assert r.status_code == 404 and r.json()["data"]["code"] == (
                "ISP_DASHBOARD_DISABLED"
            )
            os.environ["ISP_DASHBOARD_ENABLED"] = "true"
            get_dashboard_settings.cache_clear()

            async def dash(qs: str = "") -> dict:
                return await call("GET", f"/dashboard/subscribers?{qs}")

            async def drill_all(qs: str, tiles: dict) -> None:
                for key, n in tiles.items():
                    if key not in TILE_KEYS:
                        continue
                    d = await call(
                        "GET",
                        f"/dashboard/subscribers/list?tile={key}&page_size=200&{qs}",
                    )
                    assert d["total"] == n == len(d["items"]), (key, qs, d["total"], n)

            d = await dash()
            t = d["tiles"]
            want = {
                "active": 4,  # active, expiring, renewal, online (c2 is suspended)
                "pending": 2,
                "suspended": 2,
                "frozen": 1,
                "blocked": 1,
                "expired": 1,
                "churned": 1,
                "other": 1,
                "total": 13,
                "online": 1,
                "expiring_7d": 1,
                "scheduled_renewals": 1,
            }
            for k, v in want.items():
                assert t[k] == v, (k, t)
            assert sum(t[b] for b in d["buckets"]) == t["total"]
            assert d["online"]["hotspot_sessions"] == 1
            assert d["online"]["pppoe_enabled"] is False
            assert d["online"]["pppoe_sessions"] == 0
            assert d["pending_leads"] is None  # ISP_APPS_ENABLED off
            await drill_all("", t)
            names = {
                i["id"]
                for i in (
                    await call(
                        "GET", "/dashboard/subscribers/list?tile=pending&page_size=200"
                    )
                )["items"]
            }
            assert names == {subs["scheduled"], subs["kyc"]}

            # filters: package / connection type / router / period ----------------
            fd = await dash(f"package_id={post_}")
            assert fd["tiles"]["total"] == 1 and fd["tiles"]["scheduled_renewals"] == 1
            await drill_all(f"package_id={post_}", fd["tiles"])
            fd = await dash("connection_type=fiber")
            assert fd["tiles"]["total"] == 1 and fd["tiles"]["pending"] == 1
            fd = await dash(f"isp_router_id={rtr}")
            assert fd["tiles"]["total"] == 1 and fd["tiles"]["online"] == 1
            await drill_all(f"isp_router_id={rtr}", fd["tiles"])
            fd = await dash("period=30d")
            assert fd["tiles"]["new_in_period"] == 12  # all but "active" (40 days old)
            fd = await dash("period=today")
            assert fd["tiles"]["new_in_period"] == 12
            r = await c.get(
                f"{api}/dashboard/subscribers?period=custom&date_from=2026-10-01T00:00:00Z",
                headers=ha,
            )
            assert r.status_code == 422, r.text  # plain dates only
            fd = await dash("period=custom&date_from=2020-01-01&date_to=2020-01-31")
            assert fd["tiles"]["new_in_period"] == 0
            assert fd["period"] == {
                "period": "custom",
                "date_from": "2020-01-01",
                "date_to": "2020-01-31",
            }

            # zone scope (ZONE-1) ----------------------------------------------------
            zd = await dash(f"scope_zone_id={zso}")
            assert zd["tiles"]["total"] == 2 and zd["tiles"]["suspended"] == 2
            await drill_all(f"scope_zone_id={zso}", zd["tiles"])
            zd = await dash(f"scope_zone_id={zn}")
            assert zd["tiles"]["total"] == 11
            await drill_all(f"scope_zone_id={zn}", zd["tiles"])

            # confined technician: only c2; a zone never widens it ------------------
            async with SessionLocal() as s:
                s.add(
                    IspStaffCustomerScope(
                        isp_organization_id=isps["A"],
                        user_id=users["T"],
                        customer_organization_id=uuid.UUID(c2),
                    )
                )
                await s.commit()
            as_("T")
            assert (await dash())["tiles"]["total"] == 2
            assert (await dash(f"scope_zone_id={zn}"))["tiles"]["total"] == 0
            r = await c.get(
                f"{api}/dashboard/subscribers?isp_router_id={rtr}", headers=ha
            )
            assert r.status_code == 404, r.text  # c1's router is outside the scope
            as_("A")

            # another ISP sees none of it ---------------------------------------------
            as_("B")
            assert (await dash_b())["tiles"]["total"] == 0
            r = await c.get(
                f"{api}/dashboard/subscribers?isp_router_id={rtr}", headers=hb
            )
            assert r.status_code == 404
            as_("A")
    finally:
        for k in ("ISP_ZONES_ENABLED", "ISP_DASHBOARD_ENABLED"):
            os.environ.pop(k, None)
        get_zones_settings.cache_clear()
        get_dashboard_settings.cache_clear()
        await engine.dispose()
