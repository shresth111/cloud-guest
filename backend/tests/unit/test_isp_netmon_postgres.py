"""NETMON-2 on real PostgreSQL + Redis (skipped unless ``ISP_TEST_PG_DSN`` is
set; CI has neither). Fresh scratch DB at head.

Covers: flag off; traffic cards (WAN pick, series from JAZE-2's
throughput_series, "can't read" state + hint without tunnel wording, range
validation); active sessions across routers; completed search by MAC / IP /
subscriber / text / plain dates with guest masking; ZONE-1 scope; CSV
audited; a confined technician and another ISP.
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


async def test_netmon_end_to_end() -> None:  # noqa: PLR0915
    import httpx
    from sqlalchemy import func, select

    from app.database.session import SessionLocal, engine
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.guest.models import Guest, GuestDevice, GuestSession
    from app.domains.isp_partner.models import IspPartnerProfile, IspStaffCustomerScope
    from app.domains.isp_partner.netmon_router import get_netmon_settings
    from app.domains.isp_partner.plans_models import IspSubscriber
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.isp_partner.zones_config import get_zones_settings
    from app.domains.organization.models import Organization, OrganizationMember
    from app.domains.rbac.dependencies import CurrentUser
    from app.domains.rbac.models import AuditLogEntry, Role, UserRole
    from app.domains.rbac.repository import RBACRepository
    from app.domains.rbac.seed import seed_rbac
    from app.domains.router.models import Router
    from app.domains.router_provisioning.models import RouterHealthSnapshot
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

            # setup ----------------------------------------------------------------
            for k in ("ISP_NETMON_ENABLED", "ISP_ZONES_ENABLED"):
                os.environ[k] = "true"
            get_netmon_settings.cache_clear()
            get_zones_settings.cache_clear()
            zn = (await call("POST", "/zones/tree", {"name": f"N {tag}"}))["id"]
            cust, loc, rtr = {}, {}, {}
            for i, n in enumerate(("c1", "c2")):
                cust[n] = (
                    await call(
                        "POST",
                        "/customers",
                        {"name": f"{n} {tag}", "contact_email": f"{n}{tag}@e.com"},
                    )
                )["id"]
                loc[n] = (
                    await call(
                        "POST",
                        f"/customers/{cust[n]}/locations",
                        {
                            "name": "Main",
                            "address_line1": "1",
                            "city": "c",
                            "state_province": "s",
                            "postal_code": "1",
                        },
                    )
                )["id"]
                rtr[n] = (
                    await call(
                        "POST",
                        f"/locations/{loc[n]}/routers",
                        {
                            "name": f"hEX-{n}",
                            "serial_number": f"SN{n}{tag}",
                            "mac_address": f"02:0{i}:"
                            + ":".join(tag[j : j + 2] for j in (0, 2, 4, 6)),
                            "model": "hEX",
                        },
                    )
                )["id"]
            await call("PATCH", f"/customers/{cust['c1']}", {"zone_id": zn})
            g = (
                await call(
                    "POST",
                    "/speed-groups",
                    {"name": "10M", "download_kbps": 10240, "upload_kbps": 10240},
                )
            )["id"]
            pkg = (
                await call(
                    "POST",
                    "/packages",
                    {"speed_group_id": g, "type": "prepaid", "price_paise": 10000},
                )
            )["id"]
            sid = (
                await call(
                    "POST",
                    "/subscribers",
                    {
                        "isp_customer_id": cust["c1"],
                        "identifier": f"u{tag}",
                        "package_id": pkg,
                    },
                )
            )["id"]
            now = datetime.now(UTC)
            macs = ["AA:00:00:" + tag[:2].upper() + f":00:0{i}" for i in range(3)]
            async with SessionLocal() as s:
                r1 = await s.get(Router, uuid.UUID(rtr["c1"]))
                r1.status, r1.last_seen_at, r1.snmp_enabled = "online", now, True
                r1.snmp_last_poll_status = "ok"
                for k in range(6):
                    s.add(
                        RouterHealthSnapshot(
                            router_id=r1.id,
                            recorded_at=now - timedelta(minutes=50 - k * 10),
                            interface_traffic_counters=[
                                {
                                    "if_name": "ether1",
                                    "in_octets": 10**9 + k * 75 * 10**6,
                                    "out_octets": 10**9 + k * 15 * 10**6,
                                },
                                {
                                    "if_name": "bridge",
                                    "in_octets": k * 10**6,
                                    "out_octets": k * 10**6,
                                },
                            ],
                        )
                    )
                guest = Guest(
                    organization_id=uuid.UUID(cust["c1"]),
                    location_id=uuid.UUID(loc["c1"]),
                    identifier=f"98765{tag[:5]}",
                    first_seen_at=now,
                    last_seen_at=now,
                )
                guest2 = Guest(
                    organization_id=uuid.UUID(cust["c2"]),
                    location_id=uuid.UUID(loc["c2"]),
                    identifier=f"guest{tag}@mail.test",
                    first_seen_at=now,
                    last_seen_at=now,
                )
                s.add_all([guest, guest2])
                await s.flush()
                devs = []
                for mac, gg in zip(macs, (guest, guest, guest2), strict=True):
                    d = GuestDevice(
                        guest_id=gg.id,
                        mac_address=mac,
                        first_seen_at=now,
                        last_seen_at=now,
                    )
                    s.add(d)
                    devs.append(d)
                await s.flush()

                def sess(dev, gg, n, *, active, ip, ago_h):  # noqa: ANN001, ANN202
                    return GuestSession(
                        guest_id=gg.id,
                        device_id=dev.id,
                        router_id=uuid.UUID(rtr[n]),
                        location_id=uuid.UUID(loc[n]),
                        organization_id=uuid.UUID(cust[n]),
                        auth_method="voucher",
                        status="active" if active else "ended",
                        started_at=now - timedelta(hours=ago_h + 1),
                        ended_at=None if active else now - timedelta(hours=ago_h),
                        last_activity_at=now,
                        ip_address=ip,
                        bytes_downloaded=1000,
                        bytes_uploaded=100,
                    )

                live = sess(devs[0], guest, "c1", active=True, ip="10.5.50.20", ago_h=0)
                done1 = sess(
                    devs[1], guest, "c1", active=False, ip="10.5.50.21", ago_h=30
                )
                done2 = sess(
                    devs[2], guest2, "c2", active=False, ip="10.6.0.9", ago_h=5
                )
                s.add_all([live, done1, done2])
                (await s.get(IspSubscriber, uuid.UUID(sid))).guest_id = guest.id
                await s.commit()
                ids = {
                    "live": str(live.id),
                    "done1": str(done1.id),
                    "done2": str(done2.id),
                }

            # flag off -> 404 ------------------------------------------------------
            os.environ.pop("ISP_NETMON_ENABLED")
            get_netmon_settings.cache_clear()
            r = await c.get(f"{api}/netmon/traffic", headers=ha)
            assert (
                r.status_code == 404
                and r.json()["data"]["code"] == "ISP_NETMON_DISABLED"
            )
            os.environ["ISP_NETMON_ENABLED"] = "true"
            get_netmon_settings.cache_clear()

            # traffic cards --------------------------------------------------------
            tr = await call("GET", "/netmon/traffic?range=day")
            cards = {x["isp_router_id"]: x for x in tr["routers"]}
            a = cards[rtr["c1"]]
            assert (
                a["readable"]
                and a["wan_interface"] == "ether1"
                and a["wan_basis"] == "name"
            )
            assert a["points"] and a["peak_in_mbps"] == 1.0  # 75 MB / 600 s = 1 Mbps
            b = cards[rtr["c2"]]
            assert (
                not b["readable"] and b["reason"] == "not_set_up" and b["points"] == []
            )
            for card in tr["routers"]:
                low = (card["hint"] or "").lower()
                assert "tunnel" not in low and "wireguard" not in low
            assert (await call("GET", "/netmon/traffic?range=month"))[
                "range"
            ] == "month"
            r = await c.get(f"{api}/netmon/traffic?range=year", headers=ha)
            assert r.status_code == 422

            # active sessions across routers ---------------------------------------
            act = await call("GET", "/netmon/sessions/active")
            assert [x["session_id"] for x in act["items"]] == [ids["live"]]
            x = act["items"][0]
            assert (
                x["subscriber_id"] == sid
                and x["mac"] == macs[0]
                and x["ip"] == "10.5.50.20"
            )
            assert x["bytes_down"] == 1000 and x["uptime_seconds"] >= 3600

            # completed sessions search --------------------------------------------
            async def done(qs: str = "") -> set[str]:
                d = await call("GET", f"/netmon/sessions/completed?{qs}")
                return {i["session_id"] for i in d["items"]}

            assert await done() == {ids["done1"], ids["done2"]}
            assert await done(f"mac={macs[1].lower().replace(':', '-')}") == {
                ids["done1"]
            }
            assert await done("ip=10.6.0.9") == {ids["done2"]}
            assert await done(f"subscriber_id={sid}") == {ids["done1"]}
            assert await done("search=guest") == {ids["done2"]}
            assert await done("date_from=2020-01-01&date_to=2020-01-05") == set()
            masked = (await call("GET", "/netmon/sessions/completed?ip=10.6.0.9"))[
                "items"
            ][0]
            assert (
                masked["who"] != f"guest{tag}@mail.test"
            )  # guest identity masked (F2)
            r = await c.get(f"{api}/netmon/sessions/completed?mac=zz", headers=ha)
            assert r.status_code == 422
            r = await c.get(
                f"{api}/netmon/sessions/completed?date_from=2026-10-31T18:30:00Z",
                headers=ha,
            )
            assert r.status_code == 422  # plain dates only

            # zone scope -----------------------------------------------------------
            assert await done(f"scope_zone_id={zn}") == {ids["done1"]}
            zt = await call("GET", f"/netmon/traffic?scope_zone_id={zn}")
            assert {x["isp_router_id"] for x in zt["routers"]} == {rtr["c1"]}

            # CSV, audited ---------------------------------------------------------
            r = await c.get(f"{api}/netmon/sessions/completed/export.csv", headers=ha)
            assert r.status_code == 200 and macs[1] in r.text and macs[2] in r.text
            async with SessionLocal() as s:
                n = (
                    await s.execute(
                        select(func.count()).where(
                            AuditLogEntry.action == "isp_completed_sessions_exported",
                            AuditLogEntry.organization_id == isps["A"],
                        )
                    )
                ).scalar_one()
            assert n == 1

            # confined technician (c2) and another ISP -----------------------------
            async with SessionLocal() as s:
                s.add(
                    IspStaffCustomerScope(
                        isp_organization_id=isps["A"],
                        user_id=users["T"],
                        customer_organization_id=uuid.UUID(cust["c2"]),
                    )
                )
                await s.commit()
            as_("T")
            assert await done() == {ids["done2"]}
            assert (await call("GET", "/netmon/sessions/active"))["items"] == []
            r = await c.get(
                f"{api}/netmon/sessions/active?isp_router_id={rtr['c1']}", headers=ha
            )
            assert r.status_code == 404
            r = await c.get(
                f"{api}/netmon/sessions/completed?subscriber_id={sid}", headers=ha
            )
            assert r.status_code == 422
            tt = await call("GET", "/netmon/traffic")
            assert {x["isp_router_id"] for x in tt["routers"]} == {rtr["c2"]}
            as_("B")
            d = await call("GET", "/netmon/sessions/completed", h=hb)
            assert d["items"] == []
            assert (await call("GET", "/netmon/traffic", h=hb))["routers"] == []
            as_("A")
    finally:
        for k in ("ISP_NETMON_ENABLED", "ISP_ZONES_ENABLED"):
            os.environ.pop(k, None)
        get_netmon_settings.cache_clear()
        get_zones_settings.cache_clear()
        await engine.dispose()
