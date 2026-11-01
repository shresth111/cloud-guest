"""SUB360-2 on real PostgreSQL + Redis (skipped unless ``ISP_TEST_PG_DSN`` is
set; CI has neither). Run against a FRESH scratch DB at head::

    CLOUDGUEST_DATABASE_URL=postgresql+asyncpg://postgres@localhost:55442/isp \
    CLOUDGUEST_REDIS_URL=redis://localhost:56382/0 \
    ISP_TEST_PG_DSN=1 ISP_PARTNER_ENABLED=true \
    python -m pytest tests/unit/test_isp_sub360_workbench_postgres.py

Covers: flag off; the workbench read (live hotspot sessions with NAS/MAC,
services, breadcrumb); a ticket raised from the 360 page through JAZE-5
unchanged, including the RFO rule on close-after-raising, and the open
count; a precise disconnect by MAC and by session; and authz: a technician
confined to another customer and another ISP get 404 on the workbench, its
disconnect, the ticket create and the existing JAZE-1/JAZE-6 disconnects,
without any session being touched; isp-billing gets 403 on every disconnect
(RBAC-FIX R1).
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)


async def test_workbench_ticket_and_disconnect_authz() -> None:  # noqa: PLR0915
    import httpx
    from sqlalchemy import select

    from app.database.session import SessionLocal, engine
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.guest.dependencies import get_guest_service
    from app.domains.guest.models import Guest, GuestDevice, GuestSession
    from app.domains.isp_partner.apps_common import get_isp_apps_settings
    from app.domains.isp_partner.models import IspPartnerProfile, IspStaffCustomerScope
    from app.domains.isp_partner.plans_models import IspSubscriber
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.isp_partner.workbench_router import get_workbench_settings
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
                            Role.slug.in_(
                                ("isp-owner", "isp-technician", "isp-billing")
                            )
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
                    # confinable AND holds isp_subscribers.update
                    bill = person("Bill")
                    s.add(bill)
                    await s.flush()
                    s.add_all(grant(bill, org, "isp-billing"))
                    users["Bi"] = bill.id
            await s.commit()

        app = create_app()
        state = {"user": users["A"]}
        kicked: list[dict] = []

        class _Guests:
            """Records disconnects instead of reaching a router."""

            async def disconnect_session(
                self, *, session_id, requesting_organization_id, actor_user_id, reason
            ):  # noqa: ANN001, ANN202
                kicked.append(
                    {
                        "session_id": str(session_id),
                        "org": str(requesting_organization_id),
                    }
                )
                return SimpleNamespace(disconnect_enforced=True)

        app.dependency_overrides[get_guest_service] = lambda: _Guests()
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
            for k in ("ISP_SUB360_WORKBENCH_ENABLED", "ISP_APPS_ENABLED"):
                os.environ[k] = "true"
            get_workbench_settings.cache_clear()
            get_isp_apps_settings.cache_clear()

            async def customer(name: str) -> str:
                body = {"name": f"{name} {tag}", "contact_email": f"{name}{tag}@e.com"}
                return (await call("POST", "/customers", body))["id"]

            c1, c2 = await customer("w1"), await customer("w2")
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
                        "isp_customer_id": c1,
                        "identifier": f"wb{tag}",
                        "package_id": pkg,
                    },
                )
            )["id"]
            now = datetime.now(UTC)
            mac1 = "AA:00:00:00:" + tag[:2] + ":01"
            mac2 = "AA:00:00:00:" + tag[:2] + ":02"
            async with SessionLocal() as s:
                guest = Guest(
                    organization_id=uuid.UUID(c1),
                    location_id=uuid.UUID(loc),
                    identifier=f"wbg{tag}",
                    first_seen_at=now,
                    last_seen_at=now,
                )
                s.add(guest)
                await s.flush()
                sess = []
                for mac in (mac1, mac2):
                    d = GuestDevice(
                        guest_id=guest.id,
                        mac_address=mac,
                        first_seen_at=now,
                        last_seen_at=now,
                    )
                    s.add(d)
                    await s.flush()
                    gs = GuestSession(
                        guest_id=guest.id,
                        device_id=d.id,
                        router_id=uuid.UUID(rtr),
                        location_id=uuid.UUID(loc),
                        organization_id=uuid.UUID(c1),
                        auth_method="voucher",
                        status="active",
                        started_at=now - timedelta(minutes=5),
                        last_activity_at=now,
                        ip_address="10.5.50.20",
                    )
                    s.add(gs)
                    sess.append(gs)
                (await s.get(IspSubscriber, uuid.UUID(sid))).guest_id = guest.id
                await s.commit()
                s1, s2 = str(sess[0].id), str(sess[1].id)
                for who in ("T", "Bi"):
                    s.add(
                        IspStaffCustomerScope(
                            isp_organization_id=isps["A"],
                            user_id=users[who],
                            customer_organization_id=uuid.UUID(c2),
                        )
                    )
                await s.commit()

            # flag off -> 404 --------------------------------------------------------
            os.environ.pop("ISP_SUB360_WORKBENCH_ENABLED")
            get_workbench_settings.cache_clear()
            r = await c.get(f"{api}/subscribers/{sid}/workbench", headers=ha)
            assert r.status_code == 404 and r.json()["data"]["code"] == (
                "ISP_SUB360_WORKBENCH_DISABLED"
            )
            os.environ["ISP_SUB360_WORKBENCH_ENABLED"] = "true"
            get_workbench_settings.cache_clear()

            # workbench read ---------------------------------------------------------
            wb = await call("GET", f"/subscribers/{sid}/workbench")
            assert wb["open_tickets"] == 0 and wb["tickets"] == []
            assert {x["session_id"] for x in wb["live"]} == {s1, s2}
            assert {x["mac"] for x in wb["live"]} == {mac1, mac2}
            assert all(x["kind"] == "hotspot" and x["nas"] == "hEX" for x in wb["live"])
            assert wb["auth"]["pppoe"] is False and wb["pppoe_enabled"] is False
            assert [x["kind"] for x in wb["services"]] == ["isp"]
            assert wb["breadcrumb"]["package"]["id"] == pkg
            assert wb["validity"]["seconds_left"] is None or isinstance(
                wb["validity"]["seconds_left"], int
            )

            # raise a ticket from the 360 page (JAZE-5, unchanged) --------------------
            await call("POST", "/apps/ticket-types/defaults", {})
            types = await call("GET", "/apps/ticket-types")
            types = types["items"] if isinstance(types, dict) else types
            rfo_type = next(t for t in types if t["requires_rfo"])
            base = {"isp_customer_id": c1, "subscriber_id": sid, "source": "whatsapp"}
            t1 = await call(
                "POST",
                "/apps/tickets",
                {**base, "type_id": rfo_type["id"], "subject": "No internet since 9"},
            )
            assert t1["subscriber_id"] == sid and t1["status"] == "open"
            await call(
                "POST", f"/apps/tickets/{t1['id']}/comments", {"body": "Called back"}
            )
            r = await c.post(
                f"{api}/apps/tickets",
                json={
                    **base,
                    "type_id": rfo_type["id"],
                    "subject": "Fixed on call",
                    "close_after_raising": True,
                },
                headers=ha,
            )
            assert r.status_code in (409, 422), r.text  # RFO rule (JAZE-5)
            t2 = await call(
                "POST",
                "/apps/tickets",
                {
                    **base,
                    "type_id": rfo_type["id"],
                    "subject": "Fixed on call",
                    "close_after_raising": True,
                    "rfo_reason": "cpe_fault",
                    "resolution_note": "Rebooted the ONT",
                },
            )
            assert t2["status"] in ("closed", "resolved")
            wb = await call("GET", f"/subscribers/{sid}/workbench")
            assert wb["open_tickets"] == 1
            assert {t["id"] for t in wb["tickets"]} == {t1["id"], t2["id"]}

            # precise disconnect: one device ---------------------------------
            r = await call(
                "POST", f"/subscribers/{sid}/workbench/disconnect", {"mac": mac2}
            )
            assert r["ended"] == [s2] and r["unconfirmed"] == []
            assert [k["session_id"] for k in kicked] == [s2]
            r = await call(
                "POST", f"/subscribers/{sid}/workbench/disconnect", {"session_id": s1}
            )
            assert r["ended"] == [s1]
            assert [k["session_id"] for k in kicked] == [s2, s1]
            assert all(k["org"] == c1 for k in kicked)
            r = await c.post(
                f"{api}/subscribers/{sid}/workbench/disconnect",
                json={"bogus": 1},
                headers=ha,
            )
            assert r.status_code == 422  # extra=forbid
            kicked.clear()

            # authz: a technician confined to c2 -> 404 everywhere -----------
            as_("T")
            r = await c.get(f"{api}/subscribers/{sid}/workbench", headers=ha)
            assert r.status_code == 404, r.text
            r = await c.post(
                f"{api}/apps/tickets",
                json={"isp_customer_id": c1, "subscriber_id": sid, "subject": "x"},
                headers=ha,
            )
            assert r.status_code == 404, r.text
            # RBAC-FIX R1: the confined technician now holds
            # isp_subscribers.disconnect, so outside its customer it is 404
            for body in (None, {"mac": mac1}, {"session_id": s1}):
                r = await c.post(
                    f"{api}/subscribers/{sid}/workbench/disconnect",
                    json=body,
                    headers=ha,
                )
                assert r.status_code == 404, (body, r.text)
            # the existing JAZE-1 / JAZE-6 disconnects agree
            for path in (f"{sid}/disconnect", f"{sid}/pppoe/disconnect"):
                r = await c.post(f"{api}/subscribers/{path}", headers=ha)
                assert r.status_code == 404, (path, r.text)
            # isp-billing no longer has a disconnect key (RBAC-FIX R1): 403 on
            # every disconnect route; the workbench read stays scope-404
            as_("Bi")
            assert (
                await c.get(f"{api}/subscribers/{sid}/workbench", headers=ha)
            ).status_code == 404
            for body in (None, {"mac": mac1}, {"session_id": s1}):
                r = await c.post(
                    f"{api}/subscribers/{sid}/workbench/disconnect",
                    json=body,
                    headers=ha,
                )
                assert r.status_code == 403, (body, r.text)
            r = await c.post(f"{api}/subscribers/{sid}/disconnect", headers=ha)
            assert r.status_code == 403, r.text
            # PPPoE is behind its own flag (off here): 404 before the key check
            r = await c.post(f"{api}/subscribers/{sid}/pppoe/disconnect", headers=ha)
            assert r.status_code in (403, 404), r.text

            # authz: another ISP -> 404 ---------------------------------------------
            as_("B")
            r = await c.get(f"{api}/subscribers/{sid}/workbench", headers=hb)
            assert r.status_code == 404, r.text
            r = await c.post(
                f"{api}/subscribers/{sid}/workbench/disconnect", json={}, headers=hb
            )
            assert r.status_code == 404, r.text
            r = await c.post(
                f"{api}/apps/tickets",
                json={"isp_customer_id": c1, "subscriber_id": sid, "subject": "x"},
                headers=hb,
            )
            assert r.status_code == 404, r.text
            assert kicked == []  # no session was touched by a refused call
            as_("A")
    finally:
        for k in ("ISP_SUB360_WORKBENCH_ENABLED", "ISP_APPS_ENABLED"):
            os.environ.pop(k, None)
        get_workbench_settings.cache_clear()
        get_isp_apps_settings.cache_clear()
        await engine.dispose()
