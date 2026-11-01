"""ZONE-1 on real PostgreSQL + Redis (skipped unless ``ISP_TEST_PG_DSN`` is
set; CI has neither). Run against a FRESH scratch DB at head::

    CLOUDGUEST_DATABASE_URL=postgresql+asyncpg://postgres@localhost:55442/isp \\
    CLOUDGUEST_REDIS_URL=redis://localhost:56382/0 \\
    ISP_TEST_PG_DSN=1 ISP_PARTNER_ENABLED=true \\
    python -m pytest tests/unit/test_isp_zone_tree_postgres.py

Covers: flag off (404 + scope ignored), tree create/move/cycle guard/foreign
parent, tree payload, ``scope_zone_id`` on customers / subscribers / the 360
directory expanding to descendants, the subscriber zone falling back to the
customer zone, a foreign or garbage zone -> 404, a confined technician only
ever NARROWED (never widened, empty means empty), the scope not leaking into
the next request, delete guards, and totals.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, date, datetime
from decimal import Decimal

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)


async def test_zone_tree_end_to_end() -> None:  # noqa: PLR0915
    import httpx
    from sqlalchemy import select

    from app.database.session import SessionLocal, engine
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.isp_partner.models import IspPartnerProfile, IspStaffCustomerScope
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
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

            async def ids(path: str, h=ha) -> set[str]:  # noqa: ANN001
                data = await call("GET", path, h=h)
                items = data["items"] if isinstance(data, dict) else data
                return {i["id"] for i in items}

            # zones (flat, existing API) -------------------------------------
            zn = (await call("POST", "/zones", {"name": f"North {tag}"}))["id"]
            as_("B")
            zb = (await call("POST", "/zones", {"name": f"Other {tag}"}, h=hb))["id"]
            as_("A")

            # flag OFF: tree 404, scope ignored --------------------------------
            r = await c.get(f"{api}/zones/tree", headers=ha)
            assert r.status_code == 404 and r.json()["data"]["code"] == (
                "ISP_ZONES_DISABLED"
            ), r.text
            r = await c.get(f"{api}/customers?scope_zone_id={zb}", headers=ha)
            assert r.status_code == 200, r.text  # ignored, not a 404

            os.environ["ISP_ZONES_ENABLED"] = "true"
            get_zones_settings.cache_clear()

            # tree: North > Sector > Block; South --------------------------------
            zs = (
                await call("POST", "/zones/tree", {"name": "Sector", "parent_id": zn})
            )["id"]
            block = await call(
                "POST", "/zones/tree", {"name": "Block", "parent_id": zs}
            )
            zbl = block["id"]
            assert block["depth"] == 2 and block["path_names"] == [
                f"North {tag}",
                "Sector",
                "Block",
            ]
            zso = (await call("POST", "/zones/tree", {"name": f"South {tag}"}))["id"]
            # foreign parent on create -> 404, nothing created
            await call("POST", "/zones/tree", {"name": "X", "parent_id": zb}, ok=(404,))

            # cycle guard + foreign parent on move
            for bad in (zn, zbl, zs):
                r = await c.put(
                    f"{api}/zones/{zn}/parent", json={"parent_id": bad}, headers=ha
                )
                assert r.status_code == 409, r.text
                assert r.json()["data"]["code"] == "ISP_ZONE_CYCLE"
            r = await c.put(
                f"{api}/zones/{zn}/parent", json={"parent_id": zb}, headers=ha
            )
            assert r.status_code == 404, r.text
            r = await c.put(
                f"{api}/zones/{zb}/parent", json={"parent_id": None}, headers=ha
            )
            assert r.status_code == 404, r.text
            # move South under North and back
            moved = await call("PUT", f"/zones/{zso}/parent", {"parent_id": zn})
            assert moved["parent_id"] == zn and moved["depth"] == 1
            moved = await call("PUT", f"/zones/{zso}/parent", {"parent_id": None})
            assert moved["parent_id"] is None and moved["depth"] == 0

            # customers / subscribers ------------------------------------------
            async def customer(name: str, zone: str | None) -> str:
                body = {"name": f"{name} {tag}", "contact_email": f"{name}{tag}@e.com"}
                cid = (await call("POST", "/customers", body))["id"]
                if zone:  # zone is edit-only (ADDENDUM_03 §4)
                    await call("PATCH", f"/customers/{cid}", {"zone_id": zone})
                return cid

            c1 = await customer("c1", zs)  # in Sector
            c2 = await customer("c2", zso)  # in South
            c3 = await customer("c3", None)  # no zone
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

            async def subscriber(cust: str, ident: str, zone: str | None) -> str:
                sid = (
                    await call(
                        "POST",
                        "/subscribers",
                        {
                            "isp_customer_id": cust,
                            "identifier": f"{ident}{tag}",
                            "package_id": pkg,
                        },
                    )
                )["id"]
                if zone:
                    await call("PATCH", f"/subscribers/{sid}", {"zone_id": zone})
                return sid

            s1 = await subscriber(c1, "s1", None)  # falls back to c1 -> Sector
            s2 = await subscriber(c3, "s2", zbl)  # own zone Block, customer has none
            s3 = await subscriber(c2, "s3", None)  # falls back to c2 -> South

            # tree payload
            tree = {n["id"]: n for n in (await call("GET", "/zones/tree"))["items"]}
            assert tree[zn]["subtree_customers"] == 1  # c1 (profile zone)
            assert tree[zn]["subtree_subscribers"] == 1  # s2 (own zone)
            assert tree[zn]["children"] == 1 and not tree[zn]["can_delete"]
            assert zb not in tree  # another ISP's zone is never listed

            # scope: owner ------------------------------------------------------
            q = "?page_size=100&scope_zone_id="
            assert await ids(f"/customers{q}{zn}") == {c1, c3}  # c3 holds s2
            assert await ids(f"/subscribers{q}{zn}") == {s1, s2}
            assert await ids(f"/customers{q}{zso}") == {c2}
            assert await ids(f"/subscribers{q}{zso}") == {s3}
            assert await ids(f"/customers{q}{zbl}") == {c3}
            assert await ids(f"/subscribers{q}{zbl}") == {s2}
            # Subscriber 360 directory (JAZE-1) follows without being edited
            d = await call("GET", f"/subscribers/directory{q}{zn}")
            assert {i["id"] for i in d["items"]} == {s1, s2}, d
            # the scope ends with the request
            assert {c1, c2, c3} <= await ids("/customers?page_size=100")
            assert {s1, s2, s3} <= await ids("/subscribers?page_size=100")
            # a subscriber outside the zone is a 404 inside it
            await call("GET", f"/subscribers/{s3}{q}{zn}", ok=(404,))

            # customer-owned resources follow confinement: locations
            loc_body = {
                "name": "Main",
                "address_line1": "1",
                "city": "c",
                "state_province": "s",
                "postal_code": "1",
            }
            l1 = (await call("POST", f"/customers/{c1}/locations", loc_body))["id"]
            l2 = (await call("POST", f"/customers/{c2}/locations", loc_body))["id"]
            assert await ids(f"/locations{q}{zn}") == {l1}
            assert await ids(f"/locations{q}{zso}") == {l2}
            await call("GET", f"/locations/{l2}{q}{zn}", ok=(404,))

            # foreign / garbage zone -> 404
            for bad in (zb, "not-a-uuid", str(uuid.uuid4())):
                r = await c.get(f"{api}/customers?scope_zone_id={bad}", headers=ha)
                assert r.status_code == 404, (bad, r.text)
                assert r.json()["data"]["code"] == "ISP_ZONE_NOT_FOUND"

            # scope: confined technician (c1 only) -------------------------------
            async with SessionLocal() as s:
                s.add(
                    IspStaffCustomerScope(
                        isp_organization_id=isps["A"],
                        user_id=users["T"],
                        customer_organization_id=uuid.UUID(c1),
                    )
                )
                await s.commit()
            as_("T")
            assert await ids("/customers?page_size=100") == {c1}
            assert await ids(f"/customers{q}{zn}") == {c1}  # c3 not widened in
            assert await ids(f"/subscribers{q}{zn}") == {s1}
            assert await ids(f"/customers{q}{zso}") == set()  # empty, never "all"
            assert await ids(f"/subscribers{q}{zso}") == set()
            assert await ids(f"/customers{q}{zbl}") == set()
            as_("A")

            # delete guards ----------------------------------------------------
            r = await c.delete(f"{api}/zones/{zbl}/tree", headers=ha)
            assert r.status_code == 409, r.text
            assert r.json()["data"]["code"] == "ISP_ZONE_IN_USE"
            assert r.json()["data"]["subscribers"] == 1
            r = await c.delete(f"{api}/zones/{zn}/tree", headers=ha)
            assert r.status_code == 409 and r.json()["data"]["code"] == (
                "ISP_ZONE_HAS_CHILDREN"
            )
            leaf = (
                await call("POST", "/zones/tree", {"name": "Empty", "parent_id": zs})
            )["id"]
            await call("DELETE", f"/zones/{leaf}/tree")
            tree = {n["id"] for n in (await call("GET", "/zones/tree"))["items"]}
            assert leaf not in tree
            as_("B")
            r = await c.delete(f"{api}/zones/{zn}/tree", headers=hb)
            assert r.status_code == 404, r.text
            as_("A")

            # subtree + totals -------------------------------------------------
            st = await call("GET", f"/zones/{zn}/subtree")
            assert set(st["zone_ids"]) == {zn, zs, zbl}
            today = date.today().isoformat()
            tot = await call("GET", f"/zones/totals?date_from={today}&date_to={today}")
            rows = {t["zone_id"]: t for t in tot["items"]}
            assert tot["ledger_enabled"] is False and rows[zn]["balance_paise"] is None
            assert rows[zn]["subtree_subscribers"] == 1
            assert rows[zn]["subtree_invoiced_paise"] == 0
    finally:
        os.environ.pop("ISP_ZONES_ENABLED", None)
        get_zones_settings.cache_clear()
        await engine.dispose()
