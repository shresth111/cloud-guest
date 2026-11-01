# ruff: noqa: E501, PLR0915 -- scenario test
"""SCOPE-FIX: every ``*_id`` the ISP console takes in a path is resolved inside
the caller's ISP and customer scope, on real PostgreSQL + Redis (skipped
unless ``ISP_TEST_PG_DSN``). Run::

    CLOUDGUEST_DATABASE_URL=postgresql+asyncpg://postgres@localhost:55441/scopefix \\
    CLOUDGUEST_REDIS_URL=redis://localhost:56381/0 \\
    ISP_TEST_PG_DSN=1 ISP_PARTNER_ENABLED=true ISP_APPS_ENABLED=true \\
    ISP_FIBER_ENABLED=true ISP_FINANCE_EXTRAS_ENABLED=true \\
    python -m pytest tests/unit/test_isp_scope_fix_postgres.py

ISP A has customers A1 and A2; a technician and a billing user are both
confined to A1. For each classified parameter the test proves:

* ISP B's owner, sending its own org header, gets 404 on A's id;
* a confined user gets 404 on the A2 row and NOT 404 on the A1 row (the
  positive control: the route is mounted and the row is reachable).

It also covers the two handler fixes: a confined caller's fiber route stops
at another customer's node instead of listing it, and a confined caller may
not link another customer's TR-069 device to an inventory unit.
"""

from __future__ import annotations

import os
import random
import uuid
from datetime import UTC, date, datetime
from decimal import Decimal

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)


async def test_path_ids_are_resolved_inside_isp_and_customer_scope() -> None:
    import httpx
    from sqlalchemy import select

    from app.database.session import SessionLocal
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.isp_partner import apps2_models as A2
    from app.domains.isp_partner import apps_models as A
    from app.domains.isp_partner.apps_common import get_isp_apps_settings
    from app.domains.isp_partner.compliance_models import IspSubscriberDocument
    from app.domains.isp_partner.enforcement_models import IspSubscriberMacBinding
    from app.domains.isp_partner.fiber_models import IspFiberNode
    from app.domains.isp_partner.fiber_service import get_isp_fiber_settings
    from app.domains.isp_partner.finance_config import get_finance_settings
    from app.domains.isp_partner.finance_models import (
        IspBillingProduct,
        IspStaticIpLease,
    )
    from app.domains.isp_partner.models import IspPartnerProfile, IspStaffCustomerScope
    from app.domains.isp_partner.plans_models import IspSubscriber
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.organization.models import Organization, OrganizationMember
    from app.domains.rbac.dependencies import CurrentUser
    from app.domains.rbac.models import Role, UserRole
    from app.domains.rbac.repository import RBACRepository
    from app.domains.rbac.seed import seed_rbac
    from app.domains.tr069.models import Tr069Device
    from app.main import create_app

    get_isp_apps_settings.cache_clear()
    get_isp_fiber_settings.cache_clear()
    get_finance_settings.cache_clear()
    tag = uuid.uuid4().hex[:8]
    now = datetime.now(UTC)
    async with SessionLocal() as s:
        await seed_rbac(s)
        await seed_isp_partner_rbac(RBACRepository(s))
        await s.commit()

    users: dict[str, uuid.UUID] = {}
    isps: dict[str, uuid.UUID] = {}
    async with SessionLocal() as s:
        plan = Plan(
            name=f"P {tag}",
            slug=f"psf-{tag}",
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
                        Role.slug.in_(("isp-owner", "isp-technician", "isp-billing"))
                    )
                )
            ).scalars()
        }

        def person(n: str) -> User:
            return User(
                first_name=n,
                last_name="T",
                email=f"sf{n.lower()}{tag}@example.com",
                username=f"sf{n.lower()}{tag}",
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
                    granted_at=now,
                    is_active=True,
                ),
            ]

        for n in ("A", "B"):
            org = Organization(
                name=f"SF {n} {tag}",
                slug=f"sfnet{n.lower()}{tag}",
                org_type="msp",
                status="active",
                contact_email=f"sf{n}{tag}@example.com",
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
                for who, slug in (("Tech", "isp-technician"), ("Bill", "isp-billing")):
                    u = person(who)
                    s.add(u)
                    await s.flush()
                    s.add_all(grant(u, org, slug))
                    users[who] = u.id
        await s.commit()

    app = create_app()
    state = {"user": users["A"]}
    app.dependency_overrides[CurrentUser] = lambda: AuthUser(
        id=str(state["user"]), email="o@example.com"
    )
    ha = {"X-Organization-Id": str(isps["A"])}
    hb = {"X-Organization-Id": str(isps["B"])}
    api = "/api/v1/isp"

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t"
    ) as c:

        async def customer(name: str) -> uuid.UUID:
            r = await c.post(
                f"{api}/customers",
                json={
                    "name": f"{name} {tag}",
                    "contact_email": f"{name.lower()}{tag}@example.com",
                },
                headers=ha,
            )
            assert r.status_code == 201, r.text
            return uuid.UUID(r.json()["data"]["id"])

        a1, a2 = await customer("SfA1"), await customer("SfA2")

        ids: dict[str, uuid.UUID] = {}
        async with SessionLocal() as s:
            isp_a = isps["A"]
            for who in ("Tech", "Bill"):
                s.add(
                    IspStaffCustomerScope(
                        isp_organization_id=isp_a,
                        user_id=users[who],
                        customer_organization_id=a1,
                    )
                )

            def add(key: str, row):
                s.add(row)
                return row

            subs = {}
            for k, cust in (("1", a1), ("2", a2)):
                subs[k] = add(
                    f"sub{k}",
                    IspSubscriber(
                        isp_organization_id=isp_a,
                        customer_organization_id=cust,
                        identifier=f"sf{k}{tag}",
                        status="active",
                        source="manual",
                        circuit_id=random.randint(10_000_000, 99_999_999),
                    ),
                )
            item = add(
                "item",
                A.IspInventoryItem(
                    isp_organization_id=isp_a, name="ONT", sku=f"S{tag}", category="ont"
                ),
            )
            await s.flush()
            rows = {
                "task1": A.IspFieldTask(
                    isp_organization_id=isp_a,
                    customer_organization_id=a1,
                    kind="repair",
                    title="t1",
                    status="unclaimed",
                ),
                "task2": A.IspFieldTask(
                    isp_organization_id=isp_a,
                    customer_organization_id=a2,
                    kind="repair",
                    title="t2",
                    status="unclaimed",
                ),
                "lead1": A.IspLead(
                    isp_organization_id=isp_a,
                    customer_organization_id=a1,
                    number=random.randint(1, 10**6),
                    name="l1",
                    source="phone",
                    status="new",
                ),
                "lead2": A.IspLead(
                    isp_organization_id=isp_a,
                    customer_organization_id=a2,
                    number=random.randint(1, 10**6),
                    name="l2",
                    source="phone",
                    status="new",
                ),
                "unit1": A.IspInventoryUnit(
                    isp_organization_id=isp_a,
                    item_id=item.id,
                    serial=f"U1{tag}",
                    state="assigned",
                    state_changed_at=now,
                    customer_organization_id=a1,
                ),
                "unit2": A.IspInventoryUnit(
                    isp_organization_id=isp_a,
                    item_id=item.id,
                    serial=f"U2{tag}",
                    state="assigned",
                    state_changed_at=now,
                    customer_organization_id=a2,
                ),
                "unitfree": A.IspInventoryUnit(
                    isp_organization_id=isp_a,
                    item_id=item.id,
                    serial=f"UF{tag}",
                    state="in_stock",
                    state_changed_at=now,
                ),
                "type": A.IspTicketType(isp_organization_id=isp_a, name=f"T {tag}"),
                "discount": A.IspDiscountCode(
                    isp_organization_id=isp_a,
                    code=f"D{tag}".upper(),
                    kind="flat",
                    value=100,
                ),
                "announcement": A.IspAnnouncement(
                    isp_organization_id=isp_a,
                    title="a",
                    body="b",
                    audience="all",
                    status="draft",
                ),
                "vendor": A2.IspInventoryVendor(isp_organization_id=isp_a, name="V"),
                "stockloc": A2.IspStockLocation(
                    isp_organization_id=isp_a, name="W", kind="warehouse"
                ),
                "product": IspBillingProduct(
                    isp_organization_id=isp_a, name=f"Pr {tag}", kind="other"
                ),
                "lease2": IspStaticIpLease(
                    isp_organization_id=isp_a,
                    customer_organization_id=a2,
                    ip_address="203.0.113.9",
                    monthly_amount_paise=100,
                    active_since=date.today(),
                    status="active",
                ),
                "mac1": IspSubscriberMacBinding(
                    isp_organization_id=isp_a,
                    subscriber_id=subs["1"].id,
                    mac="AA:BB:CC:00:00:01",
                    source="manual",
                ),
                "mac2": IspSubscriberMacBinding(
                    isp_organization_id=isp_a,
                    subscriber_id=subs["2"].id,
                    mac="AA:BB:CC:00:00:02",
                    source="manual",
                ),
                "doc2": IspSubscriberDocument(
                    isp_organization_id=isp_a,
                    subscriber_id=subs["2"].id,
                    kind="id_proof",
                    storage_key="x/y",
                    filename="a.pdf",
                    content_type="application/pdf",
                    size_bytes=1,
                    sha256="0" * 64,
                ),
                "dev1": Tr069Device(
                    isp_organization_id=isp_a,
                    customer_organization_id=a1,
                    genieacs_device_id=f"G1{tag}",
                    first_seen_at=now,
                ),
                "dev2": Tr069Device(
                    isp_organization_id=isp_a,
                    customer_organization_id=a2,
                    genieacs_device_id=f"G2{tag}",
                    first_seen_at=now,
                ),
                "olt": IspFiberNode(
                    isp_organization_id=isp_a, kind="olt", name="OLT shared"
                ),
            }
            s.add_all(rows.values())
            await s.flush()
            rows["node2"] = IspFiberNode(
                isp_organization_id=isp_a,
                customer_organization_id=a2,
                kind="splitter",
                name="A2 splitter",
                parent_id=rows["olt"].id,
                parent_port=1,
            )
            s.add(rows["node2"])
            await s.flush()
            rows["node1"] = IspFiberNode(
                isp_organization_id=isp_a,
                customer_organization_id=a1,
                kind="ont",
                name="A1 ont",
                parent_id=rows["node2"].id,
                parent_port=1,
            )
            rows["checkout2"] = A2.IspInventoryCheckout(
                isp_organization_id=isp_a,
                unit_id=rows["unitfree"].id,
                customer_organization_id=a2,
                status="pending",
                requested_at=now,
            )
            s.add_all([rows["node1"], rows["checkout2"]])
            await s.flush()
            ids = {k: v.id for k, v in rows.items()}
            ids["sub1"], ids["sub2"] = subs["1"].id, subs["2"].id
            ids["item"] = item.id
            await s.commit()

        async def call(
            who: str, headers: dict, method: str, url: str, body=None
        ) -> int:
            state["user"] = users[who]
            r = await c.request(method, f"{api}{url}", headers=headers, json=body)
            return r.status_code

        # -- ISP B (own header) on ISP A's ids: 404, never 200 / 403 ---------
        foreign = [
            ("GET", f"/apps/tasks/{ids['task1']}", None),
            ("POST", f"/apps/tasks/{ids['task1']}/approve", {}),
            ("GET", f"/apps/leads/{ids['lead1']}", None),
            ("GET", f"/apps/inventory/units/{ids['unit1']}", None),
            ("PUT", f"/apps/inventory/units/{ids['unit1']}/meta", {}),
            ("POST", f"/apps/inventory/checkouts/{ids['checkout2']}/approve", {}),
            ("PATCH", f"/apps/ticket-types/{ids['type']}", {"name": "x"}),
            ("PATCH", f"/apps/discounts/{ids['discount']}", {}),
            ("GET", f"/apps/announcements/{ids['announcement']}", None),
            ("PATCH", f"/apps/inventory/items/{ids['olt']}", {}),
            ("PATCH", f"/apps/inventory/vendors/{ids['vendor']}", {"name": "x"}),
            ("PATCH", f"/apps/inventory/locations/{ids['stockloc']}", {"name": "x"}),
            ("GET", f"/fiber/nodes/{ids['node1']}", None),
            ("GET", f"/fiber/nodes/{ids['node1']}/route", None),
            ("PATCH", f"/finance/products/{ids['product']}", {"name": "x"}),
            ("POST", f"/finance/static-ip-leases/{ids['lease2']}/end", {}),
            ("GET", f"/finance/contacts/customer/{a1}", None),
            ("GET", f"/finance/contacts/subscriber/{ids['sub1']}", None),
            (
                "PUT",
                f"/finance/contacts/customer/{a1}",
                {"alternate_email": "x@example.com"},
            ),
            ("DELETE", f"/subscribers/{ids['sub1']}/mac-bindings/{ids['mac1']}", None),
            (
                "GET",
                f"/compliance/subscribers/{ids['sub2']}/documents/{ids['doc2']}",
                None,
            ),
        ]
        # positive control: B is a working ISP on these surfaces
        for url in ("/apps/tasks", "/fiber/nodes", "/finance/products"):
            assert await call("B", hb, "GET", url) == 200, url
        for method, url, body in foreign:
            got = await call("B", hb, method, url, body)
            assert got == 404, (method, url, got)
        # The item PATCH above used a non-item id on purpose; A's real item:
        assert (
            await call("B", hb, "PATCH", f"/apps/inventory/items/{ids['item']}", {})
            == 404
        )

        # -- confined users: 404 outside A1, reachable inside -----------------
        pairs = [
            (
                "Tech",
                "GET",
                f"/apps/tasks/{ids['task2']}",
                f"/apps/tasks/{ids['task1']}",
                None,
            ),
            (
                "Tech",
                "GET",
                f"/apps/leads/{ids['lead2']}",
                f"/apps/leads/{ids['lead1']}",
                None,
            ),
            (
                "Tech",
                "GET",
                f"/apps/inventory/units/{ids['unit2']}",
                f"/apps/inventory/units/{ids['unit1']}",
                None,
            ),
            (
                "Tech",
                "GET",
                f"/fiber/nodes/{ids['node2']}",
                f"/fiber/nodes/{ids['node1']}",
                None,
            ),
            (
                "Bill",
                "GET",
                f"/finance/contacts/customer/{a2}",
                f"/finance/contacts/customer/{a1}",
                None,
            ),
            (
                "Bill",
                "GET",
                f"/finance/contacts/subscriber/{ids['sub2']}",
                f"/finance/contacts/subscriber/{ids['sub1']}",
                None,
            ),
        ]
        for who, method, outside, inside, body in pairs:
            assert await call(who, ha, method, outside, body) == 404, (who, outside)
            assert await call(who, ha, method, inside, body) == 200, (who, inside)
        # Child rows behind a subscriber path: A2's subscriber is invisible.
        assert (
            await call(
                "Bill",
                ha,
                "DELETE",
                f"/subscribers/{ids['sub2']}/mac-bindings/{ids['mac2']}",
            )
            == 404
        )
        # ... and A2's binding id cannot be reached through A1's subscriber.
        assert (
            await call(
                "Bill",
                ha,
                "DELETE",
                f"/subscribers/{ids['sub1']}/mac-bindings/{ids['mac2']}",
            )
            == 404
        )
        assert (
            await call(
                "Tech",
                ha,
                "GET",
                f"/compliance/subscribers/{ids['sub2']}/documents/{ids['doc2']}",
            )
            == 404
        )
        assert (
            await call(
                "Tech",
                ha,
                "GET",
                f"/compliance/subscribers/{ids['sub1']}/documents/{ids['doc2']}",
            )
            == 404
        )

        # -- fix 1: the fiber route stops at another customer's node ----------
        state["user"] = users["Tech"]
        r = await c.get(f"{api}/fiber/nodes/{ids['node1']}/route", headers=ha)
        assert r.status_code == 200, r.text
        names = [p["name"] for p in r.json()["data"]]
        assert names == ["A1 ont"], names
        assert "A2 splitter" not in r.text
        state["user"] = users["A"]
        r = await c.get(f"{api}/fiber/nodes/{ids['node1']}/route", headers=ha)
        assert [p["name"] for p in r.json()["data"]] == [
            "OLT shared",
            "A2 splitter",
            "A1 ont",
        ]

        # -- fix 2: no linking another customer's TR-069 device ---------------
        meta = f"/apps/inventory/units/{ids['unitfree']}/meta"
        assert (
            await call("Tech", ha, "PUT", meta, {"tr069_device_id": str(ids["dev2"])})
            == 404
        )
        assert (
            await call("Tech", ha, "PUT", meta, {"tr069_device_id": str(ids["dev1"])})
            == 200
        )
        # an unconfined owner still can
        assert (
            await call("A", ha, "PUT", meta, {"tr069_device_id": str(ids["dev2"])})
            == 200
        )
