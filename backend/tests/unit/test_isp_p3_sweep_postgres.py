"""P3-SWEEP on real PostgreSQL + Redis (skipped unless ``ISP_TEST_PG_DSN`` is
set). Fresh scratch DB at head.

Run: ISP_TEST_PG_DSN=1 ISP_PARTNER_ENABLED=true
PYTHONPATH=.:vendor/wyfy-device-gateway pytest tests/unit/test_isp_p3_sweep_postgres.py

Covers:
* ZONE-1 per-subscriber rule on the new lists. Customer c1 sits in zone B;
  its subscribers sA, sA2 have their own zone A, sB has none (falls back to
  B). Under ``scope_zone_id=A`` queued renewals, collection promises,
  incidents (list count + detail), referrals (both sides), static-IP leases
  and the revenue drill show only sA/sA2; under B only sB (+ c1's
  customer-level promise / lease); unscoped both. A billing user confined to
  c2 sees nothing under A (never widens); one confined to c1 sees the same
  as the owner. ISP B naming zone A -> 404.
* Queued renewals list filters (status, q, package, starts within) and the
  subscriber block; ISP B / confined c2 see none of A's rows.
* Inventory edit: explicit null -> 422, technician bag without a technician
  -> 422, rename OK, ISP B / random id -> 404.
* Collections timeline returns ``open_paise``.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)

FLAGS = (
    "ISP_ZONES_ENABLED",
    "ISP_QUEUED_RENEWAL_ENABLED",
    "ISP_COLLECTIONS_ENABLED",
    "ISP_INCIDENTS_ENABLED",
    "ISP_REFERRALS_ENABLED",
    "ISP_REVENUE_HUB_ENABLED",
    "ISP_STATICIP2_ENABLED",
    "ISP_APPS_ENABLED",
)


def _clear_settings() -> None:
    from app.domains.isp_partner.apps_common import get_isp_apps_settings
    from app.domains.isp_partner.collections_config import get_collections_settings
    from app.domains.isp_partner.incidents_config import get_incidents_settings
    from app.domains.isp_partner.queued_renewal_config import (
        get_queued_renewal_settings,
    )
    from app.domains.isp_partner.referrals_config import get_referrals_settings
    from app.domains.isp_partner.revenue_router import get_revenue_settings
    from app.domains.isp_partner.staticip_router import get_staticip2_settings
    from app.domains.isp_partner.zones_config import get_zones_settings

    for g in (
        get_isp_apps_settings,
        get_collections_settings,
        get_incidents_settings,
        get_queued_renewal_settings,
        get_referrals_settings,
        get_revenue_settings,
        get_staticip2_settings,
        get_zones_settings,
    ):
        g.cache_clear()


async def test_p3_sweep_end_to_end() -> None:  # noqa: PLR0915
    import httpx
    from sqlalchemy import select

    from app.database.session import SessionLocal
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.isp_partner.collections_models import IspCollectionPromise
    from app.domains.isp_partner.finance_models import IspStaticIpLease
    from app.domains.isp_partner.incidents_models import (
        IspIncident,
        IspIncidentSubscriber,
    )
    from app.domains.isp_partner.models import IspPartnerProfile, IspStaffCustomerScope
    from app.domains.isp_partner.plans_models import IspSubscriber
    from app.domains.isp_partner.queued_renewal_models import IspQueuedRenewal
    from app.domains.isp_partner.referrals_models import IspReferral
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.organization.models import Organization, OrganizationMember
    from app.domains.rbac.dependencies import CurrentUser
    from app.domains.rbac.models import Role, UserRole
    from app.domains.rbac.repository import RBACRepository
    from app.domains.rbac.seed import seed_rbac
    from app.main import create_app

    tag = uuid.uuid4().hex[:8]
    for f in FLAGS:
        os.environ[f] = "true"
    _clear_settings()
    try:
        async with SessionLocal() as s:
            await seed_rbac(s)
            await seed_isp_partner_rbac(RBACRepository(s))
            await s.commit()
        users, isps = {}, {}
        async with SessionLocal() as s:
            plan = Plan(
                name=f"P {tag}",
                slug=f"p3-{tag}",
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
                        select(Role).where(Role.slug.in_(("isp-owner", "isp-billing")))
                    )
                ).scalars()
            }

            def person(n: str) -> User:
                return User(
                    first_name=n,
                    last_name="P",
                    email=f"p3{n.lower()}{tag}@example.com",
                    username=f"p3{n.lower()}{tag}",
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
                    name=f"P3 {n} {tag}",
                    slug=f"p3net{n.lower()}{tag}",
                    org_type="msp",
                    status="active",
                    contact_email=f"p3{n}{tag}@example.com",
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
                    for who in ("Bill1", "Bill2"):
                        u = person(who)
                        s.add(u)
                        await s.flush()
                        s.add_all(grant(u, org, "isp-billing"))
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

        def as_(who: str) -> None:
            state["user"] = users[who]

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t"
        ) as c:

            async def call(method: str, path: str, body=None, h=ha, ok=(200, 201)):  # noqa: ANN001, ANN202
                r = await c.request(method, f"{api}{path}", json=body, headers=h)
                assert r.status_code in ok, (method, path, r.status_code, r.text)
                return r.json().get("data")

            async def status(method: str, path: str, body=None, h=ha) -> int:  # noqa: ANN001
                r = await c.request(method, f"{api}{path}", json=body, headers=h)
                return r.status_code

            # -- setup: zones, customers, subscribers ----------------------
            za = (await call("POST", "/zones/tree", {"name": f"ZA {tag}"}))["id"]
            zb = (await call("POST", "/zones/tree", {"name": f"ZB {tag}"}))["id"]
            cust = {}
            for n in ("c1", "c2"):
                cust[n] = (
                    await call(
                        "POST",
                        "/customers",
                        {"name": f"{n} {tag}", "contact_email": f"{n}{tag}@e.com"},
                    )
                )["id"]
            await call("PATCH", f"/customers/{cust['c1']}", {"zone_id": zb})
            async with SessionLocal() as s:
                for who, cn in (("Bill1", "c1"), ("Bill2", "c2")):
                    s.add(
                        IspStaffCustomerScope(
                            isp_organization_id=isps["A"],
                            user_id=users[who],
                            customer_organization_id=uuid.UUID(cust[cn]),
                        )
                    )
                await s.commit()
            g10 = (
                await call(
                    "POST",
                    "/speed-groups",
                    {"name": "10M", "download_kbps": 10240, "upload_kbps": 10240},
                )
            )["id"]
            p1 = (
                await call(
                    "POST",
                    "/packages",
                    {"speed_group_id": g10, "type": "prepaid", "price_paise": 50000},
                )
            )["id"]
            g20 = (
                await call(
                    "POST",
                    "/speed-groups",
                    {"name": "20M", "download_kbps": 20480, "upload_kbps": 20480},
                )
            )["id"]
            p2 = (
                await call(
                    "POST",
                    "/packages",
                    {"speed_group_id": g20, "type": "prepaid", "price_paise": 70000},
                )
            )["id"]

            async def sub(ident: str, cn: str, zone: str | None) -> str:
                sid = (
                    await call(
                        "POST",
                        "/subscribers",
                        {
                            "isp_customer_id": cust[cn],
                            "identifier": ident,
                            "package_id": p1,
                        },
                    )
                )["id"]
                if zone:
                    await call("PATCH", f"/subscribers/{sid}", {"zone_id": zone})
                async with SessionLocal() as s:
                    row = await s.get(IspSubscriber, uuid.UUID(sid))
                    row.valid_until = datetime.now(UTC) + timedelta(days=5)
                    row.status = "active"
                    await s.commit()
                return sid

            sa = await sub(f"pa{tag}", "c1", za)  # own zone A, customer in B
            sa2 = await sub(f"pa2{tag}", "c1", za)
            sb = await sub(f"pb{tag}", "c1", None)  # falls back to B
            sc = await sub(f"pc{tag}", "c2", None)  # no zone anywhere
            c1, c2 = uuid.UUID(cust["c1"]), uuid.UUID(cust["c2"])
            S = {
                k: uuid.UUID(v)
                for k, v in (("a", sa), ("a2", sa2), ("b", sb), ("c", sc))
            }

            # -- rows on the new tables (direct, the lanes test their writes) --
            now = datetime.now(UTC)
            async with SessionLocal() as s:
                for k, cust_id in (("a", c1), ("b", c1), ("c", c2)):
                    s.add(
                        IspQueuedRenewal(
                            isp_organization_id=isps["A"],
                            customer_organization_id=cust_id,
                            subscriber_id=S[k],
                            package_id=uuid.UUID(p2 if k == "a" else p1),
                            speed_group_id=uuid.UUID(g10),
                            previous_package_id=uuid.UUID(p1),
                            cycles=1,
                            starts_at=now + timedelta(days=2 if k == "a" else 20),
                            ends_at=now + timedelta(days=32),
                            status="pending",
                            idempotency_key=f"p3-{k}-{tag}",
                        )
                    )
                for k, cust_id in (("a", c1), ("b", c1), (None, c1), ("c", c2)):
                    s.add(
                        IspCollectionPromise(
                            isp_organization_id=isps["A"],
                            customer_organization_id=cust_id,
                            subscriber_id=S[k] if k else None,
                            promised_on=date.today() + timedelta(days=3),
                            target_paise=10000,
                            overdue_at_creation_paise=10000,
                            status="open",
                        )
                    )
                inc = IspIncident(
                    isp_organization_id=isps["A"],
                    number=1,
                    title="Fibre cut",
                    scope_kind="zone",
                    scope_label="Area",
                    severity="major",
                    status="investigating",
                    started_at=now,
                    affected_count=3,
                )
                s.add(inc)
                await s.flush()
                for k, cust_id in (("a", c1), ("b", c1), ("c", c2)):
                    s.add(
                        IspIncidentSubscriber(
                            incident_id=inc.id,
                            subscriber_id=S[k],
                            customer_organization_id=cust_id,
                            source="zone",
                        )
                    )
                for referrer, referred in (("a2", "a"), ("a", "b")):
                    s.add(
                        IspReferral(
                            isp_organization_id=isps["A"],
                            referrer_subscriber_id=S[referrer],
                            referred_subscriber_id=S[referred],
                            referrer_customer_id=c1,
                            referred_customer_id=c1,
                            status="pending",
                            history=[],
                        )
                    )
                for i, (k, cust_id) in enumerate(
                    (("a", c1), ("b", c1), (None, c1), ("c", c2)), start=1
                ):
                    s.add(
                        IspStaticIpLease(
                            isp_organization_id=isps["A"],
                            customer_organization_id=cust_id,
                            subscriber_id=S[k] if k else None,
                            ip_address=f"100.64.9.{i}",
                            monthly_amount_paise=10000,
                            price_includes_gst=False,
                            active_since=date.today(),
                            status="active",
                        )
                    )
                await s.commit()
                inc_id = str(inc.id)

            # -- helpers: what each list shows, as subscriber keys -------------
            key_of = {v: k for k, v in ((k, str(v)) for k, v in S.items())}

            def keys(ids: list) -> set:
                return {key_of.get(i, "cust" if i is None else i) for i in ids}

            def zq(zone: str | None, extra: str = "") -> str:
                parts = [
                    p for p in (extra, f"scope_zone_id={zone}" if zone else "") if p
                ]
                return ("?" + "&".join(parts)) if parts else ""

            async def queued(zone: str | None, extra: str = "") -> set:
                d = await call("GET", f"/queued-renewals{zq(zone, extra)}")
                return keys([r["subscriber_id"] for r in d["items"]])

            async def promises(zone: str | None) -> set:
                d = await call("GET", f"/collections/promises{zq(zone)}")
                return keys([r["subscriber_id"] for r in d["items"]])

            async def incident_count(zone: str | None) -> int | None:
                d = await call("GET", f"/incidents{zq(zone)}")
                mine = [i for i in d["items"] if i["id"] == inc_id]
                return mine[0]["affected_visible"] if mine else None

            async def referrals(zone: str | None) -> set:
                d = await call("GET", f"/referrals{zq(zone)}")
                return {
                    (
                        key_of[r["referrer"]["subscriber_id"]],
                        key_of[r["referred"]["subscriber_id"]],
                    )
                    for r in d["items"]
                }

            async def leases(zone: str | None) -> set:
                d = await call("GET", f"/static-ips/ledger{zq(zone)}")
                return keys([r.get("subscriber_id") for r in d["items"]])

            async def revenue(zone: str | None) -> set:
                # every subscriber bucket of the drill, whatever state it lands in
                out: set = set()
                for metric in ("active", "pending", "expired", "churned", "other"):
                    d = await call(
                        "GET",
                        f"/revenue/list{zq(zone, f'metric={metric}&page_size=200')}",
                    )
                    out |= keys([r["id"] for r in d["items"]]) & set(S)
                return out

            # -- unscoped: everything ------------------------------------------
            assert await queued(None) == {"a", "b", "c"}
            assert await promises(None) == {"a", "b", "cust", "c"}
            assert await incident_count(None) == 3
            assert await referrals(None) == {("a2", "a"), ("a", "b")}
            assert await leases(None) == {"a", "b", "cust", "c"}
            assert await revenue(None) == {"a", "a2", "b", "c"}

            # -- zone A: the subscriber's own zone wins over its customer's ----
            assert await queued(za) == {"a"}
            assert await promises(za) == {"a"}  # c1's own promise is zone B
            assert await incident_count(za) == 1
            assert await referrals(za) == {("a2", "a")}  # both sides in A
            assert await leases(za) == {"a"}
            assert await revenue(za) == {"a", "a2"}
            d = await call("GET", f"/incidents/{inc_id}{zq(za)}")
            assert d["affected_visible"] == 1
            # -- zone B: sB (no own zone -> customer zone) + c1's own rows -----
            assert await queued(zb) == {"b"}
            assert await promises(zb) == {"b", "cust"}
            assert await incident_count(zb) == 1
            assert await referrals(zb) == set()  # ("a","b"): sA is in A
            assert await leases(zb) == {"b", "cust"}
            assert await revenue(zb) == {"b"}
            # a referral outside the zone is a 404 by id inside it
            async with SessionLocal() as s:
                r_ab = (
                    await s.execute(
                        select(IspReferral.id).where(
                            IspReferral.referred_subscriber_id == S["b"]
                        )
                    )
                ).scalar_one()
            await call("GET", f"/referrals/{r_ab}{zq(za)}", ok=(404,))
            await call("GET", f"/referrals/{r_ab}")

            # -- confined staff: only ever narrowed ----------------------------
            as_("Bill2")  # confined to c2, which has nothing in zone A
            assert await queued(za) == set()
            assert await promises(za) == set()
            assert await incident_count(za) is None
            assert await referrals(za) == set()
            assert await leases(za) == set()
            assert await queued(None) == {"c"}
            assert await leases(None) == {"c"}
            as_("Bill1")  # confined to c1
            assert await queued(za) == {"a"}
            assert await promises(za) == {"a"}
            assert await incident_count(za) == 1
            assert await referrals(za) == {("a2", "a")}
            assert await leases(za) == {"a"}
            assert await queued(None) == {"a", "b"}
            as_("A")

            # -- ISP B: another ISP's zone is a 404, A's rows never listed -----
            as_("B")
            assert (
                await status("GET", f"/queued-renewals?scope_zone_id={za}", h=hb) == 404
            )
            d = await call("GET", "/queued-renewals?status=all", h=hb)
            assert d["total"] == 0
            as_("A")

            # -- queued renewals list: filters + subscriber block ----------------
            d = await call("GET", "/queued-renewals")
            assert d["total"] == 3 and d["items"][0]["subscriber_id"] == sa  # soonest
            assert d["items"][0]["subscriber"]["identifier"] == f"pa{tag}"
            assert await queued(None, f"q=pb{tag}") == {"b"}
            assert await queued(None, f"package_id={p2}") == {"a"}
            assert await queued(None, "starts_within_days=7") == {"a"}
            assert await queued(None, "status=active") == set()
            assert await queued(None, "status=all") == {"a", "b", "c"}
            assert await status("GET", "/queued-renewals?status=bogus") == 422
            async with SessionLocal() as s:
                row = (
                    await s.execute(
                        select(IspQueuedRenewal).where(
                            IspQueuedRenewal.subscriber_id == S["c"]
                        )
                    )
                ).scalar_one()
                row.status = "cancelled"
                await s.commit()
            assert await queued(None) == {"a", "b"}
            assert await queued(None, "status=cancelled") == {"c"}
            os.environ.pop("ISP_QUEUED_RENEWAL_ENABLED")
            _clear_settings()
            r = await c.get(f"{api}/queued-renewals", headers=ha)
            assert r.status_code == 404, r.text
            os.environ["ISP_QUEUED_RENEWAL_ENABLED"] = "true"
            _clear_settings()

            # -- collections timeline: open dues ---------------------------------
            t = await call("GET", f"/collections/subscribers/{sa}/timeline")
            assert t["open_paise"] == 0 and t["open_promise"] is not None

            # -- inventory edit (APPS-2 PATCH routes) ----------------------------
            item = await call(
                "POST",
                "/apps/inventory/items",
                {"name": "ONT", "sku": f"ont-{tag}", "category": "ont"},
            )
            ip = f"/apps/inventory/items/{item['id']}"
            for bad in ({"name": None}, {"sku": None}, {"category": None}):
                assert await status("PATCH", ip, bad) == 422, bad
            out = await call("PATCH", ip, {"name": "GPON ONT", "notes": "x"})
            assert out["name"] == "GPON ONT" and out["sku"] == f"ont-{tag}"
            assert await status("PATCH", ip, {"name": "Hijack"}, h=hb) in (403, 404)
            as_("B")
            assert await status("PATCH", ip, {"name": "Hijack"}, h=hb) == 404
            as_("A")
            assert (
                await status(
                    "PATCH", f"/apps/inventory/items/{uuid.uuid4()}", {"name": "x"}
                )
                == 404
            )
            loc = await call(
                "POST",
                "/apps/inventory/locations",
                {"name": "Store", "kind": "warehouse"},
            )
            lp = f"/apps/inventory/locations/{loc['id']}"
            assert await status("PATCH", lp, {"kind": "technician_bag"}) == 422
            assert await status("PATCH", lp, {"name": None}) == 422
            assert await status("PATCH", lp, {"active": None}) == 422
            out = await call(
                "PATCH",
                lp,
                {"kind": "technician_bag", "holder_user_id": str(users["A"])},
            )
            assert out["kind"] == "technician_bag"
            assert await status("PATCH", lp, {"holder_user_id": None}) == 422
            out = await call("PATCH", lp, {"name": "Ravi's bag", "active": False})
            assert out["name"] == "Ravi's bag" and out["active"] is False
            as_("B")
            assert await status("PATCH", lp, {"name": "x"}, h=hb) == 404
            as_("A")
    finally:
        for f in FLAGS:
            os.environ.pop(f, None)
        _clear_settings()
