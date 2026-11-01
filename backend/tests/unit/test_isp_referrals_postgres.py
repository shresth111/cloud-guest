"""REFERRAL-1 on real PostgreSQL + Redis (skipped unless ``ISP_TEST_PG_DSN``
is set). Fresh scratch DB at head.

Covers: flag off 404; settings (cannot switch on without a reward; audited);
create rules (self, duplicate, window, newer-than-referrer); pending until
the referred subscriber's first invoice is paid; earned; applied as a credit
note through IspBillingService.credit_note on the referrer's next unpaid
invoice, once only; the per-year limit rejects with a reason; cancel; a
billing user confined to c1 404s on a c2 referral and cannot create one with
a c2 subscriber; another ISP 404s on every id route; audit rows + history.
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


async def test_referrals_end_to_end() -> None:  # noqa: PLR0915
    import httpx
    from sqlalchemy import func, select, update

    from app.database.session import SessionLocal, engine
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.isp_partner.billing_models import IspInvoice
    from app.domains.isp_partner.models import IspPartnerProfile, IspStaffCustomerScope
    from app.domains.isp_partner.plans_models import IspSubscriber
    from app.domains.isp_partner.referrals_config import get_referrals_settings
    from app.domains.isp_partner.referrals_service import run_referrals
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.organization.models import Organization, OrganizationMember
    from app.domains.rbac.dependencies import CurrentUser
    from app.domains.rbac.models import AuditLogEntry, Role, UserRole
    from app.domains.rbac.repository import RBACRepository
    from app.domains.rbac.seed import seed_rbac
    from app.main import create_app

    tag = uuid.uuid4().hex[:8]
    os.environ.pop("ISP_REFERRALS_ENABLED", None)
    get_referrals_settings.cache_clear()
    try:
        async with SessionLocal() as s:
            await seed_rbac(s)
            await seed_isp_partner_rbac(RBACRepository(s))
            await s.commit()
        users, isps = {}, {}
        async with SessionLocal() as s:
            plan = Plan(
                name=f"P {tag}",
                slug=f"rf-{tag}",
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
                    last_name="R",
                    email=f"rf{n.lower()}{tag}@example.com",
                    username=f"rf{n.lower()}{tag}",
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
                    name=f"Rf {n} {tag}",
                    slug=f"rfnet{n.lower()}{tag}",
                    org_type="msp",
                    status="active",
                    contact_email=f"rf{n}{tag}@example.com",
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
                    u = person("Bill")
                    s.add(u)
                    await s.flush()
                    s.add_all(grant(u, org, "isp-billing"))
                    users["Bill"] = u.id
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

            async def tick() -> None:
                async with SessionLocal() as s:
                    await run_referrals(s)
                    await s.commit()

            await call(
                "PUT",
                "/billing/settings",
                {"legal_name": "Net A", "state_code": "07", "invoice_prefix": "RFA"},
            )
            cust = {}
            for n in ("c1", "c2"):
                cust[n] = (
                    await call(
                        "POST",
                        "/customers",
                        {"name": f"{n} {tag}", "contact_email": f"{n}{tag}@e.com"},
                    )
                )["id"]
            async with SessionLocal() as s:
                s.add(
                    IspStaffCustomerScope(
                        isp_organization_id=isps["A"],
                        user_id=users["Bill"],
                        customer_organization_id=uuid.UUID(cust["c1"]),
                    )
                )
                await s.commit()
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
                    {"speed_group_id": g, "type": "prepaid", "price_paise": 50000},
                )
            )["id"]

            async def sub(ident: str, n: str, age_days: int) -> str:
                sid = (
                    await call(
                        "POST",
                        "/subscribers",
                        {
                            "isp_customer_id": cust[n],
                            "identifier": ident,
                            "package_id": pkg,
                        },
                    )
                )["id"]
                async with SessionLocal() as s:
                    await s.execute(
                        update(IspSubscriber)
                        .where(IspSubscriber.id == uuid.UUID(sid))
                        .values(created_at=datetime.now(UTC) - timedelta(days=age_days))
                    )
                    await s.commit()
                return sid

            ra = await sub(f"ra{tag}", "c1", 300)
            rb = await sub(f"rb{tag}", "c1", 2)
            rc = await sub(f"rc{tag}", "c1", 1)
            rd = await sub(f"rd{tag}", "c1", 1)
            old = await sub(f"ro{tag}", "c1", 90)
            x2 = await sub(f"rx{tag}", "c2", 200)
            y2 = await sub(f"ry{tag}", "c2", 1)

            async def renew(sid: str, key: str) -> dict:
                return (
                    await call(
                        "POST", f"/subscribers/{sid}/renew", {"idempotency_key": key}
                    )
                )["invoice"]

            async def pay_first(sid: str) -> None:
                async with SessionLocal() as s:
                    inv = (
                        await s.execute(
                            select(IspInvoice)
                            .where(
                                IspInvoice.subscriber_id == uuid.UUID(sid),
                                IspInvoice.doc_type == "invoice",
                            )
                            .order_by(IspInvoice.issue_date, IspInvoice.created_at)
                            .limit(1)
                        )
                    ).scalar_one()
                    bal = inv.total_paise - inv.paid_paise - inv.credit_noted_paise
                await call(
                    "POST",
                    "/billing/payments",
                    {
                        "subscriber_id": sid,
                        "invoice_id": str(inv.id),
                        "amount_paise": bal,
                        "mode": "cash",
                    },
                )

            for sid in (rb, rc):
                await renew(sid, f"first-{sid[:8]}")

            # -- flag off ------------------------------------------------------
            assert await status("GET", "/referrals") == 404
            os.environ["ISP_REFERRALS_ENABLED"] = "true"
            get_referrals_settings.cache_clear()

            # -- settings ---------------------------------------------------------
            pair = {"referrer_subscriber_id": ra, "referred_subscriber_id": rb}
            assert await status("POST", "/referrals", pair) == 409  # off by default
            assert await status("PUT", "/referrals/settings", {"enabled": True}) == 409
            st = await call(
                "PUT",
                "/referrals/settings",
                {"enabled": True, "reward_paise": 10000, "max_rewards_per_year": 1},
            )
            assert st["enabled"] and st["reward_paise"] == 10000
            as_("Bill")
            assert await status("PUT", "/referrals/settings", {"window_days": 5}) == 403
            as_("A")

            # -- create rules ----------------------------------------------------
            r1 = await call("POST", "/referrals", pair)
            assert r1["status"] == "pending" and r1["referred"]["subscriber_id"] == rb
            assert await status("POST", "/referrals", pair) == 409  # once only
            assert (
                await status(
                    "POST",
                    "/referrals",
                    {"referrer_subscriber_id": ra, "referred_subscriber_id": ra},
                )
                == 409
            )
            assert (
                await status(
                    "POST",
                    "/referrals",
                    {"referrer_subscriber_id": rc, "referred_subscriber_id": ra},
                )
                == 409
            )  # the referrer must be the older one
            assert (
                await status(
                    "POST",
                    "/referrals",
                    {"referrer_subscriber_id": ra, "referred_subscriber_id": old},
                )
                == 409
            )  # outside the 30-day window

            # -- earn + apply -----------------------------------------------------
            await tick()
            assert (await call("GET", f"/referrals/{r1['id']}"))["status"] == "pending"
            await pay_first(rb)
            await tick()
            got = await call("GET", f"/referrals/{r1['id']}")
            assert got["status"] == "earned" and got["reward_paise"] == 10000
            # the referrer's next unpaid bill gets the credit note, once
            a_inv = await renew(ra, f"next-{tag}")
            for _ in range(2):
                await tick()
            got = await call("GET", f"/referrals/{r1['id']}")
            assert got["status"] == "applied" and got["applied_paise"] == 10000
            assert got["applied_invoice_number"] == a_inv["number"]
            assert got["credit_note_number"]
            async with SessionLocal() as s:
                inv = await s.get(IspInvoice, uuid.UUID(a_inv["id"]))
                assert inv.credit_noted_paise == 10000
                notes = (
                    await s.execute(
                        select(func.count())
                        .select_from(IspInvoice)
                        .where(
                            IspInvoice.credit_note_for_invoice_id == inv.id,
                            IspInvoice.doc_type == "credit_note",
                        )
                    )
                ).scalar_one()
            assert notes == 1
            assert [h["status"] for h in got["history"]] == [
                "pending",
                "earned",
                "applied",
            ]

            # -- the yearly limit rejects the second one -----------------------
            r2 = await call(
                "POST",
                "/referrals",
                {"referrer_subscriber_id": ra, "referred_subscriber_id": rc},
            )
            await pay_first(rc)
            await tick()
            got = await call("GET", f"/referrals/{r2['id']}")
            assert got["status"] == "rejected" and "Limit" in got["reason"]

            # -- cancel -------------------------------------------------------------
            r3 = await call(
                "POST",
                "/referrals",
                {"referrer_subscriber_id": ra, "referred_subscriber_id": rd},
            )
            done = await call(
                "POST", f"/referrals/{r3['id']}/cancel", {"reason": "entered wrongly"}
            )
            assert done["status"] == "cancelled"
            assert (
                await status(
                    "POST", f"/referrals/{r3['id']}/cancel", {"reason": "again"}
                )
                == 409
            )

            # -- confined billing user ------------------------------------------
            rx = await call(
                "POST",
                "/referrals",
                {"referrer_subscriber_id": x2, "referred_subscriber_id": y2},
            )
            as_("Bill")
            ids = {i["id"] for i in (await call("GET", "/referrals"))["items"]}
            assert rx["id"] not in ids and r1["id"] in ids
            assert await status("GET", f"/referrals/{rx['id']}") == 404
            assert (
                await status(
                    "POST", f"/referrals/{rx['id']}/cancel", {"reason": "nope"}
                )
                == 404
            )
            assert (
                await status(
                    "POST",
                    "/referrals",
                    {"referrer_subscriber_id": ra, "referred_subscriber_id": y2},
                )
                == 404
            )
            assert await status("GET", f"/referrals?subscriber_id={y2}") == 404
            as_("A")
            mine = await call("GET", f"/referrals?subscriber_id={ra}")
            assert mine["total"] == 3 and mine["summary"]["credited_paise"] == 10000

            # -- audit -----------------------------------------------------------------
            async with SessionLocal() as s:
                actions = set(
                    (
                        await s.execute(
                            select(AuditLogEntry.action).where(
                                AuditLogEntry.entity_type == "isp_referral"
                            )
                        )
                    ).scalars()
                )
            assert {
                "isp_referral_settings_updated",
                "isp_referral_created",
                "isp_referral_earned",
                "isp_referral_applied",
                "isp_referral_rejected",
                "isp_referral_cancelled",
            } <= actions

            # -- another ISP ---------------------------------------------------------
            as_("B")
            rnd = uuid.uuid4()
            for method, path, body in (
                ("GET", f"/referrals/{r1['id']}", None),
                ("GET", f"/referrals/{rnd}", None),
                ("POST", f"/referrals/{rx['id']}/cancel", {"reason": "abcd"}),
                ("POST", "/referrals", pair),
                ("GET", f"/referrals?subscriber_id={ra}", None),
            ):
                assert await status(method, path, body, h=hb) in (404,), (method, path)
            assert (await call("GET", "/referrals", h=hb))["total"] == 0
            assert (await call("GET", "/referrals/settings", h=hb))["enabled"] is False
            as_("A")
            os.environ.pop("ISP_REFERRALS_ENABLED")
            get_referrals_settings.cache_clear()
            assert await status("GET", "/referrals") == 404
    finally:
        os.environ.pop("ISP_REFERRALS_ENABLED", None)
        get_referrals_settings.cache_clear()
        await engine.dispose()
