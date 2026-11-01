"""QUEUED-RENEWAL on real PostgreSQL + Redis (skipped unless
``ISP_TEST_PG_DSN`` is set). Fresh scratch DB at head.

Covers: flag off 404; queue a different plan paid now -> the invoice is the
new plan for the period after today's expiry, today's package and speed stay,
validity extends; repeat key = same row, no second invoice; one pending per
subscriber; an expired plan cannot be queued; the activation pass does
nothing early, switches at expiry, and is idempotent; cancel of an unpaid
queue = JAZE-1 revert credit note + validity back; cancel of a paid queue
needs isp_billing.manage and voids the receipt first; a JAZE-1 revert from
the 360 page cancels the queue on the next pass; a billing user confined to
c1 and another ISP get 404 on every id route.
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


async def test_queued_renewal_end_to_end() -> None:  # noqa: PLR0915
    import httpx
    from sqlalchemy import func, select

    from app.database.session import SessionLocal, engine
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.isp_partner.billing_models import IspInvoice, IspPayment
    from app.domains.isp_partner.models import IspPartnerProfile, IspStaffCustomerScope
    from app.domains.isp_partner.plans_models import IspSubscriber
    from app.domains.isp_partner.queued_renewal_config import (
        get_queued_renewal_settings,
    )
    from app.domains.isp_partner.queued_renewal_models import IspQueuedRenewal
    from app.domains.isp_partner.queued_renewal_service import run_queued_renewals
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.isp_partner.subscriber360_models import IspSubscriberEvent
    from app.domains.organization.models import Organization, OrganizationMember
    from app.domains.rbac.dependencies import CurrentUser
    from app.domains.rbac.models import AuditLogEntry, Role, UserRole
    from app.domains.rbac.repository import RBACRepository
    from app.domains.rbac.seed import seed_rbac
    from app.main import create_app

    tag = uuid.uuid4().hex[:8]
    os.environ.pop("ISP_QUEUED_RENEWAL_ENABLED", None)
    get_queued_renewal_settings.cache_clear()
    try:
        async with SessionLocal() as s:
            await seed_rbac(s)
            await seed_isp_partner_rbac(RBACRepository(s))
            await s.commit()
        users, isps = {}, {}
        async with SessionLocal() as s:
            plan = Plan(
                name=f"P {tag}",
                slug=f"qr-{tag}",
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
                    last_name="Q",
                    email=f"qr{n.lower()}{tag}@example.com",
                    username=f"qr{n.lower()}{tag}",
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
                    name=f"Qr {n} {tag}",
                    slug=f"qrnet{n.lower()}{tag}",
                    org_type="msp",
                    status="active",
                    contact_email=f"qr{n}{tag}@example.com",
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

            await call(
                "PUT",
                "/billing/settings",
                {"legal_name": "Net A", "state_code": "07", "invoice_prefix": "QRA"},
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
            g10 = (
                await call(
                    "POST",
                    "/speed-groups",
                    {"name": "10M", "download_kbps": 10240, "upload_kbps": 10240},
                )
            )["id"]
            g50 = (
                await call(
                    "POST",
                    "/speed-groups",
                    {"name": "50M", "download_kbps": 51200, "upload_kbps": 51200},
                )
            )["id"]
            p1 = (
                await call(
                    "POST",
                    "/packages",
                    {"speed_group_id": g10, "type": "prepaid", "price_paise": 50000},
                )
            )["id"]
            p2 = (
                await call(
                    "POST",
                    "/packages",
                    {"speed_group_id": g50, "type": "prepaid", "price_paise": 90000},
                )
            )["id"]

            async def sub(ident: str, n: str) -> str:
                sid = (
                    await call(
                        "POST",
                        "/subscribers",
                        {
                            "isp_customer_id": cust[n],
                            "identifier": ident,
                            "package_id": p1,
                        },
                    )
                )["id"]
                async with SessionLocal() as s:
                    row = await s.get(IspSubscriber, uuid.UUID(sid))
                    row.valid_until = datetime.now(UTC) + timedelta(days=5)
                    row.status = "active"
                    await s.commit()
                return sid

            s1, s2, s3 = (
                await sub(f"q1{tag}", "c1"),
                await sub(f"q2{tag}", "c1"),
                await sub(f"q3{tag}", "c2"),
            )
            s4 = await sub(f"q4{tag}", "c1")
            async with SessionLocal() as s:
                (await s.get(IspSubscriber, uuid.UUID(s4))).valid_until = datetime.now(
                    UTC
                ) - timedelta(days=1)
                await s.commit()

            async def row(sid: str) -> IspSubscriber:
                async with SessionLocal() as s:
                    return await s.get(IspSubscriber, uuid.UUID(sid))

            async def invoices(sid: str) -> int:
                async with SessionLocal() as s:
                    return (
                        await s.execute(
                            select(func.count())
                            .select_from(IspInvoice)
                            .where(
                                IspInvoice.subscriber_id == uuid.UUID(sid),
                                IspInvoice.doc_type == "invoice",
                            )
                        )
                    ).scalar_one()

            base = f"/subscribers/{s1}/queued-renewals"
            body = {
                "package_id": p2,
                "paid_now": True,
                "payment": {"mode": "cash"},
                "idempotency_key": f"qk1-{tag}",
            }
            # -- flag off ------------------------------------------------------
            assert await status("POST", base, body) == 404
            os.environ["ISP_QUEUED_RENEWAL_ENABLED"] = "true"
            get_queued_renewal_settings.cache_clear()

            # -- queue a different plan, paid now -------------------------------
            before = await row(s1)
            n_inv = await invoices(s1)
            out = await call("POST", base, body)
            q = out["queued"]
            assert q["status"] == "pending" and q["package"]["id"] == p2
            assert out["invoice"]["total_paise"] == 90000 and out["payment"]
            after = await row(s1)
            assert str(after.package_id) == p1  # today's plan keeps running
            assert str(after.speed_group_id) == g10
            assert after.valid_until == before.valid_until + timedelta(days=30)
            assert q["starts_at"] == before.valid_until.isoformat()
            assert await invoices(s1) == n_inv + 1
            again = await call("POST", base, body)
            assert again["repeat"] and again["queued"]["id"] == q["id"]
            assert await invoices(s1) == n_inv + 1
            assert (
                await status("POST", base, {**body, "idempotency_key": f"qk1b-{tag}"})
                == 409
            )
            assert (
                await status(
                    "POST",
                    f"/subscribers/{s4}/queued-renewals",
                    {**body, "idempotency_key": f"qk4-{tag}"},
                )
                == 409
            )
            lst = await call("GET", base)
            assert not lst["can_queue"] and lst["items"][0]["id"] == q["id"]
            assert (await call("GET", "/queued-renewals"))["total"] == 1

            # -- activation pass --------------------------------------------------
            async with SessionLocal() as s:
                assert (await run_queued_renewals(s))["activated"] == 0
                await s.commit()
            at = before.valid_until + timedelta(seconds=1)
            for expect in (1, 0):  # idempotent
                async with SessionLocal() as s:
                    res = await run_queued_renewals(s, now=at)
                    await s.commit()
                assert res["activated"] == expect
            act = await row(s1)
            assert str(act.package_id) == p2 and str(act.speed_group_id) == g50
            assert act.valid_until == after.valid_until
            async with SessionLocal() as s:
                kinds = set(
                    (
                        await s.execute(
                            select(IspSubscriberEvent.kind).where(
                                IspSubscriberEvent.subscriber_id == uuid.UUID(s1)
                            )
                        )
                    ).scalars()
                )
            assert {"renewed", "queued_renewal", "queued_started"} <= kinds
            assert (
                await status("POST", f"{base}/{q['id']}/cancel", {"reason": "nope"})
                == 409
            )

            # -- cancel unpaid (billing user, confined to c1) ----------------------
            b2 = f"/subscribers/{s2}/queued-renewals"
            before2 = await row(s2)
            q2 = (
                await call(
                    "POST", b2, {"package_id": p2, "idempotency_key": f"qk2-{tag}"}
                )
            )["queued"]
            as_("Bill")
            done = await call(
                "POST", f"{b2}/{q2['id']}/cancel", {"reason": "changed mind"}
            )
            assert (
                done["queued"]["status"] == "cancelled" and done["credit_note_number"]
            )
            assert done["voided_receipts"] == []
            assert (await row(s2)).valid_until == before2.valid_until
            async with SessionLocal() as s:
                inv = await s.get(IspInvoice, uuid.UUID(q2["invoice"]["id"]))
                assert inv.status == "cancelled"
            # confinement: c2's subscriber is invisible
            b3 = f"/subscribers/{s3}/queued-renewals"
            assert await status("GET", b3) == 404
            assert (
                await status(
                    "POST", b3, {"package_id": p2, "idempotency_key": f"qkx-{tag}"}
                )
                == 404
            )
            as_("A")

            # -- cancel paid: needs isp_billing.manage, voids the receipt --------
            before3 = await row(s3)
            q3 = (
                await call(
                    "POST",
                    b3,
                    {
                        "package_id": p2,
                        "paid_now": True,
                        "payment": {"mode": "cash"},
                        "idempotency_key": f"qk3-{tag}",
                    },
                )
            )["queued"]
            done = await call("POST", f"{b3}/{q3['id']}/cancel", {"reason": "refund"})
            assert done["voided_receipts"] and done["credit_note_number"]
            assert (await row(s3)).valid_until == before3.valid_until
            async with SessionLocal() as s:
                pay = (
                    await s.execute(
                        select(IspPayment).where(
                            IspPayment.subscriber_id == uuid.UUID(s3)
                        )
                    )
                ).scalar_one()
                assert pay.status == "voided"
            # the billing role (no isp_billing.manage) is refused on a paid one
            q2b = (
                await call(
                    "POST",
                    b2,
                    {
                        "package_id": p2,
                        "paid_now": True,
                        "payment": {"mode": "cash"},
                        "idempotency_key": f"qk2b-{tag}",
                    },
                )
            )["queued"]
            as_("Bill")
            assert (
                await status("POST", f"{b2}/{q2b['id']}/cancel", {"reason": "x" * 5})
                == 403
            )
            as_("A")

            # -- a JAZE-1 revert from the 360 page cancels it on the next pass ---
            r = await c.post(
                f"{api}/subscribers/{s2}/revert", json={"reason": "undo it"}, headers=ha
            )
            # paid -> JAZE-1 refuses to revert a paid renewal (its own rule)
            assert r.status_code == 409
            q2c_sub = await sub(f"q5{tag}", "c1")
            b5 = f"/subscribers/{q2c_sub}/queued-renewals"
            q5 = (
                await call(
                    "POST", b5, {"package_id": p2, "idempotency_key": f"qk5-{tag}"}
                )
            )["queued"]
            r = await c.post(
                f"{api}/subscribers/{q2c_sub}/revert",
                json={"reason": "undo it"},
                headers=ha,
            )
            assert r.status_code == 200, r.text
            async with SessionLocal() as s:
                res = await run_queued_renewals(
                    s, now=datetime.now(UTC) + timedelta(days=60)
                )
                await s.commit()
                q5row = await s.get(IspQueuedRenewal, uuid.UUID(q5["id"]))
            assert res["cancelled"] >= 1 and q5row.status == "cancelled"
            assert str((await row(q2c_sub)).package_id) == p1

            # -- audit --------------------------------------------------------------
            async with SessionLocal() as s:
                actions = set(
                    (
                        await s.execute(
                            select(AuditLogEntry.action).where(
                                AuditLogEntry.entity_type == "isp_queued_renewal"
                            )
                        )
                    ).scalars()
                )
            assert {
                "isp_queued_renewal_created",
                "isp_queued_renewal_cancelled",
            } <= actions

            # -- another ISP -----------------------------------------------------------
            as_("B")
            rnd = uuid.uuid4()
            for method, path, b in (
                ("GET", base, None),
                ("POST", base, {**body, "idempotency_key": f"qkb-{tag}"}),
                ("POST", f"{base}/{q['id']}/cancel", {"reason": "abc"}),
                ("POST", f"{b2}/{q2b['id']}/cancel", {"reason": "abc"}),
                ("POST", f"{b2}/{rnd}/cancel", {"reason": "abc"}),
            ):
                assert await status(method, path, b, h=hb) == 404, (method, path)
            assert (await call("GET", "/queued-renewals", h=hb))["total"] == 0
            as_("A")
            # a queue id under the wrong subscriber is a 404 too
            assert (
                await status("POST", f"{b3}/{q2b['id']}/cancel", {"reason": "abc"})
                == 404
            )
            os.environ.pop("ISP_QUEUED_RENEWAL_ENABLED")
            get_queued_renewal_settings.cache_clear()
            assert await status("GET", base) == 404
    finally:
        os.environ.pop("ISP_QUEUED_RENEWAL_ENABLED", None)
        get_queued_renewal_settings.cache_clear()
        await engine.dispose()
