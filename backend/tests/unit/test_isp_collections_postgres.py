"""COLLECTIONS-1 on real PostgreSQL + Redis (skipped unless ``ISP_TEST_PG_DSN``
is set; CI has neither). Fresh scratch DB at head. Real JAZE-1 renew for the
bills, the real payment code for cash.

Covers: flag off 404; overdue ranking + reasons; notes + timeline; promise
open/kept (cash) and broken (daily pass -> one follow-up task, idempotent);
technician confined to one customer sees only it and 404s on the other
(timeline, cash, promise cancel, slip); cash through record_payment with
Idempotency-Key (no double payment) and spread over two bills; 58/80 mm slip;
handover submit / nothing left / self-approval 409 / approve with variance /
decide twice 409 / reject releases the payments; zone scope narrows the list;
forecast shape; audit rows; another ISP 404 on every new id route.
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


async def test_collections_end_to_end() -> None:  # noqa: PLR0915
    import httpx
    from sqlalchemy import func, select, update

    from app.database.session import SessionLocal, engine
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.isp_partner.apps_common import get_isp_apps_settings
    from app.domains.isp_partner.apps_models import IspFieldTask
    from app.domains.isp_partner.billing_models import IspInvoice, IspPayment
    from app.domains.isp_partner.collections_config import get_collections_settings
    from app.domains.isp_partner.collections_models import (
        IspCashHandoverItem,
        IspCollectionPromise,
    )
    from app.domains.isp_partner.collections_tasks import run_collections_daily
    from app.domains.isp_partner.models import IspPartnerProfile, IspStaffCustomerScope
    from app.domains.isp_partner.repository import IspRepository
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.isp_partner.tasks import _SystemContext
    from app.domains.isp_partner.zones_config import get_zones_settings
    from app.domains.organization.models import Organization, OrganizationMember
    from app.domains.rbac.dependencies import CurrentUser
    from app.domains.rbac.models import AuditLogEntry, Role, UserRole
    from app.domains.rbac.repository import RBACRepository
    from app.domains.rbac.seed import seed_rbac
    from app.main import create_app

    def clear() -> None:
        get_collections_settings.cache_clear()
        get_isp_apps_settings.cache_clear()
        get_zones_settings.cache_clear()

    tag = uuid.uuid4().hex[:8]
    os.environ.pop("ISP_COLLECTIONS_ENABLED", None)
    clear()
    try:
        async with SessionLocal() as s:
            await seed_rbac(s)
            await seed_isp_partner_rbac(RBACRepository(s))
            await s.commit()
        users, isps = {}, {}
        async with SessionLocal() as s:
            plan = Plan(
                name=f"P {tag}",
                slug=f"co-{tag}",
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
                                (
                                    "isp-owner",
                                    "isp-admin",
                                    "isp-technician",
                                    "isp-billing",
                                )
                            )
                        )
                    )
                ).scalars()
            }

            def person(n: str) -> User:
                return User(
                    first_name=n,
                    last_name="C",
                    email=f"co{n.lower()}{tag}@example.com",
                    username=f"co{n.lower()}{tag}",
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
                    name=f"Co {n} {tag}",
                    slug=f"conet{n.lower()}{tag}",
                    org_type="msp",
                    status="active",
                    contact_email=f"co{n}{tag}@example.com",
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
                    for who, slug in (
                        ("Tech", "isp-technician"),
                        ("Bill", "isp-billing"),
                        ("Adm", "isp-admin"),
                    ):
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

        def as_(who: str) -> None:
            state["user"] = users[who]

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t"
        ) as c:

            async def call(
                method: str, path: str, body=None, h=ha, ok=(200, 201), extra=None
            ):  # noqa: ANN001, ANN202, E501
                r = await c.request(
                    method, f"{api}{path}", json=body, headers={**h, **(extra or {})}
                )
                assert r.status_code in ok, (method, path, r.status_code, r.text)
                return (
                    r.json().get("data")
                    if "json" in r.headers.get("content-type", "")
                    else r
                )

            async def status(method: str, path: str, body=None, h=ha) -> int:  # noqa: ANN001
                r = await c.request(method, f"{api}{path}", json=body, headers=h)
                return r.status_code

            # -- setup --------------------------------------------------------
            await call(
                "PUT",
                "/billing/settings",
                {
                    "legal_name": "Net A Pvt Ltd",
                    "state_code": "07",
                    "gst_enabled": False,
                    "invoice_prefix": "COL",
                },
            )
            c1 = (
                await call(
                    "POST",
                    "/customers",
                    {"name": f"c1 {tag}", "contact_email": f"c1{tag}@e.com"},
                )
            )["id"]
            c2 = (
                await call(
                    "POST",
                    "/customers",
                    {"name": f"c2 {tag}", "contact_email": f"c2{tag}@e.com"},
                )
            )["id"]
            async with SessionLocal() as s:
                s.add(
                    IspStaffCustomerScope(
                        isp_organization_id=isps["A"],
                        user_id=users["Tech"],
                        customer_organization_id=uuid.UUID(c1),
                    )
                )
                await s.commit()
            g = (
                await call(
                    "POST",
                    "/speed-groups",
                    {"name": "20M", "download_kbps": 20480, "upload_kbps": 20480},
                )
            )["id"]
            pkg = (
                await call(
                    "POST",
                    "/packages",
                    {"speed_group_id": g, "type": "prepaid", "price_paise": 50000},
                )
            )["id"]

            async def subscriber(ident: str, cust: str) -> str:
                return (
                    await call(
                        "POST",
                        "/subscribers",
                        {
                            "isp_customer_id": cust,
                            "identifier": ident,
                            "package_id": pkg,
                            "phone": "9876543210",
                        },
                    )
                )["id"]

            async def bill(sid: str, key: str, due_ago: int) -> str:
                inv = (
                    await call(
                        "POST",
                        f"/subscribers/{sid}/renew",
                        {"idempotency_key": key},
                    )
                )["invoice"]
                async with SessionLocal() as s:
                    await s.execute(
                        update(IspInvoice)
                        .where(IspInvoice.id == uuid.UUID(inv["id"]))
                        .values(
                            issue_date=date.today() - timedelta(days=due_ago + 7),
                            due_date=date.today() - timedelta(days=due_ago),
                        )
                    )
                    await s.commit()
                return inv["id"]

            s1 = await subscriber(f"s1{tag}", c1)
            s2 = await subscriber(f"s2{tag}", c1)
            s3 = await subscriber(f"s3{tag}", c2)
            # every subscriber may already hold a bill from create; push those
            # far into the future so only the bills below are overdue
            async with SessionLocal() as s:
                await s.execute(
                    update(IspInvoice)
                    .where(
                        IspInvoice.subscriber_id.in_(
                            [uuid.UUID(x) for x in (s1, s2, s3)]
                        )
                    )
                    .values(due_date=date.today() + timedelta(days=300))
                )
                await s.commit()
            i1a = await bill(s1, f"a{tag}", 40)
            i1b = await bill(s1, f"b{tag}", 35)
            i2 = await bill(s2, f"c{tag}", 5)
            await bill(s3, f"d{tag}", 70)

            # -- flag off -------------------------------------------------------
            assert await status("GET", "/collections/overdue") == 404
            os.environ["ISP_COLLECTIONS_ENABLED"] = "true"
            os.environ["ISP_APPS_ENABLED"] = "true"
            clear()

            # -- overdue list ---------------------------------------------------
            data = await call("GET", "/collections/overdue")
            by_sub = {i["subscriber_id"]: i for i in data["items"]}
            assert set(by_sub) == {s1, s2, s3}
            assert by_sub[s3]["risk"]["band"] == "high"
            assert by_sub[s1]["invoices_overdue"] == 2
            assert "two_unpaid" in [r["code"] for r in by_sub[s1]["risk"]["reasons"]]
            assert by_sub[s1]["overdue_paise"] == 2 * by_sub[s2]["overdue_paise"]
            bands = [i["risk"]["band"] for i in data["items"]]
            order = {"high": 0, "medium": 1, "low": 2}
            assert bands == sorted(bands, key=order.get)
            assert data["summary"]["parties"] == 3
            high = await call("GET", "/collections/overdue?band=high")
            # s3: 70 d (50) + never paid (10); s1: 40 d (35) + 2 bills (8) + 10
            assert {i["subscriber_id"] for i in high["items"]} == {s1, s3}
            assert by_sub[s1]["risk"]["score"] == 53
            assert (await call("GET", f"/collections/overdue?search=s2{tag}"))[
                "total"
            ] == 1

            # -- notes + timeline -------------------------------------------------
            await call(
                "POST",
                "/collections/notes",
                {"subscriber_id": s1, "body": "Called, will pay", "outcome": "called"},
            )
            assert (
                await status(
                    "POST",
                    "/collections/notes",
                    {"subscriber_id": s1, "isp_customer_id": c1, "body": "x"},
                )
                == 422
            )
            tl = await call("GET", f"/collections/subscribers/{s1}/timeline")
            kinds = [e["kind"] for e in tl["items"]]
            assert "note" in kinds and "invoice" in kinds
            assert tl["overdue_paise"] == by_sub[s1]["overdue_paise"]

            # -- promises -----------------------------------------------------------
            today = date.today()
            p2 = await call(
                "POST",
                "/collections/promises",
                {
                    "subscriber_id": s2,
                    "promised_on": (today + timedelta(days=2)).isoformat(),
                },
            )
            assert (
                p2["status"] == "open"
                and p2["target_paise"] == by_sub[s2]["overdue_paise"]
            )
            p1 = await call(
                "POST",
                "/collections/promises",
                {
                    "subscriber_id": s1,
                    "promised_on": today.isoformat(),
                    "amount_paise": 100,
                },
            )
            p3 = await call(
                "POST",
                "/collections/promises",
                {"subscriber_id": s3, "promised_on": today.isoformat()},
            )
            assert (
                await status(
                    "POST",
                    "/collections/promises",
                    {
                        "subscriber_id": s1,
                        "promised_on": (today - timedelta(days=1)).isoformat(),
                    },
                )
                == 422
            )
            item = next(
                i
                for i in (await call("GET", "/collections/overdue"))["items"]
                if i["subscriber_id"] == s2
            )
            assert item["promise"]["id"] == p2["id"]
            assert "open_promise" in [r["code"] for r in item["risk"]["reasons"]]

            # s1's promise date passes without money -> broken + one task
            async with SessionLocal() as s:
                await s.execute(
                    update(IspCollectionPromise)
                    .where(IspCollectionPromise.id == uuid.UUID(p1["id"]))
                    .values(promised_on=today - timedelta(days=1))
                )
                await s.commit()
            for _ in range(2):  # idempotent
                async with SessionLocal() as s:
                    repo = IspRepository(s)
                    org = await repo.get_organization(isps["A"])
                    prof = await repo.get_profile(isps["A"])
                    await run_collections_daily(s, _SystemContext(org, prof, repo))
                    await s.commit()
            async with SessionLocal() as s:
                row = await s.get(IspCollectionPromise, uuid.UUID(p1["id"]))
                assert row.status == "broken" and row.followup_task_id is not None
                tasks = (
                    await s.execute(
                        select(func.count())
                        .select_from(IspFieldTask)
                        .where(IspFieldTask.subscriber_id == uuid.UUID(s1))
                    )
                ).scalar_one()
                assert tasks == 1
                task = await s.get(IspFieldTask, row.followup_task_id)
                assert task.assignee_user_id == users["A"]
            missed = await call("GET", "/collections/promises?due=missed")
            assert [p["id"] for p in missed["items"]] == [p1["id"]]
            tl = await call("GET", f"/collections/subscribers/{s1}/timeline")
            assert "promise_broken" in [e["kind"] for e in tl["items"]]
            item = next(
                i
                for i in (await call("GET", "/collections/overdue"))["items"]
                if i["subscriber_id"] == s1
            )
            assert item["broken_promises_90d"] == 1

            # -- the technician is confined to c1 -------------------------------
            as_("Tech")
            data = await call("GET", "/collections/overdue")
            assert {i["subscriber_id"] for i in data["items"]} == {s1, s2}
            assert await status("GET", f"/collections/subscribers/{s3}/timeline") == 404
            assert await status("GET", f"/collections/customers/{c2}/timeline") == 404
            assert (
                await status(
                    "POST", f"/collections/promises/{p3['id']}/cancel", {"reason": "x"}
                )
                == 404
            )
            assert (
                await status(
                    "POST",
                    "/collections/cash",
                    {"subscriber_id": s3, "amount_paise": 100},
                )
                == 404
            )
            assert (
                await status(
                    "POST", "/collections/notes", {"subscriber_id": s3, "body": "x"}
                )
                == 404
            )

            # cash in the field: the full s2 bill, keeps p2; a repeat is the
            # same payment
            key = {"Idempotency-Key": f"cash-{tag}"}
            amt2 = by_sub[s2]["overdue_paise"]
            first = await call(
                "POST",
                "/collections/cash",
                {"subscriber_id": s2, "amount_paise": amt2},
                extra=key,
            )
            again = await call(
                "POST",
                "/collections/cash",
                {"subscriber_id": s2, "amount_paise": amt2},
                extra=key,
            )
            assert first["payment"]["id"] == again["payment"]["id"] and again["repeat"]
            assert first["payment"]["mode"] == "cash" and first["promise_kept"] is True
            async with SessionLocal() as s:
                inv = await s.get(IspInvoice, uuid.UUID(i2))
                assert inv.status == "paid"
                n = (
                    await s.execute(
                        select(func.count())
                        .select_from(IspPayment)
                        .where(IspPayment.subscriber_id == uuid.UUID(s2))
                    )
                ).scalar_one()
                assert n == 1
                kept = await s.get(IspCollectionPromise, uuid.UUID(p2["id"]))
                assert kept.status == "kept"
            # one cash payment spread over both s1 bills, oldest first
            amt1 = by_sub[s1]["overdue_paise"]
            spread = await call(
                "POST",
                "/collections/cash",
                {"subscriber_id": s1, "amount_paise": amt1 - 100},
            )
            assert len(spread["allocations"]) == 2
            async with SessionLocal() as s:
                a = await s.get(IspInvoice, uuid.UUID(i1a))
                b = await s.get(IspInvoice, uuid.UUID(i1b))
                assert a.status == "paid" and b.status == "partially_paid"
            pid = first["payment"]["id"]
            slip = await call("GET", f"/collections/payments/{pid}/slip.pdf?width=58")
            assert slip.headers["content-type"] == "application/pdf"
            assert slip.content.startswith(b"%PDF")
            mine = await call("GET", "/collections/cash/mine")
            assert mine["pending_handover_paise"] == amt2 + amt1 - 100

            # handover: submit, nothing left, technician cannot approve
            h1 = await call(
                "POST",
                "/collections/handovers",
                {
                    "business_date": today.isoformat(),
                    "declared_paise": amt2 + amt1 - 200,
                },
            )
            assert h1["expected_paise"] == amt2 + amt1 - 100
            assert h1["declared_difference_paise"] == -100 and len(h1["items"]) == 2
            assert (
                await status(
                    "POST",
                    "/collections/handovers",
                    {"business_date": today.isoformat(), "declared_paise": 0},
                )
                == 422
            )
            assert (
                await status(
                    "POST",
                    f"/collections/handovers/{h1['id']}/approve",
                    {"received_paise": 1},
                )
                == 403
            )
            own = await call("GET", "/collections/handovers")
            assert [h["id"] for h in own["items"]] == [h1["id"]] and not own[
                "can_approve"
            ]

            # the billing user is neither the collector nor an approver
            as_("Bill")
            assert await status("GET", f"/collections/payments/{pid}/slip.pdf") == 404
            assert await status("GET", f"/collections/handovers/{h1['id']}") == 404
            assert (await call("GET", "/collections/handovers"))["items"] == []

            # owner approves with a variance; deciding twice is a 409
            as_("A")
            done = await call(
                "POST",
                f"/collections/handovers/{h1['id']}/approve",
                {"received_paise": amt2 + amt1 - 200, "note": "100 short"},
            )
            assert done["status"] == "approved" and done["variance_paise"] == -200 + 100
            assert (
                await status(
                    "POST",
                    f"/collections/handovers/{h1['id']}/approve",
                    {"received_paise": 1},
                )
                == 409
            )
            assert await call("GET", f"/collections/payments/{pid}/slip.pdf")

            # self-approval refused; reject releases the payments
            await call(
                "POST", "/collections/cash", {"subscriber_id": s3, "amount_paise": 500}
            )
            h2 = await call(
                "POST",
                "/collections/handovers",
                {"business_date": today.isoformat(), "declared_paise": 500},
            )
            r = await c.post(
                f"{api}/collections/handovers/{h2['id']}/approve",
                json={"received_paise": 500},
                headers=ha,
            )
            assert r.status_code == 409
            assert r.json()["data"]["code"] == "ISP_COLLECTION_SELF_APPROVAL"
            as_("Adm")
            assert (
                await status(
                    "POST", f"/collections/handovers/{h2['id']}/reject", {"note": ""}
                )
                == 422
            )
            rej = await call(
                "POST", f"/collections/handovers/{h2['id']}/reject", {"note": "recount"}
            )
            assert rej["status"] == "rejected"
            as_("A")
            h3 = await call(
                "POST",
                "/collections/handovers",
                {"business_date": today.isoformat(), "declared_paise": 500},
            )
            assert h3["expected_paise"] == 500
            async with SessionLocal() as s:
                live = (
                    await s.execute(
                        select(func.count())
                        .select_from(IspCashHandoverItem)
                        .where(IspCashHandoverItem.is_deleted.is_(False))
                    )
                ).scalar_one()
                assert live == 3  # h1's two + h3's one

            # promise cancel, forecast ----------------------------------------
            cancelled = await call(
                "POST",
                f"/collections/promises/{p3['id']}/cancel",
                {"reason": "dispute"},
            )
            assert cancelled["status"] == "cancelled"
            assert (
                await status(
                    "POST", f"/collections/promises/{p3['id']}/cancel", {"reason": "x"}
                )
                == 409
            )
            fc = await call("GET", "/collections/forecast")
            assert fc["collected_so_far_paise"] >= amt2 + amt1 - 100 + 500
            assert {c_["key"] for c_ in fc["components"]} >= {
                "promises",
                "due_this_week",
                "overdue_high",
            }

            # zone scope narrows the list ---------------------------------------
            os.environ["ISP_ZONES_ENABLED"] = "true"
            clear()
            z = (await call("POST", "/zones", {"name": f"Z {tag}"}))["id"]
            await call("PATCH", f"/subscribers/{s3}", {"zone_id": z})
            # bills carry the zone they were issued in (ZONE-1 invoice rule)
            async with SessionLocal() as ss:
                await ss.execute(
                    update(IspInvoice)
                    .where(IspInvoice.subscriber_id == uuid.UUID(s3))
                    .values(zone_id=uuid.UUID(z))
                )
                await ss.commit()
            scoped = await call("GET", f"/collections/overdue?scope_zone_id={z}")
            assert {i["subscriber_id"] for i in scoped["items"]} == {s3}
            os.environ.pop("ISP_ZONES_ENABLED")
            clear()

            # audit rows -----------------------------------------------------------
            async with SessionLocal() as s:
                actions = set(
                    (
                        await s.execute(
                            select(AuditLogEntry.action).where(
                                AuditLogEntry.entity_type == "isp_collections"
                            )
                        )
                    ).scalars()
                )
            assert {
                "isp_collection_promise_made",
                "isp_collection_promise_cancelled",
                "isp_collection_cash_recorded",
                "isp_cash_handover_submitted",
                "isp_cash_handover_approved",
                "isp_cash_handover_rejected",
            } <= actions

            # another ISP: 404 on every id route ---------------------------------
            as_("B")
            await call(
                "PUT",
                "/billing/settings",
                {"legal_name": "Net B", "state_code": "07", "invoice_prefix": "COB"},
                h=hb,
            )
            rnd = uuid.uuid4()
            for method, path, body in (
                ("GET", f"/collections/subscribers/{s1}/timeline", None),
                ("GET", f"/collections/customers/{c1}/timeline", None),
                ("POST", f"/collections/promises/{p2['id']}/cancel", {"reason": "x"}),
                ("POST", f"/collections/promises/{rnd}/cancel", {"reason": "x"}),
                ("GET", f"/collections/payments/{pid}/slip.pdf", None),
                ("GET", f"/collections/handovers/{h1['id']}", None),
                ("GET", f"/collections/handovers/{rnd}", None),
                (
                    "POST",
                    f"/collections/handovers/{h3['id']}/approve",
                    {"received_paise": 1},
                ),
                ("POST", f"/collections/handovers/{h3['id']}/reject", {"note": "x"}),
                ("POST", "/collections/cash", {"subscriber_id": s1, "amount_paise": 1}),
                ("POST", "/collections/notes", {"subscriber_id": s1, "body": "x"}),
                (
                    "POST",
                    "/collections/promises",
                    {"isp_customer_id": c1, "promised_on": today.isoformat()},
                ),
            ):
                assert await status(method, path, body, h=hb) == 404, (method, path)
            assert (await call("GET", "/collections/overdue", h=hb))["items"] == []
            assert (await call("GET", "/collections/handovers", h=hb))["items"] == []
            # positive control for B: its own (empty) world answers 200
            assert (await call("GET", "/collections/forecast", h=hb))[
                "predicted_total_paise"
            ] == 0
            as_("A")

            # flag off again -> 404
            os.environ.pop("ISP_COLLECTIONS_ENABLED")
            clear()
            assert await status("GET", "/collections/overdue") == 404
    finally:
        for k in ("ISP_COLLECTIONS_ENABLED", "ISP_APPS_ENABLED", "ISP_ZONES_ENABLED"):
            os.environ.pop(k, None)
        clear()
        await engine.dispose()
