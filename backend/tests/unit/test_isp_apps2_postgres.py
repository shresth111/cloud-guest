# ruff: noqa: E501 -- scenario test
"""APPS-2 on real PostgreSQL + Redis (skipped unless ``ISP_TEST_PG_DSN``;
CI has neither). Run::

    CLOUDGUEST_DATABASE_URL=postgresql+asyncpg://postgres@localhost:55441/apps2 \\
    CLOUDGUEST_REDIS_URL=redis://localhost:56381/0 \\
    ISP_TEST_PG_DSN=1 ISP_PARTNER_ENABLED=true ISP_APPS_ENABLED=true \\
    ISP_TELEGRAM_ALERTS_ENABLED=true python -m pytest tests/unit/test_isp_apps2_postgres.py

Covers:
* escalation: an open ticket older than the rule escalates once (event,
  reassignment, log row, J14 Telegram through an injected sender), a
  resolved one does not, a second pass adds nothing;
* task pipeline: completed -> approved; send back needs a reason and
  returns the task to its assignee; only isp_apps.manage decides;
* inventory: a technician cannot check a unit out directly (409), files a
  request, a manager approves it -> the unit is with the customer; vendor /
  location / meta round trip;
* leads: funnel is a GROUP BY count; contact timer starts on first move;
* a scheduled announcement is sent by the frequent pass;
* ONBOARD-1 install task: created in the same transaction; a failing task
  rolls the whole onboarding back; skipped silently with Apps off.
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


async def test_apps2_end_to_end(monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: PLR0915
    import httpx
    from sqlalchemy import func, select, update

    from app.database.session import SessionLocal
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.isp_partner import apps_tasks
    from app.domains.isp_partner.apps2_models import IspTicketEscalation
    from app.domains.isp_partner.apps2_tasks import run_apps_frequent
    from app.domains.isp_partner.apps_common import get_isp_apps_settings
    from app.domains.isp_partner.apps_models import (
        IspAnnouncement,
        IspFieldTask,
        IspTicket,
        IspTicketEvent,
    )
    from app.domains.isp_partner.finance_config import get_finance_settings
    from app.domains.isp_partner.finance_models import IspAutomationSettings
    from app.domains.isp_partner.models import IspPartnerProfile, IspStaffCustomerScope
    from app.domains.isp_partner.plans_models import IspSubscriber
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.marketing.providers import encrypt_config
    from app.domains.organization.models import Organization, OrganizationMember
    from app.domains.rbac.dependencies import CurrentUser
    from app.domains.rbac.models import Role, UserRole
    from app.domains.rbac.repository import RBACRepository
    from app.domains.rbac.seed import seed_rbac
    from app.main import create_app

    get_isp_apps_settings.cache_clear()
    get_finance_settings.cache_clear()
    tag = uuid.uuid4().hex[:8]
    async with SessionLocal() as s:
        await seed_rbac(s)
        await seed_isp_partner_rbac(RBACRepository(s))
        await s.commit()
    users: dict[str, uuid.UUID] = {}
    async with SessionLocal() as s:
        plan = Plan(
            name=f"P {tag}",
            slug=f"pap2-{tag}",
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
                    select(Role).where(Role.slug.in_(("isp-owner", "isp-technician")))
                )
            ).scalars()
        }
        org = Organization(
            name=f"Net {tag}",
            slug=f"ap2net{tag}",
            org_type="msp",
            status="active",
            contact_email=f"n{tag}@example.com",
            timezone="Asia/Kolkata",
            settings={},
        )
        s.add(org)
        await s.flush()
        s.add(
            IspPartnerProfile(organization_id=org.id, default_customer_plan_id=plan.id)
        )
        for n, slug in (("O", "isp-owner"), ("T", "isp-technician")):
            u = User(
                first_name=n,
                last_name="T",
                email=f"ap2{n.lower()}{tag}@example.com",
                username=f"ap2{n.lower()}{tag}",
                password_hash="x",
                is_active=True,
                is_verified=True,
            )
            s.add(u)
            await s.flush()
            s.add_all(
                [
                    OrganizationMember(
                        organization_id=org.id, user_id=u.id, status="active"
                    ),
                    UserRole(
                        user_id=u.id,
                        role_id=roles[slug].id,
                        scope_type="organization",
                        organization_id=org.id,
                        granted_at=datetime.now(UTC),
                        is_active=True,
                    ),
                ]
            )
            users[n] = u.id
        s.add(
            IspAutomationSettings(
                isp_organization_id=org.id,
                telegram_enabled=True,
                telegram_bot_token_encrypted=encrypt_config({"bot_token": "123:test"}),
                telegram_chat_id="-1001234",
            )
        )
        await s.commit()
        isp_id = org.id

    app = create_app()
    state = {"user": users["O"]}
    app.dependency_overrides[CurrentUser] = lambda: AuthUser(
        id=str(state["user"]), email="o@example.com"
    )
    h = {"X-Organization-Id": str(isp_id)}
    api = "/api/v1/isp"

    def as_(who: str) -> None:
        state["user"] = users[who]

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t"
    ) as c:
        r = await c.post(
            f"{api}/customers",
            json={"name": f"Cafe {tag}", "contact_email": f"c{tag}@example.com"},
            headers=h,
        )
        assert r.status_code == 201, r.text
        cust = r.json()["data"]["id"]
        async with SessionLocal() as s:
            s.add(
                IspStaffCustomerScope(
                    isp_organization_id=isp_id,
                    user_id=users["T"],
                    customer_organization_id=uuid.UUID(cust),
                )
            )
            await s.commit()

        # ---- 1. escalation ---------------------------------------------------------
        r = await c.post(
            f"{api}/apps/escalation-rules",
            json={
                "name": "Stuck 1h",
                "after_minutes": 60,
                "escalate_to_role": "isp-noc",
                "escalate_to_user_id": str(users["T"]),
            },
            headers=h,
        )
        assert r.status_code == 201, r.text
        assert (
            await c.post(
                f"{api}/apps/escalation-rules",
                json={"name": "x", "after_minutes": 60},
                headers=h,
            )
        ).status_code == 422
        assert (
            await c.post(
                f"{api}/apps/escalation-rules",
                json={"name": "x", "after_minutes": 60, "escalate_to_role": "root"},
                headers=h,
            )
        ).status_code == 422
        tickets = []
        for subject in (f"No internet {tag}", f"Slow {tag}", f"Already fixed {tag}"):
            r = await c.post(
                f"{api}/apps/tickets",
                json={"isp_customer_id": cust, "subject": subject},
                headers=h,
            )
            assert r.status_code == 201, r.text
            tickets.append(r.json()["data"]["id"])
        async with SessionLocal() as s:
            await s.execute(
                update(IspTicket)
                .where(IspTicket.id.in_([uuid.UUID(tickets[0]), uuid.UUID(tickets[2])]))
                .values(opened_at=datetime.now(UTC) - timedelta(hours=2))
            )
            await s.execute(
                update(IspTicket)
                .where(IspTicket.id == uuid.UUID(tickets[2]))
                .values(status="resolved")
            )
            await s.commit()
        sent: list[str] = []

        async def fake_telegram(token: str, chat: str, text: str) -> None:
            sent.append(f"{token}|{chat}|{text}")
            return None

        async with SessionLocal() as s:
            out = await run_apps_frequent(s, telegram=fake_telegram)
            await s.commit()
        # scoped to this run's ISP (the shared test DB may hold older ISPs)
        mine = [m for m in sent if tag in m]
        assert out["errors"] == 0 and len(mine) == 1, (out, sent)
        assert (
            mine[0].startswith("123:test|-1001234|Ticket T-")
            and f"No internet {tag}" in mine[0]
        )
        async with SessionLocal() as s:
            t0 = await s.get(IspTicket, uuid.UUID(tickets[0]))
            assert t0.assignee_user_id == users["T"]
            kinds = (
                (
                    await s.execute(
                        select(IspTicketEvent.kind).where(
                            IspTicketEvent.ticket_id == t0.id
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert "escalated" in kinds
            esc = (
                await s.execute(
                    select(IspTicketEscalation).where(
                        IspTicketEscalation.ticket_id == t0.id
                    )
                )
            ).scalar_one()
            assert esc.telegram_status == "sent" and esc.to_role == "isp-noc"
            assert (
                await s.execute(
                    select(func.count())
                    .select_from(IspTicketEscalation)
                    .where(IspTicketEscalation.ticket_id == uuid.UUID(tickets[2]))
                )
            ).scalar_one() == 0
        async with SessionLocal() as s:
            again = await run_apps_frequent(s, telegram=fake_telegram)
            await s.commit()
        assert (
            again["errors"] == 0 and len([m for m in sent if tag in m]) == 1
        )  # once per (rule, ticket)
        async with SessionLocal() as s:
            assert (
                await s.execute(
                    select(func.count())
                    .select_from(IspTicketEscalation)
                    .where(IspTicketEscalation.isp_organization_id == isp_id)
                )
            ).scalar_one() == 1
        r = await c.get(f"{api}/apps/escalations", headers=h)
        assert r.status_code == 200 and r.json()["data"]["total"] == 1
        assert r.json()["data"]["items"][0]["telegram_status"] == "sent"

        # ---- 2. task pipeline ----------------------------------------------------------
        async def task(title: str) -> str:
            r = await c.post(
                f"{api}/apps/tasks",
                json={
                    "title": title,
                    "isp_customer_id": cust,
                    "assignee_user_id": str(users["T"]),
                },
                headers=h,
            )
            assert r.status_code == 201, r.text
            return r.json()["data"]["id"]

        t_ok, t_back = await task("Fit ONT"), await task("Re-crimp")
        as_("T")
        for tid in (t_ok, t_back):
            r = await c.patch(
                f"{api}/apps/tasks/{tid}",
                json={"status": "completed", "completion_note": "done"},
                headers=h,
            )
            assert r.status_code == 200, r.text
        assert (
            await c.post(f"{api}/apps/tasks/{t_ok}/approve", json={}, headers=h)
        ).status_code == 403
        as_("O")
        r = await c.post(
            f"{api}/apps/tasks/{t_ok}/approve", json={"note": "checked"}, headers=h
        )
        assert r.status_code == 200 and r.json()["data"]["status"] == "approved"
        assert r.json()["data"]["approval"]["decision"] == "approved"
        assert (
            await c.post(f"{api}/apps/tasks/{t_ok}/approve", json={}, headers=h)
        ).status_code == 422  # not completed any more
        assert (
            await c.post(f"{api}/apps/tasks/{t_back}/send-back", json={}, headers=h)
        ).status_code == 422
        r = await c.post(
            f"{api}/apps/tasks/{t_back}/send-back",
            json={"note": "photo missing"},
            headers=h,
        )
        assert r.status_code == 200 and r.json()["data"]["status"] == "assigned"
        assert r.json()["data"]["rejected_reason"] == "photo missing"
        assert (
            await c.get(f"{api}/apps/tasks", params={"status": "approved"}, headers=h)
        ).json()["data"]["total"] == 1

        # ---- 3. inventory: vendor, location, checkout approval ----------------------------
        v = (
            await c.post(
                f"{api}/apps/inventory/vendors",
                json={"name": "Optic Supplies"},
                headers=h,
            )
        ).json()["data"]
        loc = (
            await c.post(
                f"{api}/apps/inventory/locations",
                json={"name": "Main store", "kind": "warehouse"},
                headers=h,
            )
        ).json()["data"]
        assert (
            await c.post(
                f"{api}/apps/inventory/locations",
                json={"name": "Bag", "kind": "technician_bag"},
                headers=h,
            )
        ).status_code == 422
        item = (
            await c.post(
                f"{api}/apps/inventory/items",
                json={"name": "GPON ONT", "sku": f"ONT-{tag}", "category": "ont"},
                headers=h,
            )
        ).json()["data"]
        unit = (
            await c.post(
                f"{api}/apps/inventory/units",
                json={"item_id": item["id"], "serial": f"SN{tag}"},
                headers=h,
            )
        ).json()["data"]
        r = await c.put(
            f"{api}/apps/inventory/units/{unit['id']}/meta",
            json={"vendor_id": v["id"], "stock_location_id": loc["id"]},
            headers=h,
        )
        assert (
            r.status_code == 200 and r.json()["data"]["vendor_name"] == "Optic Supplies"
        )
        assert r.json()["data"]["location_kind"] == "warehouse"
        by_loc = (
            await c.get(
                f"{api}/apps/inventory/units",
                params={"stock_location_id": loc["id"]},
                headers=h,
            )
        ).json()["data"]
        assert by_loc["total"] == 1
        as_("T")
        r = await c.post(
            f"{api}/apps/inventory/units/{unit['id']}/move",
            json={"state": "assigned", "isp_customer_id": cust},
            headers=h,
        )
        assert (
            r.status_code == 409
            and r.json()["data"]["code"] == "ISP_APPS_CHECKOUT_APPROVAL"
        )
        r = await c.post(
            f"{api}/apps/inventory/units/{unit['id']}/checkout",
            json={"isp_customer_id": cust, "task_id": t_back},
            headers=h,
        )
        assert r.status_code == 201, r.text
        co = r.json()["data"]
        assert (
            await c.post(
                f"{api}/apps/inventory/units/{unit['id']}/checkout",
                json={"isp_customer_id": cust},
                headers=h,
            )
        ).status_code == 409
        assert (
            await c.post(
                f"{api}/apps/inventory/checkouts/{co['id']}/approve", json={}, headers=h
            )
        ).status_code == 403
        as_("O")
        assert (
            await c.get(
                f"{api}/apps/inventory/checkouts",
                params={"status": "pending"},
                headers=h,
            )
        ).json()["data"][0]["id"] == co["id"]
        r = await c.post(
            f"{api}/apps/inventory/checkouts/{co['id']}/approve",
            json={"note": "ok"},
            headers=h,
        )
        assert r.status_code == 200 and r.json()["data"]["status"] == "approved"
        u2 = (
            await c.get(f"{api}/apps/inventory/units/{unit['id']}", headers=h)
        ).json()["data"]
        assert (
            u2["state"] == "assigned"
            and u2["isp_customer_id"] == cust
            and u2["pending_checkout_id"] is None
        )

        # ---- 4. leads: GROUP BY funnel + contact timer ------------------------------------
        for n in ("L1", "L2"):
            assert (
                await c.post(
                    f"{api}/apps/leads",
                    json={"name": n, "isp_customer_id": cust},
                    headers=h,
                )
            ).status_code == 201
        leads = (await c.get(f"{api}/apps/leads", headers=h)).json()["data"]["items"]
        assert (
            leads[0]["sla"]["contact_state"] == "pending"
            and leads[0]["sla"]["first_contacted_at"] is None
        )
        r = await c.patch(
            f"{api}/apps/leads/{leads[0]['id']}",
            json={"status": "contacted"},
            headers=h,
        )
        assert (
            r.status_code == 200 and r.json()["data"]["sla"]["contact_state"] == "met"
        )
        funnel = (await c.get(f"{api}/apps/leads/funnel", headers=h)).json()["data"]
        assert (
            funnel["new"] == 1 and funnel["contacted"] == 1 and funnel["converted"] == 0
        )

        # ---- 5. scheduled announcement ----------------------------------------------------
        when = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        assert (
            await c.post(
                f"{api}/apps/announcements",
                json={
                    "title": "Maintenance",
                    "body": "Tonight",
                    "scheduled_at": (
                        datetime.now(UTC) - timedelta(minutes=1)
                    ).isoformat(),
                },
                headers=h,
            )
        ).status_code == 422
        a = (
            await c.post(
                f"{api}/apps/announcements",
                json={
                    "title": "Maintenance",
                    "body": "Tonight",
                    "send_email": False,
                    "scheduled_at": when,
                },
                headers=h,
            )
        ).json()["data"]
        assert a["status"] == "draft" and a["scheduled_at"]
        async with SessionLocal() as s:
            await s.execute(
                update(IspAnnouncement)
                .where(IspAnnouncement.id == uuid.UUID(a["id"]))
                .values(scheduled_at=datetime.now(UTC) - timedelta(minutes=1))
            )
            await s.commit()
        async with SessionLocal() as s:
            out = await run_apps_frequent(s, telegram=fake_telegram)
            await s.commit()
        assert out["errors"] == 0, out
        assert (await c.get(f"{api}/apps/announcements/{a['id']}", headers=h)).json()[
            "data"
        ]["status"] == "sent"

        # ---- 6. ONBOARD-1 install task ---------------------------------------------------
        g = (
            await c.post(
                f"{api}/speed-groups",
                json={"name": "20 Mbps", "download_kbps": 20480, "upload_kbps": 20480},
                headers=h,
            )
        ).json()["data"]
        pid = (
            await c.post(
                f"{api}/packages",
                json={
                    "speed_group_id": g["id"],
                    "type": "prepaid",
                    "price_paise": 50000,
                },
                headers=h,
            )
        ).json()["data"]["id"]

        def body(ident: str) -> dict:
            return {
                "subscriber": {
                    "isp_customer_id": cust,
                    "identifier": ident,
                    "package_id": pid,
                    "first_name": "Asha",
                }
            }

        r = await c.post(f"{api}/onboarding", json=body(f"ob-{tag}"), headers=h)
        assert r.status_code == 201, r.text
        d = r.json()["data"]
        assert (
            d["task"]["status"] == "unclaimed"
            and d["task"]["subscriber_id"] == d["subscriber"]["id"]
        )
        assert any(x["step"] == "task" and x["status"] == "done" for x in d["steps"])

        async def boom(self, isp, data, **kw):  # noqa: ANN001, ANN202
            from app.domains.isp_partner.apps_common import IspAppsInvalidError

            raise IspAppsInvalidError("task store down")

        monkeypatch.setattr(apps_tasks.FieldTaskService, "create", boom)
        r = await c.post(f"{api}/onboarding", json=body(f"rb-{tag}"), headers=h)
        assert r.status_code == 422 and r.json()["data"]["step"] == "task"
        async with SessionLocal() as s:
            assert (
                await s.execute(
                    select(func.count())
                    .select_from(IspSubscriber)
                    .where(IspSubscriber.identifier == f"rb-{tag}")
                )
            ).scalar_one() == 0
        monkeypatch.undo()

        monkeypatch.setenv("ISP_APPS_ENABLED", "false")
        get_isp_apps_settings.cache_clear()
        try:
            r = await c.post(f"{api}/onboarding", json=body(f"off-{tag}"), headers=h)
            assert r.status_code == 201, r.text
            d = r.json()["data"]
            assert (
                d["task"] is None
                and next(x for x in d["steps"] if x["step"] == "task")["status"]
                == "skipped"
            )
            async with SessionLocal() as s:
                sid = uuid.UUID(d["subscriber"]["id"])
                assert (
                    await s.execute(
                        select(func.count())
                        .select_from(IspFieldTask)
                        .where(IspFieldTask.subscriber_id == sid)
                    )
                ).scalar_one() == 0
        finally:
            monkeypatch.delenv("ISP_APPS_ENABLED", raising=False)
            get_isp_apps_settings.cache_clear()
