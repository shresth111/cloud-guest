# ruff: noqa: E501, PLR0915 -- scenario test
"""COMMS-2b on real PostgreSQL + Redis (skipped unless ``ISP_TEST_PG_DSN``).
Run::

    CLOUDGUEST_DATABASE_URL=postgresql+asyncpg://postgres@localhost:55441/comms2b \\
    CLOUDGUEST_REDIS_URL=redis://localhost:56381/0 \\
    ISP_TEST_PG_DSN=1 ISP_PARTNER_ENABLED=true \\
    python -m pytest tests/unit/test_isp_comms2b_postgres.py

Covers: nothing is sent (and nothing is logged) while the automation flag is
off; overdue goes out at most once per invoice per day; welcome once per
subscriber and only once it is mapped (an unmapped welcome writes no row);
the rendered parameters are stored beside the log row and shown by the logs
page; the invoice reminder email keeps today's text with no enabled
template (and with the hub off) and uses the template when one is enabled;
the email-sender choice appears only with a verified own sender, and an
"own" send goes through it.
"""

from __future__ import annotations

import os
import random
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)


async def test_comms_2b_end_to_end(monkeypatch) -> None:  # noqa: ANN001
    import httpx
    from sqlalchemy import func, select, update

    from app.database.session import SessionLocal
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.isp_partner import automation, comms2b, finance_config
    from app.domains.isp_partner.billing_models import IspInvoice
    from app.domains.isp_partner.comms2b_models import IspMessageContent
    from app.domains.isp_partner.comms_router import get_comms_settings
    from app.domains.isp_partner.finance_models import IspMessageLog
    from app.domains.isp_partner.models import IspPartnerProfile
    from app.domains.isp_partner.plans_models import IspSubscriber
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.marketing.models import OrgMarketingProvider
    from app.domains.marketing.providers import encrypt_config
    from app.domains.notification.models import NotificationDelivery
    from app.domains.organization.models import Organization, OrganizationMember
    from app.domains.rbac.dependencies import CurrentUser
    from app.domains.rbac.models import Role, UserRole
    from app.domains.rbac.repository import RBACRepository
    from app.domains.rbac.seed import seed_rbac
    from app.main import create_app

    flags = finance_config.IspFinanceSettings(
        finance_extras_enabled=True,
        zone_ledger_enabled=False,
        whatsapp_automation_enabled=False,
        telegram_alerts_enabled=False,
        pay_link_base_url="https://network-staging.wyfyguest.com",
    )
    monkeypatch.setattr(finance_config, "get_finance_settings", lambda: flags)
    monkeypatch.setattr(automation, "get_finance_settings", lambda: flags)
    os.environ.pop("ISP_COMMS_HUB_ENABLED", None)
    get_comms_settings.cache_clear()

    sent: list[tuple] = []

    class _Res:
        message_id = "wamid.C2B"

    class FakeSender:
        async def send_waba_template(self, to, *, template_name, language, parameters):  # noqa: ANN001
            sent.append((to, template_name, list(parameters)))
            return _Res()

        async def list_templates(self):
            return [
                {
                    "name": "unpaid_v1",
                    "language": "en",
                    "status": "APPROVED",
                    "components": [{"type": "BODY", "text": "{{1}} {{2}} {{3}} {{4}}"}],
                }
            ]

    async def _fake_sender(session, isp_org_id):  # noqa: ANN001
        return FakeSender()

    monkeypatch.setattr(automation, "_whatsapp_sender", _fake_sender)

    tag = uuid.uuid4().hex[:8]
    async with SessionLocal() as s:
        await seed_rbac(s)
        await seed_isp_partner_rbac(RBACRepository(s))
        await s.commit()
    async with SessionLocal() as s:
        plan = Plan(
            name=f"P {tag}",
            slug=f"pc2b-{tag}",
            plan_type="standard",
            billing_cycle="monthly",
            base_price=Decimal("0"),
            currency="INR",
            is_active=True,
            is_public=False,
        )
        s.add(plan)
        owner = (
            await s.execute(select(Role).where(Role.slug == "isp-owner"))
        ).scalar_one()
        org = Organization(
            name=f"C2B Net {tag}",
            slug=f"c2bnet{tag}",
            org_type="msp",
            status="active",
            contact_email=f"c2b{tag}@example.com",
            timezone="Asia/Kolkata",
            settings={},
        )
        user = User(
            first_name="O",
            last_name="T",
            email=f"c2bo{tag}@example.com",
            username=f"c2bo{tag}",
            password_hash="x",
            is_active=True,
            is_verified=True,
        )
        s.add_all([org, user])
        await s.flush()
        s.add(
            IspPartnerProfile(organization_id=org.id, default_customer_plan_id=plan.id)
        )
        s.add_all(
            [
                OrganizationMember(
                    organization_id=org.id, user_id=user.id, status="active"
                ),
                UserRole(
                    user_id=user.id,
                    role_id=owner.id,
                    scope_type="organization",
                    organization_id=org.id,
                    granted_at=datetime.now(UTC),
                    is_active=True,
                ),
            ]
        )
        isp_id, user_id = org.id, user.id
        await s.commit()

    app = create_app()
    app.dependency_overrides[CurrentUser] = lambda: AuthUser(
        id=str(user_id), email="o@example.com"
    )
    from app.core.storage import get_object_storage

    class _Storage:  # the invoice PDF upload; no object store in this test
        async def upload(self, **kw):  # noqa: ANN003
            return kw["key"]

    app.dependency_overrides[get_object_storage] = lambda: _Storage()
    ha = {"X-Organization-Id": str(isp_id)}
    api = "/api/v1/isp"

    async def logs(trigger: str) -> list:
        async with SessionLocal() as s:
            return list(
                (
                    await s.execute(
                        select(IspMessageLog).where(
                            IspMessageLog.isp_organization_id == isp_id,
                            IspMessageLog.trigger == trigger,
                        )
                    )
                ).scalars()
            )

    async def daily(day) -> None:  # noqa: ANN001
        async with SessionLocal() as s:
            await automation.run_whatsapp_daily(s, isp_id, day)
            await s.commit()

    async def events() -> None:
        async with SessionLocal() as s:
            await automation.run_whatsapp_events(s, isp_id)
            await s.commit()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t"
    ) as c:
        r = await c.put(
            f"{api}/billing/settings",
            json={
                "legal_name": "C2B Pvt Ltd",
                "state_code": "08",
                "gst_enabled": True,
                "invoice_prefix": "CTB",
                "upi_vpa": "c2b@upi",
            },
            headers=ha,
        )
        assert r.status_code == 200, r.text
        r = await c.post(
            f"{api}/customers",
            json={
                "name": f"Cafe & Co {tag}",
                "contact_email": f"cafe{tag}@example.com",
                "contact_phone": "9876543210",
            },
            headers=ha,
        )
        assert r.status_code == 201, r.text
        cust = r.json()["data"]["id"]
        r = await c.put(
            f"{api}/finance/contacts/customer/{cust}",
            json={"whatsapp_opt_in": True},
            headers=ha,
        )
        assert r.status_code == 200, r.text
        r = await c.post(
            f"{api}/billing/invoices",
            json={
                "isp_customer_id": cust,
                "description": "Bandwidth",
                "amount_paise": 100000,
            },
            headers=ha,
        )
        assert r.status_code == 201, r.text
        inv_id = r.json()["data"]["id"]
        inv_no = r.json()["data"]["number"]
        today = datetime.now(UTC).date()
        async with SessionLocal() as s:
            await s.execute(
                update(IspInvoice)
                .where(IspInvoice.id == uuid.UUID(inv_id))
                .values(due_date=today - timedelta(days=3))
            )
            await s.commit()
        flags.whatsapp_automation_enabled = True  # the PUT refuses while off
        r = await c.put(
            f"{api}/finance/automation",
            json={
                "whatsapp_enabled": True,
                "whatsapp_templates": {
                    "overdue": {"template_name": "overdue_v1", "language": "en"}
                },
            },
            headers=ha,
        )
        assert r.status_code == 200, r.text
        assert "overdue" in r.json()["data"]["triggers"]
        flags.whatsapp_automation_enabled = False

        async def new_subscriber(n: str) -> uuid.UUID:
            async with SessionLocal() as s:
                sub = IspSubscriber(
                    isp_organization_id=isp_id,
                    customer_organization_id=uuid.UUID(cust),
                    identifier=f"c2b{n}{tag}",
                    first_name=f"Sub{n}",
                    phone="9812345678",
                    reminder_opt_in={"whatsapp": True},
                    status="active",
                    source="manual",
                    circuit_id=random.randint(10_000_000, 99_999_999),
                )
                s.add(sub)
                await s.flush()
                sid = sub.id
                await s.commit()
                return sid

        sub1 = await new_subscriber("1")

        # -- flag OFF: nothing sent, nothing logged ---------------------------
        await daily(today)
        await events()
        assert sent == []
        assert await logs("overdue") == [] and await logs("welcome") == []

        # -- flag ON: overdue once per invoice per day -------------------------
        flags.whatsapp_automation_enabled = True
        await daily(today)
        await daily(today)
        od = [x for x in sent if x[1] == "overdue_v1"]
        assert len(od) == 1, sent
        assert od[0][0] == "+919876543210" and od[0][2][1] == inv_no
        assert od[0][2][3].startswith(
            "https://network-staging.wyfyguest.com/partner/pay/"
        )
        await daily(today + timedelta(days=1))
        assert len([x for x in sent if x[1] == "overdue_v1"]) == 2
        rows = await logs("overdue")
        assert len(rows) == 2 and {r.status for r in rows} == {"sent"}

        # rendered parameters stored beside the log row
        async with SessionLocal() as s:
            content = (
                await s.execute(
                    select(IspMessageContent).where(
                        IspMessageContent.message_log_id == rows[0].id
                    )
                )
            ).scalar_one()
        assert content.template_name == "overdue_v1"
        assert [p["variable"] for p in content.parameters] == [
            "name",
            "invoice_number",
            "balance",
            "pay_link",
        ]
        assert content.parameters[1]["value"] == inv_no

        # -- welcome: unmapped -> silent; mapped -> once per subscriber --------
        await events()
        assert await logs("welcome") == []  # not mapped: no "skipped" row either
        r = await c.put(
            f"{api}/finance/automation",
            json={
                "whatsapp_templates": {
                    "overdue": {"template_name": "overdue_v1"},
                    "welcome": {"template_name": "welcome_v1"},
                }
            },
            headers=ha,
        )
        assert r.status_code == 200, r.text
        sub2 = await new_subscriber("2")
        await events()
        await events()
        wl = [x for x in sent if x[1] == "welcome_v1"]
        assert sorted(x[2][1] for x in wl) == sorted([f"c2b1{tag}", f"c2b2{tag}"])
        assert len(await logs("welcome")) == 2
        assert {r.subscriber_id for r in await logs("welcome")} == {sub1, sub2}

        # -- logs page shows the real content (hub on) -------------------------
        os.environ["ISP_COMMS_HUB_ENABLED"] = "true"
        get_comms_settings.cache_clear()
        r = await c.get(f"{api}/comms/logs", params={"event": "overdue"}, headers=ha)
        assert r.status_code == 200, r.text
        item = (
            r.json()["data"]["items"][0]
            if isinstance(r.json()["data"], dict)
            else r.json()["data"][0]
        )
        assert item["template_name"] == "overdue_v1"
        assert inv_no in item["content"] and "pay_link:" in item["content"]
        assert item["summary"].startswith("Overdue")

        # -- invoice reminder email: fallback, then the template ---------------
        async def last_delivery() -> NotificationDelivery:
            async with SessionLocal() as s:
                return (
                    await s.execute(
                        select(NotificationDelivery)
                        .where(NotificationDelivery.organization_id == isp_id)
                        .order_by(NotificationDelivery.created_at.desc())
                        .limit(1)
                    )
                ).scalar_one()

        for hub in ("false", "true"):  # no enabled template: today's text either way
            os.environ["ISP_COMMS_HUB_ENABLED"] = hub
            get_comms_settings.cache_clear()
            r = await c.post(
                f"{api}/invoices/{inv_id}/remind", json={"channel": "email"}, headers=ha
            )
            assert r.status_code == 200 and r.json()["data"]["queued"] is True, r.text
            d = await last_delivery()
            assert d.subject == f"C2B Net {tag}: invoice {inv_no} due"
            assert "has a balance of Rs" in d.body
        r = await c.put(
            f"{api}/comms/templates/unpaid_invoice/email",
            json={
                "enabled": True,
                "email_subject": "Pay {{invoice_number}} now",
                "email_body": "Hi {{name}},\n\nBalance {{balance}}.\nPay: {{pay_link}}",
            },
            headers=ha,
        )
        assert r.status_code == 200, r.text
        r = await c.post(
            f"{api}/invoices/{inv_id}/remind", json={"channel": "email"}, headers=ha
        )
        assert r.status_code == 200, r.text
        d = await last_delivery()
        assert d.subject == f"Pay {inv_no} now"
        assert (
            f"Hi Cafe &amp; Co {tag}," in d.body
            and "<br>Pay: https://network-staging.wyfyguest.com/partner/pay/" in d.body
        )
        assert "has a balance of" not in d.body
        # hub off again -> template ignored, today's text
        os.environ["ISP_COMMS_HUB_ENABLED"] = "false"
        get_comms_settings.cache_clear()
        r = await c.post(
            f"{api}/invoices/{inv_id}/remind", json={"channel": "email"}, headers=ha
        )
        assert "has a balance of Rs" in (await last_delivery()).body

        # -- email sender choice -----------------------------------------------
        r = await c.get(f"{api}/finance/email-senders", headers=ha)
        assert r.status_code == 200, r.text
        assert r.json()["data"]["choice_available"] is False
        assert [x["key"] for x in r.json()["data"]["senders"]] == ["platform"]
        r = await c.post(
            f"{api}/finance/invoices/{inv_id}/email", json={"sender": "own"}, headers=ha
        )
        assert r.status_code == 422, r.text
        async with SessionLocal() as s:
            s.add(
                OrgMarketingProvider(
                    organization_id=isp_id,
                    channel="email",
                    provider_type="smtp",
                    config_encrypted=encrypt_config(
                        {
                            "host": "smtp.example.com",
                            "port": 587,
                            "username": "u",
                            "password": "SMTP-SECRET",
                            "from_address": "billing@isp.example.com",
                        }
                    ),
                    display={"from_address": "billing@isp.example.com"},
                    status="verified",
                    enabled=True,
                )
            )
            await s.commit()
        r = await c.get(f"{api}/finance/email-senders", headers=ha)
        data = r.json()["data"]
        assert data["choice_available"] is True and [
            x["key"] for x in data["senders"]
        ] == ["platform", "own"]
        assert "SMTP-SECRET" not in r.text

        mails: list[tuple] = []

        class _Mail:
            message_id = "<m1@isp>"

        class OwnFake:
            async def send(self, email, *, subject, html_body, from_name, headers):  # noqa: ANN001
                mails.append((email, subject, from_name))
                return _Mail()

        monkeypatch.setattr(
            comms2b, "own_sender_with_attachment", lambda *_a: OwnFake()
        )
        async with SessionLocal() as s:
            before = (
                await s.execute(
                    select(func.count())
                    .select_from(NotificationDelivery)
                    .where(NotificationDelivery.organization_id == isp_id)
                )
            ).scalar_one()
        r = await c.post(
            f"{api}/finance/invoices/{inv_id}/email", json={"sender": "own"}, headers=ha
        )
        assert r.status_code == 200, r.text
        assert (
            r.json()["data"]["sender"] == "own" and len(r.json()["data"]["sent"]) == 1
        )
        assert mails == [
            (
                f"cafe{tag}@example.com",
                f"C2B Net {tag}: invoice {inv_no}",
                f"C2B Net {tag}",
            )
        ]
        async with SessionLocal() as s:
            after = (
                await s.execute(
                    select(func.count())
                    .select_from(NotificationDelivery)
                    .where(NotificationDelivery.organization_id == isp_id)
                )
            ).scalar_one()
        assert after == before  # not through the platform outbox
        rows = [r for r in await logs("invoice_email") if "own sender" in r.summary]
        assert len(rows) == 1 and rows[0].status == "sent"
        # the default is unchanged: platform outbox
        r = await c.post(f"{api}/finance/invoices/{inv_id}/email", json={}, headers=ha)
        assert r.status_code == 200 and r.json()["data"]["queued"], r.text

    os.environ.pop("ISP_COMMS_HUB_ENABLED", None)
    get_comms_settings.cache_clear()
