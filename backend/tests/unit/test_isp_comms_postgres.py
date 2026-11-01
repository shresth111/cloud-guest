"""COMMS-2 on real PostgreSQL + Redis (skipped unless ``ISP_TEST_PG_DSN`` is
set; CI has neither). Fresh scratch DB at head. The Meta sender is faked;
everything else is real.

Covers: flag off; log filters (channel, event, phone, email, plain dates);
the Meta handshake; unsigned / wrongly signed callbacks refused; receipts
only for this ISP's messages, idempotent; delivered/read only from receipts
and the JAZE-4 row never rewritten; CSV; confined scope; templates (unknown
variables refused, approved-only WhatsApp, variable count, JAZE-4 mapping
written and cleared, previews with the pay-link scheme).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from datetime import UTC, datetime
from decimal import Decimal

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)


async def test_comms_hub_end_to_end() -> None:  # noqa: PLR0915
    import httpx
    from sqlalchemy import select

    from app.database.session import SessionLocal, engine
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.isp_partner import automation as automation_mod
    from app.domains.isp_partner.comms_router import get_comms_settings
    from app.domains.isp_partner.finance_models import (
        IspAutomationSettings,
        IspMessageLog,
    )
    from app.domains.isp_partner.models import IspPartnerProfile, IspStaffCustomerScope
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.isp_partner.zones_config import get_zones_settings

    _real_sender = automation_mod._whatsapp_sender

    async def _async(v):  # noqa: ANN001, ANN202
        return v

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
                    bill = person("Bill")
                    s.add(bill)
                    await s.flush()
                    s.add_all(grant(bill, org, "isp-billing"))
                    users["Bi"] = bill.id
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
            os.environ["ISP_COMMS_HUB_ENABLED"] = "true"
            get_comms_settings.cache_clear()
            cust = {}
            for n in ("c1", "c2"):
                cust[n] = (
                    await call(
                        "POST",
                        "/customers",
                        {"name": f"{n} {tag}", "contact_email": f"{n}{tag}@e.com"},
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
            phone = "98" + "".join(str(ord(ch) % 10) for ch in tag)[:8]
            sid = (
                await call(
                    "POST",
                    "/subscribers",
                    {
                        "isp_customer_id": cust["c1"],
                        "identifier": f"u{tag}",
                        "package_id": pkg,
                        "phone": phone,
                        "email": f"sub{tag}@e.com",
                    },
                )
            )["id"]
            async with SessionLocal() as s:
                rows = [
                    IspMessageLog(
                        isp_organization_id=isps["A"],
                        channel="whatsapp",
                        trigger="unpaid",
                        recipient_masked="98XXXXXX12",
                        customer_organization_id=uuid.UUID(cust["c1"]),
                        subscriber_id=uuid.UUID(sid),
                        summary="Unpaid INV-1",
                        status="sent",
                        provider_message_id=f"wamid.A{tag}",
                    ),
                    IspMessageLog(
                        isp_organization_id=isps["A"],
                        channel="whatsapp",
                        trigger="receipt",
                        recipient_masked="98XXXXXX12",
                        customer_organization_id=uuid.UUID(cust["c1"]),
                        subscriber_id=uuid.UUID(sid),
                        summary="Receipt R-1",
                        status="sent",
                        provider_message_id=f"wamid.B{tag}",
                    ),
                    IspMessageLog(
                        isp_organization_id=isps["A"],
                        channel="email",
                        trigger="invoice_email",
                        recipient_masked="c2***@e.com",
                        customer_organization_id=uuid.UUID(cust["c2"]),
                        summary="Invoice INV-2 emailed",
                        status="sent",
                    ),
                    IspMessageLog(
                        isp_organization_id=isps["B"],
                        channel="whatsapp",
                        trigger="unpaid",
                        recipient_masked="x",
                        summary="other ISP",
                        status="sent",
                        provider_message_id=f"wamid.Z{tag}",
                    ),
                ]
                s.add_all(rows)
                await s.commit()

            # flag off -> 404 ------------------------------------------------------
            os.environ.pop("ISP_COMMS_HUB_ENABLED")
            get_comms_settings.cache_clear()
            r = await c.get(f"{api}/comms/logs", headers=ha)
            assert r.status_code == 404 and r.json()["data"]["code"] == (
                "ISP_COMMS_HUB_DISABLED"
            )
            os.environ["ISP_COMMS_HUB_ENABLED"] = "true"
            get_comms_settings.cache_clear()

            async def logs(qs: str = "", h=ha) -> dict:  # noqa: ANN001
                return await call("GET", f"/comms/logs?{qs}", h=h)

            d = await logs()
            assert d["total"] == 3 and {i["status"] for i in d["items"]} == {"sent"}
            assert (await logs("channel=email"))["total"] == 1
            assert (await logs("event=receipt"))["total"] == 1
            assert (await logs(f"phone={phone}"))["total"] == 2
            assert (await logs(f"email=SUB{tag}@e.com"))["total"] == 2
            assert (await logs(f"email=c2{tag}@e.com"))["total"] == 1
            assert (await logs("phone=9000000000"))["total"] == 0
            assert (await logs("date_from=2020-01-01&date_to=2020-01-02"))["total"] == 0
            r = await c.get(
                f"{api}/comms/logs?date_from=2026-10-31T18:30:00Z", headers=ha
            )
            assert r.status_code == 422  # plain dates only

            # webhook: set up, Meta handshake, signed callbacks -------------------
            w = await call("PUT", "/comms/webhook", {"app_secret": "meta-app-secret"})
            assert w["app_secret_set"] and "meta-app-secret" not in str(w)
            path = w["callback_path"]
            r = await c.get(
                path,
                params={
                    "hub.mode": "subscribe",
                    "hub.verify_token": w["verify_token"],
                    "hub.challenge": "12345",
                },
            )
            assert r.status_code == 200 and r.text == "12345"
            r = await c.get(
                path,
                params={
                    "hub.mode": "subscribe",
                    "hub.verify_token": "x",
                    "hub.challenge": "1",
                },
            )
            assert r.status_code == 403

            def signed(payload: dict, secret: str = "meta-app-secret") -> tuple:
                raw = json.dumps(payload).encode()
                sig = (
                    "sha256="
                    + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
                )
                return raw, {
                    "X-Hub-Signature-256": sig,
                    "Content-Type": "application/json",
                }

            def statuses(*items: tuple) -> dict:
                return {
                    "entry": [
                        {
                            "changes": [
                                {
                                    "value": {
                                        "statuses": [
                                            {
                                                "id": i,
                                                "status": st,
                                                "timestamp": "1761973200",
                                            }
                                            for i, st in items
                                        ]
                                    }
                                }
                            ]
                        }
                    ]
                }

            body_ = statuses((f"wamid.A{tag}", "delivered"))
            raw, _hdr = signed(body_)
            r = await c.post(
                path, content=raw, headers={"Content-Type": "application/json"}
            )
            assert r.status_code == 403  # unsigned: nothing recorded
            raw, hdr = signed(body_, "wrong-secret")
            assert (await c.post(path, content=raw, headers=hdr)).status_code == 403
            assert (await logs("status=delivered"))[
                "total"
            ] == 0  # never without a receipt

            raw, hdr = signed(
                statuses(
                    (f"wamid.A{tag}", "sent"),
                    (f"wamid.A{tag}", "delivered"),
                    (f"wamid.A{tag}", "read"),
                    (f"wamid.B{tag}", "failed"),
                    (f"wamid.Z{tag}", "delivered"),  # ISP B's message: ignored
                    ("wamid.unknown", "delivered"),
                )
            )
            r = await c.post(path, content=raw, headers=hdr)
            assert r.status_code == 200, r.text
            assert r.json() == {"received": 6, "stored": 4}
            r = await c.post(path, content=raw, headers=hdr)  # replay: idempotent
            assert r.json()["stored"] == 0
            d = await logs("channel=whatsapp")
            by = {i["provider_message_id"]: i for i in d["items"]}
            assert by[f"wamid.A{tag}"]["status"] == "read"
            assert [x["status"] for x in by[f"wamid.A{tag}"]["receipts"]] == [
                "sent",
                "delivered",
                "read",
            ]
            assert by[f"wamid.B{tag}"]["status"] == "failed"
            assert (await logs("status=read"))["total"] == 1
            assert (await logs("status=failed"))["total"] == 1
            assert (await logs("status=sent"))["total"] == 1  # the email
            async with SessionLocal() as s:
                st = (
                    await s.execute(
                        select(IspMessageLog.status).where(
                            IspMessageLog.provider_message_id == f"wamid.A{tag}"
                        )
                    )
                ).scalar_one()
            assert st == "sent"  # the JAZE-4 row itself is never rewritten
            as_("B")
            assert (await logs(h=hb))["items"][0]["status"] == "sent"
            as_("A")

            # CSV ------------------------------------------------------------------
            r = await c.get(f"{api}/comms/logs/export.csv?channel=whatsapp", headers=ha)
            assert r.status_code == 200 and "read" in r.text and "Receipt R-1" in r.text

            # confined technician: only its customer's rows ------------------------
            async with SessionLocal() as s:
                s.add(
                    IspStaffCustomerScope(
                        isp_organization_id=isps["A"],
                        user_id=users["Bi"],
                        customer_organization_id=uuid.UUID(cust["c2"]),
                    )
                )
                await s.commit()
            as_("Bi")  # isp-billing (holds isp_billing.read), confined to c2
            d = (await c.get(f"{api}/comms/logs", headers=ha)).json()["data"]
            assert d["total"] == 1 and d["items"][0]["channel"] == "email"
            assert (await c.get(f"{api}/comms/logs?phone={phone}", headers=ha)).json()[
                "data"
            ]["total"] == 0
            as_("A")

            # template library -----------------------------------------------------
            t = await call("GET", "/comms/templates")
            assert len(t["items"]) == 16  # 8 events x 2 channels (+INCIDENTS-1)
            r = await c.put(
                f"{api}/comms/templates/unpaid_invoice/email",
                json={
                    "enabled": True,
                    "email_subject": "Due",
                    "email_body": "Hi {{iban}}",
                },
                headers=ha,
            )
            assert r.status_code == 400 or r.status_code == 422, r.text
            await call(
                "PUT",
                "/comms/templates/unpaid_invoice/email",
                {
                    "enabled": True,
                    "email_subject": "Invoice {{invoice_number}}",
                    "email_body": "Hi {{name}}, pay {{balance}}: {{pay_link}}",
                },
            )
            pv = await call("POST", "/comms/templates/unpaid_invoice/email/preview", {})
            assert pv["subject"] == "Invoice INV/26-27/0042"
            assert "/partner/pay/SAMPLE-TOKEN" in pv["body"]

            class _Sender:
                async def list_templates(self):  # noqa: ANN202
                    return [
                        {
                            "name": "unpaid_v1",
                            "language": "en",
                            "status": "APPROVED",
                            "components": [
                                {"type": "BODY", "text": "{{1}} {{2}} {{3}} {{4}}"}
                            ],
                        },
                        {
                            "name": "pending_v1",
                            "language": "en",
                            "status": "PENDING",
                            "components": [],
                        },
                        {
                            "name": "two_vars",
                            "language": "en",
                            "status": "APPROVED",
                            "components": [{"type": "BODY", "text": "{{1}} {{2}}"}],
                        },
                    ]

            r = await c.put(
                f"{api}/comms/templates/unpaid_invoice/whatsapp",
                json={"enabled": True, "wa_template_name": "unpaid_v1"},
                headers=ha,
            )
            assert r.status_code == 409  # no sender connected
            automation_mod._whatsapp_sender = _fake_sender = (  # noqa: F841
                lambda *_a: _async(_Sender())
            )
            for name, code in (("pending_v1", 422), ("two_vars", 422), ("ghost", 422)):
                r = await c.put(
                    f"{api}/comms/templates/unpaid_invoice/whatsapp",
                    json={"enabled": True, "wa_template_name": name},
                    headers=ha,
                )
                assert r.status_code == code, (name, r.text)
            ok_ = await call(
                "PUT",
                "/comms/templates/unpaid_invoice/whatsapp",
                {"enabled": True, "wa_template_name": "unpaid_v1", "wa_language": "en"},
            )
            assert ok_["wa_approval_status"] == "APPROVED" and ok_["enabled"]
            async with SessionLocal() as s:
                mapping = (
                    await s.execute(
                        select(IspAutomationSettings.whatsapp_templates).where(
                            IspAutomationSettings.isp_organization_id == isps["A"]
                        )
                    )
                ).scalar_one()
            assert mapping == {
                "unpaid": {"template_name": "unpaid_v1", "language": "en"}
            }
            await call(
                "PUT",
                "/comms/templates/unpaid_invoice/whatsapp",
                {
                    "enabled": False,
                    "wa_template_name": "unpaid_v1",
                    "wa_language": "en",
                },
            )
            async with SessionLocal() as s:
                mapping = (
                    await s.execute(
                        select(IspAutomationSettings.whatsapp_templates).where(
                            IspAutomationSettings.isp_organization_id == isps["A"]
                        )
                    )
                ).scalar_one()
            assert mapping == {}
            pw = await call(
                "POST", "/comms/templates/unpaid_invoice/whatsapp/preview", {}
            )
            assert [p["variable"] for p in pw["parameters"]] == [
                "name",
                "invoice_number",
                "balance",
                "pay_link",
            ]
    finally:
        automation_mod._whatsapp_sender = _real_sender
        os.environ.pop("ISP_COMMS_HUB_ENABLED", None)
        get_comms_settings.cache_clear()
        await engine.dispose()
