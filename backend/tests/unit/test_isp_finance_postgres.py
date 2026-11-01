# ruff: noqa: E501, PLR0915 -- scenario test
"""JAZE-4 on real PostgreSQL + Redis (skipped unless ``ISP_TEST_PG_DSN``;
CI has neither). Run with the CLOUDGUEST_DATABASE_URL/REDIS_URL of a scratch
database that ``alembic upgrade head`` has been run against.

Covers: flags OFF = 404; invoice template + bank block on the PDF; products;
package billing + price preview; static-IP lease billing (idempotent);
security deposits (no over-refund); billing contacts + invoice email
recipients; zone ledger (credit limit, audit trail, revenue, TDS); WhatsApp
sweep with a fake sender (opt-in, dedupe, no backfill); Telegram debounce with
a mock transport; public pay page; isolation (ISP B gets 404 everywhere) and a
technician confined to another customer (404).
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


async def test_finance_end_to_end(monkeypatch) -> None:  # noqa: ANN001
    import httpx
    from sqlalchemy import select

    from app.database.session import SessionLocal
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.isp_partner import automation, finance_config
    from app.domains.isp_partner.finance_models import (
        IspAlertDeviceState,
        IspMessageLog,
    )
    from app.domains.isp_partner.models import (
        IspPartnerProfile,
        IspStaffCustomerScope,
    )
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.organization.models import Organization, OrganizationMember
    from app.domains.rbac.dependencies import CurrentUser
    from app.domains.rbac.models import Role, UserRole
    from app.domains.rbac.repository import RBACRepository
    from app.domains.rbac.seed import seed_rbac
    from app.main import create_app

    flags = finance_config.IspFinanceSettings(
        finance_extras_enabled=False,
        zone_ledger_enabled=False,
        whatsapp_automation_enabled=False,
        telegram_alerts_enabled=False,
        pay_link_base_url="https://network-staging.wyfyguest.com",
    )
    monkeypatch.setattr(finance_config, "get_finance_settings", lambda: flags)
    monkeypatch.setattr(automation, "get_finance_settings", lambda: flags)
    from app.domains.isp_partner import finance_tasks

    monkeypatch.setattr(finance_tasks, "get_finance_settings", lambda: flags)

    tag = uuid.uuid4().hex[:8]
    async with SessionLocal() as s:
        await seed_rbac(s)
        await seed_isp_partner_rbac(RBACRepository(s))
        await s.commit()
    users, isps = {}, {}
    async with SessionLocal() as s:
        plan = Plan(
            name=f"P {tag}",
            slug=f"jz4-{tag}",
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
        tech = (
            await s.execute(select(Role).where(Role.slug == "isp-billing"))
        ).scalar_one()
        for n in ("A", "B", "T"):
            if n in ("A", "B"):
                org = Organization(
                    name=f"Net {n} {tag}",
                    slug=f"jz4{n.lower()}{tag}",
                    org_type="msp",
                    status="active",
                    contact_email=f"{n}{tag}@example.com",
                    timezone="Asia/Kolkata",
                    settings={},
                )
                s.add(org)
                await s.flush()
                s.add(
                    IspPartnerProfile(
                        organization_id=org.id,
                        default_customer_plan_id=plan.id,
                        support_phone="9000000000",
                    )
                )
                isps[n] = org.id
            user = User(
                first_name=n,
                last_name="O",
                email=f"jz4{n}{tag}@example.com",
                username=f"jz4{n}{tag}",
                password_hash="x",
                is_active=True,
                is_verified=True,
            )
            s.add(user)
            await s.flush()
            org_id = isps["A"] if n == "T" else isps[n]
            s.add(
                OrganizationMember(
                    organization_id=org_id, user_id=user.id, status="active"
                )
            )
            s.add(
                UserRole(
                    user_id=user.id,
                    role_id=(tech if n == "T" else owner).id,
                    scope_type="organization",
                    organization_id=org_id,
                    granted_at=datetime.now(UTC),
                    is_active=True,
                )
            )
            users[n] = user.id
        await s.commit()

    app = create_app()
    state = {"user": users["A"]}
    app.dependency_overrides[CurrentUser] = lambda: AuthUser(
        id=str(state["user"]), email="o@example.com"
    )
    ha = {"X-Organization-Id": str(isps["A"])}
    hb = {"X-Organization-Id": str(isps["B"])}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t"
    ) as c:
        # -- flags OFF: every JAZE-4 surface is a plain 404 ----------------
        for path in (
            "/api/v1/isp/finance/products",
            "/api/v1/isp/finance/zones",
            "/api/v1/isp/finance/invoice-template",
        ):
            r = await c.get(path, headers=ha)
            assert r.status_code == 404, (path, r.text)
        r = await c.get("/api/v1/isp/public/pay/abcdef", headers={})
        assert r.status_code == 404
        flags.finance_extras_enabled = True
        flags.zone_ledger_enabled = True

        # -- setup: billing settings, a customer, a zone ------------------
        r = await c.put(
            "/api/v1/isp/billing/settings",
            json={
                "legal_name": "Net A Pvt Ltd",
                "state_code": "08",
                "gst_enabled": True,
                "invoice_prefix": "JZA",
                "upi_vpa": "neta@upi",
            },
            headers=ha,
        )
        assert r.status_code == 200, r.text
        cust = (
            await c.post(
                "/api/v1/isp/customers",
                json={
                    "name": f"Cafe {tag}",
                    "contact_email": f"cafe{tag}@example.com",
                    "contact_phone": "9876543210",
                },
                headers=ha,
            )
        ).json()["data"]["id"]
        cust2 = (
            await c.post(
                "/api/v1/isp/customers",
                json={"name": f"Shop {tag}", "contact_email": f"shop{tag}@example.com"},
                headers=ha,
            )
        ).json()["data"]["id"]
        zone = (
            await c.post(
                "/api/v1/isp/zones",
                json={"name": f"Kota {tag}", "state_code": "08"},
                headers=ha,
            )
        ).json()["data"]["id"]
        r = await c.patch(
            f"/api/v1/isp/customers/{cust}", json={"zone_id": zone}, headers=ha
        )
        assert r.status_code == 200, r.text

        # -- template validation + PDF bank block ------------------------
        r = await c.put(
            "/api/v1/isp/finance/invoice-template",
            json={"bank_ifsc": "BAD"},
            headers=ha,
        )
        assert r.status_code == 422
        r = await c.put(
            "/api/v1/isp/finance/invoice-template",
            json={
                "bank_name": "Test Bank",
                "bank_account_number": "123456789012",
                "bank_ifsc": "TEST0001234",
                "pan": "ABCDE1234F",
                "care_phone": "9000000001",
            },
            headers=ha,
        )
        assert r.status_code == 200, r.text
        inv = await c.post(
            "/api/v1/isp/billing/invoices",
            json={
                "isp_customer_id": cust,
                "description": "Bandwidth",
                "amount_paise": 100000,
            },
            headers=ha,
        )
        assert inv.status_code == 201, inv.text
        inv_id = inv.json()["data"]["id"]
        pdf = await c.get(f"/api/v1/isp/invoices/{inv_id}/pdf", headers=ha)
        assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"
        th = await c.get(
            f"/api/v1/isp/finance/invoices/{inv_id}/thermal.pdf", headers=ha
        )
        assert th.status_code == 200 and th.content[:4] == b"%PDF"
        assert (
            await c.get(
                f"/api/v1/isp/finance/invoices/{inv_id}/thermal.pdf", headers=hb
            )
        ).status_code == 404

        # -- products + package billing + price preview -------------------
        r = await c.post("/api/v1/isp/finance/products/standard", headers=ha)
        assert r.status_code == 200 and len(r.json()["data"]["items"]) == 4
        assert all(p["sac_code"] == "998422" for p in r.json()["data"]["items"])
        r = await c.post(
            "/api/v1/isp/finance/products",
            json={"name": "bandwidth", "kind": "bandwidth"},
            headers=ha,
        )
        assert r.status_code == 422  # name is case-insensitively unique
        r = await c.get(
            "/api/v1/isp/finance/price-preview",
            params={"amount_paise": 14900},
            headers=ha,
        )
        p = r.json()["data"]
        assert (
            p["taxable_paise"],
            p["cgst_paise"],
            p["sgst_paise"],
            p["total_paise"],
        ) == (14900, 1341, 1341, 17582)
        r = await c.get(
            "/api/v1/isp/finance/price-preview",
            params={"amount_paise": 14900, "place_of_supply_state_code": "27"},
            headers=ha,
        )
        assert r.json()["data"]["igst_paise"] == 2682
        gid = (
            await c.post(
                "/api/v1/isp/speed-groups",
                json={"name": "10 Mbps", "download_kbps": 10240, "upload_kbps": 10240},
                headers=ha,
            )
        ).json()["data"]["id"]
        pkg = (
            await c.post(
                "/api/v1/isp/packages",
                json={"speed_group_id": gid, "type": "prepaid", "price_paise": 14900},
                headers=ha,
            )
        ).json()["data"]["id"]
        r = await c.get(f"/api/v1/isp/finance/packages/{pkg}/billing", headers=ha)
        assert r.status_code == 200 and r.json()["data"]["configured"] is False
        assert r.json()["data"]["preview"]["total_paise"] == 17582
        r = await c.put(
            f"/api/v1/isp/finance/packages/{pkg}/billing",
            json={
                "plan_kind": "prepaid",
                "chargeable_unit": "months",
                "chargeable_count": 1,
                "invoice_description": "10 Mbps monthly",
            },
            headers=ha,
        )
        assert r.status_code == 200 and r.json()["data"]["configured"] is True
        assert (
            await c.get(f"/api/v1/isp/finance/packages/{pkg}/billing", headers=hb)
        ).status_code == 404

        # -- static IP leases ---------------------------------------------
        since = (datetime.now(UTC) - timedelta(days=40)).date().isoformat()
        r = await c.post(
            "/api/v1/isp/finance/static-ip-leases",
            json={
                "isp_customer_id": cust,
                "ip_address": "203.0.113.10",
                "monthly_amount_paise": 50000,
                "active_since": since,
            },
            headers=ha,
        )
        assert r.status_code == 201, r.text
        lease = r.json()["data"]["id"]
        r = await c.post(
            "/api/v1/isp/finance/static-ip-leases",
            json={
                "isp_customer_id": cust2,
                "ip_address": "203.0.113.10",
                "monthly_amount_paise": 1,
            },
            headers=ha,
        )
        assert r.status_code == 409
        r = await c.post(
            "/api/v1/isp/finance/static-ip-leases",
            json={
                "isp_customer_id": cust,
                "ip_address": "not-an-ip",
                "monthly_amount_paise": 1,
            },
            headers=ha,
        )
        assert r.status_code == 422
        r1 = (
            await c.post("/api/v1/isp/finance/static-ip-leases/bill", headers=ha)
        ).json()["data"]
        r2 = (
            await c.post("/api/v1/isp/finance/static-ip-leases/bill", headers=ha)
        ).json()["data"]
        assert r1["invoices_issued"] == 2 and r2["invoices_issued"] == 0
        assert (
            await c.post(
                f"/api/v1/isp/finance/static-ip-leases/{lease}/end", json={}, headers=hb
            )
        ).status_code == 404

        # -- security deposits ------------------------------------------
        r = await c.post(
            "/api/v1/isp/finance/deposits",
            json={
                "isp_customer_id": cust,
                "entry_kind": "collect",
                "item": "ont",
                "amount_paise": 150000,
                "mode": "cash",
            },
            headers=ha,
        )
        assert r.status_code == 201, r.text
        r = await c.post(
            "/api/v1/isp/finance/deposits",
            json={
                "isp_customer_id": cust,
                "entry_kind": "refund",
                "item": "ont",
                "amount_paise": 200000,
                "mode": "cash",
            },
            headers=ha,
        )
        assert r.status_code == 409
        r = await c.post(
            "/api/v1/isp/finance/deposits",
            json={
                "isp_customer_id": cust,
                "entry_kind": "refund",
                "item": "ont",
                "amount_paise": 50000,
                "mode": "upi",
            },
            headers=ha,
        )
        assert r.status_code == 201
        d = (
            await c.get(
                "/api/v1/isp/finance/deposits",
                params={"isp_customer_id": cust},
                headers=ha,
            )
        ).json()["data"]
        assert d["held_paise"] == 100000 and len(d["items"]) == 2
        assert (
            await c.get(
                "/api/v1/isp/finance/deposits",
                params={"isp_customer_id": cust},
                headers=hb,
            )
        ).status_code == 404

        # -- contacts + invoice email recipients --------------------------
        r = await c.post(
            f"/api/v1/isp/finance/invoices/{inv_id}/email",
            json={"send_to": "alternate"},
            headers=ha,
        )
        assert r.status_code == 422  # no alternate on file
        r = await c.put(
            f"/api/v1/isp/finance/contacts/customer/{cust}",
            json={"alternate_email": f"accounts{tag}@example.com"},
            headers=ha,
        )
        assert r.status_code == 200
        r = await c.post(
            f"/api/v1/isp/finance/invoices/{inv_id}/email",
            json={"send_to": "both"},
            headers=ha,
        )
        assert r.status_code == 200, r.text
        assert len(r.json()["data"]["queued"]) == 2
        log = (
            await c.get(
                "/api/v1/isp/finance/messages", params={"channel": "email"}, headers=ha
            )
        ).json()["data"]
        assert log["total"] == 2 and all("•" in i["recipient"] for i in log["items"])
        assert (
            await c.post(
                f"/api/v1/isp/finance/invoices/{inv_id}/email",
                json={"send_to": "both"},
                headers=hb,
            )
        ).status_code == 404

        # -- zone ledger --------------------------------------------------
        r = await c.put(
            f"/api/v1/isp/finance/zones/{zone}/profile",
            json={"gstin": "08AAAAA0000A1Z0"},
            headers=ha,
        )
        assert r.status_code == 422  # bad check digit
        r = await c.put(
            f"/api/v1/isp/finance/zones/{zone}/profile",
            json={
                "revenue_share_bp": 5000,
                "operator_name": "LCO One",
                "operator_phone": "9111111111",
                "pan": "ABCDE1234F",
            },
            headers=ha,
        )
        assert r.status_code == 200, r.text
        r = await c.post(
            f"/api/v1/isp/finance/zones/{zone}/entries",
            json={"entry_kind": "reduce", "amount_paise": 1000},
            headers=ha,
        )
        assert r.status_code == 409  # no credit yet
        r = await c.post(
            f"/api/v1/isp/finance/zones/{zone}/entries",
            json={"entry_kind": "credit_limit", "credit_limit_paise": 2500000},
            headers=ha,
        )
        assert r.status_code == 201
        r = await c.post(
            f"/api/v1/isp/finance/zones/{zone}/entries",
            json={"entry_kind": "reduce", "amount_paise": 589234, "mode": "adjustment"},
            headers=ha,
        )
        assert r.status_code == 201
        z = r.json()["data"]["zone"]
        assert (
            z["balance_paise"] == -589234
            and z["standing"] == "unpaid"
            and z["available_paise"] == 2500000 - 589234
        )
        r = await c.post(
            f"/api/v1/isp/finance/zones/{zone}/entries",
            json={
                "entry_kind": "add",
                "amount_paise": 1000000,
                "mode": "bank_transfer",
                "reference": "NEFT1",
            },
            headers=ha,
        )
        z = r.json()["data"]
        assert (
            z["zone"]["standing"] == "paid"
            and len(z["entries"]) == 3
            and z["entries"][0]["recorded_by"]
        )
        today = datetime.now(UTC).date()
        r = await c.get(
            "/api/v1/isp/finance/zones/revenue",
            params={
                "date_from": (today - timedelta(days=60)).isoformat(),
                "date_to": today.isoformat(),
            },
            headers=ha,
        )
        assert r.status_code == 200
        r = await c.get("/api/v1/isp/finance/zones/tds-194h", headers=ha)
        assert r.status_code == 200 and r.json()["data"]["section"] == "194H"
        assert (
            await c.get(f"/api/v1/isp/finance/zones/{zone}", headers=hb)
        ).status_code == 404

        # -- isolation: a billing user confined to cust2 cannot see cust --
        async with SessionLocal() as s:
            s.add(
                IspStaffCustomerScope(
                    isp_organization_id=isps["A"],
                    user_id=users["T"],
                    customer_organization_id=uuid.UUID(cust2),
                )
            )
            await s.commit()
        state["user"] = users["T"]
        assert (
            await c.get(
                "/api/v1/isp/finance/deposits",
                params={"isp_customer_id": cust},
                headers=ha,
            )
        ).status_code == 404
        assert (
            await c.get(
                f"/api/v1/isp/finance/invoices/{inv_id}/thermal.pdf", headers=ha
            )
        ).status_code == 404
        leases = (
            await c.get("/api/v1/isp/finance/static-ip-leases", headers=ha)
        ).json()["data"]["items"]
        assert leases == []
        state["user"] = users["A"]

        # -- WhatsApp: fake sender; opt-in required; dedupe; pay link ------
        flags.whatsapp_automation_enabled = True
        sent: list[tuple] = []

        class _Res:
            message_id = "wamid.TEST"

        class FakeSender:
            async def send_waba_template(
                self, to, *, template_name, language, parameters
            ):  # noqa: ANN001
                sent.append((to, template_name, parameters))
                return _Res()

        async def _fake_sender(session, isp_org_id):  # noqa: ANN001
            return FakeSender()

        monkeypatch.setattr(automation, "_whatsapp_sender", _fake_sender)
        r = await c.put(
            "/api/v1/isp/finance/automation",
            json={
                "whatsapp_enabled": True,
                "whatsapp_templates": {
                    "unpaid": {"template_name": "unpaid_v1", "language": "en"},
                    "receipt": {"template_name": "receipt_v1"},
                },
                "unpaid_reminder_after_days": 0,
            },
            headers=ha,
        )
        assert r.status_code == 200, r.text
        async with SessionLocal() as s:
            res = await automation.run_whatsapp_daily(
                s, isps["A"], today + timedelta(days=40)
            )
            await s.commit()
        assert sent == [] and res["sent"] == 0  # customer has not opted in
        await c.put(
            f"/api/v1/isp/finance/contacts/customer/{cust}",
            json={"whatsapp_opt_in": True},
            headers=ha,
        )
        for _ in range(2):
            async with SessionLocal() as s:
                await automation.run_whatsapp_daily(
                    s, isps["A"], today + timedelta(days=40)
                )
                await s.commit()
        assert len(sent) >= 1 and all(x[0] == "+919876543210" for x in sent)
        assert len(sent) == len({x[2][1] for x in sent})  # one per invoice per week
        link = sent[0][2][3]
        assert link.startswith("https://network-staging.wyfyguest.com/partner/pay/")
        token = link.rsplit("/", 1)[1]
        r = await c.get(f"/api/v1/isp/public/pay/{token}")
        assert r.status_code == 200, r.text
        pv = r.json()["data"]
        assert (
            pv["balance_paise"] > 0
            and pv["upi_uri"].startswith("upi://pay")
            and pv["bank"]["ifsc"] == "TEST0001234"
        )
        assert "contact_email" not in str(pv)
        assert (await c.get("/api/v1/isp/public/pay/nope")).status_code == 404
        # a payment recorded now -> receipt on the frequent sweep, once
        r = await c.post(
            "/api/v1/isp/billing/payments",
            json={"isp_customer_id": cust, "amount_paise": 1000, "mode": "cash"},
            headers={**ha, "Idempotency-Key": uuid.uuid4().hex},
        )
        assert r.status_code == 201, r.text
        before = len(sent)
        for _ in range(2):
            async with SessionLocal() as s:
                await automation.run_whatsapp_events(s, isps["A"])
                await s.commit()
        assert len(sent) == before + 1 and sent[-1][1] == "receipt_v1"

        # -- Telegram: debounce with a mock transport -------------------
        flags.telegram_alerts_enabled = True
        r = await c.put(
            "/api/v1/isp/finance/automation",
            json={
                "telegram_enabled": True,
                "telegram_bot_token": "123456:" + "A" * 35,
                "telegram_chat_id": "-1001234567",
                "telegram_debounce_minutes": 3,
                "telegram_include_aps": False,
            },
            headers=ha,
        )
        assert r.status_code == 200, r.text
        view = r.json()["data"]
        assert (
            view["telegram_bot_token"] == {"set": True, "hint": "…AAAA"}
            and "AAAAAAAA" not in r.text
        )
        posts: list[dict] = []

        def handler(req: httpx.Request) -> httpx.Response:
            import json

            posts.append(json.loads(req.content))
            return httpx.Response(200, json={"ok": True})

        rid = uuid.uuid4()

        async def statuses(session, child_ids, include_aps):  # noqa: ANN001
            return [("router", rid, "Cafe hEX", state["router"], uuid.UUID(cust))]

        monkeypatch.setattr(automation, "_device_statuses", statuses)
        t0 = datetime.now(UTC)
        transport = httpx.MockTransport(handler)
        for status, at in (
            ("up", 0),
            ("down", 1),
            ("down", 2),
            ("down", 5),
            ("down", 6),
            ("up", 7),
            ("up", 11),
        ):
            state["router"] = status
            async with SessionLocal() as s:
                await automation.run_telegram(
                    s,
                    isps["A"],
                    [uuid.UUID(cust)],
                    now=t0 + timedelta(minutes=at),
                    transport=transport,
                )
                await s.commit()
        texts = [p["text"] for p in posts]
        assert len(texts) == 2 and "DOWN" in texts[0] and "UP" in texts[1], texts
        async with SessionLocal() as s:
            row = (
                await s.execute(
                    select(IspAlertDeviceState).where(
                        IspAlertDeviceState.device_id == rid
                    )
                )
            ).scalar_one()
            assert row.notified_status == "up"
            tg = (
                (
                    await s.execute(
                        select(IspMessageLog).where(
                            IspMessageLog.isp_organization_id == isps["A"],
                            IspMessageLog.channel == "telegram",
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert len(tg) == 2 and all("123456" not in (m.error or "") for m in tg)
        # ISP B sees none of A's messages
        logb = (await c.get("/api/v1/isp/finance/messages", headers=hb)).json()["data"]
        assert logb["total"] == 0
