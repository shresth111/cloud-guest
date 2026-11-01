# ruff: noqa: E501, PLR0915 -- scenario test
"""BILL-2 on real PostgreSQL + Redis (skipped unless ``ISP_TEST_PG_DSN``).

Flag off: ``/isp/gst/gstr1`` is 404 and a 3-cycle recharge is refused with
ISP_RENEW_CYCLES_OFF. Flag on: a 3-cycle recharge is one invoice at 3x the
price (line quantity 3) and moves validity 3 x 30 days; the invoice PDF gets
the account + previous-balance block; GSTR-1 for the month puts the
registered subscriber in B2B, nets a credit note into B2CS and sums the SAC
summary; zone branding is per ISP (ISP B gets 404 on A's zone).
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from fastapi import Request

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)

_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _gstin(body14: str) -> str:
    total = 0
    for i, ch in enumerate(body14):
        p = _CHARS.index(ch) * (2 if i % 2 else 1)
        total += p // 36 + p % 36
    return body14 + _CHARS[(36 - total % 36) % 36]


async def test_bill2_end_to_end(monkeypatch) -> None:  # noqa: ANN001
    import httpx
    from sqlalchemy import select

    from app.database.session import SessionLocal, engine
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.isp_partner import bill2_config
    from app.domains.isp_partner.billing_extras import pdf_extras
    from app.domains.isp_partner.billing_models import IspInvoice
    from app.domains.isp_partner.models import IspPartnerProfile
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.organization.models import Organization, OrganizationMember
    from app.domains.rbac.dependencies import CurrentUser
    from app.domains.rbac.models import Role, UserRole
    from app.domains.rbac.repository import RBACRepository
    from app.domains.rbac.seed import seed_rbac
    from app.main import create_app

    flag = {"on": False}
    monkeypatch.setattr(
        bill2_config,
        "get_bill2_settings",
        lambda: bill2_config.Bill2Settings(enabled=flag["on"]),
    )
    tag = uuid.uuid4().hex[:8]
    try:
        async with SessionLocal() as s:
            await seed_rbac(s)
            await seed_isp_partner_rbac(RBACRepository(s))
            await s.commit()
        users, isps = {}, {}
        async with SessionLocal() as s:
            plan = Plan(
                name=f"P {tag}",
                slug=f"pb2-{tag}",
                plan_type="standard",
                billing_cycle="monthly",
                base_price=Decimal("0"),
                currency="INR",
                is_active=True,
                is_public=False,
            )
            s.add(plan)
            role = (
                await s.execute(select(Role).where(Role.slug == "isp-owner"))
            ).scalar_one()
            for n in ("A", "B"):
                org = Organization(
                    name=f"Net {n} {tag}",
                    slug=f"b2{n.lower()}{tag}",
                    org_type="msp",
                    status="active",
                    contact_email=f"{n}{tag}@example.com",
                    timezone="Asia/Kolkata",
                    settings={},
                )
                user = User(
                    first_name=n,
                    last_name="O",
                    email=f"b2{n}{tag}@example.com",
                    username=f"b2{n}{tag}",
                    password_hash="x",
                    is_active=True,
                    is_verified=True,
                )
                s.add_all([org, user])
                await s.flush()
                s.add(
                    IspPartnerProfile(
                        organization_id=org.id, default_customer_plan_id=plan.id
                    )
                )
                s.add(
                    OrganizationMember(
                        organization_id=org.id, user_id=user.id, status="active"
                    )
                )
                s.add(
                    UserRole(
                        user_id=user.id,
                        role_id=role.id,
                        scope_type="organization",
                        organization_id=org.id,
                        granted_at=datetime.now(UTC),
                        is_active=True,
                    )
                )
                users[n], isps[n] = user.id, org.id
            await s.commit()

        app = create_app()
        # hb calls run as ISP B's own owner (typed Request param for FastAPI)

        def _user(request: Request) -> AuthUser:
            org = request.headers.get("X-Organization-Id")
            return AuthUser(
                id=str(users["B"] if org == str(isps["B"]) else users["A"]),
                email="o@example.com",
            )

        app.dependency_overrides[CurrentUser] = _user
        ha = {"X-Organization-Id": str(isps["A"])}
        hb = {"X-Organization-Id": str(isps["B"])}
        month = datetime.now(UTC).strftime("%Y-%m")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t"
        ) as c:
            r = await c.put(
                "/api/v1/isp/billing/settings",
                json={
                    "legal_name": "Net A",
                    "state_code": "07",
                    "gst_enabled": True,
                    "invoice_prefix": "NB2",
                },
                headers=ha,
            )
            assert r.status_code == 200, r.text
            cust = (
                await c.post(
                    "/api/v1/isp/customers",
                    json={
                        "name": f"Cafe {tag}",
                        "contact_email": f"c{tag}@example.com",
                    },
                    headers=ha,
                )
            ).json()["data"]["id"]
            gid = (
                await c.post(
                    "/api/v1/isp/speed-groups",
                    json={
                        "name": "20 Mbps",
                        "download_kbps": 20480,
                        "upload_kbps": 20480,
                    },
                    headers=ha,
                )
            ).json()["data"]["id"]
            r = await c.post(
                "/api/v1/isp/packages",
                json={
                    "speed_group_id": gid,
                    "type": "prepaid",
                    "validity_days": 30,
                    "price_paise": 50000,
                    "price_includes_gst": False,
                },
                headers=ha,
            )
            assert r.status_code == 201, r.text
            pkg = r.json()["data"]["id"]
            zone = (
                await c.post(
                    "/api/v1/isp/zones",
                    json={"name": f"North {tag}", "state_code": "07"},
                    headers=ha,
                )
            ).json()["data"]["id"]

            async def subscriber(ident, **extra):
                r = await c.post(
                    "/api/v1/isp/subscribers",
                    json={
                        "isp_customer_id": cust,
                        "identifier": ident,
                        "package_id": pkg,
                        "first_name": ident,
                        "state_code": "07",
                        **extra,
                    },
                    headers=ha,
                )
                assert r.status_code == 201, r.text
                return r.json()["data"]

            home = await subscriber(f"home{tag}", zone_id=zone)
            biz = await subscriber(f"biz{tag}", gstin=_gstin("07ABCDE1234F1Z"))

            # ---- flag off ----------------------------------------------------
            assert (
                await c.get(f"/api/v1/isp/gst/gstr1?month={month}", headers=ha)
            ).status_code == 404
            assert (
                await c.get(f"/api/v1/isp/zones/{zone}/branding", headers=ha)
            ).status_code == 404
            r = await c.post(
                f"/api/v1/isp/subscribers/{home['id']}/recharge",
                json={"package_id": pkg, "cycles": 3},
                headers=ha,
            )
            assert r.status_code == 422 and "ISP_RENEW_CYCLES_OFF" in r.text, r.text

            # ---- flag on: 3 cycles in one invoice ------------------------------
            flag["on"] = True
            before = datetime.fromisoformat(home["valid_until"])
            r = await c.post(
                f"/api/v1/isp/subscribers/{home['id']}/recharge",
                json={"package_id": pkg, "cycles": 3, "idempotency_key": f"c3-{tag}"},
                headers=ha,
            )
            assert r.status_code == 201, r.text
            rc = r.json()["data"]
            inv3 = rc["invoice"]
            assert (
                inv3["taxable_paise"] == 150000 and inv3["total_paise"] == 177000
            ), inv3
            after = datetime.fromisoformat(rc["subscriber"]["valid_until"])
            assert abs(
                (after - max(before, datetime.now(UTC))) - timedelta(days=90)
            ) < timedelta(minutes=5)
            detail = (
                await c.get(f"/api/v1/isp/invoices/{inv3['id']}", headers=ha)
            ).json()["data"]
            assert detail["lines"][0]["quantity"] == 3
            assert "x 3" in detail["lines"][0]["description"]
            # replay with the same key: nothing new
            r2 = await c.post(
                f"/api/v1/isp/subscribers/{home['id']}/recharge",
                json={"package_id": pkg, "cycles": 3, "idempotency_key": f"c3-{tag}"},
                headers=ha,
            )
            assert r2.json()["data"]["invoice"]["id"] == inv3["id"]

            # second (single) invoice: previous balance = the 3-cycle one
            inv1 = (
                await c.post(
                    f"/api/v1/isp/subscribers/{home['id']}/recharge",
                    json={"package_id": pkg},
                    headers=ha,
                )
            ).json()["data"]["invoice"]
            async with SessionLocal() as s:
                row = await s.get(IspInvoice, uuid.UUID(inv1["id"]))
                fake_isp = type(
                    "I",
                    (),
                    {
                        "isp_org_id": isps["A"],
                        "organization": type("O", (), {"timezone": "Asia/Kolkata"})(),
                    },
                )()
                ex = await pdf_extras(s, fake_isp, row)
            dues = ex["bill2"]["dues"]
            assert dues["previous_balance_paise"] == 177000, dues
            assert dues["total_due_paise"] == 177000 + 59000
            acct = ex["bill2"]["account"]
            assert acct["customer_id"] == f"home{tag}" and acct["static_ip"] == "No"
            assert acct["next_bill_date"] and acct["billing_period"]
            pdf = await c.get(f"/api/v1/isp/invoices/{inv1['id']}/pdf", headers=ha)
            assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"

            # zone branding: A sets it, B cannot touch it
            r = await c.put(
                f"/api/v1/isp/zones/{zone}/branding",
                json={
                    "invoice_name": "North Franchise",
                    "bank_name": "HDFC",
                    "bank_account_number": "50100123456789",
                    "bank_ifsc": "HDFC0001234",
                },
                headers=ha,
            )
            assert r.status_code == 200, r.text
            assert (
                await c.get(f"/api/v1/isp/zones/{zone}/branding", headers=hb)
            ).status_code == 404
            assert (
                await c.put(
                    f"/api/v1/isp/zones/{zone}/branding",
                    json={"invoice_name": "x"},
                    headers=hb,
                )
            ).status_code == 404
            async with SessionLocal() as s:
                row = await s.get(IspInvoice, uuid.UUID(inv1["id"]))
                ex = await pdf_extras(s, fake_isp, row)
            assert row.zone_id is not None  # subscriber invoices carry the zone
            assert ex["bill2"]["billed_through"] == "North Franchise"
            assert ex["bank"]["ifsc"] == "HDFC0001234"

            # B2B subscriber + a partial credit note on the single invoice
            invb = (
                await c.post(
                    f"/api/v1/isp/subscribers/{biz['id']}/recharge",
                    json={"package_id": pkg},
                    headers=ha,
                )
            ).json()["data"]["invoice"]
            r = await c.post(
                f"/api/v1/isp/invoices/{inv1['id']}/credit-note",
                json={"amount_paise": 11800, "reason": "goodwill"},
                headers=ha,
            )
            assert r.status_code in (200, 201), r.text

            g = (
                await c.get(
                    f"/api/v1/isp/gst/gstr1?month={month}&format=json", headers=ha
                )
            ).json()
            assert [row["Invoice Number"] for row in g["b2b"]] == [invb["number"]]
            assert g["b2b"][0]["GSTIN/UIN of Recipient"] == biz["gstin"]
            (b2cs,) = g["b2cs"]
            # 1500 + 500 taxable, less the note's 100 taxable
            assert b2cs["Taxable Value"] == 1900.0 and b2cs["Rate"] == 18
            assert not g["cdnr"] and not g["cdnur"]
            (hsn,) = g["hsn"]
            assert hsn["Total Quantity"] == 3 + 1 + 1 - 1
            # csv: one section per file; all-sections csv is refused
            assert (
                await c.get(
                    f"/api/v1/isp/gst/gstr1?month={month}&format=csv", headers=ha
                )
            ).status_code == 422
            csv = await c.get(
                f"/api/v1/isp/gst/gstr1?month={month}&format=csv&section=b2b",
                headers=ha,
            )
            assert csv.status_code == 200 and csv.text.startswith(
                "GSTIN/UIN of Recipient"
            )
            xlsx = await c.get(f"/api/v1/isp/gst/gstr1?month={month}", headers=ha)
            assert xlsx.status_code == 200 and xlsx.content[:2] == b"PK"
            # ISP B's own return is empty: nothing of A's leaks
            gb = (
                await c.get(
                    f"/api/v1/isp/gst/gstr1?month={month}&format=json", headers=hb
                )
            ).json()
            assert all(
                not gb[k] for k in ("b2b", "b2cl", "b2cs", "cdnr", "cdnur", "hsn")
            )
    finally:
        await engine.dispose()
        from app.database.redis import redis_client

        await redis_client.connection_pool.disconnect()
