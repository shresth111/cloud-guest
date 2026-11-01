# ruff: noqa: E501, PLR0915 -- scenario test
"""QA #16 (JAZE QA 2026-11-01): a multi-cycle renewal (BILL-2, ``cycles``
2-12) must carry its billing period on the invoice and on its line, and the
PDF must print it. Single-cycle invoices behave exactly as before.

Real PostgreSQL + Redis (skipped unless ``ISP_TEST_PG_DSN``). Run::

    CLOUDGUEST_DATABASE_URL=postgresql+asyncpg://postgres@localhost:55471/qa16 \\
    CLOUDGUEST_REDIS_URL=redis://localhost:56391/1 \\
    ISP_TEST_PG_DSN=1 ISP_PARTNER_ENABLED=true \\
    python -m pytest tests/unit/test_isp_qa16_renewal_period_postgres.py

Period rule: start = the validity the renewal started from (the old
``valid_until`` when it is still in the future, else now), end = the new
``valid_until``; both as dates in the ISP's time zone.
"""

from __future__ import annotations

import base64
import os
import re
import uuid
import zlib
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from zoneinfo import ZoneInfo

import pytest
from fastapi import Request

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)

_TZ = ZoneInfo("Asia/Kolkata")


def _pdf_text(pdf: bytes) -> str:
    """Concatenate every decoded content stream (reportlab writes
    ASCII85 + Flate) so plain strings can be searched."""
    out = []
    for m in re.finditer(rb"<<(.*?)>>\s*stream\r?\n(.*?)endstream", pdf, re.S):
        header, raw = m.group(1), m.group(2)
        try:
            if b"ASCII85Decode" in header:
                data = raw.strip()
                if data.startswith(b"<~"):
                    data = data[2:]
                if data.endswith(b"~>"):
                    data = data[:-2]
                raw = base64.a85decode(data)
            if b"FlateDecode" in header:
                raw = zlib.decompress(raw)
        except (ValueError, zlib.error):
            continue
        out.append(raw.decode("latin-1"))
    return "\n".join(out)


def _local(iso: str) -> str:
    return datetime.fromisoformat(iso).astimezone(_TZ).date().isoformat()


async def test_multi_cycle_renewal_fills_billing_period(monkeypatch) -> None:  # noqa: ANN001
    import httpx
    from sqlalchemy import select

    from app.database.session import SessionLocal, engine
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.isp_partner import bill2_config
    from app.domains.isp_partner.billing_models import IspInvoice, IspInvoiceLine
    from app.domains.isp_partner.models import IspPartnerProfile
    from app.domains.isp_partner.plans_models import IspSubscriber
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.organization.models import Organization, OrganizationMember
    from app.domains.rbac.dependencies import CurrentUser
    from app.domains.rbac.models import Role, UserRole
    from app.domains.rbac.repository import RBACRepository
    from app.domains.rbac.seed import seed_rbac
    from app.main import create_app

    monkeypatch.setattr(
        bill2_config,
        "get_bill2_settings",
        lambda: bill2_config.Bill2Settings(enabled=True),
    )
    tag = uuid.uuid4().hex[:8]
    try:
        async with SessionLocal() as s:
            await seed_rbac(s)
            await seed_isp_partner_rbac(RBACRepository(s))
            await s.commit()
        async with SessionLocal() as s:
            plan = Plan(
                name=f"P {tag}",
                slug=f"pq16-{tag}",
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
            org = Organization(
                name=f"Net {tag}",
                slug=f"q16{tag}",
                org_type="msp",
                status="active",
                contact_email=f"q16{tag}@example.com",
                timezone="Asia/Kolkata",
                settings={},
            )
            user = User(
                first_name="Q",
                last_name="O",
                email=f"q16u{tag}@example.com",
                username=f"q16u{tag}",
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
            isp_id, user_id = org.id, user.id
            await s.commit()

        app = create_app()

        def _user(request: Request) -> AuthUser:
            return AuthUser(id=str(user_id), email="o@example.com")

        app.dependency_overrides[CurrentUser] = _user
        h = {"X-Organization-Id": str(isp_id)}
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t"
        ) as c:
            r = await c.put(
                "/api/v1/isp/billing/settings",
                json={
                    "legal_name": "Net Q16",
                    "state_code": "08",
                    "gst_enabled": True,
                    "invoice_prefix": "Q16",
                },
                headers=h,
            )
            assert r.status_code == 200, r.text
            cust = (
                await c.post(
                    "/api/v1/isp/customers",
                    json={
                        "name": f"Cafe {tag}",
                        "contact_email": f"c{tag}@example.com",
                    },
                    headers=h,
                )
            ).json()["data"]["id"]
            gid = (
                await c.post(
                    "/api/v1/isp/speed-groups",
                    json={
                        "name": "50 Mbps",
                        "download_kbps": 51200,
                        "upload_kbps": 51200,
                    },
                    headers=h,
                )
            ).json()["data"]["id"]
            r = await c.post(
                "/api/v1/isp/packages",
                json={
                    "speed_group_id": gid,
                    "type": "prepaid",
                    "validity_days": 30,
                    "price_paise": 59900,
                    "price_includes_gst": True,
                },
                headers=h,
            )
            assert r.status_code == 201, r.text
            pkg = r.json()["data"]["id"]

            async def subscriber(ident: str) -> dict:
                r = await c.post(
                    "/api/v1/isp/subscribers",
                    json={
                        "isp_customer_id": cust,
                        "identifier": ident,
                        "package_id": pkg,
                        "first_name": ident,
                        "state_code": "08",
                    },
                    headers=h,
                )
                assert r.status_code == 201, r.text
                return r.json()["data"]

            async def check_period(inv_id: str, start: str, end: str) -> dict:
                async with SessionLocal() as s:
                    inv = await s.get(IspInvoice, uuid.UUID(inv_id))
                    (line,) = (
                        (
                            await s.execute(
                                select(IspInvoiceLine).where(
                                    IspInvoiceLine.invoice_id == inv.id
                                )
                            )
                        )
                        .scalars()
                        .all()
                    )
                    got = (
                        str(inv.period_start),
                        str(inv.period_end),
                        str(line.period_from),
                        str(line.period_to),
                    )
                assert got == (start, end, start, end), (got, start, end)
                d = (await c.get(f"/api/v1/isp/invoices/{inv_id}", headers=h)).json()[
                    "data"
                ]
                assert d["lines"][0]["period_from"] == start
                assert d["lines"][0]["period_to"] == end
                assert d["period_start"] == start and d["period_end"] == end, d
                pdf = await c.get(f"/api/v1/isp/invoices/{inv_id}/pdf", headers=h)
                assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"
                text = _pdf_text(pdf.content)
                assert f"{start} - {end}" in text, "line period missing in PDF"
                assert f"{start} to {end}" in text, "billing period missing in PDF"
                return d

            # 1. renew x3 from the 360 while still valid: starts at old validity
            a = await subscriber(f"qa16a{tag}")
            old_until = a["valid_until"]
            assert old_until and datetime.fromisoformat(old_until) > datetime.now(UTC)
            r = await c.post(
                f"/api/v1/isp/subscribers/{a['id']}/renew",
                json={"cycles": 3, "idempotency_key": f"q16-renew-{tag}"},
                headers=h,
            )
            assert r.status_code == 201, r.text
            rc = r.json()["data"]
            new_until = rc["subscriber"]["valid_until"]
            assert datetime.fromisoformat(new_until) - datetime.fromisoformat(
                old_until
            ) == timedelta(days=90)
            d = await check_period(
                rc["invoice"]["id"], _local(old_until), _local(new_until)
            )
            assert d["lines"][0]["quantity"] == 3

            # 2. recharge x12 of an EXPIRED subscriber: starts now
            b = await subscriber(f"qa16b{tag}")
            past = datetime.now(UTC) - timedelta(days=5)
            async with SessionLocal() as s:
                row = await s.get(IspSubscriber, uuid.UUID(b["id"]))
                row.valid_until = past
                row.status = "expired"
                await s.commit()
            t0 = datetime.now(UTC)
            r = await c.post(
                f"/api/v1/isp/subscribers/{b['id']}/recharge",
                json={"package_id": pkg, "cycles": 12},
                headers=h,
            )
            assert r.status_code == 201, r.text
            rc = r.json()["data"]
            new_until = rc["subscriber"]["valid_until"]
            start_dt = datetime.fromisoformat(new_until) - timedelta(days=360)
            assert abs(start_dt - t0) < timedelta(minutes=5)
            await check_period(
                rc["invoice"]["id"], _local(start_dt.isoformat()), _local(new_until)
            )

            # 3. a single-cycle renewal is unchanged: same period rule, qty 1,
            #    the description is the plain package name
            before = rc["subscriber"]["valid_until"]
            r = await c.post(
                f"/api/v1/isp/subscribers/{b['id']}/renew", json={}, headers=h
            )
            assert r.status_code == 201, r.text
            rc = r.json()["data"]
            d = await check_period(
                rc["invoice"]["id"],
                _local(before),
                _local(rc["subscriber"]["valid_until"]),
            )
            assert d["lines"][0]["quantity"] == 1
            assert " x " not in d["lines"][0]["description"]
    finally:
        await engine.dispose()
        from app.database.redis import redis_client

        await redis_client.connection_pool.disconnect()
