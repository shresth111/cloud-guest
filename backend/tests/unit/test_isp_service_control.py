# ruff: noqa: E501 -- scenario test, long fixture lines kept readable
"""ADDENDUM_01 §A.9 tests 1-7 and ADDENDUM_03 numbering/isolation, on a
real PostgreSQL + Redis (skipped unless ``ISP_TEST_PG_DSN`` is set; CI has
neither). Run as described in ``test_isp_partner_postgres.py``.

The live kick (RouterOS 8728) is replaced at ``issue_live_disconnect`` --
nothing here talks to a router -- and is a spy, so test 4 can prove no
session of another org is ever passed to it.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from datetime import UTC, datetime
from decimal import Decimal

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)


async def _nas_snapshot(session, exclude_org=None):
    from sqlalchemy import text

    rows = await session.execute(
        text(
            "select id, organization_id, status, is_active, updated_at from radius_nas_clients "
            + ("where organization_id <> :o " if exclude_org else "")
            + "order by id"
        ),
        {"o": exclude_org} if exclude_org else {},
    )
    return [tuple(r) for r in rows.all()]


async def test_suspend_cuts_only_the_customer_and_billing_is_isolated(
    monkeypatch,
) -> None:  # noqa: PLR0915
    import httpx
    from sqlalchemy import select, text

    from app.database.session import SessionLocal, engine
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.guest import service as guest_service_module
    from app.domains.guest.models import Guest, GuestSession, RadiusNasClient
    from app.domains.isp_partner.models import IspPartnerProfile
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.location.models import Location
    from app.domains.organization.models import Organization, OrganizationMember
    from app.domains.rbac.dependencies import CurrentUser
    from app.domains.rbac.models import Role, UserRole
    from app.domains.rbac.repository import RBACRepository
    from app.domains.rbac.seed import seed_rbac
    from app.domains.router.crypto import encrypt_secret
    from app.domains.router.models import Router
    from app.main import create_app

    tag = uuid.uuid4().hex[:8]
    kicked: list = []
    unreachable: set = set()

    async def fake_live_disconnect(
        repository, *, session, terminator=None, already_ended_on_device=False
    ):
        kicked.append((session.id, session.organization_id))
        enforced = session.router_id not in unreachable
        await repository.update_session(session, {"disconnect_enforced": enforced})
        return enforced

    monkeypatch.setattr(
        guest_service_module, "issue_live_disconnect", fake_live_disconnect
    )

    try:
        async with SessionLocal() as s:
            await seed_rbac(s)
            await seed_isp_partner_rbac(RBACRepository(s))
            await s.commit()

        users = {}
        async with SessionLocal() as s:
            plan = Plan(
                name=f"P {tag}",
                slug=f"p-{tag}",
                plan_type="standard",
                billing_cycle="monthly",
                base_price=Decimal("0"),
                currency="INR",
                is_active=True,
                is_public=False,
            )
            s.add(plan)
            owner_role = (
                await s.execute(select(Role).where(Role.slug == "isp-owner"))
            ).scalar_one()
            isps = {}
            for name in ("A", "B"):
                org = Organization(
                    name=f"ISP {name} {tag}",
                    slug=f"isp-{name.lower()}-{tag}",
                    org_type="msp",
                    status="active",
                    contact_email=f"{name}-{tag}@example.com",
                    timezone="Asia/Kolkata",
                    settings={},
                )
                user = User(
                    first_name=name,
                    last_name="Owner",
                    email=f"own-{name}-{tag}@example.com",
                    username=f"own-{name}-{tag}",
                    password_hash="x",
                    is_active=True,
                    is_verified=True,
                )
                s.add_all([org, user])
                await s.flush()
                s.add(
                    IspPartnerProfile(
                        organization_id=org.id,
                        default_customer_plan_id=plan.id,
                        support_phone="+911100000000",
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
                        role_id=owner_role.id,
                        scope_type="organization",
                        organization_id=org.id,
                        granted_at=datetime.now(UTC),
                        is_active=True,
                    )
                )
                isps[name] = org.id
                users[name] = user.id
            # A normal, non-ISP tenant with its own live router and session.
            x = Organization(
                name=f"Venue X {tag}",
                slug=f"venue-x-{tag}",
                org_type="standard",
                status="active",
                contact_email=f"x-{tag}@example.com",
                timezone="Asia/Kolkata",
                settings={},
            )
            s.add(x)
            await s.flush()
            xl = Location(
                organization_id=x.id,
                name="X",
                slug=f"x-{tag}",
                status="active",
                address_line1="1",
                city="c",
                state_province="s",
                postal_code="1",
                country="IN",
                timezone="Asia/Kolkata",
                settings={},
            )
            s.add(xl)
            await s.flush()
            xr = Router(
                location_id=xl.id,
                organization_id=x.id,
                name="X hEX",
                serial_number=f"XS{tag}",
                mac_address=f"02:00:00:{tag[:2]}:{tag[2:4]}:99",
                model="RB",
                vendor="mikrotik",
                status="online",
                settings={},
            )
            s.add(xr)
            await s.commit()
            x_id, x_loc, x_router = x.id, xl.id, xr.id

        app = create_app()
        state = {"user": users["A"]}
        app.dependency_overrides[CurrentUser] = lambda: AuthUser(
            id=str(state["user"]), email="o@example.com"
        )
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            ha = {"X-Organization-Id": str(isps["A"])}
            hb = {"X-Organization-Id": str(isps["B"])}

            async def customer(h, name):
                r = await c.post(
                    "/api/v1/isp/customers",
                    json={
                        "name": f"{name} {tag}",
                        "contact_email": f"c-{tag}@example.com",
                    },
                    headers=h,
                )
                assert r.status_code == 201, r.text
                cid = r.json()["data"]["id"]
                r = await c.post(
                    f"/api/v1/isp/customers/{cid}/locations",
                    json={
                        "name": "Main",
                        "address_line1": "1",
                        "city": "c",
                        "state_province": "s",
                        "postal_code": "1",
                    },
                    headers=h,
                )
                assert r.status_code == 201, r.text
                return uuid.UUID(cid), uuid.UUID(r.json()["data"]["id"])

            state["user"] = users["A"]
            c1, c1loc = await customer(ha, "C1")
            c2, c2loc = await customer(ha, "C2")
            state["user"] = users["B"]
            b1, b1loc = await customer(hb, "B1")
            state["user"] = users["A"]

            async with SessionLocal() as s:

                def router(org, loc, n, status="online"):
                    return Router(
                        location_id=loc,
                        organization_id=org,
                        name=f"r{n}",
                        serial_number=f"S{tag}{n}",
                        mac_address=f"02:00:{tag[:2]}:{tag[2:4]}:{tag[4:6]}:{n:02d}",
                        model="RB",
                        vendor="mikrotik",
                        status=status,
                        settings={},
                    )

                r1, r2, r3, r4 = (
                    router(c1, c1loc, 1),
                    router(c1, c1loc, 2, "offline"),
                    router(c2, c2loc, 3),
                    router(b1, b1loc, 4),
                )
                s.add_all([r1, r2, r3, r4])
                await s.flush()

                def nas(rt, org, loc, status="active"):
                    return RadiusNasClient(
                        router_id=rt.id,
                        organization_id=org,
                        location_id=loc,
                        nas_identifier=f"cg-{rt.id.hex[:12]}",
                        shared_secret_encrypted=encrypt_secret("s3cret-test"),
                        status=status,
                        is_active=status == "active",
                        device_push_status="pending",
                        vendor="MikroTik",
                    )

                s.add_all(
                    [
                        nas(r1, c1, c1loc),
                        nas(r2, c1, c1loc, "disabled"),
                        nas(r3, c2, c2loc),
                        nas(r4, b1, b1loc),
                        RadiusNasClient(
                            router_id=x_router,
                            organization_id=x_id,
                            location_id=x_loc,
                            nas_identifier=f"cg-x-{tag}",
                            shared_secret_encrypted=encrypt_secret("s3cret-test"),
                            status="active",
                            is_active=True,
                            device_push_status="pending",
                            vendor="MikroTik",
                        ),
                    ]
                )
                now = datetime.now(UTC)
                for org, loc, rt in (
                    (c1, c1loc, r1),
                    (c1, c1loc, r2),
                    (c2, c2loc, r3),
                    (x_id, x_loc, x_router),
                ):
                    g = Guest(
                        organization_id=org,
                        location_id=loc,
                        identifier=f"+9190000{rt.hex[:5] if hasattr(rt,'hex') else uuid.uuid4().hex[:5]}",
                        first_seen_at=now,
                        last_seen_at=now,
                    )
                    s.add(g)
                    await s.flush()
                    s.add(
                        GuestSession(
                            guest_id=g.id,
                            router_id=rt if isinstance(rt, uuid.UUID) else rt.id,
                            location_id=loc,
                            organization_id=org,
                            auth_method="otp_sms",
                            status="active",
                            started_at=now,
                            last_activity_at=now,
                        )
                    )
                await s.commit()
                r1_id, r2_id = r1.id, r2.id
            unreachable.add(r2_id)

            async with SessionLocal() as s:
                others_before = await _nas_snapshot(s, exclude_org=c1)

            # ---- test 1 + 4: suspend C1 ------------------------------------
            r = await c.post(
                f"/api/v1/isp/customers/{c1}/service/suspend",
                json={"reason": "non_payment", "show_suspended_page": True},
                headers={**ha, "Idempotency-Key": f"k-{tag}"},
            )
            assert r.status_code == 200, r.text
            data = r.json()["data"]
            assert data["state"] == "suspend_pending"  # r2 unreachable
            async with SessionLocal() as s:
                assert (
                    await _nas_snapshot(s, exclude_org=c1) == others_before
                )  # byte-identical
                statuses = dict(
                    (
                        await s.execute(
                            text(
                                "select router_id, status from radius_nas_clients where organization_id = :o"
                            ),
                            {"o": c1},
                        )
                    ).all()
                )
                assert statuses == {r1_id: "disabled", r2_id: "disabled"}
                assert (
                    await s.scalar(
                        text("select status from organizations where id = :o"),
                        {"o": c1},
                    )
                    == "suspended"
                )
                assert (
                    await s.scalar(
                        text(
                            "select count(*) from guest_sessions where organization_id = :o and status = 'active'"
                        ),
                        {"o": c1},
                    )
                    == 0
                )
                assert (
                    await s.scalar(
                        text(
                            "select count(*) from guest_sessions where organization_id = :o and status = 'active'"
                        ),
                        {"o": x_id},
                    )
                    == 1
                )
                paused = await s.scalar(
                    text(
                        "select count(*) from captive_portal_configs where location_id = :l and is_active and name = 'isp-suspended'"
                    ),
                    {"l": c1loc},
                )
                assert paused == 1
            assert {org for _, org in kicked} == {c1}
            # idempotent repeat with the same key
            again = await c.post(
                f"/api/v1/isp/customers/{c1}/service/suspend",
                json={"reason": "non_payment"},
                headers={**ha, "Idempotency-Key": f"k-{tag}"},
            )
            assert again.json()["data"]["requested_at"] == data["requested_at"]
            # customer view and TR-069 badge carry the state
            cv = await c.get(f"/api/v1/isp/customers/{c1}", headers=ha)
            assert cv.json()["data"]["service_state"] == "suspend_pending"

            # ---- retry once the router answers -------------------------------
            unreachable.clear()
            r = await c.post(f"/api/v1/isp/customers/{c1}/service/retry", headers=ha)
            assert r.json()["data"]["state"] == "suspended", r.text

            # ---- test 3: a forged step pointing at org X's router -------------
            from app.domains.isp_partner.billing_models import IspServiceAction
            from app.domains.isp_partner.exceptions import IspScopeViolation
            from app.domains.isp_partner.service_control import IspServiceControl

            async with SessionLocal() as s:
                st = await IspServiceControl(session=s).get_state(c1)
                st.state = "suspend_pending"
                s.add(
                    IspServiceAction(
                        state_id=st.id,
                        transition="suspend",
                        router_id=x_router,
                        kind="kick_sessions",
                        status="pending",
                        attempts=0,
                        prior_state={"unconfirmed_session_ids": []},
                    )
                )
                await s.flush()
                with pytest.raises(IspScopeViolation):
                    await IspServiceControl(session=s).retry(isps["A"], c1, force=True)
                await s.rollback()
            async with SessionLocal() as s:
                assert (
                    await s.scalar(
                        text(
                            "select status from radius_nas_clients where router_id = :r"
                        ),
                        {"r": x_router},
                    )
                    == "active"
                )

            # ---- test 2: a non-ISP org through the API and the service ---------
            r = await c.post(
                f"/api/v1/isp/customers/{x_id}/service/suspend",
                json={"reason": "other"},
                headers=ha,
            )
            assert (
                r.status_code == 404
                and r.json()["data"]["code"] == "ISP_CUSTOMER_NOT_FOUND"
            )
            async with SessionLocal() as s:
                xorg = await s.get(Organization, x_id)
                with pytest.raises(IspScopeViolation):
                    await IspServiceControl(session=s).suspend(
                        isps["A"], xorg, actor=users["A"], reason="other"
                    )
                await s.rollback()
            async with SessionLocal() as s:
                assert await _nas_snapshot(s, exclude_org=c1) == others_before

            # ---- test 7: a NAS registered while suspended is cut at once -------
            async with SessionLocal() as s:
                late = Router(
                    location_id=c1loc,
                    organization_id=c1,
                    name="late",
                    serial_number=f"L{tag}",
                    mac_address=f"02:01:{tag[:2]}:{tag[2:4]}:{tag[4:6]}:aa",
                    model="RB",
                    vendor="mikrotik",
                    status="online",
                    settings={},
                )
                s.add(late)
                await s.flush()
                s.add(
                    RadiusNasClient(
                        router_id=late.id,
                        organization_id=c1,
                        location_id=c1loc,
                        nas_identifier=f"cg-late-{tag}",
                        shared_secret_encrypted=encrypt_secret("s3cret-test"),
                        status="active",
                        is_active=True,
                        device_push_status="pending",
                        vendor="MikroTik",
                    )
                )
                await s.flush()

                class Radius:
                    async def disable_nas(
                        self,
                        *,
                        nas_id,
                        requesting_organization_id,
                        actor_user_id,
                        reason=None,
                    ):
                        row = await s.get(RadiusNasClient, nas_id)
                        assert row.organization_id == requesting_organization_id == c1
                        row.status, row.is_active = "disabled", False

                await IspServiceControl(
                    session=s, radius_service=Radius()
                ).after_nas_registered(isps["A"], late, users["A"])
                assert (
                    await s.scalar(
                        text(
                            "select status from radius_nas_clients where router_id = :r"
                        ),
                        {"r": late.id},
                    )
                ) == "disabled"
                await s.commit()
                late_id = late.id

            # ---- test 5: resume restores only what suspend changed --------------
            r = await c.post(
                f"/api/v1/isp/customers/{c1}/service/resume", json={}, headers=ha
            )
            assert (
                r.status_code == 200 and r.json()["data"]["state"] == "active"
            ), r.text
            async with SessionLocal() as s:
                statuses = dict(
                    (
                        await s.execute(
                            text(
                                "select router_id, status from radius_nas_clients where organization_id = :o"
                            ),
                            {"o": c1},
                        )
                    ).all()
                )
                assert statuses == {
                    r1_id: "active",
                    r2_id: "disabled",
                    late_id: "active",
                }
                assert (
                    await s.scalar(
                        text("select status from organizations where id = :o"),
                        {"o": c1},
                    )
                    == "active"
                )
                assert (
                    await s.scalar(
                        text(
                            "select count(*) from captive_portal_configs where location_id = :l and is_active and name = 'isp-suspended'"
                        ),
                        {"l": c1loc},
                    )
                    == 0
                )
                assert (
                    await s.scalar(
                        text(
                            "select count(*) from captive_portal_configs where location_id = :l and is_active"
                        ),
                        {"l": c1loc},
                    )
                    == 1
                )
                assert await _nas_snapshot(s, exclude_org=c1) == others_before

            # ---- test 6: a concurrent transition gets 409 ------------------------
            async with SessionLocal() as locker:
                await locker.execute(
                    text(
                        "select id from isp_customer_service_state where customer_organization_id = :c for update"
                    ),
                    {"c": c1},
                )
                r = await c.post(
                    f"/api/v1/isp/customers/{c1}/service/suspend",
                    json={"reason": "other"},
                    headers=ha,
                )
                assert (
                    r.status_code == 409
                    and r.json()["data"]["code"] == "ISP_SERVICE_TRANSITION_IN_PROGRESS"
                )
                await locker.rollback()

            # ---- billing: settings, invoices, payments, credit notes ------------
            r = await c.get(f"/api/v1/isp/billing/customers/{c2}/plan", headers=ha)
            assert r.status_code == 200 and r.json()["data"] is None
            r = await c.post(
                "/api/v1/isp/billing/invoices",
                json={
                    "isp_customer_id": str(c2),
                    "description": "x",
                    "amount_paise": 100,
                },
                headers=ha,
            )
            assert (
                r.status_code == 409
                and r.json()["data"]["code"] == "ISP_BILLING_NOT_CONFIGURED"
            )
            r = await c.put(
                "/api/v1/isp/billing/settings",
                json={
                    "legal_name": "ISP A Pvt Ltd",
                    "state_code": "07",
                    "gst_enabled": True,
                    "invoice_prefix": "NETX",
                    "upi_vpa": "ispa@upi",
                },
                headers=ha,
            )
            assert r.status_code == 200, r.text
            bad = await c.put(
                "/api/v1/isp/billing/settings",
                json={"invoice_prefix": "TOOLONG"},
                headers=ha,
            )
            assert bad.status_code == 422
            r = await c.post(
                "/api/v1/isp/billing/invoices",
                json={
                    "isp_customer_id": str(c2),
                    "description": "Monthly",
                    "amount_paise": 18500,
                },
                headers=ha,
            )
            assert r.status_code == 201, r.text
            inv = r.json()["data"]
            assert (
                inv["number"].startswith("NETX/")
                and inv["total_paise"] == 21830
                and inv["status"] == "issued"
            )
            assert inv["cgst_paise"] == 1665 and inv["sgst_paise"] == 1665
            pay = await c.post(
                "/api/v1/isp/billing/payments",
                json={
                    "isp_customer_id": str(c2),
                    "invoice_id": inv["id"],
                    "amount_paise": 10000,
                    "mode": "upi",
                },
                headers=ha,
            )
            assert (
                pay.status_code == 422
                and pay.json()["data"]["code"] == "ISP_PAYMENT_REFERENCE_REQUIRED"
            )
            key = {"Idempotency-Key": f"pay-{tag}"}
            pay = await c.post(
                "/api/v1/isp/billing/payments",
                json={
                    "isp_customer_id": str(c2),
                    "invoice_id": inv["id"],
                    "amount_paise": 10000,
                    "mode": "cash",
                },
                headers={**ha, **key},
            )
            assert pay.status_code == 201, pay.text
            again = await c.post(
                "/api/v1/isp/billing/payments",
                json={
                    "isp_customer_id": str(c2),
                    "invoice_id": inv["id"],
                    "amount_paise": 10000,
                    "mode": "cash",
                },
                headers={**ha, **key},
            )
            assert again.json()["data"]["id"] == pay.json()["data"]["id"]
            detail = (
                await c.get(f"/api/v1/isp/invoices/{inv['id']}", headers=ha)
            ).json()["data"]
            assert (
                detail["status"] == "partially_paid"
                and detail["balance_paise"] == 11830
            )
            assert detail["payments"][0]["receipt_number"].startswith("RCT/")
            cn = await c.post(
                f"/api/v1/isp/invoices/{inv['id']}/credit-note",
                json={"reason": "goodwill"},
                headers=ha,
            )
            assert cn.status_code == 201, cn.text
            assert (
                cn.json()["data"]["number"].startswith("CN/")
                and cn.json()["data"]["credit_note_for"]["number"] == inv["number"]
            )
            detail = (
                await c.get(f"/api/v1/isp/invoices/{inv['id']}", headers=ha)
            ).json()["data"]
            assert detail["balance_paise"] == 0 and detail["status"] == "paid"
            lst = (await c.get("/api/v1/isp/invoices", headers=ha)).json()["data"]
            assert (
                lst["totals"]["invoiced_paise"] == 10000
                and lst["totals"]["outstanding_paise"] == 0
            )
            pdf = await c.get(f"/api/v1/isp/invoices/{inv['id']}/pdf", headers=ha)
            assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"
            rc = await c.get(
                f"/api/v1/isp/billing/payments/{pay.json()['data']['id']}/receipt.pdf",
                headers=ha,
            )
            assert rc.status_code == 200 and rc.content[:4] == b"%PDF"
            zip_ = await c.post(
                "/api/v1/isp/invoices/bulk",
                json={"action": "download_pdfs", "invoice_ids": [inv["id"]]},
                headers=ha,
            )
            assert zip_.headers["content-type"] == "application/zip"

            # ISP B can see none of it
            state["user"] = users["B"]
            for path in (
                f"/api/v1/isp/invoices/{inv['id']}",
                f"/api/v1/isp/billing/invoices/{inv['id']}",
                f"/api/v1/isp/billing/payments/{pay.json()['data']['id']}/receipt.pdf",
            ):
                assert (await c.get(path, headers=hb)).status_code == 404, path
            assert (await c.get("/api/v1/isp/invoices", headers=hb)).json()["data"][
                "total"
            ] == 0
            state["user"] = users["A"]

            # suspend-for-dues needs an overdue invoice
            r = await c.post(
                f"/api/v1/isp/billing/customers/{c2}/suspend-for-dues", headers=ha
            )
            assert (
                r.status_code == 409
                and r.json()["data"]["code"] == "ISP_NO_OVERDUE_INVOICES"
            )
            r = await c.post(
                "/api/v1/isp/billing/invoices",
                json={
                    "isp_customer_id": str(c2),
                    "description": "Old",
                    "amount_paise": 5000,
                },
                headers=ha,
            )
            old_id = r.json()["data"]["id"]
            async with SessionLocal() as s:
                await s.execute(
                    text(
                        "update isp_invoices set due_date = due_date - 60 where id = :i"
                    ),
                    {"i": uuid.UUID(old_id)},
                )
                await s.commit()
            ledger = (
                await c.get(f"/api/v1/isp/billing/customers/{c2}/ledger", headers=ha)
            ).json()["data"]
            assert (
                ledger["overdue_paise"] > 0 and old_id in ledger["overdue_invoice_ids"]
            )
            r = await c.post(
                f"/api/v1/isp/billing/customers/{c2}/suspend-for-dues", headers=ha
            )
            assert r.status_code == 200 and r.json()["data"]["reason"] == "non_payment"
            ledger = (
                await c.get(f"/api/v1/isp/billing/customers/{c2}/ledger", headers=ha)
            ).json()["data"]
            assert ledger["can_resume"] is False
            pay2 = await c.post(
                "/api/v1/isp/billing/payments",
                json={
                    "isp_customer_id": str(c2),
                    "invoice_id": old_id,
                    "amount_paise": 10000,
                    "mode": "cash",
                },
                headers=ha,
            )
            assert pay2.json()["data"]["can_resume"] is True and pay2.json()["data"][
                "unallocated_paise"
            ] == 10000 - 5000 - (5000 * 1800 // 10000)

        # ---- gap-free numbering under concurrency + rollback ------------------
        from app.domains.isp_partner.billing_service import IspBillingService
        from app.domains.isp_partner.repository import IspRepository
        from app.domains.isp_partner.tasks import _SystemContext

        async def issue_one(fail: bool = False):
            async with SessionLocal() as s:
                repo = IspRepository(s)
                org = await repo.get_organization(isps["A"])
                prof = await repo.get_profile(isps["A"])
                svc = IspBillingService(session=s)
                await svc.issue_invoice(
                    _SystemContext(org, prof, repo),
                    c2,
                    lines=[{"description": "c", "amount_paise": 100}],
                    invoice_kind="manual",
                )
                if fail:
                    await s.rollback()
                else:
                    await s.commit()

        await asyncio.gather(*(issue_one(fail=(i % 5 == 0)) for i in range(25)))
        async with SessionLocal() as s:
            seqs = [
                r[0]
                for r in (
                    await s.execute(
                        text(
                            "select seq from isp_invoices where isp_organization_id = :i and doc_type = 'invoice' order by seq"
                        ),
                        {"i": isps["A"]},
                    )
                ).all()
            ]
        assert seqs == list(range(1, len(seqs) + 1)), seqs  # gap-free 1..n
        assert (
            len(seqs) == 2 + 20
        )  # two earlier + 20 committed (5 rolled back left no gap)
    finally:
        await engine.dispose()
