# ruff: noqa: E501 -- scenario test
"""ADDENDUM_03 Part B (BE-I9..I12) on real PostgreSQL + Redis (skipped unless
``ISP_TEST_PG_DSN``; CI has neither).

- circuit ids: unique per ISP, gap-free, assigned on every creation path;
- coupon activation: one PAID invoice + one ``prepaid_coupon`` payment per
  activation; a second sync makes none; toggle off makes none; a ₹0 package
  makes none;
- recharge: invoice + same-transaction payment + validity from
  ``max(now, valid_until)``; idempotent replay; error codes;
- postpaid cycle on generate-due, idempotent, rolls the period forward;
- subscriber bills never reach a customer's ledger / overdue / 1b alias;
- isolation: ISP B cannot read, pay or recharge A's rows (404); nothing is
  written for a non-ISP org.
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


async def test_subscriber_invoices_end_to_end() -> None:  # noqa: PLR0915
    import httpx
    from sqlalchemy import select, text

    from app.database.session import SessionLocal, engine
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.isp_partner import plans_service
    from app.domains.isp_partner.models import IspPartnerProfile
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.organization.models import Organization, OrganizationMember
    from app.domains.rbac.dependencies import CurrentUser
    from app.domains.rbac.models import Role, UserRole
    from app.domains.rbac.repository import RBACRepository
    from app.domains.rbac.seed import seed_rbac
    from app.main import create_app

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
                slug=f"p3-{tag}",
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
                    slug=f"inv{n.lower()}{tag}",
                    org_type="msp",
                    status="active",
                    contact_email=f"{n}{tag}@example.com",
                    timezone="Asia/Kolkata",
                    settings={},
                )
                user = User(
                    first_name=n,
                    last_name="O",
                    email=f"iv{n}{tag}@example.com",
                    username=f"iv{n}{tag}",
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
            x = Organization(
                name=f"Venue {tag}",
                slug=f"venue3-{tag}",
                org_type="standard",
                status="active",
                contact_email=f"v{tag}@example.com",
                timezone="Asia/Kolkata",
                settings={},
            )
            s.add(x)
            await s.commit()
            x_id = x.id

        app = create_app()
        state = {"user": users["A"]}
        app.dependency_overrides[CurrentUser] = lambda: AuthUser(
            id=str(state["user"]), email="o@example.com"
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t"
        ) as c:
            ha, hb = (
                {"X-Organization-Id": str(isps["A"])},
                {"X-Organization-Id": str(isps["B"])},
            )

            async def sync_invoices(**params):
                plans_service._last_sync.clear()  # the 60 s throttle
                r = await c.get(
                    "/api/v1/isp/invoices",
                    params={"bill_to_kind": "subscriber", "page_size": 100, **params},
                    headers=ha,
                )
                assert r.status_code == 200, r.text
                return r.json()["data"]

            r = await c.put(
                "/api/v1/isp/billing/settings",
                json={
                    "legal_name": "Net A Pvt Ltd",
                    "state_code": "07",
                    "gst_enabled": True,
                    "invoice_prefix": "NETX",
                },
                headers=ha,
            )
            assert r.status_code == 200, r.text
            assert r.json()["data"]["coupon_invoice_on_activation"] is True
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
            loc = (
                await c.post(
                    f"/api/v1/isp/customers/{cust}/locations",
                    json={
                        "name": "Main",
                        "address_line1": "1",
                        "city": "c",
                        "state_province": "s",
                        "postal_code": "1",
                    },
                    headers=ha,
                )
            ).json()["data"]["id"]
            gid = (
                await c.post(
                    "/api/v1/isp/speed-groups",
                    json={
                        "name": "15 Mbps",
                        "download_kbps": 15360,
                        "upload_kbps": 15360,
                    },
                    headers=ha,
                )
            ).json()["data"]["id"]

            async def package(**body):
                r = await c.post(
                    "/api/v1/isp/packages",
                    json={"speed_group_id": gid, **body},
                    headers=ha,
                )
                assert r.status_code == 201, r.text
                return r.json()["data"]["id"]

            paid_pkg = await package(type="prepaid", price_paise=18500)
            free_pkg = await package(type="prepaid", validity_days=7, price_paise=0)
            post_pkg = await package(
                type="postpaid",
                validity_days=30,
                price_paise=50000,
                price_includes_gst=False,
            )

            async def coupons(pkg, qty):
                r = await c.post(
                    "/api/v1/isp/coupon-batches",
                    json={
                        "package_id": pkg,
                        "isp_customer_id": cust,
                        "isp_location_id": loc,
                        "quantity": qty,
                    },
                    headers=ha,
                )
                assert r.status_code == 201, r.text
                b = r.json()["data"]
                items = (
                    await c.get(
                        f"/api/v1/isp/coupon-batches/{b['id']}/coupons",
                        headers=ha,
                    )
                ).json()["data"]["items"]
                return b["id"], items

            paid_batch, paid_coupons = await coupons(paid_pkg, 3)
            _, free_coupons = await coupons(free_pkg, 1)
            now = datetime.now(UTC)

            async def redeem(coupon, ident):
                async with SessionLocal() as s:
                    await s.execute(
                        text(
                            "update vouchers set status='active', use_count=1, redeemed_at=:n, redeemed_identifier=:i, expires_at=:e where id=:v"
                        ),
                        {
                            "n": now,
                            "i": ident,
                            "e": now + timedelta(days=30),
                            "v": uuid.UUID(coupon["id"]),
                        },
                    )
                    await s.commit()

            # ---- BE-I11: coupon activation -> paid invoice + prepaid_coupon -----
            await redeem(paid_coupons[0], "+919000000001")
            await redeem(paid_coupons[1], "+919000000002")
            await redeem(free_coupons[0], "+919000000003")
            data = await sync_invoices()
            assert data["total"] == 2, data  # the ₹0 package makes none
            for row in data["items"]:
                assert row["bill_to_kind"] == "subscriber" and row["customer"] is None
                assert row["invoice_kind"] == "coupon"
                assert row["status"] == "paid" and row["balance_paise"] == 0
                assert row["total_paise"] == 18500  # inclusive: price == total
                assert row["cgst_paise"] + row["sgst_paise"] == 2822
                assert row["package"]["id"] == paid_pkg
                assert row["subscriber"]["circuit_id"] >= 1
                assert "+91900" not in row["subscriber"]["username"]  # masked
            circuits = sorted(r["subscriber"]["circuit_id"] for r in data["items"])
            assert len(set(circuits)) == 2
            async with SessionLocal() as s:
                pays = (
                    await s.execute(
                        text(
                            "select mode, coupon_batch_id, reference, subscriber_id is not null from isp_payments where isp_organization_id = :i"
                        ),
                        {"i": isps["A"]},
                    )
                ).all()
            assert len(pays) == 2
            assert all(
                p[0] == "prepaid_coupon"
                and str(p[1]) == paid_batch
                and p[2].endswith(("-0001", "-0002", "-0003"))
                and p[3]
                for p in pays
            ), pays
            # idempotent: a second (and third) sync issues nothing new
            assert (await sync_invoices())["total"] == 2
            assert (await sync_invoices())["total"] == 2

            # toggle off -> a new activation makes no invoice
            r = await c.put(
                "/api/v1/isp/invoices/settings",
                json={"coupon_invoice_on_activation": False},
                headers=ha,
            )
            assert (
                r.status_code == 200
                and r.json()["data"]["coupon_invoice_on_activation"] is False
            ), r.text
            await redeem(paid_coupons[2], "+919000000004")
            assert (await sync_invoices())["total"] == 2
            subs = (await c.get("/api/v1/isp/subscribers", headers=ha)).json()["data"]
            assert subs["total"] == 4
            sub_circuits = sorted(s_["circuit_id"] for s_ in subs["items"])
            assert sub_circuits == list(range(1, 5)), sub_circuits  # gap-free

            # ---- BE-I9: manual subscriber gets the next circuit id ------------
            r = await c.post(
                "/api/v1/isp/subscribers",
                json={
                    "isp_customer_id": cust,
                    "identifier": "flat-12b",
                    "package_id": paid_pkg,
                    "first_name": "Test",
                    "last_name": "Subscriber",
                    "state_code": "09",
                    "reminder_opt_in": {"sms": True},
                },
                headers=ha,
            )
            assert r.status_code == 201, r.text
            manual = r.json()["data"]
            assert manual["circuit_id"] == 5
            assert manual["reminder_opt_in"] == {
                "email": True,
                "sms": True,
                "whatsapp": False,
            }
            sid = manual["id"]
            before_until = datetime.fromisoformat(manual["valid_until"])

            # ---- BE-I10: recharge ---------------------------------------------
            key = f"rch-{tag}"
            body = {
                "package_id": paid_pkg,
                "paid_now": True,
                "payment": {"mode": "cash"},
                "idempotency_key": key,
            }
            r = await c.post(
                f"/api/v1/isp/subscribers/{sid}/recharge", json=body, headers=ha
            )
            assert r.status_code == 201, r.text
            rc = r.json()["data"]
            assert rc["invoice"]["status"] == "paid"
            assert rc["invoice"]["invoice_kind"] == "recharge"
            # place of supply = subscriber's state 09 != seller 07 -> IGST
            assert rc["invoice"]["igst_paise"] == 2822
            assert rc["invoice"]["cgst_paise"] == 0
            assert rc["invoice"]["subscriber"]["first_name"] == "Test"
            assert rc["invoice"]["subscriber"]["circuit_id"] == 5
            assert (
                rc["payment"]["receipt_number"]
                and rc["payment"]["amount_paise"] == 18500
            )
            new_until = datetime.fromisoformat(rc["subscriber"]["valid_until"])
            assert new_until - before_until == timedelta(days=30)  # from valid_until
            # replay: same invoice, no second extension, no second payment
            r2 = await c.post(
                f"/api/v1/isp/subscribers/{sid}/recharge", json=body, headers=ha
            )
            assert r2.status_code == 201
            assert r2.json()["data"]["invoice"]["id"] == rc["invoice"]["id"]
            assert r2.json()["data"]["payment"]["id"] == rc["payment"]["id"]
            assert (
                r2.json()["data"]["subscriber"]["valid_until"]
                == rc["subscriber"]["valid_until"]
            )
            # UPI needs a reference
            r = await c.post(
                f"/api/v1/isp/subscribers/{sid}/recharge",
                json={
                    "package_id": paid_pkg,
                    "paid_now": True,
                    "payment": {"mode": "upi"},
                },
                headers=ha,
            )
            assert r.json()["data"]["code"] == "ISP_PAYMENT_REFERENCE_REQUIRED", r.text
            # ₹0 package
            r = await c.post(
                f"/api/v1/isp/subscribers/{sid}/recharge",
                json={"package_id": free_pkg},
                headers=ha,
            )
            assert r.status_code == 409
            assert r.json()["data"]["code"] == "ISP_PACKAGE_NEEDS_PRICE"
            # unpaid recharge, then a partial payment against it
            r = await c.post(
                f"/api/v1/isp/subscribers/{sid}/recharge",
                json={"package_id": paid_pkg},
                headers=ha,
            )
            unpaid = r.json()["data"]["invoice"]
            assert unpaid["status"] == "issued" and unpaid["status_label"] == "Unpaid"
            assert r.json()["data"]["payment"] is None
            r = await c.post(
                "/api/v1/isp/billing/payments",
                json={
                    "subscriber_id": sid,
                    "invoice_id": unpaid["id"],
                    "amount_paise": 5000,
                    "mode": "cash",
                },
                headers=ha,
            )
            assert r.status_code == 201, r.text
            assert r.json()["data"]["subscriber_id"] == sid
            detail = (
                await c.get(f"/api/v1/isp/invoices/{unpaid['id']}", headers=ha)
            ).json()["data"]
            assert detail["status"] == "partially_paid"
            assert detail["balance_paise"] == 13500
            assert detail["lines"][0]["package_id"] == paid_pkg
            # both parties at once is refused
            r = await c.post(
                "/api/v1/isp/billing/payments",
                json={
                    "subscriber_id": sid,
                    "isp_customer_id": cust,
                    "amount_paise": 100,
                    "mode": "cash",
                },
                headers=ha,
            )
            assert r.status_code == 422, r.text
            # credit note on a subscriber invoice (check constraint holds)
            r = await c.post(
                f"/api/v1/isp/invoices/{unpaid['id']}/credit-note",
                json={"reason": "goodwill"},
                headers=ha,
            )
            assert r.status_code in (200, 201), r.text
            # disabled subscriber
            await c.post(f"/api/v1/isp/subscribers/{sid}/disable", headers=ha)
            r = await c.post(
                f"/api/v1/isp/subscribers/{sid}/recharge",
                json={"package_id": paid_pkg, "idempotency_key": f"x-{tag}"},
                headers=ha,
            )
            assert r.json()["data"]["code"] == "ISP_SUBSCRIBER_DISABLED", r.text
            await c.post(f"/api/v1/isp/subscribers/{sid}/enable", headers=ha)

            # manual invoice billed to a subscriber
            r = await c.post(
                "/api/v1/isp/invoices",
                json={
                    "bill_to": {"kind": "subscriber", "subscriber_id": sid},
                    "lines": [
                        {
                            "description": "Installation",
                            "amount_paise": 50000,
                            "price_includes_gst": False,
                        }
                    ],
                },
                headers=ha,
            )
            assert r.status_code == 201, r.text
            assert r.json()["data"]["bill_to_kind"] == "subscriber"
            assert (
                await c.post(
                    "/api/v1/isp/invoices",
                    json={
                        "bill_to": {"kind": "subscriber"},
                        "lines": [{"description": "x", "amount_paise": 1}],
                    },
                    headers=ha,
                )
            ).status_code == 422

            # ---- BE-I12: postpaid cycle ---------------------------------------
            r = await c.post(
                "/api/v1/isp/subscribers",
                json={
                    "isp_customer_id": cust,
                    "identifier": "office-7",
                    "package_id": post_pkg,
                },
                headers=ha,
            )
            post_sid = r.json()["data"]["id"]
            async with SessionLocal() as s:
                await s.execute(
                    text("update isp_subscribers set valid_until = :t where id = :i"),
                    {"t": now - timedelta(days=1), "i": uuid.UUID(post_sid)},
                )
                await s.commit()
            r = await c.post("/api/v1/isp/billing/invoices/generate-due", headers=ha)
            assert r.status_code in (200, 201), r.text
            cyc = await sync_invoices(subscriber_id=post_sid)
            assert cyc["total"] == 1, cyc
            assert cyc["items"][0]["invoice_kind"] == "cycle"
            assert cyc["items"][0]["total_paise"] == 59000  # exclusive + 18%
            await c.post("/api/v1/isp/billing/invoices/generate-due", headers=ha)
            assert (await sync_invoices(subscriber_id=post_sid))["total"] == 1
            post = (
                await c.get(f"/api/v1/isp/subscribers/{post_sid}", headers=ha)
            ).json()["data"]
            assert datetime.fromisoformat(post["valid_until"]) > now

            # ---- filters + export ---------------------------------------------
            assert (await sync_invoices(username="flat-12"))["total"] == 4
            assert (await sync_invoices(package_id=post_pkg))["total"] == 1
            exp = await c.get(
                "/api/v1/isp/invoices/export",
                params={"bill_to_kind": "subscriber"},
                headers=ha,
            )
            assert exp.status_code == 200
            assert "Circuit Id" in exp.text and ",5," in exp.text

            # ---- subscriber bills never touch customer billing -----------------
            ledger = (
                await c.get(f"/api/v1/isp/billing/customers/{cust}/ledger", headers=ha)
            ).json()["data"]
            assert ledger["invoices"] == [] and ledger["payments"] == []
            assert ledger["balance_paise"] == 0 and ledger["overdue_paise"] == 0
            alias = (await c.get("/api/v1/isp/billing/invoices", headers=ha)).json()[
                "data"
            ]
            assert alias["total"] == 0

            # ---- numbering: one gap-free series across kinds -------------------
            async with SessionLocal() as s:
                seqs = (
                    (
                        await s.execute(
                            text(
                                "select seq from isp_invoices where isp_organization_id = :i and doc_type = 'invoice' order by seq"
                            ),
                            {"i": isps["A"]},
                        )
                    )
                    .scalars()
                    .all()
                )
            assert seqs == list(range(1, len(seqs) + 1)), seqs

            # ---- isolation ------------------------------------------------------
            state["user"] = users["B"]
            assert (
                await c.get(f"/api/v1/isp/invoices/{unpaid['id']}", headers=hb)
            ).status_code == 404
            assert (
                await c.post(
                    f"/api/v1/isp/subscribers/{sid}/recharge",
                    json={"package_id": paid_pkg},
                    headers=hb,
                )
            ).status_code == 404
            r = await c.post(
                "/api/v1/isp/billing/payments",
                json={"subscriber_id": sid, "amount_paise": 100, "mode": "cash"},
                headers=hb,
            )
            assert r.status_code == 404, r.text
            assert (
                await c.get(
                    "/api/v1/isp/invoices",
                    params={"bill_to_kind": "subscriber"},
                    headers=hb,
                )
            ).json()["data"]["total"] == 0
            state["user"] = users["A"]

        async with SessionLocal() as s:
            for t in ("isp_invoices", "isp_payments", "isp_subscribers"):
                assert (
                    await s.scalar(
                        text(
                            f"select count(*) from {t} where customer_organization_id = :x"
                        ),
                        {"x": x_id},
                    )
                    == 0
                ), t
            # B's series untouched by A's activity
            assert (
                await s.scalar(
                    text(
                        "select count(*) from isp_invoice_sequences where isp_organization_id = :b and series in ('invoice', 'circuit')"
                    ),
                    {"b": isps["B"]},
                )
                == 0
            )
    finally:
        await engine.dispose()
        from app.database.redis import redis_client

        await redis_client.connection_pool.disconnect()
