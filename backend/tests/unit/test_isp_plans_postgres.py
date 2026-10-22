# ruff: noqa: E501 -- scenario test
"""ADDENDUM_02 BE-P8 on real PostgreSQL + Redis (skipped unless
``ISP_TEST_PG_DSN``; CI has neither): groups/packages and their delete
rules, ladder idempotency, coupon batches over the real VoucherService
(including a >1000 split), subscriber sync from redemptions, the X1 rate for
an ISP coupon session, and isolation (nothing created in a non-ISP org;
ISP B sees none of ISP A's rows)."""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)


async def test_plans_coupons_subscribers_end_to_end() -> None:  # noqa: PLR0915
    import httpx
    from sqlalchemy import select, text

    from app.database.session import SessionLocal, engine
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
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
                slug=f"p2-{tag}",
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
                    slug=f"net{n.lower()}{tag}",
                    org_type="msp",
                    status="active",
                    contact_email=f"{n}{tag}@example.com",
                    timezone="Asia/Kolkata",
                    settings={},
                )
                user = User(
                    first_name=n,
                    last_name="O",
                    email=f"pl{n}{tag}@example.com",
                    username=f"pl{n}{tag}",
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
                slug=f"venue2-{tag}",
                org_type="standard",
                status="active",
                contact_email=f"v{tag}@example.com",
                timezone="Asia/Kolkata",
                settings={},
            )
            s.add(x)
            await s.commit()
            x_id = x.id

        async def per_org_counts(org_ids):
            async with SessionLocal() as s:
                out = {}
                for t in ("queue_profiles", "voucher_plans", "voucher_batches"):
                    out[t] = await s.scalar(
                        text(
                            f"select count(*) from {t} where organization_id not in (select customer_organization_id from isp_customer_profiles)"
                        )
                    )
                return out

        before = await per_org_counts([x_id])
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
            r = await c.post(
                "/api/v1/isp/customers",
                json={"name": f"Cafe {tag}", "contact_email": f"c{tag}@example.com"},
                headers=ha,
            )
            cust = r.json()["data"]["id"]
            r = await c.post(
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
            loc = r.json()["data"]["id"]

            # groups + packages ------------------------------------------------
            assert (await c.get("/api/v1/isp/plan-settings", headers=ha)).json()[
                "data"
            ]["default_validity_days"] == 30
            g = await c.post(
                "/api/v1/isp/speed-groups",
                json={"name": "15 Mbps", "download_kbps": 15360, "upload_kbps": 15360},
                headers=ha,
            )
            assert g.status_code == 201, g.text
            gid = g.json()["data"]["id"]
            bad = await c.post(
                "/api/v1/isp/speed-groups",
                json={
                    "name": "x",
                    "download_kbps": 1024,
                    "upload_kbps": 1024,
                    "burst": {"download_kbps": 2048},
                },
                headers=ha,
            )
            assert (
                bad.status_code == 422
                and bad.json()["data"]["code"] == "ISP_BURST_INCOMPLETE"
            )
            sug = await c.get(
                "/api/v1/isp/packages/suggest-name",
                params={"speed_group_id": gid, "type": "prepaid", "validity_days": 30},
                headers=ha,
            )
            assert sug.json()["data"]["name"] == "15 Mbps · Prepaid · 30 days"
            p = await c.post(
                "/api/v1/isp/packages",
                json={"speed_group_id": gid, "type": "prepaid", "price_paise": 18500},
                headers=ha,
            )
            assert (
                p.status_code == 201 and p.json()["data"]["validity_days"] == 30
            ), p.text
            pid = p.json()["data"]["id"]
            dup = await c.post(
                f"/api/v1/isp/packages/{pid}/duplicate",
                json={"validity_days": 90, "price_paise": 49900},
                headers=ha,
            )
            assert dup.json()["data"]["name"] == "15 Mbps · Prepaid · 90 days"
            assert (
                await c.delete(f"/api/v1/isp/speed-groups/{gid}", headers=ha)
            ).json()["data"]["code"] == "ISP_GROUP_IN_USE"
            lad = await c.post(
                "/api/v1/isp/packages/ladder",
                json={
                    "speeds_mbps": [10, 15],
                    "validities_days": [30, 90],
                    "prices_paise": {"10:30": 9900},
                },
                headers=ha,
            )
            assert (
                lad.json()["data"]["created_groups"] == 1
                and lad.json()["data"]["created_packages"] == 2
            ), lad.text
            lad2 = await c.post(
                "/api/v1/isp/packages/ladder",
                json={"speeds_mbps": [10, 15], "validities_days": [30, 90]},
                headers=ha,
            )
            assert (
                lad2.json()["data"]["created_packages"] == 0
                and len(lad2.json()["data"]["skipped"]) == 4
            )
            pk = (
                await c.get(
                    "/api/v1/isp/packages",
                    params={"search": "10 Mbps · Prepaid · 90"},
                    headers=ha,
                )
            ).json()["data"]["items"][0]
            assert pk["needs_price"] is True and pk["status"] == "disabled"

            # coupons -------------------------------------------------------------
            r = await c.post(
                "/api/v1/isp/coupon-batches",
                json={
                    "package_id": pid,
                    "isp_customer_id": cust,
                    "isp_location_id": loc,
                    "quantity": 1200,
                },
                headers=ha,
            )
            assert r.status_code == 201, r.text
            batch = r.json()["data"]
            assert batch["counts"]["unused"] == 1200 and batch["quantity"] == 1200
            assert batch["coupon_login_disabled_at_locations"] == [
                {"isp_location_id": loc, "name": "Main"}
            ]
            async with SessionLocal() as s:
                parts = await s.scalar(
                    text(
                        "select count(*) from isp_coupon_batch_parts where coupon_batch_id = :b"
                    ),
                    {"b": uuid.UUID(batch["id"])},
                )
                assert parts == 2
            coupons = (
                await c.get(
                    f"/api/v1/isp/coupon-batches/{batch['id']}/coupons",
                    params={"page_size": 5},
                    headers=ha,
                )
            ).json()["data"]
            assert coupons["total"] == 1200 and coupons["items"][0]["serial"].endswith(
                "-0001"
            )
            first = coupons["items"][0]
            csv_ = await c.get(
                f"/api/v1/isp/coupon-batches/{batch['id']}/export.csv", headers=ha
            )
            assert csv_.text.count("\n") == 1201
            pdf = await c.get(
                f"/api/v1/isp/coupon-batches/{batch['id']}/print.pdf",
                params={"layout": "a4-40"},
                headers=ha,
            )
            assert pdf.content[:4] == b"%PDF"

            # a redemption (as the portal's voucher login records it) ---------------
            now = datetime.now(UTC)
            async with SessionLocal() as s:
                await s.execute(
                    text(
                        "update vouchers set status='active', use_count=1, redeemed_at=:n, redeemed_identifier=:i, expires_at=:e where id=:v"
                    ),
                    {
                        "n": now,
                        "i": "+919000012345",
                        "e": now + timedelta(days=30),
                        "v": uuid.UUID(first["id"]),
                    },
                )
                await s.commit()
            from app.domains.isp_partner import plans_service

            plans_service._last_sync.clear()  # the 60 s sync throttle (spec)
            subs = (await c.get("/api/v1/isp/subscribers", headers=ha)).json()["data"]
            assert subs["total"] == 1
            sub = subs["items"][0]
            assert (
                sub["package"]["id"] == pid
                and sub["speed_group"]["id"] == gid
                and sub["source"] == "coupon"
            )
            assert "12345" in sub["identifier"] and "90000" not in sub["identifier"]
            groups = (await c.get("/api/v1/isp/speed-groups", headers=ha)).json()[
                "data"
            ]["items"]
            g15 = next(x for x in groups if x["id"] == gid)
            assert g15["total_users"] == 1
            # package in use: immutable validity, cannot delete
            assert (
                await c.patch(
                    f"/api/v1/isp/packages/{pid}",
                    json={"validity_days": 60},
                    headers=ha,
                )
            ).json()["data"]["code"] == "ISP_PACKAGE_IN_USE"
            assert (
                await c.delete(f"/api/v1/isp/packages/{pid}", headers=ha)
            ).status_code == 409

            # X1: an ISP coupon session gets the group rate --------------------------
            from app.domains.guest.models import Guest, GuestSession
            from app.domains.isp_partner.rate_limit import (
                IspRateLimitLookup,
                _isp_customer_cache,
            )
            from app.domains.router.models import Router

            async with SessionLocal() as s:
                rt = Router(
                    location_id=uuid.UUID(loc),
                    organization_id=uuid.UUID(cust),
                    name="r",
                    serial_number=f"PS{tag}",
                    mac_address=f"02:03:{tag[:2]}:{tag[2:4]}:{tag[4:6]}:01",
                    model="RB",
                    vendor="mikrotik",
                    status="online",
                    settings={},
                )
                gst = Guest(
                    organization_id=uuid.UUID(cust),
                    location_id=uuid.UUID(loc),
                    identifier="+919000012345",
                    first_seen_at=now,
                    last_seen_at=now,
                )
                s.add_all([rt, gst])
                await s.flush()
                gs = GuestSession(
                    guest_id=gst.id,
                    router_id=rt.id,
                    location_id=uuid.UUID(loc),
                    organization_id=uuid.UUID(cust),
                    auth_method="voucher",
                    status="active",
                    started_at=now,
                    last_activity_at=now,
                    voucher_id=uuid.UUID(first["id"]),
                )
                s.add(gs)
                await s.flush()

                class Inner:
                    repository = type("R", (), {"session": s})()

                    async def rate_limit_reply_for_authorize(self, session_id, **kw):
                        return "INNER"

                _isp_customer_cache.clear()
                os.environ["ISP_PARTNER_ENABLED"] = "true"
                rate = await IspRateLimitLookup(Inner()).rate_limit_reply_for_authorize(
                    gs.id, organization_id=uuid.UUID(cust), location_id=uuid.UUID(loc)
                )
                assert rate is not None and rate.startswith("15360k/15360k"), rate
                # a non-ISP org through the same wrapper: the inner answer
                assert (
                    await IspRateLimitLookup(Inner()).rate_limit_reply_for_authorize(
                        gs.id, organization_id=x_id
                    )
                    == "INNER"
                )
                await s.rollback()

            # group rate edit propagates to the materialized QueueProfile -------------
            await c.patch(
                f"/api/v1/isp/speed-groups/{gid}",
                json={"download_kbps": 20480},
                headers=ha,
            )
            async with SessionLocal() as s:
                rates = (
                    (
                        await s.execute(
                            text(
                                "select q.download_rate_kbps from queue_profiles q join isp_package_materializations m on m.queue_profile_id = q.id where m.customer_organization_id = :c"
                            ),
                            {"c": uuid.UUID(cust)},
                        )
                    )
                    .scalars()
                    .all()
                )
                assert rates and set(rates) == {20480}

            # revoke unused only --------------------------------------------------------
            rv = await c.post(
                f"/api/v1/isp/coupon-batches/{batch['id']}/revoke", headers=ha
            )
            assert (
                rv.json()["data"]["revoked"] == 1199
                and rv.json()["data"]["counts"]["active"] == 1
            )

            # ISP B sees nothing of A -------------------------------------------------
            state["user"] = users["B"]
            for path in (
                f"/api/v1/isp/speed-groups/{gid}",
                f"/api/v1/isp/packages/{pid}",
                f"/api/v1/isp/coupon-batches/{batch['id']}",
                f"/api/v1/isp/subscribers/{sub['id']}",
            ):
                assert (await c.get(path, headers=hb)).status_code == 404, path
            assert (
                await c.post(f"/api/v1/isp/coupons/{first['id']}/revoke", headers=hb)
            ).status_code == 404
            assert (await c.get("/api/v1/isp/speed-groups", headers=hb)).json()["data"][
                "total"
            ] == 0
            state["user"] = users["A"]

        # nothing was created in any non-ISP org
        assert await per_org_counts([x_id]) == before
    finally:
        await engine.dispose()
        # the app-global redis client pools sockets bound to this test's loop
        from app.database.redis import redis_client

        await redis_client.connection_pool.disconnect()
