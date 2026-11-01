# ruff: noqa: E501, PLR0915 -- scenario test
"""DIR-2 on real PostgreSQL + Redis (skipped unless ``ISP_TEST_PG_DSN``).

Flag off -> 404. Export (CSV + XLSX) follows the directory filters. Bulk:
dry run changes nothing and reports skips; apply blocks the eligible ones
and skips the already-blocked one; bulk renew is idempotent per bulk_key
(a retried batch adds no invoice); bulk move by filter; ISP B's ids are
"not_found" for ISP A and A's subscribers are invisible to B.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from decimal import Decimal

import pytest
from fastapi import Request

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)


async def test_dir2_end_to_end(monkeypatch) -> None:  # noqa: ANN001
    import httpx
    from sqlalchemy import func, select

    from app.database.session import SessionLocal, engine
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.isp_partner import directory_bulk_router as dbr
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
        dbr, "get_dir2_settings", lambda: dbr.IspDir2Settings(enabled=flag["on"])
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
                slug=f"pd2-{tag}",
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
                    slug=f"d2{n.lower()}{tag}",
                    org_type="msp",
                    status="active",
                    contact_email=f"{n}{tag}@example.com",
                    timezone="Asia/Kolkata",
                    settings={},
                )
                u = User(
                    first_name=n,
                    last_name="O",
                    email=f"d2{n}{tag}@example.com",
                    username=f"d2{n}{tag}",
                    password_hash="x",
                    is_active=True,
                    is_verified=True,
                )
                s.add_all([org, u])
                await s.flush()
                s.add(
                    IspPartnerProfile(
                        organization_id=org.id, default_customer_plan_id=plan.id
                    )
                )
                s.add(
                    OrganizationMember(
                        organization_id=org.id, user_id=u.id, status="active"
                    )
                )
                s.add(
                    UserRole(
                        user_id=u.id,
                        role_id=role.id,
                        scope_type="organization",
                        organization_id=org.id,
                        granted_at=datetime.now(UTC),
                        is_active=True,
                    )
                )
                users[n], isps[n] = u.id, org.id
            await s.commit()

        app = create_app()

        def _user(request: Request) -> AuthUser:
            org = request.headers.get("X-Organization-Id")
            return AuthUser(
                id=str(users["B"] if org == str(isps["B"]) else users["A"]),
                email="o@example.com",
            )

        app.dependency_overrides[CurrentUser] = _user
        ha = {"X-Organization-Id": str(isps["A"])}
        hb = {"X-Organization-Id": str(isps["B"])}
        api = "/api/v1/isp"
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t"
        ) as c:

            async def setup(h, n):
                assert (
                    await c.put(
                        f"{api}/billing/settings",
                        json={
                            "legal_name": "Net",
                            "state_code": "07",
                            "gst_enabled": True,
                            "invoice_prefix": f"D2{n.upper()}",
                        },
                        headers=h,
                    )
                ).status_code == 200
                custs = [
                    (
                        await c.post(
                            f"{api}/customers",
                            json={
                                "name": f"Cafe {n}{i} {tag}",
                                "contact_email": f"c{n}{i}{tag}@example.com",
                            },
                            headers=h,
                        )
                    ).json()["data"]["id"]
                    for i in (1, 2)
                ]
                gid = (
                    await c.post(
                        f"{api}/speed-groups",
                        json={
                            "name": "8 Mbps",
                            "download_kbps": 8192,
                            "upload_kbps": 8192,
                        },
                        headers=h,
                    )
                ).json()["data"]["id"]
                pkg = (
                    await c.post(
                        f"{api}/packages",
                        json={
                            "speed_group_id": gid,
                            "type": "prepaid",
                            "price_paise": 25000,
                        },
                        headers=h,
                    )
                ).json()["data"]["id"]
                subs = []
                for i in range(4):
                    r = await c.post(
                        f"{api}/subscribers",
                        json={
                            "isp_customer_id": custs[0],
                            "identifier": f"d2{n}{i}{tag}",
                            "package_id": pkg,
                            "first_name": f"Sub{i}",
                            "state_code": "07",
                        },
                        headers=h,
                    )
                    assert r.status_code == 201, r.text
                    subs.append(r.json()["data"]["id"])
                return custs, subs

            custs, subs = await setup(ha, "a")
            _, subs_b = await setup(hb, "b")

            # flag off
            assert (
                await c.get(f"{api}/subscriber-directory/export", headers=ha)
            ).status_code == 404
            assert (
                await c.post(
                    f"{api}/subscriber-bulk/status",
                    json={"action": "block", "subscriber_ids": subs},
                    headers=ha,
                )
            ).status_code == 404
            flag["on"] = True

            # export follows the filter
            csv = await c.get(
                f"{api}/subscriber-directory/export?search=d2a{tag[:0]}", headers=ha
            )
            assert csv.status_code == 200 and csv.text.startswith(
                "Subscriber ID,Circuit ID"
            )
            assert (
                all(f"d2a{i}{tag}" in csv.text for i in range(4))
                and f"d2b0{tag}" not in csv.text
            )
            one = await c.get(
                f"{api}/subscriber-directory/export?search=d2a1{tag}", headers=ha
            )
            assert one.text.count("\n") == 2  # header + 1 row
            xlsx = await c.get(
                f"{api}/subscriber-directory/export?format=xlsx", headers=ha
            )
            assert xlsx.status_code == 200 and xlsx.content[:2] == b"PK"

            # pre-block one so the bulk run has a skip
            assert (
                await c.post(
                    f"{api}/subscribers/{subs[0]}/block",
                    json={"kind": "temporary"},
                    headers=ha,
                )
            ).status_code == 200
            body = {
                "action": "block",
                "subscriber_ids": [*subs, subs_b[0]],
                "reason": "maintenance",
            }
            dry = (
                await c.post(f"{api}/subscriber-bulk/status", json=body, headers=ha)
            ).json()["data"]
            assert (
                dry["dry_run"] is True and dry["matched"] == 5 and dry["eligible"] == 3
            )
            reasons = {x["id"]: x["reason"] for x in dry["skipped"]}
            assert reasons == {subs[0]: "already_blocked", subs_b[0]: "not_found"}
            # nothing changed by the dry run
            v = (await c.get(f"{api}/subscribers/{subs[1]}/360", headers=ha)).json()[
                "data"
            ]
            assert v["display_state"] != "blocked"
            r = await c.post(
                f"{api}/subscriber-bulk/status",
                json={**body, "dry_run": False},
                headers=ha,
            )
            assert r.status_code == 422  # apply needs a bulk_key
            res = (
                await c.post(
                    f"{api}/subscriber-bulk/status",
                    json={**body, "dry_run": False, "bulk_key": f"blk-{tag}"},
                    headers=ha,
                )
            ).json()["data"]
            assert res["applied"] == 3 and res["failed"] == []
            for sid in subs[1:]:
                assert (await c.get(f"{api}/subscribers/{sid}/360", headers=ha)).json()[
                    "data"
                ]["display_state"] == "blocked"
            # B's subscriber untouched
            assert (
                await c.get(f"{api}/subscribers/{subs_b[0]}/360", headers=hb)
            ).json()["data"]["display_state"] != "blocked"
            # unblock them all again by filter
            res = (
                await c.post(
                    f"{api}/subscriber-bulk/status",
                    json={
                        "action": "unblock",
                        "filter": {"search": tag},
                        "dry_run": False,
                        "bulk_key": f"ubl-{tag}",
                    },
                    headers=ha,
                )
            ).json()["data"]
            assert res["matched"] == 4 and res["applied"] == 4

            # bulk renew: idempotent per bulk_key
            async def invoices():
                async with SessionLocal() as s:
                    return await s.scalar(
                        select(func.count())
                        .select_from(IspInvoice)
                        .where(
                            IspInvoice.isp_organization_id == isps["A"],
                            IspInvoice.invoice_kind == "recharge",
                        )
                    )

            before = await invoices()
            rb = {
                "subscriber_ids": subs[:2],
                "dry_run": False,
                "bulk_key": f"rnw-{tag}",
            }
            res = (
                await c.post(f"{api}/subscriber-bulk/renew", json=rb, headers=ha)
            ).json()["data"]
            assert res["applied"] == 2, res
            assert await invoices() == before + 2
            res = (
                await c.post(f"{api}/subscriber-bulk/renew", json=rb, headers=ha)
            ).json()["data"]
            assert (
                res["applied"] == 2 and await invoices() == before + 2
            )  # replay: no new invoice

            # bulk move by filter to customer 2, then the directory agrees
            mv = {"filter": {"search": f"d2a3{tag}"}, "isp_customer_id": custs[1]}
            dry = (
                await c.post(f"{api}/subscriber-bulk/move", json=mv, headers=ha)
            ).json()["data"]
            assert dry["eligible"] == 1
            res = (
                await c.post(
                    f"{api}/subscriber-bulk/move",
                    json={**mv, "dry_run": False, "bulk_key": f"mov-{tag}"},
                    headers=ha,
                )
            ).json()["data"]
            assert res["applied"] == 1
            d = (
                await c.get(
                    f"{api}/subscribers/directory?isp_customer_id={custs[1]}",
                    headers=ha,
                )
            ).json()["data"]
            assert [x["identifier"] for x in d["items"]] == [f"d2a3{tag}"]
            # moving to another ISP's customer is a 404
            assert (
                await c.post(
                    f"{api}/subscriber-bulk/move",
                    json={**mv, "isp_customer_id": str(uuid.uuid4())},
                    headers=ha,
                )
            ).status_code == 404
    finally:
        await engine.dispose()
        from app.database.redis import redis_client

        await redis_client.connection_pool.disconnect()
