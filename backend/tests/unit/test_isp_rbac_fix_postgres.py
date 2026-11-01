# ruff: noqa: E501, PLR0915 -- scenario test
"""RBAC-FIX (founder 2026-11-01, QA R1-R3) on real PostgreSQL + Redis.

Full role matrix, one ISP, two customers; the technician is confined to the
second. Feature flags are switched on so each answer is the permission
check, not a "feature off" 404.

| action          | owner admin noc tech billing viewer |
| disconnect (x2) |  Y     Y    Y   Y*   N       N      |
| GSTR-1          |  Y     Y    N   N    Y       N      |
| CAF detail+PDF  |  Y     Y    N   Y*   Y       N      |
| KYC read        |  Y     Y    N   Y*   Y       N      |

Y = not 401/403/404, N = 403, * = only for its own customer (404 outside).
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

ROLES = ("owner", "admin", "noc", "technician", "billing", "viewer")
ALLOW = {
    "disconnect": {"owner", "admin", "noc", "technician"},
    "gstr1": {"owner", "admin", "billing"},
    "caf": {"owner", "admin", "technician", "billing"},
    "kyc": {"owner", "admin", "technician", "billing"},
}


async def test_rbac_fix_role_matrix(monkeypatch) -> None:  # noqa: ANN001
    import httpx
    from sqlalchemy import select

    from app.database.session import SessionLocal, engine
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.isp_partner import bill2_config, caf_service, workbench_router
    from app.domains.isp_partner.models import IspPartnerProfile, IspStaffCustomerScope
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
    monkeypatch.setattr(
        caf_service,
        "get_isp_caf_settings",
        lambda: caf_service.IspCafSettings(enabled=True),
    )
    monkeypatch.setattr(
        workbench_router,
        "get_workbench_settings",
        lambda: workbench_router.IspWorkbenchSettings(sub360_workbench_enabled=True),
    )
    tag = uuid.uuid4().hex[:8]
    try:
        async with SessionLocal() as s:
            await seed_rbac(s)
            await seed_isp_partner_rbac(RBACRepository(s))
            await s.commit()
        users: dict[str, uuid.UUID] = {}
        async with SessionLocal() as s:
            plan = Plan(
                name=f"P {tag}",
                slug=f"prb-{tag}",
                plan_type="standard",
                billing_cycle="monthly",
                base_price=Decimal("0"),
                currency="INR",
                is_active=True,
                is_public=False,
            )
            s.add(plan)
            isp = Organization(
                name=f"Net {tag}",
                slug=f"rb{tag}",
                org_type="msp",
                status="active",
                contact_email=f"rb{tag}@example.com",
                timezone="Asia/Kolkata",
                settings={},
            )
            s.add(isp)
            await s.flush()
            s.add(
                IspPartnerProfile(
                    organization_id=isp.id, default_customer_plan_id=plan.id
                )
            )
            for name in ROLES:
                role = (
                    await s.execute(select(Role).where(Role.slug == f"isp-{name}"))
                ).scalar_one()
                u = User(
                    first_name=name,
                    last_name="R",
                    email=f"rb{name}{tag}@example.com",
                    username=f"rb{name}{tag}",
                    password_hash="x",
                    is_active=True,
                    is_verified=True,
                )
                s.add(u)
                await s.flush()
                s.add(
                    OrganizationMember(
                        organization_id=isp.id, user_id=u.id, status="active"
                    )
                )
                s.add(
                    UserRole(
                        user_id=u.id,
                        role_id=role.id,
                        scope_type="organization",
                        organization_id=isp.id,
                        granted_at=datetime.now(UTC),
                        is_active=True,
                    )
                )
                users[name] = u.id
            await s.commit()
            isp_id = isp.id

        app = create_app()
        state = {"user": users["owner"]}

        def _user(request: Request) -> AuthUser:  # noqa: ARG001
            return AuthUser(id=str(state["user"]), email="o@example.com")

        app.dependency_overrides[CurrentUser] = _user
        h = {"X-Organization-Id": str(isp_id)}
        month = datetime.now(UTC).strftime("%Y-%m")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t"
        ) as c:
            assert (
                await c.put(
                    "/api/v1/isp/billing/settings",
                    json={
                        "legal_name": "Net",
                        "state_code": "07",
                        "gst_enabled": True,
                        "invoice_prefix": "RBF",
                    },
                    headers=h,
                )
            ).status_code == 200
            custs = []
            for n in (1, 2):
                r = await c.post(
                    "/api/v1/isp/customers",
                    json={
                        "name": f"Cafe {n} {tag}",
                        "contact_email": f"c{n}{tag}@example.com",
                    },
                    headers=h,
                )
                assert r.status_code == 201, r.text
                custs.append(r.json()["data"]["id"])
            gid = (
                await c.post(
                    "/api/v1/isp/speed-groups",
                    json={"name": "5 Mbps", "download_kbps": 5120, "upload_kbps": 5120},
                    headers=h,
                )
            ).json()["data"]["id"]
            pkg = (
                await c.post(
                    "/api/v1/isp/packages",
                    json={
                        "speed_group_id": gid,
                        "type": "prepaid",
                        "price_paise": 30000,
                    },
                    headers=h,
                )
            ).json()["data"]["id"]
            subs = []
            for i, cust in enumerate(custs):
                r = await c.post(
                    "/api/v1/isp/subscribers",
                    json={
                        "isp_customer_id": cust,
                        "identifier": f"rb{i}{tag}",
                        "package_id": pkg,
                        "first_name": f"S{i}",
                        "state_code": "07",
                    },
                    headers=h,
                )
                assert r.status_code == 201, r.text
                subs.append(r.json()["data"]["id"])
        # the technician covers customer 2 only
        async with SessionLocal() as s:
            s.add(
                IspStaffCustomerScope(
                    isp_organization_id=isp_id,
                    user_id=users["technician"],
                    customer_organization_id=uuid.UUID(custs[1]),
                )
            )
            await s.commit()

        own, other = subs[1], subs[0]  # "own" = inside the technician's scope

        def calls(sub: str) -> dict[str, list[tuple[str, str, dict | None]]]:
            return {
                "disconnect": [
                    ("POST", f"/api/v1/isp/subscribers/{sub}/disconnect", None),
                    ("POST", f"/api/v1/isp/subscribers/{sub}/workbench/disconnect", {}),
                ],
                "gstr1": [
                    ("GET", f"/api/v1/isp/gst/gstr1?month={month}&format=json", None)
                ],
                "caf": [
                    ("GET", f"/api/v1/isp/caf/subscribers/{sub}", None),
                    ("GET", f"/api/v1/isp/caf/subscribers/{sub}/caf.pdf", None),
                ],
                "kyc": [("GET", f"/api/v1/isp/compliance/subscribers/{sub}/kyc", None)],
            }

        failures: list[str] = []
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t"
        ) as c:
            for role in ROLES:
                state["user"] = users[role]
                for action, reqs in calls(own).items():
                    for method, url, body in reqs:
                        r = await c.request(method, url, json=body, headers=h)
                        allowed = role in ALLOW[action]
                        ok = (
                            (r.status_code not in (401, 403, 404))
                            if allowed
                            else r.status_code == 403
                        )
                        if not ok:
                            failures.append(
                                f"{role} {action} {method} {url.split('/api/v1/isp')[1]} -> {r.status_code} {r.text[:120]}"
                            )
                # confinement: the technician gets 404 on the other customer's
                # subscriber for every per-subscriber action it holds a key for
                if role == "technician":
                    for action in ("disconnect", "caf", "kyc"):
                        for method, url, body in calls(other)[action]:
                            r = await c.request(method, url, json=body, headers=h)
                            if r.status_code != 404:
                                failures.append(
                                    f"technician {action} OUTSIDE scope {url.split('/api/v1/isp')[1]} -> {r.status_code}"
                                )
        assert not failures, "\n".join(failures)
    finally:
        await engine.dispose()
        from app.database.redis import redis_client

        await redis_client.connection_pool.disconnect()
