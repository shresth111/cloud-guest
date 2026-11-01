# ruff: noqa: E501 -- test helper
"""Shared setup for the SMALL-n PostgreSQL scenario tests (two ISPs, A and B,
each with an isp-owner user, plus extra users on A with other roles).

Only imported from ``test_isp_small*_postgres.py`` files, which skip unless
``ISP_TEST_PG_DSN`` is set.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from fastapi import Request


@dataclass
class World:
    tag: str
    isps: dict[str, uuid.UUID]
    users: dict[str, uuid.UUID]
    app: Any
    api: str = "/api/v1/isp"
    # header sets: "A", "B" (owners) and any extra user key on A
    headers: dict[str, dict[str, str]] = field(default_factory=dict)


async def make_world(
    extra_users_on_a: dict[str, str] | None = None,
) -> World:
    """Seed RBAC, create ISPs A and B with owners, and the app with a
    ``CurrentUser`` override that picks the user from ``X-Test-User``
    (default: the owner of the ``X-Organization-Id`` ISP).

    ``extra_users_on_a`` maps a key to a role slug (e.g. ``{"tech":
    "isp-technician"}``); those users get the role on ISP A.
    """
    from sqlalchemy import select

    from app.database.session import SessionLocal
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
    async with SessionLocal() as s:
        await seed_rbac(s)
        await seed_isp_partner_rbac(RBACRepository(s))
        await s.commit()
    users: dict[str, uuid.UUID] = {}
    isps: dict[str, uuid.UUID] = {}
    async with SessionLocal() as s:
        plan = Plan(
            name=f"P {tag}",
            slug=f"psm-{tag}",
            plan_type="standard",
            billing_cycle="monthly",
            base_price=Decimal("0"),
            currency="INR",
            is_active=True,
            is_public=False,
        )
        s.add(plan)

        async def role_id(slug: str) -> uuid.UUID:
            return (
                await s.execute(select(Role.id).where(Role.slug == slug))
            ).scalar_one()

        async def add_user(key: str, org_id: uuid.UUID, slug: str) -> None:
            u = User(
                first_name=key,
                last_name="T",
                email=f"sm{key}{tag}@example.com",
                username=f"sm{key}{tag}",
                password_hash="x",
                is_active=True,
                is_verified=True,
            )
            s.add(u)
            await s.flush()
            s.add(
                OrganizationMember(
                    organization_id=org_id, user_id=u.id, status="active"
                )
            )
            s.add(
                UserRole(
                    user_id=u.id,
                    role_id=await role_id(slug),
                    scope_type="organization",
                    organization_id=org_id,
                    granted_at=datetime.now(UTC),
                    is_active=True,
                )
            )
            users[key] = u.id

        for n in ("A", "B"):
            org = Organization(
                name=f"Net {n} {tag}",
                slug=f"sm{n.lower()}{tag}",
                org_type="msp",
                status="active",
                contact_email=f"sm{n}{tag}@example.com",
                timezone="Asia/Kolkata",
                settings={},
            )
            s.add(org)
            await s.flush()
            await s.flush()
            s.add(
                IspPartnerProfile(
                    organization_id=org.id, default_customer_plan_id=plan.id
                )
            )
            isps[n] = org.id
            await add_user(n, org.id, "isp-owner")
        for key, slug in (extra_users_on_a or {}).items():
            await add_user(key, isps["A"], slug)
        await s.commit()

    app = create_app()

    def _user(request: Request) -> AuthUser:
        who = request.headers.get("X-Test-User")
        if not who:
            org = request.headers.get("X-Organization-Id")
            who = "B" if org == str(isps["B"]) else "A"
        return AuthUser(id=str(users[who]), email="o@example.com")

    app.dependency_overrides[CurrentUser] = _user
    w = World(tag=tag, isps=isps, users=users, app=app)
    w.headers = {
        "A": {"X-Organization-Id": str(isps["A"])},
        "B": {"X-Organization-Id": str(isps["B"])},
    }
    for key in extra_users_on_a or {}:
        w.headers[key] = {"X-Organization-Id": str(isps["A"]), "X-Test-User": key}
    return w


async def dispose() -> None:
    from app.database.redis import redis_client
    from app.database.session import engine

    await engine.dispose()
    await redis_client.connection_pool.disconnect()


class Api:
    """Thin JSON helper over an httpx client."""

    def __init__(self, client: Any, w: World) -> None:
        self.c = client
        self.w = w

    async def call(
        self,
        method: str,
        path: str,
        body: Any = None,
        *,
        who: str = "A",
        code: int | tuple[int, ...] = 200,
        params: dict | None = None,
    ) -> Any:
        r = await self.c.request(
            method,
            f"{self.w.api}{path}",
            json=body,
            params=params,
            headers=self.w.headers[who],
        )
        codes = code if isinstance(code, tuple) else (code,)
        assert r.status_code in codes, (method, path, r.status_code, r.text[:600])
        js = (
            r.json()
            if r.headers.get("content-type", "").startswith("application/json")
            else None
        )
        if (
            js is not None
            and r.status_code < 300
            and isinstance(js, dict)
            and "data" in js
        ):
            return js["data"]
        return js

    async def get(self, path: str, **kw: Any) -> Any:
        return await self.call("GET", path, **kw)

    async def post(self, path: str, body: Any = None, **kw: Any) -> Any:
        kw.setdefault("code", (200, 201))
        return await self.call("POST", path, body, **kw)

    async def put(self, path: str, body: Any = None, **kw: Any) -> Any:
        return await self.call("PUT", path, body, **kw)

    async def patch(self, path: str, body: Any = None, **kw: Any) -> Any:
        return await self.call("PATCH", path, body, **kw)


async def billing_setup(
    api: Api, who: str, *, state: str = "07", gst: bool = True
) -> None:
    await api.put(
        "/billing/settings",
        {
            "legal_name": "Net",
            "state_code": state,
            "gst_enabled": gst,
            "invoice_prefix": f"SM{who}",
        },
        who=who,
    )


async def customer(api: Api, who: str, name: str) -> str:
    return (
        await api.post(
            "/customers",
            {
                "name": f"{name} {api.w.tag}",
                "contact_email": f"{name.lower()}{api.w.tag}@example.com",
            },
            who=who,
        )
    )["id"]


async def package(
    api: Api, who: str, *, price: int, incl: bool = False, name: str | None = None
) -> str:
    gid = (
        await api.post(
            "/speed-groups",
            {
                "name": f"G{price}{name or ''}",
                "download_kbps": 8192,
                "upload_kbps": 8192,
            },
            who=who,
        )
    )["id"]
    body = {
        "speed_group_id": gid,
        "type": "prepaid",
        "validity_days": 30,
        "price_paise": price,
        "price_includes_gst": incl,
    }
    if name:
        body["name"] = name
    return (await api.post("/packages", body, who=who))["id"]


async def subscriber(
    api: Api, who: str, cust: str, pkg: str, ident: str, *, state: str = "07"
) -> str:
    return (
        await api.post(
            "/subscribers",
            {
                "isp_customer_id": cust,
                "identifier": f"{ident}{api.w.tag}",
                "package_id": pkg,
                "first_name": ident,
                "state_code": state,
            },
            who=who,
        )
    )["id"]
