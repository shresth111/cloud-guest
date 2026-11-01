"""AUDIT-LOG on real PostgreSQL + Redis (skipped unless ``ISP_TEST_PG_DSN``).

Covers: an audit row written outside ``/isp`` is byte-identical with and
without the listener registered; ISP actions get the request IP from the
trusted client address (a spoofed X-Forwarded-For is ignored); the
ContextVar is empty again after a real request (rows written afterwards get
no IP); flag off = 404 and no IP captured; sign-ins with their recorded IP;
owner/admin only (technician 403); filters; CSV export (audited); another ISP
sees none of it and 404s on A's customer filter.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from decimal import Decimal

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)


async def test_audit_log_end_to_end() -> None:  # noqa: PLR0915
    import httpx
    from sqlalchemy import select

    from app.database.session import SessionLocal, engine
    from app.domains.auth.models import AuthUser, LoginAttempt, User
    from app.domains.billing.models import Plan
    from app.domains.isp_partner import audit_ip
    from app.domains.isp_partner.audit_log_config import get_audit_log_settings
    from app.domains.isp_partner.models import IspPartnerProfile
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.organization.models import Organization, OrganizationMember
    from app.domains.rbac.dependencies import CurrentUser
    from app.domains.rbac.models import AuditLogEntry, Role, UserRole
    from app.domains.rbac.repository import RBACRepository
    from app.domains.rbac.seed import seed_rbac
    from app.main import create_app

    tag = uuid.uuid4().hex[:8]
    os.environ.pop("ISP_AUDIT_LOG_ENABLED", None)
    get_audit_log_settings.cache_clear()

    async def write_plain(meta: dict) -> AuditLogEntry:
        async with SessionLocal() as s:
            row = await RBACRepository(s).create_audit_log_entry(
                actor_user_id=None,
                action="tenant_thing",
                entity_type="thing",
                entity_id=None,
                description="regular tenant action",
                event_metadata=dict(meta),
                organization_id=None,
                location_id=None,
            )
            await s.commit()
            got = await s.get(AuditLogEntry, row.id)
            await s.refresh(got)
            return got

    try:
        # -- 1. outside /isp the listener changes nothing ----------------------
        os.environ["ISP_AUDIT_LOG_ENABLED"] = "true"  # even with the flag on
        get_audit_log_settings.cache_clear()
        meta = {"console": "customer", "nested": {"a": [1, 2]}, "n": 3}
        with_listener = await write_plain(meta)
        audit_ip.unregister()
        try:
            without = await write_plain(meta)
        finally:
            audit_ip.register()

        def shape(r: AuditLogEntry) -> tuple:
            return (
                r.actor_user_id,
                r.action,
                r.entity_type,
                r.entity_id,
                r.description,
                r.event_metadata,
                r.organization_id,
                r.location_id,
            )

        assert shape(with_listener) == shape(without)
        assert with_listener.event_metadata == meta
        os.environ.pop("ISP_AUDIT_LOG_ENABLED")
        get_audit_log_settings.cache_clear()

        # -- setup ---------------------------------------------------------------
        async with SessionLocal() as s:
            await seed_rbac(s)
            await seed_isp_partner_rbac(RBACRepository(s))
            await s.commit()
        users, isps = {}, {}
        async with SessionLocal() as s:
            plan = Plan(
                name=f"P {tag}",
                slug=f"au-{tag}",
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
                            Role.slug.in_(("isp-owner", "isp-admin", "isp-technician"))
                        )
                    )
                ).scalars()
            }

            def person(n: str) -> User:
                return User(
                    first_name=n,
                    last_name="U",
                    email=f"au{n.lower()}{tag}@example.com",
                    username=f"au{n.lower()}{tag}",
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
                    name=f"Au {n} {tag}",
                    slug=f"aunet{n.lower()}{tag}",
                    org_type="msp",
                    status="active",
                    contact_email=f"au{n}{tag}@example.com",
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
                    for who, slug in (("Adm", "isp-admin"), ("Tech", "isp-technician")):
                        u = person(who)
                        s.add(u)
                        await s.flush()
                        s.add_all(grant(u, org, slug))
                        users[who] = u.id
            s.add(
                LoginAttempt(
                    user_id=users["A"],
                    email=f"aua{tag}@example.com",
                    ip_address="198.51.100.2",
                    user_agent="pytest",
                    success=True,
                )
            )
            await s.commit()

        app = create_app()
        state = {"user": users["A"]}
        app.dependency_overrides[CurrentUser] = lambda: AuthUser(
            id=str(state["user"]), email="o@example.com"
        )
        ha = {"X-Organization-Id": str(isps["A"]), "X-Forwarded-For": "9.9.9.9"}
        hb = {"X-Organization-Id": str(isps["B"])}
        api = "/api/v1/isp"

        def as_(who: str) -> None:
            state["user"] = users[who]

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, client=("203.0.113.7", 4321)),
            base_url="http://t",
        ) as c:

            async def call(method: str, path: str, body=None, h=ha, ok=(200, 201)):  # noqa: ANN001, ANN202
                r = await c.request(method, f"{api}{path}", json=body, headers=h)
                assert r.status_code in ok, (method, path, r.status_code, r.text)
                return (
                    r
                    if "csv" in r.headers.get("content-type", "")
                    else r.json()["data"]
                )

            async def status(method: str, path: str, h=ha) -> int:
                return (await c.request(method, f"{api}{path}", headers=h)).status_code

            # flag off: 404, and an ISP action records no IP
            assert await status("GET", "/audit-log") == 404
            off = (
                await call(
                    "POST",
                    "/customers",
                    {"name": f"off {tag}", "contact_email": f"off{tag}@e.com"},
                )
            )["id"]
            os.environ["ISP_AUDIT_LOG_ENABLED"] = "true"
            get_audit_log_settings.cache_clear()

            c1 = (
                await call(
                    "POST",
                    "/customers",
                    {"name": f"c1 {tag}", "contact_email": f"c1{tag}@e.com"},
                )
            )["id"]
            as_("Adm")
            c2 = (
                await call(
                    "POST",
                    "/customers",
                    {"name": f"c2 {tag}", "contact_email": f"c2{tag}@e.com"},
                )
            )["id"]
            as_("A")
            # nothing leaked out of the request into this context
            assert audit_ip.current_request_ip() is None
            after = await write_plain({"console": "customer"})
            assert "ip" not in after.event_metadata

            data = await call("GET", "/audit-log?source=actions")
            created = [
                i
                for i in data["items"]
                if i["action"] == "isp_customer_created"
                and i["entity_id"] in (c1, c2, off)
            ]
            by_entity = {i["entity_id"]: i for i in created}
            assert by_entity[c1]["ip"] == "203.0.113.7"  # not the spoofed header
            assert by_entity[c2]["actor"]["role"] == "isp-admin"
            assert by_entity[off]["ip"] is None and not by_entity[off]["ip_recorded"]
            # sign-ins come with the auth code's IP
            si = await call("GET", "/audit-log?source=sign_ins")
            assert si["items"][0]["ip"] == "198.51.100.2"
            assert si["items"][0]["action"] == "sign_in"
            # filters
            mine = await call("GET", f"/audit-log?isp_user_id={users['Adm']}")
            assert mine["items"] and all(
                i["actor"]["isp_user_id"] == str(users["Adm"]) for i in mine["items"]
            )
            assert (
                await call(
                    "GET", "/audit-log?action=isp_customer_created&source=actions"
                )
            )["total"] >= 3
            assert (await call("GET", "/audit-log?search=203.0.113.7"))["total"] >= 2
            assert (await call("GET", "/audit-log?since=2000-01-01&until=2000-01-02"))[
                "total"
            ] == 0
            assert (
                await status("GET", "/audit-log?since=2026-11-02&until=2026-11-01")
                == 422
            )
            fac = await call("GET", "/audit-log/facets")
            assert "isp_customer_created" in {a["action"] for a in fac["actions"]}
            assert {p["role"] for p in fac["staff"]} >= {"isp-owner", "isp-admin"}
            # CSV export, audited
            r = await call("GET", "/audit-log/export.csv")
            assert "203.0.113.7" in r.text and r.headers["x-row-count"] != "0"
            async with SessionLocal() as s:
                exp = (
                    await s.execute(
                        select(AuditLogEntry).where(
                            AuditLogEntry.action == "isp_audit_log_exported",
                            AuditLogEntry.actor_user_id == users["A"],
                        )
                    )
                ).scalar_one()
                assert exp.event_metadata["ip"] == "203.0.113.7"

            # owner/admin only
            as_("Tech")
            assert await status("GET", "/audit-log") == 403
            assert await status("GET", "/audit-log/export.csv") == 403
            as_("A")

            # another ISP sees none of A's rows
            as_("B")
            b = await call("GET", "/audit-log", h=hb)
            assert not any(i["entity_id"] in (c1, c2) for i in b["items"]) and all(
                (i["actor"] or {}).get("isp_user_id") != str(users["A"])
                for i in b["items"]
            )
            assert await status("GET", f"/audit-log?isp_customer_id={c1}", h=hb) == 404
            assert (await call("GET", f"/audit-log?isp_user_id={users['A']}", h=hb))[
                "total"
            ] == 0
            as_("A")
            assert audit_ip.current_request_ip() is None
    finally:
        os.environ.pop("ISP_AUDIT_LOG_ENABLED", None)
        get_audit_log_settings.cache_clear()
        audit_ip.register()
        await engine.dispose()
