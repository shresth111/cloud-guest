"""INCIDENTS-1 on real PostgreSQL + Redis (skipped unless ``ISP_TEST_PG_DSN``
is set). Fresh scratch DB at head.

Covers: flag off 404; affected from a router (hotspot session), a fiber node
(JAZE-6 downstream) and a zone (ZONE-1 subtree rule); status timeline with
the RFO required to resolve and no going back; grace dry run then apply via
JAZE-1 (once per subscriber, ever); broadcast with automation off = share
links + CSV and nothing logged or sent; with the automation path ready = sent
through JAZE-4 ``_WhatsappRun`` to opted-in subscribers only, deduped; network
health %; a technician confined to c1 sees c1's router incident but 404s on
c2's, and sees only c1's subscribers on a zone incident; another ISP 404s on
every id route.
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


async def test_incidents_end_to_end(monkeypatch) -> None:  # noqa: ANN001, PLR0915
    import httpx
    from sqlalchemy import func, select

    from app.database.session import SessionLocal, engine
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.guest.models import Guest, GuestDevice, GuestSession
    from app.domains.isp_partner import automation, finance_config
    from app.domains.isp_partner.fiber_service import get_isp_fiber_settings
    from app.domains.isp_partner.finance_models import (
        IspAutomationSettings,
        IspMessageLog,
    )
    from app.domains.isp_partner.incidents_config import get_incidents_settings
    from app.domains.isp_partner.models import IspPartnerProfile, IspStaffCustomerScope
    from app.domains.isp_partner.plans_models import IspSubscriber
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.isp_partner.zones_config import get_zones_settings
    from app.domains.organization.models import Organization, OrganizationMember
    from app.domains.rbac.dependencies import CurrentUser
    from app.domains.rbac.models import AuditLogEntry, Role, UserRole
    from app.domains.rbac.repository import RBACRepository
    from app.domains.rbac.seed import seed_rbac
    from app.domains.router.models import Router
    from app.main import create_app

    def clear() -> None:
        get_incidents_settings.cache_clear()
        get_isp_fiber_settings.cache_clear()
        get_zones_settings.cache_clear()

    flags = {"wa": False}

    def fin():  # noqa: ANN202
        return finance_config.IspFinanceSettings(
            finance_extras_enabled=False,
            zone_ledger_enabled=False,
            whatsapp_automation_enabled=flags["wa"],
            telegram_alerts_enabled=False,
        )

    monkeypatch.setattr(finance_config, "get_finance_settings", fin)
    monkeypatch.setattr(automation, "get_finance_settings", fin)
    sent: list[tuple] = []

    class _Res:
        message_id = "wamid.INC"

    class FakeSender:
        async def send_waba_template(self, to, *, template_name, language, parameters):  # noqa: ANN001
            sent.append((to, template_name, list(parameters)))
            return _Res()

    async def _sender(session, isp_org_id):  # noqa: ANN001, ANN202
        return FakeSender() if flags["wa"] else None

    monkeypatch.setattr(automation, "_whatsapp_sender", _sender)

    tag = uuid.uuid4().hex[:8]
    for k in ("ISP_INCIDENTS_ENABLED",):
        os.environ.pop(k, None)
    os.environ["ISP_FIBER_ENABLED"] = "true"
    os.environ["ISP_ZONES_ENABLED"] = "true"
    clear()
    try:
        async with SessionLocal() as s:
            await seed_rbac(s)
            await seed_isp_partner_rbac(RBACRepository(s))
            await s.commit()
        users, isps = {}, {}
        async with SessionLocal() as s:
            plan = Plan(
                name=f"P {tag}",
                slug=f"in-{tag}",
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
                            Role.slug.in_(("isp-owner", "isp-technician", "isp-noc"))
                        )
                    )
                ).scalars()
            }

            def person(n: str) -> User:
                return User(
                    first_name=n,
                    last_name="I",
                    email=f"in{n.lower()}{tag}@example.com",
                    username=f"in{n.lower()}{tag}",
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
                    name=f"In {n} {tag}",
                    slug=f"innet{n.lower()}{tag}",
                    org_type="msp",
                    status="active",
                    contact_email=f"in{n}{tag}@example.com",
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
                    for who, slug in (("Tech", "isp-technician"), ("Noc", "isp-noc")):
                        u = person(who)
                        s.add(u)
                        await s.flush()
                        s.add_all(grant(u, org, slug))
                        users[who] = u.id
            await s.commit()

        app = create_app()
        state = {"user": users["A"]}
        app.dependency_overrides[CurrentUser] = lambda: AuthUser(
            id=str(state["user"]), email="o@example.com"
        )
        ha = {"X-Organization-Id": str(isps["A"])}
        hb = {"X-Organization-Id": str(isps["B"])}
        api = "/api/v1/isp"

        def as_(who: str) -> None:
            state["user"] = users[who]

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t"
        ) as c:

            async def call(method: str, path: str, body=None, h=ha, ok=(200, 201)):  # noqa: ANN001, ANN202
                r = await c.request(method, f"{api}{path}", json=body, headers=h)
                assert r.status_code in ok, (method, path, r.status_code, r.text)
                if "json" in r.headers.get("content-type", ""):
                    return r.json().get("data")
                return r

            async def status(method: str, path: str, body=None, h=ha) -> int:  # noqa: ANN001
                r = await c.request(method, f"{api}{path}", json=body, headers=h)
                return r.status_code

            # -- setup: 2 customers, 1 router each, 3 subscribers -------------
            cust, loc, rtr = {}, {}, {}
            for i, n in enumerate(("c1", "c2")):
                cust[n] = (
                    await call(
                        "POST",
                        "/customers",
                        {"name": f"{n} {tag}", "contact_email": f"{n}{tag}@e.com"},
                    )
                )["id"]
                loc[n] = (
                    await call(
                        "POST",
                        f"/customers/{cust[n]}/locations",
                        {
                            "name": "Main",
                            "address_line1": "1",
                            "city": "c",
                            "state_province": "s",
                            "postal_code": "1",
                        },
                    )
                )["id"]
                rtr[n] = (
                    await call(
                        "POST",
                        f"/locations/{loc[n]}/routers",
                        {
                            "name": f"hEX-{n}",
                            "serial_number": f"IN{n}{tag}",
                            "mac_address": f"02:1{i}:"
                            + ":".join(tag[j : j + 2] for j in (0, 2, 4, 6)),
                            "model": "hEX",
                        },
                    )
                )["id"]
            async with SessionLocal() as s:
                s.add(
                    IspStaffCustomerScope(
                        isp_organization_id=isps["A"],
                        user_id=users["Tech"],
                        customer_organization_id=uuid.UUID(cust["c1"]),
                    )
                )
                await s.commit()
            g = (
                await call(
                    "POST",
                    "/speed-groups",
                    {"name": "10M", "download_kbps": 10240, "upload_kbps": 10240},
                )
            )["id"]
            pkg = (
                await call(
                    "POST",
                    "/packages",
                    {"speed_group_id": g, "type": "prepaid", "price_paise": 10000},
                )
            )["id"]

            async def sub(ident: str, n: str, phone: str) -> str:
                return (
                    await call(
                        "POST",
                        "/subscribers",
                        {
                            "isp_customer_id": cust[n],
                            "identifier": ident,
                            "package_id": pkg,
                            "phone": phone,
                        },
                    )
                )["id"]

            s1 = await sub(f"i1{tag}", "c1", "9876500001")
            s2 = await sub(f"i2{tag}", "c1", "9876500002")
            s3 = await sub(f"i3{tag}", "c2", "9876500003")
            z = (await call("POST", "/zones", {"name": f"IZ {tag}"}))["id"]
            for sid in (s2, s3):
                await call("PATCH", f"/subscribers/{sid}", {"zone_id": z})
            now = datetime.now(UTC)
            async with SessionLocal() as s:
                r1 = await s.get(Router, uuid.UUID(rtr["c1"]))
                r1.status = "online"
                r2 = await s.get(Router, uuid.UUID(rtr["c2"]))
                r2.status = "offline"
                guest = Guest(
                    organization_id=uuid.UUID(cust["c1"]),
                    location_id=uuid.UUID(loc["c1"]),
                    identifier=f"98765{tag[:5]}",
                    first_seen_at=now,
                    last_seen_at=now,
                )
                s.add(guest)
                await s.flush()
                dev = GuestDevice(
                    guest_id=guest.id,
                    mac_address="AA:00:00:" + tag[:2].upper() + ":00:01",
                    first_seen_at=now,
                    last_seen_at=now,
                )
                s.add(dev)
                await s.flush()
                s.add(
                    GuestSession(
                        guest_id=guest.id,
                        device_id=dev.id,
                        router_id=r1.id,
                        location_id=uuid.UUID(loc["c1"]),
                        organization_id=uuid.UUID(cust["c1"]),
                        auth_method="voucher",
                        status="ended",
                        started_at=now - timedelta(hours=3),
                        ended_at=now - timedelta(hours=2),
                        last_activity_at=now,
                        ip_address="10.5.50.20",
                        bytes_downloaded=1,
                        bytes_uploaded=1,
                    )
                )
                s1_row = await s.get(IspSubscriber, uuid.UUID(s1))
                s1_row.guest_id = guest.id
                for sid in (s1, s2, s3):
                    row = await s.get(IspSubscriber, uuid.UUID(sid))
                    row.reminder_opt_in = {"whatsapp": sid != s2}
                await s.commit()
            olt = (
                await call(
                    "POST",
                    "/fiber/nodes",
                    {"kind": "olt", "name": f"OLT{tag}", "port_count": 16},
                )
            )["id"]
            spl = (
                await call(
                    "POST",
                    "/fiber/nodes",
                    {
                        "kind": "splitter",
                        "name": f"SPL{tag}",
                        "parent_id": olt,
                        "parent_port": 1,
                        "port_count": 8,
                    },
                )
            )["id"]
            await call("PUT", f"/fiber/nodes/{spl}/ports/3", {"subscriber_id": s2})

            # -- flag off ----
            assert await status("GET", "/incidents") == 404
            os.environ["ISP_INCIDENTS_ENABLED"] = "true"
            clear()

            # -- affected: router / fiber / zone ------------------------------------
            pv = await call(
                "GET", f"/incidents/preview?scope_kind=router&isp_router_id={rtr['c1']}"
            )
            assert pv["affected_total"] == 1 and pv["sample"][0]["subscriber_id"] == s1
            pv = await call(
                "GET", f"/incidents/preview?scope_kind=fiber_node&fiber_node_id={olt}"
            )
            assert [x["subscriber_id"] for x in pv["sample"]] == [s2]
            pv = await call("GET", f"/incidents/preview?scope_kind=zone&zone_id={z}")
            assert {x["subscriber_id"] for x in pv["sample"]} == {s2, s3}
            assert (
                await status(
                    "GET",
                    f"/incidents/preview?scope_kind=router&isp_router_id={rtr['c1']}&zone_id={z}",
                )
                == 422
            )

            started = (now - timedelta(hours=2)).isoformat()
            ir = await call(
                "POST",
                "/incidents",
                {
                    "scope_kind": "router",
                    "isp_router_id": rtr["c1"],
                    "started_at": started,
                    "note": "Router not responding",
                },
            )
            assert ir["code"] == "INC-00001" and ir["affected_total"] == 1
            assert ir["status"] == "investigating"
            iz = await call(
                "POST",
                "/incidents",
                {"scope_kind": "zone", "zone_id": z, "severity": "minor"},
            )
            assert iz["number"] == 2 and iz["affected_total"] == 2
            ic2 = await call(
                "POST",
                "/incidents",
                {"scope_kind": "router", "isp_router_id": rtr["c2"]},
            )

            # -- status timeline + RFO ------------------------------------------------
            await call(
                "POST",
                f"/incidents/{ir['id']}/status",
                {"status": "identified", "note": "PSU"},
            )
            assert (
                await status(
                    "POST", f"/incidents/{ir['id']}/status", {"status": "resolved"}
                )
                == 422
            )
            done = await call(
                "POST",
                f"/incidents/{ir['id']}/status",
                {
                    "status": "resolved",
                    "rfo_reason": "power_olt",
                    "rfo_note": "PSU swapped",
                },
            )
            assert done["status"] == "resolved" and done["rfo_label"] == "Power / OLT"
            assert [e["kind"] for e in done["events"]] == [
                "created",
                "status",
                "status",
            ]
            assert done["suggested_grace_hours"] in (2, 3)
            assert (
                await status(
                    "POST", f"/incidents/{ir['id']}/status", {"status": "identified"}
                )
                == 409
            )

            # -- grace: only once resolved, dry run first, once per subscriber --
            assert (
                await status(
                    "POST",
                    f"/incidents/{iz['id']}/grace",
                    {"hours": 2, "dry_run": True},
                )
                == 409
            )
            async with SessionLocal() as s:
                before = (await s.get(IspSubscriber, uuid.UUID(s1))).valid_until
            dry = await call(
                "POST", f"/incidents/{ir['id']}/grace", {"hours": 3, "dry_run": True}
            )
            assert dry["eligible"] == 1 and dry["applied"] == 0
            async with SessionLocal() as s:
                assert (await s.get(IspSubscriber, uuid.UUID(s1))).valid_until == before
            # the NOC role broadcasts but cannot grant grace
            as_("Noc")
            r = await c.post(
                f"{api}/incidents/{ir['id']}/grace",
                json={"hours": 3, "dry_run": False},
                headers=ha,
            )
            assert r.status_code == 403
            as_("A")
            applied = await call(
                "POST", f"/incidents/{ir['id']}/grace", {"hours": 3, "dry_run": False}
            )
            assert applied["applied"] == 1
            async with SessionLocal() as s:
                after = (await s.get(IspSubscriber, uuid.UUID(s1))).valid_until
            assert after == before + timedelta(hours=3)
            again = await call(
                "POST", f"/incidents/{ir['id']}/grace", {"hours": 3, "dry_run": False}
            )
            assert again["applied"] == 0 and again["eligible"] == 0

            # -- broadcast: automation off = share links, nothing sent ----------
            b = await call(
                "POST",
                f"/incidents/{iz['id']}/broadcast",
                {"kind": "outage", "dry_run": False},
            )
            assert b["mode"] == "share" and b["sent"] == 0 and b["unavailable_reasons"]
            # s2 has not opted in, s3 has
            assert b["recipients"] == 1 and b["no_consent"] == 1
            assert b["share"][0]["whatsapp_url"].startswith("https://wa.me/91")
            csv = await call("GET", f"/incidents/{iz['id']}/affected.csv")
            assert csv.headers["content-type"].startswith("text/csv")
            assert f"i3{tag}" in csv.text and f"i2{tag}" in csv.text
            async with SessionLocal() as s:
                logs = (
                    await s.execute(
                        select(func.count())
                        .select_from(IspMessageLog)
                        .where(IspMessageLog.isp_organization_id == isps["A"])
                    )
                ).scalar_one()
            assert logs == 0 and sent == []

            # -- broadcast through the JAZE-4 automation path -------------------
            flags["wa"] = True
            async with SessionLocal() as s:
                s.add(
                    IspAutomationSettings(
                        isp_organization_id=isps["A"],
                        whatsapp_enabled=True,
                        whatsapp_enabled_at=now,
                        whatsapp_templates={
                            "outage": {"template_name": "outage_v1", "language": "en"},
                            "restored": {"template_name": "back_v1", "language": "en"},
                        },
                    )
                )
                await s.commit()
            dry = await call(
                "POST", f"/incidents/{iz['id']}/broadcast", {"kind": "outage"}
            )
            assert dry["mode"] == "whatsapp" and dry["dry_run"] and sent == []
            b = await call(
                "POST",
                f"/incidents/{iz['id']}/broadcast",
                {"kind": "outage", "dry_run": False},
            )
            assert b["sent"] == 1 and len(sent) == 1
            assert sent[0][1] == "outage_v1" and sent[0][2][1] == f"Zone IZ {tag}"
            b = await call(
                "POST",
                f"/incidents/{iz['id']}/broadcast",
                {"kind": "outage", "dry_run": False},
            )
            assert b["sent"] == 0 and b["already"] == 1 and len(sent) == 1
            assert (
                await status(
                    "POST", f"/incidents/{iz['id']}/broadcast", {"kind": "restored"}
                )
                == 409
            )
            async with SessionLocal() as s:
                row = (
                    await s.execute(
                        select(IspMessageLog).where(
                            IspMessageLog.isp_organization_id == isps["A"]
                        )
                    )
                ).scalar_one()
            assert row.trigger == "outage" and row.status == "sent"

            # -- health ----
            h = await call("GET", "/incidents/health")
            assert h["routers_up"] == 1 and h["routers_down"] == 1
            assert h["health_percent"] == 50.0 and h["open_incidents"] == 2

            # -- history list ----
            hist = await call("GET", "/incidents")
            assert hist["total"] == 3 and hist["summary"]["resolved"] == 1
            assert (await call("GET", "/incidents?open_only=true"))["total"] == 2

            # -- confined technician ----
            as_("Tech")
            ids = {i["id"] for i in (await call("GET", "/incidents"))["items"]}
            assert ids == {ir["id"], iz["id"]}
            assert await status("GET", f"/incidents/{ic2['id']}") == 404
            zd = await call("GET", f"/incidents/{iz['id']}")
            assert [a["subscriber_id"] for a in zd["affected"]] == [s2]
            assert zd["affected_total"] == 2 and zd["affected_visible"] == 1
            assert (
                await status(
                    "POST",
                    "/incidents",
                    {"scope_kind": "router", "isp_router_id": rtr["c2"]},
                )
                == 404
            )
            assert await status("GET", f"/incidents/{iz['id']}/affected.csv") == 403
            assert (
                await status(
                    "POST", f"/incidents/{iz['id']}/broadcast", {"kind": "outage"}
                )
                == 403
            )
            as_("A")

            # -- audit ----
            async with SessionLocal() as s:
                actions = set(
                    (
                        await s.execute(
                            select(AuditLogEntry.action).where(
                                AuditLogEntry.entity_type == "isp_incident"
                            )
                        )
                    ).scalars()
                )
            assert {
                "isp_incident_opened",
                "isp_incident_status",
                "isp_incident_resolved",
                "isp_incident_grace",
                "isp_incident_broadcast",
                "isp_incident_affected_exported",
            } <= actions

            # -- another ISP ----------------------------------------------------------
            as_("B")
            rnd = uuid.uuid4()
            for method, path, body in (
                ("GET", f"/incidents/{ir['id']}", None),
                ("GET", f"/incidents/{rnd}", None),
                (
                    "POST",
                    f"/incidents/{ir['id']}/status",
                    {"status": "resolved", "rfo_reason": "other"},
                ),
                ("POST", f"/incidents/{iz['id']}/notes", {"body": "x"}),
                ("POST", f"/incidents/{iz['id']}/refresh", None),
                ("POST", f"/incidents/{ir['id']}/grace", {"hours": 1}),
                ("POST", f"/incidents/{iz['id']}/broadcast", {"kind": "outage"}),
                ("GET", f"/incidents/{iz['id']}/affected.csv", None),
                (
                    "GET",
                    f"/incidents/preview?scope_kind=router&isp_router_id={rtr['c1']}",
                    None,
                ),
                ("GET", f"/incidents/preview?scope_kind=zone&zone_id={z}", None),
                (
                    "GET",
                    f"/incidents/preview?scope_kind=fiber_node&fiber_node_id={olt}",
                    None,
                ),
                ("POST", "/incidents", {"scope_kind": "zone", "zone_id": z}),
            ):
                assert await status(method, path, body, h=hb) == 404, (method, path)
            assert (await call("GET", "/incidents", h=hb))["total"] == 0
            assert (await call("GET", "/incidents/health", h=hb))["routers_total"] == 0
            as_("A")

            os.environ.pop("ISP_INCIDENTS_ENABLED")
            clear()
            assert await status("GET", "/incidents") == 404
    finally:
        for k in ("ISP_INCIDENTS_ENABLED", "ISP_FIBER_ENABLED", "ISP_ZONES_ENABLED"):
            os.environ.pop(k, None)
        clear()
        await engine.dispose()
