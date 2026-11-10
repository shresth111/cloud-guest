"""IPLOGS-SELFSERVE on real PostgreSQL + Redis (skipped unless
``ISP_TEST_PG_DSN`` is set). Run with ``scripts/run_isp_pg_tests.py``:
ISP_IPLOGS_SELFSERVE_ENABLED=true CLOUDGUEST_DEVICE_LOGS_ENABLED=true

Covers: flag off 404; a router without its management connection
(``needs_link``, enable 409, no script); script + enable writes the intent
rows (export with ``ipdr_ports``) and an audit row; arrivals turn the card
green, with double-NAT / clock / NAT-event warnings; disable; the fleet
list; **ISP B cannot see, script or enable ISP A's router, nor list it**;
a technician confined to another customer gets 404.
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


async def test_iplogs_end_to_end() -> None:  # noqa: PLR0915
    import httpx
    from sqlalchemy import func, select

    from app.core.config import get_settings
    from app.database.session import SessionLocal, engine
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.device_logs.models import DeviceLogEvent, RouterRemoteLogging
    from app.domains.isp_partner.iplogs_router import get_iplogs_settings
    from app.domains.isp_partner.models import IspPartnerProfile, IspStaffCustomerScope
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.organization.models import Organization, OrganizationMember
    from app.domains.rbac.dependencies import CurrentUser
    from app.domains.rbac.models import AuditLogEntry, Role, UserRole
    from app.domains.rbac.repository import RBACRepository
    from app.domains.rbac.seed import seed_rbac
    from app.domains.router.models import Router
    from app.domains.traffic_flow.flow_record_models import TrafficFlowRecord
    from app.domains.traffic_flow.models import RouterTrafficFlowExport
    from app.domains.wireguard.models import WireGuardPeer, WireGuardServer
    from app.main import create_app

    tag = uuid.uuid4().hex[:8]
    os.environ.pop("ISP_IPLOGS_SELFSERVE_ENABLED", None)
    get_iplogs_settings.cache_clear()
    try:
        async with SessionLocal() as s:
            await seed_rbac(s)
            await seed_isp_partner_rbac(RBACRepository(s))
            await s.commit()
        users, isps = {}, {}
        async with SessionLocal() as s:
            plan = Plan(
                name=f"P {tag}",
                slug=f"il-{tag}",
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
                            Role.slug.in_(("isp-owner", "isp-technician"))
                        )
                    )
                ).scalars()
            }

            def person(n: str) -> User:
                return User(
                    first_name=n,
                    last_name="I",
                    email=f"il{n.lower()}{tag}@example.com",
                    username=f"il{n.lower()}{tag}",
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
                    name=f"IL {n} {tag}",
                    slug=f"ilisp{n.lower()}{tag}",
                    org_type="msp",
                    status="active",
                    contact_email=f"il{n}{tag}@example.com",
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
                    tech = person("Tech")
                    s.add(tech)
                    await s.flush()
                    s.add_all(grant(tech, org, "isp-technician"))
                    users["T"] = tech.id
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
                return r.json().get("data")

            async def status(method: str, path: str, h=ha) -> int:  # noqa: ANN001
                return (await c.request(method, f"{api}{path}", headers=h)).status_code

            # setup: two customers of ISP A, one router each -------------------
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
                            "name": f"Hotel {n} Main",
                            "serial_number": f"SN{n}{tag}",
                            "mac_address": f"02:1{i}:"
                            + ":".join(tag[j : j + 2] for j in (0, 2, 4, 6)),
                            "model": "hEX",
                        },
                    )
                )["id"]
            r1 = rtr["c1"]

            # flag off -> 404 on every route ----------------------------------
            for m, p in (
                ("GET", f"/routers/{r1}/ip-logs"),
                ("GET", f"/routers/{r1}/ip-logs/script"),
                ("POST", f"/routers/{r1}/ip-logs/enable"),
                ("GET", "/ip-logs/routers"),
            ):
                assert await status(m, p) == 404, p
            os.environ["ISP_IPLOGS_SELFSERVE_ENABLED"] = "true"
            get_iplogs_settings.cache_clear()

            # no management connection yet ------------------------------------
            d = await call("GET", f"/routers/{r1}/ip-logs")
            assert d["state"] == "needs_link" and d["blocker"] == "needs_link"
            assert "tunnel" not in d["blocker_hint"].lower()
            sc = await call("GET", f"/routers/{r1}/ip-logs/script")
            assert sc["available"] is False and sc["enable_script"] is None
            r = await c.post(f"{api}/routers/{r1}/ip-logs/enable", headers=ha)
            assert r.status_code == 409
            assert r.json()["data"]["code"] == "ISP_IPLOGS_NEEDS_LINK"

            # give router 1 its management connection -------------------------
            now = datetime.now(UTC)
            async with SessionLocal() as s:
                server = WireGuardServer(
                    name=f"hub {tag}",
                    endpoint_host="hub.example.com",
                    endpoint_port=51820,
                    public_key=f"srv{tag}".ljust(44, "A"),
                    private_key_encrypted="x",
                    tunnel_network_cidr="10.66.0.0/24",
                )
                s.add(server)
                await s.flush()
                s.add(
                    WireGuardPeer(
                        router_id=uuid.UUID(r1),
                        server_id=server.id,
                        tunnel_ip_address="10.66.0.77",
                        public_key=f"peer{tag}".ljust(44, "A"),
                        private_key_encrypted="x",
                    )
                )
                router = await s.get(Router, uuid.UUID(r1))
                router.status, router.last_seen_at = "online", now
                router.routeros_version = "7.20.1"
                await s.commit()

            d = await call("GET", f"/routers/{r1}/ip-logs")
            assert d["state"] == "not_set_up" and d["blocker"] is None
            sc = await call("GET", f"/routers/{r1}/ip-logs/script")
            text = "\n".join(sc["enable_script"])
            assert sc["available"] is True
            assert "src-address=10.66.0.77" in text
            assert get_settings().device_logs_remote_host or "remote=10.66.0.1" in text
            assert "nat-events=yes" in text
            assert sc["filename"].endswith(".rsc")
            assert sc["router_name_on_device"] == "Hotel-c1-Main"

            # enable: intent rows + audit ------------------------------------
            d = await call("POST", f"/routers/{r1}/ip-logs/enable")
            assert d["set_up"] is True
            assert d["state"] in ("waiting", "not_set_up")
            async with SessionLocal() as s:
                exp = (
                    await s.execute(
                        select(RouterTrafficFlowExport).where(
                            RouterTrafficFlowExport.router_id == uuid.UUID(r1)
                        )
                    )
                ).scalar_one()
                assert exp.enabled and exp.ipdr_ports
                assert exp.src_address == "10.66.0.77"
                assert exp.target_host == "10.66.0.1"
                rl = (
                    await s.execute(
                        select(RouterRemoteLogging).where(
                            RouterRemoteLogging.router_id == uuid.UUID(r1)
                        )
                    )
                ).scalar_one()
                assert rl.enabled and rl.src_address == "10.66.0.77"
                assert rl.tag == uuid.UUID(r1).hex[:8]
                n = (
                    await s.execute(
                        select(func.count()).where(
                            AuditLogEntry.action == "isp_ip_logs_enabled",
                            AuditLogEntry.entity_id == uuid.UUID(r1),
                        )
                    )
                ).scalar_one()
                assert n == 1
            # idempotent
            await call("POST", f"/routers/{r1}/ip-logs/enable")
            async with SessionLocal() as s:
                assert (
                    await s.execute(
                        select(func.count()).where(
                            RouterTrafficFlowExport.router_id == uuid.UUID(r1)
                        )
                    )
                ).scalar_one() == 1
            d = await call("GET", f"/routers/{r1}/ip-logs")
            assert d["pipes"]["syslog"]["state"] == "awaiting_first"
            assert d["state"] == "waiting"
            # flows collector is off in this env: said plainly, not hidden
            assert d["pipes"]["flows"]["state"] == "collector_off"
            assert "flows_not_collected" in {w["code"] for w in d["warnings"]}

            # arrivals: one syslog line (clock 10 min slow), NAT records ------
            async with SessionLocal() as s:
                s.add(
                    DeviceLogEvent(
                        received_at=now,
                        device_time=now - timedelta(minutes=10),
                        organization_id=uuid.UUID(cust["c1"]),
                        location_id=uuid.UUID(loc["c1"]),
                        router_id=uuid.UUID(r1),
                        source_ip="10.66.0.77",
                        vendor="mikrotik",
                        source="syslog",
                        message="wyfy: IP logs set up",
                        attribution="tunnel_ip",
                        claimed_tag=uuid.UUID(r1).hex[:8],
                    )
                )
                s.add(
                    TrafficFlowRecord(
                        router_id=uuid.UUID(r1),
                        organization_id=uuid.UUID(cust["c1"]),
                        location_id=uuid.UUID(loc["c1"]),
                        source="ipfix",
                        window_start=now - timedelta(minutes=5),
                        window_seconds=300,
                        src_address="10.5.50.20",
                        src_port=51000,
                        dst_address="142.250.1.1",
                        dst_port=443,
                        protocol=6,
                        nat_src_address="192.168.1.2",
                        nat_src_port=40001,
                        direction="upload",
                        exporter_address="10.66.0.77",
                        bytes=100,
                    )
                )
                await s.commit()
            d = await call("GET", f"/routers/{r1}/ip-logs")
            assert d["state"] == "logs_arriving", d
            assert d["state_label"] == "Logs arriving"
            assert d["pipes"]["syslog"]["state"] == "receiving"
            assert d["pipes"]["syslog"]["count_last_hour"] == 1
            assert d["pipes"]["syslog"]["last_at_ist"]
            codes = {w["code"] for w in d["warnings"]}
            assert {"double_nat", "clock_off"} <= codes, codes
            assert 590 <= d["clock_offset_seconds"] <= 610

            # fleet list -------------------------------------------------------
            fl = await call("GET", "/ip-logs/routers")
            by = {i["isp_router_id"]: i for i in fl["items"]}
            assert set(by) == {r1, rtr["c2"]}
            assert by[r1]["state"] == "logs_arriving"
            assert by[rtr["c2"]]["state"] == "needs_link"
            one = await call("GET", f"/ip-logs/routers?isp_customer_id={cust['c2']}")
            assert {i["isp_router_id"] for i in one["items"]} == {rtr["c2"]}

            # ISP B cannot see, script, enable or list ISP A's router ---------
            as_("B")
            for m, p in (
                ("GET", f"/routers/{r1}/ip-logs"),
                ("GET", f"/routers/{r1}/ip-logs/script"),
                ("POST", f"/routers/{r1}/ip-logs/enable"),
                ("POST", f"/routers/{r1}/ip-logs/disable"),
                ("GET", f"/ip-logs/routers?isp_customer_id={cust['c1']}"),
            ):
                assert await status(m, p, h=hb) == 404, p
            assert (await call("GET", "/ip-logs/routers", h=hb))["items"] == []
            # ...and pointing B's user at A's org is refused by the guards
            assert await status("GET", f"/routers/{r1}/ip-logs", h=ha) in (403, 404)

            # technician confined to c2 cannot reach c1's router --------------
            async with SessionLocal() as s:
                s.add(
                    IspStaffCustomerScope(
                        isp_organization_id=isps["A"],
                        user_id=users["T"],
                        customer_organization_id=uuid.UUID(cust["c2"]),
                    )
                )
                await s.commit()
            as_("T")
            assert await status("GET", f"/routers/{r1}/ip-logs") == 404
            fl = await call("GET", "/ip-logs/routers")
            assert {i["isp_router_id"] for i in fl["items"]} == {rtr["c2"]}
            as_("A")

            # disable ----------------------------------------------------------
            d = await call("POST", f"/routers/{r1}/ip-logs/disable")
            assert d["set_up"] is False
            async with SessionLocal() as s:
                exp = (
                    await s.execute(
                        select(RouterTrafficFlowExport).where(
                            RouterTrafficFlowExport.router_id == uuid.UUID(r1)
                        )
                    )
                ).scalar_one()
                assert exp.enabled is False
                n = (
                    await s.execute(
                        select(func.count()).where(
                            AuditLogEntry.action == "isp_ip_logs_disabled",
                            AuditLogEntry.entity_id == uuid.UUID(r1),
                        )
                    )
                ).scalar_one()
                assert n == 1
    finally:
        os.environ.pop("ISP_IPLOGS_SELFSERVE_ENABLED", None)
        get_iplogs_settings.cache_clear()
        await engine.dispose()
