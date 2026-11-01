"""IPDR-2 on real PostgreSQL + Redis (skipped unless ``ISP_TEST_PG_DSN`` is
set; CI has neither). Fresh scratch DB at head. The IPDR join is faked (one
record), everything else is real: NAT rows in ``traffic_flow_records``, the
subscriber + KYC dossier, audit rows, RBAC.

Covers: flag off; LEA reference + reason mandatory; JSON/PDF/XLSX each
audited with the reference; event vs receipt time apart (and empty event
time never filled); gap flag; masked ID only; technician refused (and not
audited); another ISP sees nothing and gets 404 for A's customer; the
retention card; field coverage; nothing deleted.
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


async def test_lea_trace_retention_coverage() -> None:  # noqa: PLR0915
    import httpx
    from sqlalchemy import func, select

    from app.database.session import SessionLocal, engine
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.ipdr.dependencies import get_ipdr_service
    from app.domains.isp_partner.compliance_models import IspSubscriberKyc
    from app.domains.isp_partner.ipdr_lea_router import get_ipdr_lea_settings
    from app.domains.isp_partner.models import IspPartnerProfile
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.isp_partner.zones_config import get_zones_settings
    from app.domains.organization.models import Organization, OrganizationMember
    from app.domains.rbac.dependencies import CurrentUser
    from app.domains.rbac.models import AuditLogEntry, Role, UserRole
    from app.domains.rbac.repository import RBACRepository
    from app.domains.rbac.seed import seed_rbac
    from app.domains.traffic_flow.flow_record_models import TrafficFlowRecord
    from app.main import create_app

    tag = uuid.uuid4().hex[:8]
    os.environ.pop("ISP_ZONES_ENABLED", None)
    get_zones_settings.cache_clear()
    try:
        async with SessionLocal() as s:
            await seed_rbac(s)
            await seed_isp_partner_rbac(RBACRepository(s))
            await s.commit()
        users, isps = {}, {}
        async with SessionLocal() as s:
            plan = Plan(
                name=f"P {tag}",
                slug=f"z1-{tag}",
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
                    last_name="Z",
                    email=f"z1{n.lower()}{tag}@example.com",
                    username=f"z1{n.lower()}{tag}",
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
                    name=f"Zn {n} {tag}",
                    slug=f"z1net{n.lower()}{tag}",
                    org_type="msp",
                    status="active",
                    contact_email=f"z{n}{tag}@example.com",
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

            async def ids(path: str, h=ha) -> set[str]:  # noqa: ANN001
                data = await call("GET", path, h=h)
                items = data["items"] if isinstance(data, dict) else data
                return {i["id"] for i in items}

            # setup --------------------
            os.environ["ISP_IPDR_LEA_ENABLED"] = "true"
            get_ipdr_lea_settings.cache_clear()
            c1 = (
                await call(
                    "POST",
                    "/customers",
                    {"name": f"L1 {tag}", "contact_email": f"l1{tag}@e.com"},
                )
            )["id"]
            loc = (
                await call(
                    "POST",
                    f"/customers/{c1}/locations",
                    {
                        "name": "Main",
                        "address_line1": "1",
                        "city": "c",
                        "state_province": "s",
                        "postal_code": "1",
                    },
                )
            )["id"]
            rtr = (
                await call(
                    "POST",
                    f"/locations/{loc}/routers",
                    {
                        "name": "hEX",
                        "serial_number": f"SN{tag}",
                        "mac_address": "02:00:"
                        + ":".join(tag[i : i + 2] for i in (0, 2, 4, 6)),
                        "model": "hEX",
                    },
                )
            )["id"]
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
            ident = "98765" + tag[:5].translate(str.maketrans("abcdef", "123456"))
            sid = (
                await call(
                    "POST",
                    "/subscribers",
                    {"isp_customer_id": c1, "identifier": ident, "package_id": pkg},
                )
            )["id"]
            at = datetime(2026, 10, 30, 10, 0, tzinfo=UTC)
            async with SessionLocal() as s:
                s.add(
                    IspSubscriberKyc(
                        isp_organization_id=isps["A"],
                        subscriber_id=uuid.UUID(sid),
                        full_name="Asha Test",
                        id_proof_type="aadhaar",
                        id_number_masked="XXXX XXXX 4321",
                        id_number_last4="4321",
                        permanent_address="12 Old Road",
                        installation_address="7 New Street",
                        caf_number="CAF-0007",
                    )
                )
                base = {
                    "router_id": uuid.UUID(rtr),
                    "organization_id": uuid.UUID(c1),
                    "location_id": uuid.UUID(loc),
                    "source": "ipfix",
                    "window_seconds": 60,
                    "src_address": "10.5.50.20",
                    "src_port": 51000,
                    "dst_address": "142.250.1.1",
                    "dst_port": 443,
                    "protocol": 6,
                    "nat_src_address": "203.0.113.9",
                    "nat_src_port": 40001,
                    "direction": "out",
                    "exporter_address": "100.64.0.2",
                    "bytes": 100,
                }
                s.add_all(
                    [
                        # router timestamp, received 9 min later -> flagged
                        TrafficFlowRecord(
                            **base,
                            window_start=at,
                            flow_start=at,
                            flow_end=at + timedelta(seconds=20),
                            arrived_at=at + timedelta(minutes=9),
                        ),
                        # no router timestamp: event time must stay empty
                        TrafficFlowRecord(
                            **base,
                            window_start=at + timedelta(seconds=30),
                            arrived_at=at + timedelta(seconds=40),
                        ),
                        # other port: not part of the answer
                        TrafficFlowRecord(
                            **{**base, "nat_src_port": 40002},
                            window_start=at,
                            flow_start=at,
                            arrived_at=at,
                        ),
                    ]
                )
                await s.commit()

            record = {
                "ts": at.isoformat(),
                "ts_end": (at + timedelta(seconds=20)).isoformat(),
                "ts_source": "flow",
                "window_start": at.isoformat(),
                "organization_id": c1,
                "router_id": rtr,
                "user_known": True,
                "user_id": ident,
                "name": None,
                "phone": ident,
                "email": None,
                "mac": "AA:BB:CC:00:00:01",
                "alloc_start": (at - timedelta(hours=1)).isoformat(),
                "alloc_end": None,
                "src_ip": "10.5.50.20",
                "src_port": 51000,
                "nat_ip": "203.0.113.9",
                "nat_port": 40001,
                "nat_source": "nat_event",
                "dst_ip": "142.250.1.1",
                "dst_port": 443,
                "protocol": 6,
            }

            class _Ipdr:
                async def build_filters(self, *, organization_id, **_kw):  # noqa: ANN001, ANN003, ANN202
                    return str(organization_id)

                async def iter_records(self, f):  # noqa: ANN001, ANN202
                    if f == c1:
                        yield dict(record)

            app.dependency_overrides[get_ipdr_service] = lambda: _Ipdr()
            body = {
                "public_ip": "203.0.113.9",
                "public_port": 40001,
                "at": "2026-10-30T15:30:00",
                "tz": "Asia/Kolkata",
                "tolerance_seconds": 120,
                "lea_reference": "DCP/CYB/2026/0912",
                "reason": "Notice under section 94 BNSS",
            }

            async def audits() -> int:
                async with SessionLocal() as s:
                    return int(
                        (
                            await s.execute(
                                select(func.count()).where(
                                    AuditLogEntry.action == "isp_lea_trace_report",
                                    AuditLogEntry.organization_id == isps["A"],
                                )
                            )
                        ).scalar_one()
                    )

            # flag off -> 404 --------------------
            os.environ.pop("ISP_IPDR_LEA_ENABLED")
            get_ipdr_lea_settings.cache_clear()
            for method, path, js in (
                ("POST", "/compliance/lea-trace", body),
                ("GET", "/compliance/retention", None),
                ("GET", "/compliance/ipdr-field-coverage", None),
            ):
                r = await c.request(method, f"{api}{path}", json=js, headers=ha)
                assert r.status_code == 404 and r.json()["data"]["code"] == (
                    "ISP_IPDR_LEA_DISABLED"
                ), path
            os.environ["ISP_IPDR_LEA_ENABLED"] = "true"
            get_ipdr_lea_settings.cache_clear()

            # LEA reference is mandatory --------------------
            for drop in ("lea_reference", "reason"):
                r = await c.post(
                    f"{api}/compliance/lea-trace",
                    json={k: v for k, v in body.items() if k != drop},
                    headers=ha,
                )
                assert r.status_code == 422, (drop, r.text)
            assert await audits() == 0

            # owner: JSON run --------------------
            rep = await call("POST", "/compliance/lea-trace", body)
            assert rep["lea_reference"] == "DCP/CYB/2026/0912"
            assert rep["verdict"] == "unique_match"
            assert len(rep["nat_rows"]) == 2  # the other port is excluded
            timed, untimed = sorted(
                rep["nat_rows"], key=lambda r: r["event_time_reported"]
            )[::-1]
            assert timed["event_time_ist"] == "2026-10-30 15:30:00 IST"
            assert timed["receipt_time_ist"] == "2026-10-30 15:39:00 IST"
            assert timed["gap_minutes"] == 9.0 and timed["gap_flag"] is True
            assert untimed["event_time_ist"] is None  # never replaced by receipt time
            assert untimed["receipt_time_ist"] == "2026-10-30 15:30:40 IST"
            (m,) = rep["matches"]
            assert m["confidence"] == "high" and m["subscriber_id"] == sid
            assert m["id_number_masked"] == "XXXX XXXX 4321"
            assert m["permanent_address"] == "12 Old Road"
            assert m["installation_address"] == "7 New Street"
            assert m["caf_number"] == "CAF-0007"
            assert m["caf_pdf"].endswith(f"/caf/subscribers/{sid}/caf.pdf")
            assert m["lease_start_ist"] == "2026-10-30 14:30:00 IST"
            assert "4321" in str(rep) and "Aadhaar" not in str(
                m.get("id_number_masked")
            )
            assert await audits() == 1

            # PDF + XLSX, each audited --------------------
            r = await c.post(
                f"{api}/compliance/lea-trace",
                json={**body, "format": "pdf"},
                headers=ha,
            )
            assert r.status_code == 200 and r.content[:4] == b"%PDF"
            assert "DCP_CYB_2026_0912" in r.headers["content-disposition"]
            r = await c.post(
                f"{api}/compliance/lea-trace",
                json={**body, "format": "xlsx"},
                headers=ha,
            )
            assert r.status_code == 200 and r.content[:2] == b"PK"
            assert await audits() == 3
            async with SessionLocal() as s:
                meta = (
                    (
                        await s.execute(
                            select(AuditLogEntry.event_metadata).where(
                                AuditLogEntry.action == "isp_lea_trace_report",
                                AuditLogEntry.organization_id == isps["A"],
                            )
                        )
                    )
                    .scalars()
                    .all()
                )
            assert {x["format"] for x in meta} == {"json", "pdf", "xlsx"}
            assert all(x["lea_reference"] == "DCP/CYB/2026/0912" for x in meta)

            # technician: no isp_ipdr.export -> refused, not audited ------------------
            as_("T")
            r = await c.post(f"{api}/compliance/lea-trace", json=body, headers=ha)
            assert r.status_code == 403, r.text
            as_("A")
            assert await audits() == 3

            # another ISP: its own scope only -> nothing of A's ---------------------
            as_("B")
            rb = (
                await c.post(f"{api}/compliance/lea-trace", json=body, headers=hb)
            ).json()["data"]
            assert rb["matches"] == [] and rb["nat_rows"] == []
            r = await c.post(
                f"{api}/compliance/lea-trace",
                json={**body, "isp_customer_id": c1},
                headers=hb,
            )
            assert r.status_code == 404, r.text
            as_("A")

            # retention card + coverage --------------------
            ret = await call("GET", "/compliance/retention")
            (row,) = [x for x in ret["routers"] if x["isp_router_id"] == rtr]
            assert row["oldest_nat_ist"] == "2026-10-30 15:30:00 IST"
            assert row["target_days"] == 730 and row["target_met"] is False
            assert "guest_sessions" in ret["never_pruned"]
            cov = await call("GET", "/compliance/ipdr-field-coverage")
            assert any(f["status"] == "not_collected" for f in cov["fields"])
            # nothing was deleted along the way
            async with SessionLocal() as s:
                n = (
                    await s.execute(
                        select(func.count()).where(
                            TrafficFlowRecord.router_id == uuid.UUID(rtr)
                        )
                    )
                ).scalar_one()
            assert n == 3
    finally:
        os.environ.pop("ISP_IPDR_LEA_ENABLED", None)
        get_ipdr_lea_settings.cache_clear()
        await engine.dispose()
