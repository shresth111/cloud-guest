# ruff: noqa: E501 -- scenario test
"""CAF-2 workbench on real PostgreSQL + Redis (skipped unless
``ISP_TEST_PG_DSN``; CI has neither). Run::

    CLOUDGUEST_DATABASE_URL=postgresql+asyncpg://postgres@localhost:55441/caf2 \\
    CLOUDGUEST_REDIS_URL=redis://localhost:56381/0 \\
    ISP_TEST_PG_DSN=1 ISP_PARTNER_ENABLED=true ISP_CAF_WORKBENCH_ENABLED=true \\
    ISP_APPS_ENABLED=true python -m pytest tests/unit/test_isp_caf_postgres.py

Covers: isolation (ISP B -> 404 on ISP A's subscriber, a technician confined
to customer A1 -> 404 on A2's subscriber for prefill, PDF, extras and
export), the Aadhaar rule end to end (a full number typed into JAZE-3 KYC is
stored as the last four only; neither the single PDF nor any PDF in the ZIP
contains a 12-digit run), extras saved in the CAF-2 table, custom CAF
numbers unique per ISP, lead -> subscriber conversion without re-entering
data (extras follow), and an audit row for every generation and export.
"""

from __future__ import annotations

import io
import os
import re
import uuid
import zipfile
from datetime import UTC, datetime
from decimal import Decimal

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)

FULL = "718190937865"  # synthetic, Verhoeff-valid, not anyone's number


def _no_aadhaar(pdf: bytes) -> str:
    from tests.unit.test_isp_caf_unit import pdf_text

    text = pdf_text(pdf)
    for s in text.splitlines():
        assert not re.search(r"\d{12}", re.sub(r"[\s\-]", "", s)), s
    return text


async def test_caf_workbench_end_to_end() -> None:  # noqa: PLR0915
    import httpx
    from sqlalchemy import func, select

    from app.database.session import SessionLocal
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.isp_partner.apps_common import get_isp_apps_settings
    from app.domains.isp_partner.caf_models import IspCafExtras
    from app.domains.isp_partner.caf_service import get_isp_caf_settings
    from app.domains.isp_partner.compliance_models import IspSubscriberKyc
    from app.domains.isp_partner.models import IspPartnerProfile, IspStaffCustomerScope
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.organization.models import Organization, OrganizationMember
    from app.domains.rbac.dependencies import CurrentUser
    from app.domains.rbac.models import AuditLogEntry, Role, UserRole
    from app.domains.rbac.repository import RBACRepository
    from app.domains.rbac.seed import seed_rbac
    from app.main import create_app

    get_isp_caf_settings.cache_clear()
    get_isp_apps_settings.cache_clear()
    tag = uuid.uuid4().hex[:8]
    async with SessionLocal() as s:
        await seed_rbac(s)
        await seed_isp_partner_rbac(RBACRepository(s))
        await s.commit()
    users, isps = {}, {}
    async with SessionLocal() as s:
        plan = Plan(
            name=f"P {tag}",
            slug=f"pcaf-{tag}",
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
                    select(Role).where(Role.slug.in_(("isp-owner", "isp-technician")))
                )
            ).scalars()
        }

        def person(n: str) -> User:
            return User(
                first_name=n,
                last_name="T",
                email=f"cf{n.lower()}{tag}@example.com",
                username=f"cf{n.lower()}{tag}",
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
                name=f"Net {n} {tag}",
                slug=f"cfnet{n.lower()}{tag}",
                org_type="msp",
                status="active",
                contact_email=f"{n}{tag}@example.com",
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

        async def customer(headers: dict, name: str) -> str:
            r = await c.post(
                f"{api}/customers",
                json={
                    "name": f"{name} {tag}",
                    "contact_email": f"{name.lower()}{tag}@example.com",
                },
                headers=headers,
            )
            assert r.status_code == 201, r.text
            return r.json()["data"]["id"]

        a1, a2 = await customer(ha, "CafeA1"), await customer(ha, "CafeA2")
        async with SessionLocal() as s:
            s.add(
                IspStaffCustomerScope(
                    isp_organization_id=isps["A"],
                    user_id=users["T"],
                    customer_organization_id=uuid.UUID(a1),
                )
            )
            await s.commit()
        g = await c.post(
            f"{api}/speed-groups",
            json={"name": "20 Mbps", "download_kbps": 20480, "upload_kbps": 20480},
            headers=ha,
        )
        p = await c.post(
            f"{api}/packages",
            json={
                "speed_group_id": g.json()["data"]["id"],
                "type": "prepaid",
                "price_paise": 50000,
            },
            headers=ha,
        )
        pid = p.json()["data"]["id"]
        r = await c.put(
            f"{api}/compliance/settings",
            json={
                "legal_name": "Net A Pvt Ltd",
                "licence_number": "LIC-TEST-1",
                "gstin": "27AAPFU0939F1ZV",
            },
            headers=ha,
        )
        assert r.status_code == 200, r.text

        async def subscriber(cust: str, ident: str) -> str:
            r = await c.post(
                f"{api}/subscribers/onboard",
                json={
                    "isp_customer_id": cust,
                    "identifier": ident,
                    "package_id": pid,
                    "first_name": "Asha",
                },
                headers=ha,
            )
            assert r.status_code == 201, r.text
            sid = r.json()["data"]["id"]
            r = await c.put(
                f"{api}/compliance/subscribers/{sid}/kyc",
                json={
                    "full_name": "Asha T",
                    "id_proof_type": "aadhaar",
                    "id_number": FULL,
                },
                headers=ha,
            )
            assert r.status_code == 200, r.text
            return sid

        s1 = await subscriber(a1, f"a1-{tag}")
        s2 = await subscriber(a2, f"a2-{tag}")

        # Aadhaar at rest: last four only
        async with SessionLocal() as s:
            masked = (
                await s.execute(
                    select(IspSubscriberKyc.id_number_masked).where(
                        IspSubscriberKyc.subscriber_id == uuid.UUID(s1)
                    )
                )
            ).scalar_one()
        assert masked == "XXXX XXXX 7865"

        # ---- prefill + extras + numbers (owner) --------------------------------
        r = await c.get(f"{api}/caf/subscribers/{s1}", headers=ha)
        assert r.status_code == 200, r.text
        v = r.json()["data"]
        assert v["kyc"]["id_number"] == "XXXX XXXX 7865" and FULL not in r.text
        assert set(v["missing"]) == {"photo", "signature"}
        r = await c.put(
            f"{api}/caf/subscribers/{s1}/extras",
            json={
                "applicant_category": "proprietor",
                "plot_no": "14B",
                "locality": "Old Market",
                "district": "Test District",
            },
            headers=ha,
        )
        assert (
            r.status_code == 200
            and r.json()["data"]["applicant_category"] == "proprietor"
        )
        async with SessionLocal() as s:
            row = (
                await s.execute(
                    select(IspCafExtras).where(
                        IspCafExtras.subscriber_id == uuid.UUID(s1)
                    )
                )
            ).scalar_one()
            assert (row.plot_no, row.district) == ("14B", "Test District")
        r = await c.post(
            f"{api}/caf/subscribers/{s1}/number",
            json={"mode": "custom", "number": f"PAPER-{tag}"},
            headers=ha,
        )
        assert (
            r.status_code == 200
            and r.json()["data"]["caf_number"] == f"PAPER-{tag}".upper()
        )
        r = await c.post(
            f"{api}/caf/subscribers/{s2}/number",
            json={"mode": "custom", "number": f"paper-{tag}"},
            headers=ha,
        )
        assert (
            r.status_code == 409 and r.json()["data"]["code"] == "ISP_CAF_NUMBER_TAKEN"
        )
        r = await c.post(
            f"{api}/caf/subscribers/{s2}/number", json={"mode": "auto"}, headers=ha
        )
        assert r.status_code == 200 and r.json()["data"]["source"] == "auto"

        # ---- the PDF never carries a full Aadhaar ------------------------------
        r = await c.get(f"{api}/caf/subscribers/{s1}/caf.pdf", headers=ha)
        assert r.status_code == 200 and r.headers["content-type"] == "application/pdf"
        text = _no_aadhaar(r.content)
        assert "XXXX XXXX 7865" in text and "LIC-TEST-1" in text and "14B" in text

        # ---- isolation ------------------------------------------------------------------
        as_("B")
        for path in (f"/caf/subscribers/{s1}", f"/caf/subscribers/{s1}/caf.pdf"):
            assert (await c.get(f"{api}{path}", headers=hb)).status_code == 404
        as_("T")
        assert (
            await c.get(f"{api}/caf/subscribers/{s1}", headers=ha)
        ).status_code == 200
        # read: inside the confinement 200, outside 404 (not 403: no hint it exists)
        assert (
            await c.get(f"{api}/caf/subscribers/{s2}", headers=ha)
        ).status_code == 404
        # RBAC-FIX R3: the technician holds isp_subscribers.kyc, so it reads
        # the CAF PDF of its own customers; outside them it is 404
        r = await c.get(f"{api}/caf/subscribers/{s1}/caf.pdf", headers=ha)
        assert r.status_code == 200, r.text
        r = await c.get(f"{api}/caf/subscribers/{s2}/caf.pdf", headers=ha)
        assert r.status_code == 404, r.text
        r = await c.put(
            f"{api}/caf/subscribers/{s2}/extras", json={"plot_no": "x"}, headers=ha
        )
        assert r.status_code in (403, 404), r.text
        r = await c.post(
            f"{api}/caf/export", json={"subscriber_ids": [s1, s2]}, headers=ha
        )
        assert r.status_code in (403, 404), r.text
        hits = (
            await c.get(f"{api}/caf/search", params={"q": "a2-"}, headers=ha)
        ).json()["data"]
        assert all(h["id"] != s2 for h in hits)
        as_("A")

        # ---- bulk export ------------------------------------------------------------------
        r = await c.post(
            f"{api}/caf/export", json={"subscriber_ids": [s1, s2]}, headers=ha
        )
        assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
        with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
            pdfs = [n for n in zf.namelist() if n.endswith(".pdf")]
            assert len(pdfs) == 2
            for n in pdfs:
                _no_aadhaar(zf.read(n))
        today = datetime.now(UTC).date().isoformat()
        r = await c.post(
            f"{api}/caf/export", json={"since": today, "until": today}, headers=ha
        )
        assert r.status_code == 200

        # ---- lead -> subscriber, data not asked again ---------------------------------
        r = await c.post(
            f"{api}/apps/leads",
            json={
                "name": "Ravi Lead",
                "phone": "9876500077",
                "address": "Lane 4",
                "isp_customer_id": a1,
                "interested_package_id": pid,
            },
            headers=ha,
        )
        assert r.status_code == 201, r.text
        lead = r.json()["data"]["id"]
        hits = (
            await c.get(
                f"{api}/caf/search", params={"q": "Ravi", "source": "lead"}, headers=ha
            )
        ).json()["data"]
        assert [h["id"] for h in hits] == [lead]
        r = await c.put(
            f"{api}/caf/leads/{lead}/extras",
            json={"applicant_category": "partnership", "district": "Lead District"},
            headers=ha,
        )
        assert r.status_code == 200, r.text
        r = await c.post(f"{api}/caf/leads/{lead}/convert", json={}, headers=ha)
        assert r.status_code == 200, r.text
        conv = r.json()["data"]
        assert conv["subscriber"]["username"] == "9876500077"  # the lead's phone
        assert (
            conv["subscriber"]["phone"] == "9876500077"
            and conv["subscriber"]["address"] == "Lane 4"
        )
        assert conv["extras"]["applicant_category"] == "partnership"
        assert conv["extras"]["district"] == "Lead District"

        # ---- every generation and export is audited ------------------------------------
        async with SessionLocal() as s:
            n = dict(
                (
                    await s.execute(
                        select(AuditLogEntry.action, func.count())
                        .where(
                            AuditLogEntry.action.in_(
                                ("isp_caf2_generated", "isp_caf2_exported")
                            ),
                            AuditLogEntry.actor_user_id == users["A"],
                        )
                        .group_by(AuditLogEntry.action)
                    )
                ).all()
            )
        assert n.get("isp_caf2_generated") == 1 and n.get("isp_caf2_exported") == 2
