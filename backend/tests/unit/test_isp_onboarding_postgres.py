# ruff: noqa: E501 -- scenario test
"""ONBOARD-1 ``/isp/onboarding`` on real PostgreSQL + Redis (skipped unless
``ISP_TEST_PG_DSN``; CI has neither). Run::

    CLOUDGUEST_DATABASE_URL=postgresql+asyncpg://postgres@localhost:55441/onboard \\
    CLOUDGUEST_REDIS_URL=redis://localhost:56381/0 \\
    ISP_TEST_PG_DSN=1 ISP_PARTNER_ENABLED=true ISP_PPPOE_ENABLED=true \\
    python -m pytest tests/unit/test_isp_onboarding_postgres.py

The rollback promise: a failure in the LAST step (static IP, unknown venue)
after subscriber + profile + PPPoE login + MAC bind + KYC + CAF number +
first invoice + payment were all written leaves none of them behind -- no
subscriber, credential, binding, KYC row, invoice, payment, timeline event
or audit row -- and the gap-free circuit-id and CAF counters do not move. A
failure in the middle (PPPoE username taken) is the same. Then the full
success path, which reuses the circuit id the failed attempts did not take.
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


async def test_onboarding_is_one_transaction() -> None:  # noqa: PLR0915
    import httpx
    from sqlalchemy import func, select

    from app.database.session import SessionLocal
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.isp_partner.billing_models import IspInvoice, IspPayment
    from app.domains.isp_partner.compliance_models import IspSubscriberKyc
    from app.domains.isp_partner.enforcement_models import IspSubscriberMacBinding
    from app.domains.isp_partner.models import IspPartnerProfile
    from app.domains.isp_partner.plans_models import IspSubscriber
    from app.domains.isp_partner.pppoe_config import get_isp_pppoe_settings
    from app.domains.isp_partner.pppoe_models import IspPppoeCredential
    from app.domains.isp_partner.seed import seed_isp_partner_rbac
    from app.domains.isp_partner.subscriber360_models import IspSubscriberEvent
    from app.domains.organization.models import Organization, OrganizationMember
    from app.domains.rbac.dependencies import CurrentUser
    from app.domains.rbac.models import AuditLogEntry, Role, UserRole
    from app.domains.rbac.repository import RBACRepository
    from app.domains.rbac.seed import seed_rbac
    from app.main import create_app

    get_isp_pppoe_settings.cache_clear()
    tag = uuid.uuid4().hex[:8]
    async with SessionLocal() as s:
        await seed_rbac(s)
        await seed_isp_partner_rbac(RBACRepository(s))
        await s.commit()
    async with SessionLocal() as s:
        plan = Plan(
            name=f"P {tag}",
            slug=f"pob-{tag}",
            plan_type="standard",
            billing_cycle="monthly",
            base_price=Decimal("0"),
            currency="INR",
            is_active=True,
            is_public=False,
        )
        owner_role = (
            await s.execute(select(Role).where(Role.slug == "isp-owner"))
        ).scalar_one()
        org = Organization(
            name=f"Net {tag}",
            slug=f"obnet{tag}",
            org_type="msp",
            status="active",
            contact_email=f"o{tag}@example.com",
            timezone="Asia/Kolkata",
            settings={},
        )
        user = User(
            first_name="Owner",
            last_name="T",
            email=f"ob{tag}@example.com",
            username=f"ob{tag}",
            password_hash="x",
            is_active=True,
            is_verified=True,
        )
        s.add_all([plan, org, user])
        await s.flush()
        s.add(
            IspPartnerProfile(organization_id=org.id, default_customer_plan_id=plan.id)
        )
        s.add_all(
            [
                OrganizationMember(
                    organization_id=org.id, user_id=user.id, status="active"
                ),
                UserRole(
                    user_id=user.id,
                    role_id=owner_role.id,
                    scope_type="organization",
                    organization_id=org.id,
                    granted_at=datetime.now(UTC),
                    is_active=True,
                ),
            ]
        )
        await s.commit()
        isp_id, user_id = org.id, user.id

    app = create_app()
    app.dependency_overrides[CurrentUser] = lambda: AuthUser(
        id=str(user_id), email="o@example.com"
    )
    h = {"X-Organization-Id": str(isp_id)}
    api = "/api/v1/isp"

    async def counts(identifier: str) -> dict:
        async with SessionLocal() as s:

            async def n(model, *where) -> int:
                return int(
                    (
                        await s.execute(
                            select(func.count()).select_from(model).where(*where)
                        )
                    ).scalar_one()
                )

            subs = (
                (
                    await s.execute(
                        select(IspSubscriber.id).where(
                            IspSubscriber.isp_organization_id == isp_id,
                            IspSubscriber.identifier == identifier,
                        )
                    )
                )
                .scalars()
                .all()
            )
            return {
                "subscribers": len(subs),
                "pppoe": await n(
                    IspPppoeCredential, IspPppoeCredential.isp_organization_id == isp_id
                ),
                "macs": await n(
                    IspSubscriberMacBinding,
                    IspSubscriberMacBinding.isp_organization_id == isp_id,
                ),
                "kyc": await n(
                    IspSubscriberKyc, IspSubscriberKyc.isp_organization_id == isp_id
                ),
                "invoices": await n(
                    IspInvoice,
                    IspInvoice.isp_organization_id == isp_id,
                    IspInvoice.bill_to_kind == "subscriber",
                ),
                "payments": await n(
                    IspPayment, IspPayment.isp_organization_id == isp_id
                ),
                "events": await n(
                    IspSubscriberEvent, IspSubscriberEvent.isp_organization_id == isp_id
                ),
                "audit": await n(
                    AuditLogEntry,
                    AuditLogEntry.action == "isp_subscriber_onboarded",
                    AuditLogEntry.actor_user_id == user_id,
                ),
            }

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t"
    ) as c:
        r = await c.post(
            f"{api}/customers",
            json={"name": f"Cafe {tag}", "contact_email": f"c{tag}@example.com"},
            headers=h,
        )
        assert r.status_code == 201, r.text
        cust = r.json()["data"]["id"]
        r = await c.put(
            f"{api}/billing/settings",
            json={
                "legal_name": "Net Pvt Ltd",
                "state_code": "07",
                "gst_enabled": True,
                "invoice_prefix": "OB",
            },
            headers=h,
        )
        assert r.status_code == 200, r.text
        g = await c.post(
            f"{api}/speed-groups",
            json={"name": "50 Mbps", "download_kbps": 51200, "upload_kbps": 51200},
            headers=h,
        )
        p = await c.post(
            f"{api}/packages",
            json={
                "speed_group_id": g.json()["data"]["id"],
                "type": "prepaid",
                "price_paise": 50000,
            },
            headers=h,
        )
        assert p.status_code == 201, p.text
        pid = p.json()["data"]["id"]
        inclusive = bool(p.json()["data"].get("price_includes_gst"))

        opts = (await c.get(f"{api}/onboarding/options", headers=h)).json()["data"]
        assert opts["features"]["pppoe"] is True
        assert opts["features"]["static_queue_push"] is False
        circuit0 = opts["next_circuit_id"]
        caf0 = (await c.get(f"{api}/compliance/settings", headers=h)).json()["data"][
            "caf_next_seq"
        ]

        ident = f"flat-{tag}"
        body = {
            "subscriber": {
                "isp_customer_id": cust,
                "identifier": ident,
                "package_id": pid,
                "first_name": "Asha",
                "phone": "9876500001",
                "state_code": "07",
                "welcome_whatsapp": True,
                "profile": {"override_price_paise": 40000, "user_type": "home"},
            },
            "pppoe": {"username": f"asha{tag}", "generate_password": True},
            "macs": ["aa-bb-cc-00-00-01"],
            "kyc": {
                "full_name": "Asha T",
                "id_proof_type": "aadhaar",
                "id_number": "7865",
            },
            "caf": {"mode": "auto"},
            "billing": {
                "issue_invoice": True,
                "paid_now": True,
                "payment": {"mode": "cash"},
            },
        }
        before = await counts(ident)
        assert before["subscribers"] == 0

        # ---- 1. failure in the LAST step rolls back everything ---------------
        bad = {
            **body,
            "static_ips": [
                {"isp_location_id": str(uuid.uuid4()), "pool_id": str(uuid.uuid4())}
            ],
        }
        r = await c.post(f"{api}/onboarding", json=bad, headers=h)
        assert r.status_code == 404, r.text
        assert r.json()["data"]["step"] == "static_ip"
        assert await counts(ident) == before
        again = (await c.get(f"{api}/onboarding/options", headers=h)).json()["data"]
        assert again["next_circuit_id"] == circuit0  # circuit series rolled back
        caf1 = (await c.get(f"{api}/compliance/settings", headers=h)).json()["data"][
            "caf_next_seq"
        ]
        assert caf1 == caf0  # CAF series rolled back

        # ---- 2. failure in the middle (PPPoE username taken) -------------------
        other = {
            "subscriber": {**body["subscriber"], "identifier": f"other-{tag}"},
            "pppoe": {"username": f"taken{tag}"},
        }
        r = await c.post(f"{api}/onboarding", json=other, headers=h)
        assert r.status_code == 201, r.text
        circuit_used = r.json()["data"]["subscriber"]["circuit_id"]
        assert circuit_used == circuit0
        mid = {**body, "pppoe": {"username": f"taken{tag}"}}
        after_other = await counts(ident)
        r = await c.post(f"{api}/onboarding", json=mid, headers=h)
        assert r.status_code == 409, r.text
        d = r.json()["data"]
        assert (d["step"], d["code"]) == ("pppoe", "ISP_PPPOE_USERNAME_TAKEN")
        assert await counts(ident) == after_other
        assert (await c.get(f"{api}/onboarding/options", headers=h)).json()["data"][
            "next_circuit_id"
        ] == circuit0 + 1

        # ---- 3. success: everything in one go ------------------------------------
        r = await c.post(f"{api}/onboarding", json=body, headers=h)
        assert r.status_code == 201, r.text
        out = r.json()["data"]
        done = [x["step"] for x in out["steps"] if x["status"] == "done"]
        from app.domains.isp_partner.apps_common import get_isp_apps_settings

        expected = ["subscriber", "pppoe", "mac", "kyc", "caf", "invoice", "payment"]
        if get_isp_apps_settings().enabled:  # APPS-2 install task (default on)
            expected.append("task")
        assert done == expected
        assert out["subscriber"]["circuit_id"] == circuit0 + 1
        assert out["subscriber"]["welcome"]["whatsapp_share_url"].startswith(
            "https://wa.me/91"
        )
        assert len(out["pppoe"]["password"]) >= 8
        assert out["macs"][0]["mac"] == "AA:BB:CC:00:00:01"
        assert out["kyc"]["id_number"] == "XXXX XXXX 7865"
        assert out["caf_number"]
        # the override price (400.00), not the package's 500.00; GST on top
        # unless the package price already includes it
        total = 40000 if inclusive else 47200
        assert out["invoice"]["total_paise"] == total
        assert out["payment"]["amount_paise"] == total
        assert out["invoice"]["balance_paise"] == 0
        now = await counts(ident)
        assert now["subscribers"] == 1 and now["audit"] == after_other["audit"] + 1
        assert now["invoices"] == after_other["invoices"] + 1
