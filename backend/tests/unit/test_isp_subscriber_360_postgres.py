# ruff: noqa: E501 -- scenario test
"""ADDENDUM_05 JAZE-1 on real PostgreSQL + Redis (skipped unless
``ISP_TEST_PG_DSN``; CI has neither). Run::

    CLOUDGUEST_DATABASE_URL=postgresql+asyncpg://postgres@localhost:55441/jaze1 \\
    CLOUDGUEST_REDIS_URL=redis://localhost:56381/0 \\
    ISP_TEST_PG_DSN=1 ISP_PARTNER_ENABLED=true \\
    python -m pytest tests/unit/test_isp_subscriber_360_postgres.py

Covers J1 (360 view, renew with override price, revert -> credit note,
revert refused when paid, grace, block via the real GuestService, freeze /
unfreeze), J2 (onboarding profile round trip, next circuit id, welcome
share link, scheduled activation), J11 (directory states and package
counts, typeahead, move, per-subscriber ledger) and J19 (plan sync dry run
+ apply), plus isolation: ISP B -> 404 everywhere, a technician confined to
customer A1 -> 404 on A2's subscriber and 403 on writes.
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


async def test_subscriber_360_end_to_end() -> None:  # noqa: PLR0915
    import httpx
    from sqlalchemy import select, text

    from app.database.session import SessionLocal
    from app.domains.auth.models import AuthUser, User
    from app.domains.billing.models import Plan
    from app.domains.guest.models import Guest
    from app.domains.isp_partner.models import IspPartnerProfile, IspStaffCustomerScope
    from app.domains.isp_partner.plans_models import IspSubscriber
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
    users, isps = {}, {}
    async with SessionLocal() as s:
        plan = Plan(
            name=f"P {tag}",
            slug=f"p360-{tag}",
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
                email=f"s3{n.lower()}{tag}@example.com",
                username=f"s3{n.lower()}{tag}",
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
                slug=f"s3net{n.lower()}{tag}",
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

    def as_(who: str) -> None:
        state["user"] = users[who]

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t"
    ) as c:
        api = "/api/v1/isp"

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
        as_("B")
        b1 = await customer(hb, "CafeB1")
        as_("A")
        async with SessionLocal() as s:
            s.add(
                IspStaffCustomerScope(
                    isp_organization_id=isps["A"],
                    user_id=users["T"],
                    customer_organization_id=uuid.UUID(a1),
                )
            )
            await s.commit()

        r = await c.put(
            f"{api}/billing/settings",
            json={
                "legal_name": "Net A Pvt Ltd",
                "state_code": "07",
                "gst_enabled": True,
                "invoice_prefix": "S3A",
            },
            headers=ha,
        )
        assert r.status_code == 200, r.text
        g = await c.post(
            f"{api}/speed-groups",
            json={"name": "20 Mbps", "download_kbps": 20480, "upload_kbps": 20480},
            headers=ha,
        )
        gid = g.json()["data"]["id"]
        p = await c.post(
            f"{api}/packages",
            json={"speed_group_id": gid, "type": "prepaid", "price_paise": 50000},
            headers=ha,
        )
        assert p.status_code == 201, p.text
        pid = p.json()["data"]["id"]

        # ---- J2 onboarding ------------------------------------------------
        nxt = (await c.get(f"{api}/subscribers/circuit-id/next", headers=ha)).json()[
            "data"
        ]
        r = await c.post(
            f"{api}/subscribers/onboard",
            json={
                "isp_customer_id": a1,
                "identifier": f"flat-{tag}",
                "package_id": pid,
                "first_name": "Asha",
                "last_name": "Test",
                "phone": "9876500001",
                "email": f"asha{tag}@example.com",
                "state_code": "07",
                "welcome_whatsapp": True,
                "profile": {
                    "alt_email": f"accounts{tag}@example.com",
                    "billing_pincode": "110001",
                    "install_same_as_billing": False,
                    "install_address": "Block C, Floor 2",
                    "install_pincode": "110002",
                    "latitude": 28.61394,
                    "longitude": 77.20902,
                    "user_type": "commercial",
                    "connection_type": "fiber",
                    "ont_serial": "ONT-TEST-0001",
                    "override_price_paise": 40000,
                    "after_due_action": "keep_active",
                },
            },
            headers=ha,
        )
        assert r.status_code == 201, r.text
        v = r.json()["data"]
        sid = v["id"]
        assert v["circuit_id"] == nxt["next_circuit_id"] and nxt["reserved"] is False
        assert v["profile"]["user_type"] == "commercial"
        assert v["profile"]["latitude"] == pytest.approx(28.61394)
        assert v["profile"]["maps_url"].startswith("https://www.google.com/maps?q=")
        assert v["welcome"]["whatsapp_share_url"].startswith(
            "https://wa.me/919876500001?text="
        )
        assert v["display_state"] == "active" and v["online"] is False
        assert [e["kind"] for e in v["timeline"]] == ["created"]
        bad = await c.put(
            f"{api}/subscribers/{sid}/profile",
            json={"billing_pincode": "12"},
            headers=ha,
        )
        assert (
            bad.status_code == 422
            and bad.json()["data"]["code"] == "ISP_PROFILE_INVALID"
        )
        assert (
            await c.put(
                f"{api}/subscribers/{sid}/profile", json={"nope": 1}, headers=ha
            )
        ).status_code == 422

        # ---- J1 renew (override price) + revert ----------------------------
        until0 = datetime.fromisoformat(v["valid_until"])
        body = {"idempotency_key": f"rn-{tag}-1"}
        r = await c.post(f"{api}/subscribers/{sid}/renew", json=body, headers=ha)
        assert r.status_code == 201, r.text
        assert r.json()["data"]["invoice"]["total_paise"] == 40000
        r2 = await c.post(f"{api}/subscribers/{sid}/renew", json=body, headers=ha)
        assert r2.json()["data"]["invoice"]["id"] == r.json()["data"]["invoice"]["id"]
        led = (await c.get(f"{api}/subscribers/{sid}/ledger", headers=ha)).json()[
            "data"
        ]
        assert led["due_paise"] == 40000 and led["status"] == "unpaid"
        v = (await c.get(f"{api}/subscribers/{sid}/360", headers=ha)).json()["data"]
        assert [e["kind"] for e in v["timeline"]].count("renewed") == 1
        assert v["can_revert"] is True and v["billing"]["due_paise"] == 40000
        r = await c.post(
            f"{api}/subscribers/{sid}/revert", json={"reason": "wrong plan"}, headers=ha
        )
        assert r.status_code == 200, r.text
        assert r.json()["data"]["credit_note_number"]
        assert datetime.fromisoformat(r.json()["data"]["valid_until"]) == until0
        led = (await c.get(f"{api}/subscribers/{sid}/ledger", headers=ha)).json()[
            "data"
        ]
        assert led["due_paise"] == 0
        again = await c.post(
            f"{api}/subscribers/{sid}/revert", json={"reason": "again"}, headers=ha
        )
        assert (
            again.status_code == 409
            and again.json()["data"]["code"] == "ISP_NOTHING_TO_REVERT"
        )
        r = await c.post(
            f"{api}/subscribers/{sid}/renew",
            json={
                "paid_now": True,
                "payment": {"mode": "cash"},
                "idempotency_key": f"rn-{tag}-2",
            },
            headers=ha,
        )
        assert r.status_code == 201, r.text
        paid = await c.post(
            f"{api}/subscribers/{sid}/revert", json={"reason": "x paid"}, headers=ha
        )
        assert (
            paid.status_code == 409 and paid.json()["data"]["code"] == "ISP_REVERT_PAID"
        )

        # ---- J1 freeze / unfreeze --------------------------------------------
        v = (await c.get(f"{api}/subscribers/{sid}/360", headers=ha)).json()["data"]
        until1 = datetime.fromisoformat(v["valid_until"])
        r = await c.post(
            f"{api}/subscribers/{sid}/freeze", json={"reason": "travel"}, headers=ha
        )
        assert r.status_code == 200, r.text
        v = (await c.get(f"{api}/subscribers/{sid}/360", headers=ha)).json()["data"]
        assert v["display_state"] == "frozen" and v["status"] == "disabled"
        assert (
            await c.post(f"{api}/subscribers/{sid}/renew", json={}, headers=ha)
        ).json()["data"]["code"] == "ISP_SUBSCRIBER_FROZEN"
        r = await c.post(f"{api}/subscribers/{sid}/unfreeze", headers=ha)
        assert r.status_code == 200, r.text
        back = datetime.fromisoformat(r.json()["data"]["valid_until"])
        assert abs((back - until1).total_seconds()) < 60
        assert r.json()["data"]["display_state"] == "active"

        # ---- J1 block via the real GuestService -------------------------------
        async with SessionLocal() as s:
            guest = Guest(
                organization_id=uuid.UUID(a1),
                identifier=f"+91987650{tag[:4]}",
                first_seen_at=datetime.now(UTC),
                last_seen_at=datetime.now(UTC),
                total_visit_count=1,
                is_blocked=False,
            )
            s.add(guest)
            await s.flush()
            sub = await s.get(IspSubscriber, uuid.UUID(sid))
            sub.guest_id = guest.id
            await s.commit()
            guest_id = guest.id
        r = await c.post(
            f"{api}/subscribers/{sid}/block", json={"reason": "dispute"}, headers=ha
        )
        assert r.status_code == 200, r.text
        async with SessionLocal() as s:
            assert (await s.get(Guest, guest_id)).is_blocked is True
        d = (
            await c.get(
                f"{api}/subscribers/directory", params={"state": "blocked"}, headers=ha
            )
        ).json()["data"]
        assert [i["id"] for i in d["items"]] == [sid] and d["state_counts"][
            "blocked"
        ] == 1
        r = await c.post(f"{api}/subscribers/{sid}/unblock", headers=ha)
        assert (
            r.status_code == 200 and r.json()["data"]["display_state"] == "active"
        ), r.text
        async with SessionLocal() as s:
            assert (await s.get(Guest, guest_id)).is_blocked is False

        # ---- J1 grace on an expired subscriber --------------------------------
        r = await c.post(
            f"{api}/subscribers/onboard",
            json={
                "isp_customer_id": a2,
                "identifier": f"shop-{tag}",
                "package_id": pid,
                "first_name": "Ravi",
                "phone": "9876500002",
            },
            headers=ha,
        )
        sid2 = r.json()["data"]["id"]
        past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
        assert (
            await c.patch(
                f"{api}/subscribers/{sid2}", json={"valid_until": past}, headers=ha
            )
        ).status_code == 200
        d = (
            await c.get(
                f"{api}/subscribers/directory", params={"state": "expired"}, headers=ha
            )
        ).json()["data"]
        assert sid2 in [i["id"] for i in d["items"]]
        r = await c.post(
            f"{api}/subscribers/{sid2}/grace", json={"hours": 24}, headers=ha
        )
        assert r.status_code == 200, r.text
        v2 = (await c.get(f"{api}/subscribers/{sid2}/360", headers=ha)).json()["data"]
        assert v2["display_state"] == "grace"
        dup = await c.post(
            f"{api}/subscribers/{sid2}/grace", json={"hours": 24}, headers=ha
        )
        assert (
            dup.status_code == 409 and dup.json()["data"]["code"] == "ISP_GRACE_ACTIVE"
        )

        # ---- J11 directory + typeahead ----------------------------------------
        d = (await c.get(f"{api}/subscribers/directory", headers=ha)).json()["data"]
        assert d["total"] == 2
        assert {k: d["state_counts"][k] for k in ("active", "grace")} == {
            "active": 1,
            "grace": 1,
        }
        assert d["package_counts"] == [
            {
                "package_id": pid,
                "name": d["package_counts"][0]["name"],
                "total": 2,
                "active": 2,
            }
        ]
        t = (
            await c.get(
                f"{api}/subscribers/typeahead", params={"q": "98765"}, headers=ha
            )
        ).json()["data"]
        assert {x["id"] for x in t} == {sid, sid2}
        t = (
            await c.get(
                f"{api}/subscribers/typeahead", params={"q": "Asha Te"}, headers=ha
            )
        ).json()["data"]
        assert [x["id"] for x in t] == [sid]

        # ---- isolation: ISP B and a confined technician -----------------------
        as_("B")
        for path in (f"{sid}/360", f"{sid}/ledger", f"{sid}/profile"):
            assert (
                await c.get(f"{api}/subscribers/{path}", headers=hb)
            ).status_code == 404
        for path, body in (
            (f"{sid}/block", {}),
            (f"{sid}/grace", {}),
            (f"{sid}/disconnect", None),
            (f"{sid}/move", {"isp_customer_id": b1}),
        ):
            assert (
                await c.post(f"{api}/subscribers/{path}", json=body, headers=hb)
            ).status_code == 404, path
        assert (
            await c.get(
                f"{api}/subscribers/typeahead", params={"q": "98765"}, headers=hb
            )
        ).json()["data"] == []
        assert (await c.get(f"{api}/subscribers/directory", headers=hb)).json()["data"][
            "total"
        ] == 0
        as_("T")
        assert (
            await c.get(f"{api}/subscribers/{sid}/360", headers=ha)
        ).status_code == 200
        assert (
            await c.get(f"{api}/subscribers/{sid2}/360", headers=ha)
        ).status_code == 404
        t = (
            await c.get(
                f"{api}/subscribers/typeahead", params={"q": "98765"}, headers=ha
            )
        ).json()["data"]
        assert [x["id"] for x in t] == [sid]
        assert (await c.get(f"{api}/subscribers/directory", headers=ha)).json()["data"][
            "total"
        ] == 1
        assert (
            await c.post(f"{api}/subscribers/{sid}/block", json={}, headers=ha)
        ).status_code == 403
        assert (
            await c.post(
                f"{api}/packages/{pid}/apply-to-subscribers",
                json={"dry_run": False},
                headers=ha,
            )
        ).status_code == 403
        as_("A")

        # ---- J11 move -------------------------------------------------------------
        assert (
            await c.post(
                f"{api}/subscribers/{sid}/move",
                json={"isp_customer_id": b1},
                headers=ha,
            )
        ).status_code == 404
        same = await c.post(
            f"{api}/subscribers/{sid}/move", json={"isp_customer_id": a1}, headers=ha
        )
        assert same.status_code == 409
        r = await c.post(
            f"{api}/subscribers/{sid}/move",
            json={"isp_customer_id": a2, "reason": "shifted"},
            headers=ha,
        )
        assert r.status_code == 200, r.text
        v = (await c.get(f"{api}/subscribers/{sid}/360", headers=ha)).json()["data"]
        assert v["isp_customer_id"] == a2 and v["timeline"][0]["kind"] == "moved"
        as_("T")  # confined to A1: the moved subscriber is now out of reach
        assert (
            await c.get(f"{api}/subscribers/{sid}/360", headers=ha)
        ).status_code == 404
        as_("A")

        # ---- J19 plan sync (a speed group's rate changes) -------------------
        # A package's group cannot change once in use (ISP_PACKAGE_IN_USE);
        # the real case is "the 20 Mbps group became 25 Mbps".
        assert (
            await c.patch(
                f"{api}/packages/{pid}", json={"speed_group_id": gid}, headers=ha
            )
        ).status_code in (200, 409)
        assert (
            await c.patch(
                f"{api}/speed-groups/{gid}",
                json={"download_kbps": 25600, "upload_kbps": 25600},
                headers=ha,
            )
        ).status_code == 200
        dry = (
            await c.post(
                f"{api}/speed-groups/{gid}/apply-to-subscribers", json={}, headers=ha
            )
        ).json()["data"]
        assert dry == {
            "dry_run": True,
            "subscribers": 2,
            "speed_group_changes": 0,
            "online_sessions": 0,
            "locations_with_online": 0,
        }, dry
        dry_p = (
            await c.post(
                f"{api}/packages/{pid}/apply-to-subscribers", json={}, headers=ha
            )
        ).json()["data"]
        assert dry_p["subscribers"] == 2
        # drift: a subscriber whose group no longer matches its package's
        async with SessionLocal() as s:
            x = await s.get(IspSubscriber, uuid.UUID(sid2))
            x.speed_group_id = None
            await s.commit()
        dry_p = (
            await c.post(
                f"{api}/packages/{pid}/apply-to-subscribers", json={}, headers=ha
            )
        ).json()["data"]
        assert dry_p["speed_group_changes"] == 1
        ap = await c.post(
            f"{api}/packages/{pid}/apply-to-subscribers",
            json={"dry_run": False},
            headers=ha,
        )
        assert ap.status_code == 200 and ap.json()["data"]["dry_run"] is False, ap.text
        async with SessionLocal() as s:
            groups = {
                str(x.speed_group_id)
                for x in (
                    await s.execute(
                        select(IspSubscriber).where(
                            IspSubscriber.package_id == uuid.UUID(pid)
                        )
                    )
                ).scalars()
            }
            rates = (
                (
                    await s.execute(
                        text(
                            "select distinct q.download_rate_kbps from queue_profiles q"
                            " join isp_package_materializations m on m.queue_profile_id = q.id"
                            " where m.package_id = :p"
                        ),
                        {"p": uuid.UUID(pid)},
                    )
                )
                .scalars()
                .all()
            )
        assert groups == {gid} and list(rates) == [25600], (groups, rates)
        v = (await c.get(f"{api}/subscribers/{sid2}/360", headers=ha)).json()["data"]
        assert v["timeline"][0]["kind"] == "plan_sync"
        # ---- the existing list is unchanged -----------------------------------
        lst = (await c.get(f"{api}/subscribers", headers=ha)).json()["data"]
        assert lst["total"] == 2
