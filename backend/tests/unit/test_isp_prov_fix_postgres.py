# ruff: noqa: E501, PLR0915 -- scenario test
"""PROV-FIX on real PostgreSQL (skipped unless ``ISP_TEST_PG_DSN``). Run with
``scripts/run_isp_pg_tests.py``. ISP_PROV_FIX_ENABLED=true

The test switches ISP_WORKFLOW_ENABLED / ISP_ZONES_ENABLED itself.

1. New partner routes are ISP-confined: ISP B's owner gets 404 on ISP A's
   router for ``/monitoring``, ``/monitoring/enable|disable`` and
   ``/setup/check-in``; A's technician may not switch monitoring (403); a
   check-in with B's token on A's router is refused before anything is
   allocated.
2. Item 9: on a customer shared by zones ZA and ZB, franchisee FA sees only
   ZA's subscriber's payments (``/billing/payments``), FB only ZB's; a payment
   with no subscriber keeps the customer narrowing (both see it); the owner
   sees all of them.
3. Item 10: a coupon batch an owner made before the zone was recorded (no
   row) stays visible to both franchisees; a batch FA makes on the shared
   customer is recorded in ZA, listed for FA and the owner, and is a 404 for
   FB (list and detail).
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)


def _clear() -> None:
    from app.domains.isp_partner.prov_fix_router import get_prov_fix_settings
    from app.domains.isp_partner.workflow_config import get_workflow_settings
    from app.domains.isp_partner.zones_config import get_zones_settings

    get_workflow_settings.cache_clear()
    get_zones_settings.cache_clear()
    get_prov_fix_settings.cache_clear()


async def _router(w, cust: str, n: int) -> tuple[str, str]:
    from app.database.session import SessionLocal
    from app.domains.location.models import Location
    from app.domains.router.models import Router

    async with SessionLocal() as s:
        loc = Location(
            organization_id=uuid.UUID(cust),
            name=f"PF Site{n}",
            slug=f"pf{n}{w.tag}",
            address_line1="1",
            city="c",
            state_province="s",
            postal_code="1",
            country="IN",
            settings={},
        )
        s.add(loc)
        await s.flush()
        r = Router(
            location_id=loc.id,
            organization_id=uuid.UUID(cust),
            name=f"PF R{n}",
            serial_number=f"SNPF{n}{w.tag}",
            mac_address=f"06:2{n}:{w.tag[0:2]}:{w.tag[2:4]}:{w.tag[4:6]}:{w.tag[6:8]}",
            model="hEX",
            vendor="mikrotik",
            status="pending_provisioning",
            settings={},
        )
        s.add(r)
        await s.commit()
        return str(r.id), str(loc.id)


async def _payment(w, isp: str, cust: str, sub: str | None, n: int) -> str:
    from app.database.session import SessionLocal
    from app.domains.isp_partner.billing_models import IspPayment

    async with SessionLocal() as s:
        p = IspPayment(
            isp_organization_id=uuid.UUID(isp),
            customer_organization_id=uuid.UUID(cust),
            subscriber_id=uuid.UUID(sub) if sub else None,
            amount_paise=1000 + n,
            unallocated_paise=1000 + n,
            mode="cash",
            reference=f"pf{n}",
            received_at=datetime.now(UTC),
            receipt_fy="2627",
            receipt_seq=9000 + n,
            receipt_number=f"PF/{w.tag}/{n}",
            status="active",
        )
        s.add(p)
        await s.commit()
        return str(p.id)


async def test_prov_fix_scoping(monkeypatch) -> None:  # noqa: ANN001, C901
    import httpx

    from .isp_small_pg_helpers import Api, customer, dispose, make_world, package

    monkeypatch.setenv("ISP_PROV_FIX_ENABLED", "true")
    monkeypatch.setenv("ISP_WORKFLOW_ENABLED", "true")
    monkeypatch.setenv("ISP_ZONES_ENABLED", "true")
    _clear()
    try:
        w = await make_world(
            extra_users_on_a={
                "FA": "isp-franchisee",
                "FB": "isp-franchisee",
                "tech": "isp-technician",
            }
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=w.app), base_url="http://t"
        ) as c:
            api = Api(c, w)

            # ---- 1. new partner routes: cross-ISP + role
            ca = await customer(api, "A", "PfA")
            cb_other = await customer(api, "B", "PfB")
            ra, _ = await _router(w, ca, 1)
            rb, _ = await _router(w, cb_other, 2)
            assert (await api.get("/setup-fixes"))["check_in_fallback"] is True
            m = await api.get(f"/routers/{ra}/monitoring")
            assert m["enabled"] is False and m["can_change"] is True
            await api.get(f"/routers/{ra}/monitoring", who="B", code=404)
            await api.post(f"/routers/{ra}/monitoring/enable", who="B", code=404)
            await api.post(f"/routers/{ra}/monitoring/disable", who="B", code=404)
            await api.post(
                f"/routers/{ra}/setup/check-in", {"token": "x" * 20}, who="B", code=404
            )
            await api.post(f"/routers/{ra}/monitoring/enable", who="tech", code=403)
            assert (await api.get(f"/routers/{ra}/monitoring", who="tech"))[
                "can_change"
            ] is False
            # B's own token presented on A's router path: still 404 (scope first)
            tok_b = (await api.post(f"/routers/{rb}/provisioning-token", who="B"))[
                "token"
            ]
            await api.post(
                f"/routers/{ra}/setup/check-in", {"token": tok_b}, who="B", code=404
            )
            # A presenting B's token on A's router: refused, nothing allocated
            body = await api.post(
                f"/routers/{ra}/setup/check-in", {"token": tok_b}, code=409
            )
            assert "ISP_SETUP_TOKEN_MISMATCH" in str(body), body

            # ---- world for items 9 / 10
            za = (await api.post("/zones/tree", {"name": f"PZA{w.tag}"}))["id"]
            zb = (await api.post("/zones/tree", {"name": f"PZB{w.tag}"}))["id"]
            cs = await customer(api, "A", "PfShared")
            await api.patch(f"/customers/{cs}", {"zone_id": zb})
            await _router(w, cs, 3)
            p1 = await package(api, "A", price=50000, name="PfOne")

            # ---- [POSTFIX-1] package policy summaries: own ISP only
            await api.put(
                f"/packages/{p1}/policy",
                {
                    "fup_limit_mb": 3000000,
                    "fup_reset": "cycle",
                    "fup_fallback_speed_group_id": None,
                    "fup_exclude_upload": False,
                    "fup_carry_forward": False,
                    "boost_speed_group_id": None,
                    "boost_start_minute": None,
                    "boost_end_minute": None,
                    "validity_starts": "first_login",
                    "queue_priority": None,
                    "mac_bind_count": 0,
                    "mac_restriction": False,
                    "ip_restriction": False,
                    "max_simultaneous": None,
                    "idle_timeout_s": None,
                    "hard_timeout_s": None,
                },
            )
            mine = {
                i["package_id"]: i
                for i in (await api.get("/package-policy-summaries"))["items"]
            }
            assert mine[p1]["fup_limit_mb"] == 3000000, mine
            assert mine[p1]["validity_starts"] == "first_login"
            theirs = (await api.get("/package-policy-summaries", who="B"))["items"]
            assert p1 not in {i["package_id"] for i in theirs}

            async def sub(cust, zone, ident):
                return (
                    await api.post(
                        "/subscribers",
                        {
                            "isp_customer_id": cust,
                            "identifier": f"{ident}{w.tag}",
                            "package_id": p1,
                            "first_name": ident,
                            "state_code": "07",
                            "zone_id": zone,
                        },
                    )
                )["id"]

            s_sa = await sub(cs, za, "pfa")  # shared site, zone A
            s_sb = await sub(cs, zb, "pfb")  # shared site, zone B
            fa, fb = str(w.users["FA"]), str(w.users["FB"])
            await api.put(f"/workflow/franchisees/{fa}/zones", {"zone_ids": [za]})
            await api.put(f"/workflow/franchisees/{fb}/zones", {"zone_ids": [zb]})

            # ---- 2. item 9: subscriber-keyed rows follow the zone
            isp_a = str(w.isps["A"])
            pay_a = await _payment(w, isp_a, cs, s_sa, 1)
            pay_b = await _payment(w, isp_a, cs, s_sb, 2)
            pay_none = await _payment(w, isp_a, cs, None, 3)

            async def pays(who):
                return {
                    p["id"]
                    for p in (
                        await api.get(
                            "/billing/payments",
                            who=who,
                            params={"page_size": 100, "isp_customer_id": cs},
                        )
                    )["items"]
                }

            assert await pays("A") == {pay_a, pay_b, pay_none}
            assert await pays("FA") == {pay_a, pay_none}, await pays("FA")
            assert await pays("FB") == {pay_b, pay_none}, await pays("FB")

            # ---- 3. item 10: coupon batch zone
            monkeypatch.setenv("ISP_WORKFLOW_ENABLED", "false")
            _clear()  # an "old" batch: made before zones were recorded
            old = await api.post(
                "/coupon-batches",
                {"package_id": p1, "isp_customer_id": cs, "quantity": 1},
            )
            monkeypatch.setenv("ISP_WORKFLOW_ENABLED", "true")
            _clear()
            mine = await api.post(
                "/coupon-batches",
                {"package_id": p1, "isp_customer_id": cs, "quantity": 1},
                who="FA",
            )

            async def batches(who):
                return {
                    b["id"]
                    for b in (
                        await api.get(
                            "/coupon-batches",
                            who=who,
                            params={"page_size": 100, "isp_customer_id": cs},
                        )
                    )["items"]
                }

            assert await batches("A") == {old["id"], mine["id"]}
            assert await batches("FA") == {old["id"], mine["id"]}
            assert await batches("FB") == {old["id"]}, await batches("FB")
            await api.get(f"/coupon-batches/{mine['id']}", who="FB", code=404)
            await api.get(f"/coupon-batches/{mine['id']}", who="FA")
            await api.get(f"/coupon-batches/{old['id']}", who="FB")

            from sqlalchemy import select

            from app.database.session import SessionLocal
            from app.domains.isp_partner.prov_fix_zone import IspCouponBatchZone

            async with SessionLocal() as s:
                rows = (await s.execute(select(IspCouponBatchZone))).scalars().all()
                by_batch = {str(r.coupon_batch_id): str(r.zone_id) for r in rows}
            assert by_batch.get(mine["id"]) == za, by_batch
            assert old["id"] not in by_batch
    finally:
        _clear()
        await dispose()
