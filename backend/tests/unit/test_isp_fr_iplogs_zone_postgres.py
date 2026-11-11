# ruff: noqa: E501, PLR0915 -- scenario test
"""FR-IPLOGS-ZONE on real PostgreSQL (skipped unless ``ISP_TEST_PG_DSN``). Run
with ``scripts/run_isp_pg_tests.py``. ISP_IPLOGS_SELFSERVE_ENABLED=true
CLOUDGUEST_DEVICE_LOGS_ENABLED=true

The test switches ISP_WORKFLOW_ENABLED / ISP_ZONES_ENABLED itself.

World (as FR-GENERATE): ISP A with zones ZA and ZB; customers cA (profile ZA),
cB (profile ZB) and cS (profile ZB, with a ZA subscriber: a shared site FA can
*see*), one router each; ISP B with its own router. Franchisee FA holds ZA.

Covers:
* FA turns IP logs on and off on cA's router (200), and its status says
  ``can_change: true``;
* FA on cB's router (other zone), cS's router (shared site) and ISP B's
  router: enable / disable are 404 ``ISP_ROUTER_NOT_FOUND``, never 403, and
  nothing is recorded; cS's read-only status still answers, with
  ``can_change: false``; the fleet list marks rows the same way;
* the owner is unchanged (enable/disable on every own-ISP router, no
  ``can_change`` key) and ISP B's router stays 404 for the owner;
* once the owner links cS's router to ZA, FA may change it.
"""

from __future__ import annotations

import os
import uuid

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


async def _router(w, cust: str, n: int) -> str:
    from app.database.session import SessionLocal
    from app.domains.location.models import Location
    from app.domains.router.models import Router

    async with SessionLocal() as s:
        loc = Location(
            organization_id=uuid.UUID(cust),
            name=f"FI Site{n}",
            slug=f"fi{n}{w.tag}",
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
            name=f"FI R{n}",
            serial_number=f"SNFI{n}{w.tag}",
            mac_address=f"06:4{n}:{w.tag[0:2]}:{w.tag[2:4]}:{w.tag[4:6]}:{w.tag[6:8]}",
            model="hEX",
            vendor="mikrotik",
            status="pending_provisioning",
            settings={},
        )
        s.add(r)
        await s.commit()
        return str(r.id)


async def _wanted(rid: str) -> bool | None:
    from app.database.session import SessionLocal
    from app.domains.isp_partner.iplogs_default import ip_logs_wanted

    async with SessionLocal() as s:
        return (await ip_logs_wanted(s, [uuid.UUID(rid)])).get(uuid.UUID(rid))


async def test_franchisee_iplogs_switch_own_zone_only(monkeypatch) -> None:  # noqa: ANN001
    import httpx

    from .isp_small_pg_helpers import Api, customer, dispose, make_world, package

    monkeypatch.setenv("ISP_WORKFLOW_ENABLED", "true")
    monkeypatch.setenv("ISP_ZONES_ENABLED", "true")
    _clear()
    try:
        w = await make_world(extra_users_on_a={"FA": "isp-franchisee"})
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=w.app), base_url="http://t"
        ) as c:
            api = Api(c, w)
            za = (await api.post("/zones/tree", {"name": f"FIZA{w.tag}"}))["id"]
            zb = (await api.post("/zones/tree", {"name": f"FIZB{w.tag}"}))["id"]
            ca = await customer(api, "A", "FiA")
            cb = await customer(api, "A", "FiB")
            cs = await customer(api, "A", "FiS")
            cx = await customer(api, "B", "FiX")
            for cid, z in ((ca, za), (cb, zb), (cs, zb)):
                await api.patch(f"/customers/{cid}", {"zone_id": z})
            p1 = await package(api, "A", price=50000, name="FiOne")
            await api.post(
                "/subscribers",
                {
                    "isp_customer_id": cs,
                    "identifier": f"fis{w.tag}",
                    "package_id": p1,
                    "first_name": "S",
                    "state_code": "07",
                    "zone_id": za,
                },
            )
            ra = await _router(w, ca, 1)
            rb = await _router(w, cb, 2)
            rs = await _router(w, cs, 3)
            rx = await _router(w, cx, 4)
            fa = str(w.users["FA"])
            await api.put(f"/workflow/franchisees/{fa}/zones", {"zone_ids": [za]})

            # ---- own zone: on, off, status says it may change
            st = await api.post(f"/routers/{ra}/ip-logs/enable", who="FA")
            assert st["switch_on"] is True and st["can_change"] is True, st
            assert await _wanted(ra) is True
            st = await api.post(f"/routers/{ra}/ip-logs/disable", who="FA")
            assert st["switch_on"] is False, st
            assert await _wanted(ra) is False
            st = await api.get(f"/routers/{ra}/ip-logs", who="FA")
            assert st["can_change"] is True

            # ---- other zone / shared site / other ISP: 404, never 403
            for rid in (rb, rs, rx):
                for verb in ("enable", "disable"):
                    body = await api.post(
                        f"/routers/{rid}/ip-logs/{verb}", who="FA", code=404
                    )
                    assert "ISP_ROUTER_NOT_FOUND" in str(body), body
                assert await _wanted(rid) is None
            # read-only status of the shared site is kept, marked read-only
            st = await api.get(f"/routers/{rs}/ip-logs", who="FA")
            assert st["can_change"] is False, st
            await api.get(f"/routers/{rb}/ip-logs", who="FA", code=404)
            fleet = await api.get("/ip-logs/routers", who="FA")
            rows = {i["isp_router_id"]: i for i in fleet["items"]}
            assert rows[ra]["can_change"] is True
            assert rows[rs]["can_change"] is False
            assert rb not in rows and rx not in rows

            # ---- owner unchanged: every own-ISP router, no new key
            for rid in (ra, rb, rs):
                st = await api.post(f"/routers/{rid}/ip-logs/enable")
                assert "can_change" not in st, st
                await api.post(f"/routers/{rid}/ip-logs/disable")
            fleet = await api.get("/ip-logs/routers")
            assert all("can_change" not in i for i in fleet["items"])
            await api.post(f"/routers/{rx}/ip-logs/enable", code=404)

            # ---- the owner links cS's router to ZA: now inside FA's zones
            await api.put(f"/workflow/routers/{rs}/zones", {"zone_ids": [za, zb]})
            st = await api.post(f"/routers/{rs}/ip-logs/enable", who="FA")
            assert st["switch_on"] is True and st["can_change"] is True, st
            await api.post(f"/routers/{rs}/ip-logs/disable", who="FA")
            # still nothing on cB / ISP B
            await api.post(f"/routers/{rb}/ip-logs/enable", who="FA", code=404)
            await api.post(f"/routers/{rx}/ip-logs/enable", who="FA", code=404)
    finally:
        _clear()
        await dispose()
