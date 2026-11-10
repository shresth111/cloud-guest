# ruff: noqa: E501, PLR0915 -- scenario test
"""DECISIONS-1: a franchisee adds a router at a site inside its zones, on real
PostgreSQL (skipped unless ``ISP_TEST_PG_DSN``). Run with
``scripts/run_isp_pg_tests.py``. The test switches ISP_WORKFLOW_ENABLED /
ISP_ZONES_ENABLED itself (env + cache_clear).

World: ISP A with zones ZA (child ZA1) and ZB; customers cA (profile ZA1), cB
(profile ZB) and cS (profile ZB, a subscriber in ZA: shared site), one
location each, created by the owner. Franchisee FA holds ZA, FB holds ZB.
ISP B has its own customer + location.

Covers:
* FA lists only cA's site for "Add router" (not cB, not the shared cS while no
  router there serves ZA, never ISP B's);
* FA adds a router at cA's site: 201, linked to ZA1 (the site's profile zone)
  in isp_router_zones, visible in FA's router list and under ZA1's routers;
* FA cannot add a router at FB's site (cB), at the shared cS site, at ISP B's
  site, or link it to ZB (zone_ref outside its subtree): all 404, nothing
  written;
* once the owner links a cS router to ZA, FA may add a router at cS too
  (linked to ZA), and FB still may (cS profile zone is ZB);
* FA still cannot create a customer or a location, or use the owner's router
  route (403); an owner calling the franchisee route gets 403;
* flag off: the franchisee route is 404.
"""

from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)


def _clear() -> None:
    from app.domains.isp_partner.workflow_config import get_workflow_settings
    from app.domains.isp_partner.zones_config import get_zones_settings

    get_workflow_settings.cache_clear()
    get_zones_settings.cache_clear()


def _loc_body(name: str, tag: str) -> dict:
    return {
        "name": name,
        "slug": f"{name.lower()}-{tag}",
        "address_line1": "1 Main Rd",
        "city": "Noida",
        "state_province": "UP",
        "postal_code": "201301",
    }


async def test_franchisee_adds_router_in_own_zone_only(monkeypatch) -> None:  # noqa: ANN001, C901
    import httpx
    from sqlalchemy import func, select

    from app.database.session import SessionLocal
    from app.domains.isp_partner.workflow_models import IspRouterZone
    from app.domains.router.models import Router

    from .isp_small_pg_helpers import Api, customer, dispose, make_world, package

    monkeypatch.setenv("ISP_WORKFLOW_ENABLED", "true")
    monkeypatch.setenv("ISP_ZONES_ENABLED", "true")
    _clear()
    try:
        w = await make_world(
            extra_users_on_a={"FA": "isp-franchisee", "FB": "isp-franchisee"}
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=w.app), base_url="http://t"
        ) as c:
            api = Api(c, w)
            n = iter(range(10, 99))

            def rbody(**extra):
                i = next(n)
                t = w.tag
                return {
                    "name": f"FR{i}",
                    "serial_number": f"SNDEC{i}{t}",
                    "mac_address": f"06:2{i % 10}:{t[0:2]}:{t[2:4]}:{t[4:6]}:{t[6:8]}",
                    "model": "hEX",
                    **extra,
                }

            async def router_count() -> int:
                async with SessionLocal() as s:
                    return (
                        await s.execute(
                            select(func.count())
                            .select_from(Router)
                            .where(Router.serial_number.like(f"SNDEC%{w.tag}"))
                        )
                    ).scalar_one()

            async def links(rid: str) -> set[str]:
                async with SessionLocal() as s:
                    return {
                        str(z)
                        for z in (
                            await s.execute(
                                select(IspRouterZone.zone_id).where(
                                    IspRouterZone.router_id == uuid.UUID(rid)
                                )
                            )
                        ).scalars()
                    }

            za = (await api.post("/zones/tree", {"name": f"ZA{w.tag}"}))["id"]
            za1 = (
                await api.post("/zones/tree", {"name": f"ZA1{w.tag}", "parent_id": za})
            )["id"]
            zb = (await api.post("/zones/tree", {"name": f"ZB{w.tag}"}))["id"]
            ca = await customer(api, "A", "DCa")
            cb = await customer(api, "A", "DCb")
            cs = await customer(api, "A", "DCs")
            cx = await customer(api, "B", "DCx")
            for cid, z in ((ca, za1), (cb, zb), (cs, zb)):
                await api.patch(f"/customers/{cid}", {"zone_id": z})
            la = (await api.post(f"/customers/{ca}/locations", _loc_body("La", w.tag)))[
                "id"
            ]
            lb = (await api.post(f"/customers/{cb}/locations", _loc_body("Lb", w.tag)))[
                "id"
            ]
            ls = (await api.post(f"/customers/{cs}/locations", _loc_body("Ls", w.tag)))[
                "id"
            ]
            lx = (
                await api.post(
                    f"/customers/{cx}/locations", _loc_body("Lx", w.tag), who="B"
                )
            )["id"]
            p1 = await package(api, "A", price=50000, name="One")
            # shared site: a ZA subscriber on cS (so FA can *see* cS)
            await api.post(
                "/subscribers",
                {
                    "isp_customer_id": cs,
                    "identifier": f"dss{w.tag}",
                    "package_id": p1,
                    "first_name": "S",
                    "state_code": "07",
                    "zone_id": za,
                },
            )
            fa, fb = str(w.users["FA"]), str(w.users["FB"])
            await api.put(f"/workflow/franchisees/{fa}/zones", {"zone_ids": [za]})
            await api.put(f"/workflow/franchisees/{fb}/zones", {"zone_ids": [zb]})

            # ---- the picker lists only sites inside FA's zones
            sites = (await api.get("/workflow/franchisee/router-sites", who="FA"))[
                "items"
            ]
            assert [s["isp_location_id"] for s in sites] == [la], sites
            assert sites[0]["zone"]["id"] == za1
            sites_b = (await api.get("/workflow/franchisee/router-sites", who="FB"))[
                "items"
            ]
            assert {s["isp_location_id"] for s in sites_b} == {lb, ls}, sites_b
            # owner is not a franchisee: 403 on both routes
            await api.get("/workflow/franchisee/router-sites", code=403)
            await api.post(
                f"/workflow/franchisee/sites/{la}/routers", rbody(), code=403
            )

            # ---- FA adds a router at its own site
            made = await api.post(
                f"/workflow/franchisee/sites/{la}/routers", rbody(), who="FA"
            )
            rid = made["id"]
            assert made["isp_location_id"] == la and made["isp_customer_id"] == ca
            assert [z["id"] for z in made["zones"]] == [za1]
            assert await links(rid) == {za1}
            mine = (await api.get("/routers", who="FA", params={"page_size": 100}))[
                "items"
            ]
            assert rid in {r["id"] for r in mine}
            zr = await api.get(f"/workflow/zones/{za1}/routers", who="FA")
            assert [i["isp_router_id"] for i in zr["items"]] == [rid]
            # explicit zone_ref inside the subtree is honoured
            made2 = await api.post(
                f"/workflow/franchisee/sites/{la}/routers", rbody(zone_ref=za), who="FA"
            )
            assert await links(made2["id"]) == {za}
            assert await router_count() == 2

            # ---- refused: FB's site, shared site (no ZA router yet), other ISP,
            #      a zone outside the subtree. Nothing is written.
            await api.post(
                f"/workflow/franchisee/sites/{lb}/routers", rbody(), who="FA", code=404
            )
            await api.post(
                f"/workflow/franchisee/sites/{ls}/routers", rbody(), who="FA", code=404
            )
            await api.post(
                f"/workflow/franchisee/sites/{lx}/routers", rbody(), who="FA", code=404
            )
            await api.post(
                f"/workflow/franchisee/sites/{la}/routers",
                rbody(zone_ref=zb),
                who="FA",
                code=404,
            )
            await api.post(
                f"/workflow/franchisee/sites/{la}/routers", rbody(), who="FB", code=404
            )
            assert await router_count() == 2

            # ---- FA still cannot create customers / locations / use owner route
            await api.post(
                "/customers",
                {"name": f"New {w.tag}", "contact_email": f"dn{w.tag}@example.com"},
                who="FA",
                code=403,
            )
            await api.post(
                f"/customers/{ca}/locations",
                _loc_body("Lnew", w.tag),
                who="FA",
                code=403,
            )
            await api.post(f"/locations/{la}/routers", rbody(), who="FA", code=403)
            assert await router_count() == 2

            # ---- shared site: once a cS router serves ZA, FA may add there
            r_fb = await api.post(
                f"/workflow/franchisee/sites/{ls}/routers", rbody(), who="FB"
            )
            assert await links(r_fb["id"]) == {zb}
            await api.put(
                f"/workflow/routers/{r_fb['id']}/zones", {"zone_ids": [za, zb]}
            )
            sites = (await api.get("/workflow/franchisee/router-sites", who="FA"))[
                "items"
            ]
            assert {s["isp_location_id"] for s in sites} == {la, ls}
            r_fa = await api.post(
                f"/workflow/franchisee/sites/{ls}/routers", rbody(), who="FA"
            )
            assert await links(r_fa["id"]) == {za}
            assert await router_count() == 4

            # ---- flag off: route gone
            monkeypatch.setenv("ISP_WORKFLOW_ENABLED", "false")
            _clear()
            await api.post(
                f"/workflow/franchisee/sites/{la}/routers", rbody(), code=404
            )
    finally:
        _clear()
        await dispose()
