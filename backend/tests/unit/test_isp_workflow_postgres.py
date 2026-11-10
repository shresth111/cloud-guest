# ruff: noqa: E501, PLR0915 -- scenario test
"""RAKESH-FS: franchisee logins + router zones + placement on real PostgreSQL
(skipped unless ``ISP_TEST_PG_DSN``). Run with ``scripts/run_isp_pg_tests.py``.

The test switches ISP_WORKFLOW_ENABLED / ISP_ZONES_ENABLED itself (env +
cache_clear).

World: ISP A with zones ZA (child ZA1) and ZB; customers cA (profile ZA), cB
(profile ZB) and cS (profile ZB, but one subscriber in ZA: a shared site /
router). Franchisee FA holds ZA, franchisee FB holds ZB. ISP B is another ISP.

Covers: flags off -> franchisee 403 and the role cannot be granted; flags on:
FA sees only ZA-subtree subscribers (incl. its one on the shared site), never
FB's, by list, by path id and by export; another zone or ISP's zone in a path
or ``scope_zone_id`` -> 404; FA cannot create a subscriber in ZB, move one
there, add a customer, a user or a franchisee, or set zones; FA's zone tree
shows only ZA; a zone package allowlist hides other packages from FA (a
disallowed package cannot be sold); several zones on one router; placement
picks the linked router first; subscriber router must be on its own customer.
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


async def _router(w, cust: str, n: int) -> str:
    from app.database.session import SessionLocal
    from app.domains.location.models import Location
    from app.domains.router.models import Router

    async with SessionLocal() as s:
        loc = Location(
            organization_id=uuid.UUID(cust),
            name=f"Site{n}",
            slug=f"wf{n}{w.tag}",
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
            name=f"R{n}",
            serial_number=f"SNWF{n}{w.tag}",
            mac_address=f"06:1{n}:{w.tag[0:2]}:{w.tag[2:4]}:{w.tag[4:6]}:{w.tag[6:8]}",
            model="hEX",
            vendor="mikrotik",
            status="offline",
            settings={},
        )
        s.add(r)
        await s.commit()
        return str(r.id)


async def test_franchisee_scoping_and_workflow(monkeypatch) -> None:  # noqa: ANN001, C901
    import httpx

    from app.domains.isp_partner import directory_bulk_router as dbr

    from .isp_small_pg_helpers import Api, customer, dispose, make_world, package

    monkeypatch.setattr(
        dbr, "get_dir2_settings", lambda: dbr.IspDir2Settings(enabled=True)
    )
    monkeypatch.setenv("ISP_WORKFLOW_ENABLED", "false")
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

            # ---- flags off: franchisee refused, role cannot be granted
            await api.get("/overview", who="FA", code=403)
            await api.get("/workflow/features", code=404)
            body = await api.post(
                "/users",
                {
                    "email": f"fx{w.tag}@example.com",
                    "first_name": "F",
                    "last_name": "X",
                    "role": "isp-franchisee",
                },
                code=(422, 400),
            )
            assert "Franchisee" in str(body), body

            monkeypatch.setenv("ISP_WORKFLOW_ENABLED", "true")
            _clear()

            # ---- owner builds the hierarchy
            za = (await api.post("/zones/tree", {"name": f"ZA{w.tag}"}))["id"]
            za1 = (
                await api.post("/zones/tree", {"name": f"ZA1{w.tag}", "parent_id": za})
            )["id"]
            zb = (await api.post("/zones/tree", {"name": f"ZB{w.tag}"}))["id"]
            zother = (await api.post("/zones/tree", {"name": f"ZO{w.tag}"}, who="B"))[
                "id"
            ]
            ca = await customer(api, "A", "Ca")
            cb = await customer(api, "A", "Cb")
            cs = await customer(api, "A", "Cs")
            for cid, z in ((ca, za), (cb, zb), (cs, zb)):
                await api.patch(f"/customers/{cid}", {"zone_id": z})
            p1 = await package(api, "A", price=50000, name="One")
            p2 = await package(api, "A", price=90000, name="Two")

            async def sub(cust, zone, ident, who="A", code=(200, 201)):
                return await api.post(
                    "/subscribers",
                    {
                        "isp_customer_id": cust,
                        "identifier": f"{ident}{w.tag}",
                        "package_id": p1,
                        "first_name": ident,
                        "state_code": "07",
                        "zone_id": zone,
                    },
                    who=who,
                    code=code,
                )

            s_a = (await sub(ca, za1, "sa"))["id"]
            s_b = (await sub(cb, zb, "sb"))["id"]
            s_sa = (await sub(cs, za, "ssa"))["id"]  # shared site, zone A
            s_sb = (await sub(cs, zb, "ssb"))["id"]  # shared site, zone B

            # ---- franchisee zones (owner only)
            fa, fb = str(w.users["FA"]), str(w.users["FB"])
            await api.put(f"/workflow/franchisees/{fa}/zones", {"zone_ids": [za]})
            await api.put(f"/workflow/franchisees/{fb}/zones", {"zone_ids": [zb]})
            # another ISP's zone / a non-franchisee user -> 404
            await api.put(
                f"/workflow/franchisees/{fa}/zones", {"zone_ids": [zother]}, code=404
            )
            await api.put(
                f"/workflow/franchisees/{w.users['A']}/zones",
                {"zone_ids": [za]},
                code=404,
            )
            lst = await api.get("/workflow/franchisees")
            assert {i["user_id"] for i in lst["items"]} == {fa, fb}
            # a franchisee cannot assign zones, create users or customers
            await api.put(
                f"/workflow/franchisees/{fa}/zones",
                {"zone_ids": [za, zb]},
                who="FA",
                code=403,
            )
            await api.get("/workflow/franchisees", who="FA", code=403)
            await api.post(
                "/users",
                {
                    "email": f"fy{w.tag}@example.com",
                    "first_name": "F",
                    "last_name": "Y",
                    "role": "isp-franchisee",
                },
                who="FA",
                code=403,
            )
            await api.post(
                "/customers",
                {"name": f"New {w.tag}", "contact_email": f"n{w.tag}@example.com"},
                who="FA",
                code=403,
            )
            await api.post("/zones/tree", {"name": "Mine"}, who="FA", code=403)

            # ---- reads: list, path id, zone tree, me
            me = await api.get("/workflow/me", who="FA")
            assert me["is_franchisee"] and [z["id"] for z in me["zones"]] == [za]
            ids = {
                s["id"]
                for s in (
                    await api.get("/subscribers", who="FA", params={"page_size": 100})
                )["items"]
            }
            assert ids == {s_a, s_sa}, ids
            ids_b = {
                s["id"]
                for s in (
                    await api.get("/subscribers", who="FB", params={"page_size": 100})
                )["items"]
            }
            assert ids_b == {s_b, s_sb}, ids_b
            await api.get(f"/subscribers/{s_b}", who="FA", code=404)
            await api.get(
                f"/subscribers/{s_sb}", who="FA", code=404
            )  # shared site, other zone
            await api.get(f"/subscribers/{s_a}", who="FB", code=404)
            await api.get(f"/customers/{cb}", who="FA", code=404)
            await api.get(f"/customers/{ca}", who="FA")
            tree = await api.get("/zones/tree", who="FA")
            names = str(tree)
            assert f"ZA{w.tag}" in names and f"ZB{w.tag}" not in names, tree
            # zone ids outside the subtree in a path or as scope -> 404
            await api.get(f"/zones/{zb}/subtree", who="FA", code=404)
            await api.get(
                "/subscribers", who="FA", params={"scope_zone_id": zb}, code=404
            )
            await api.get(
                "/subscribers", who="FA", params={"scope_zone_id": zother}, code=404
            )
            narrowed = await api.get(
                "/subscribers", who="FA", params={"scope_zone_id": za1}
            )
            assert {s["id"] for s in narrowed["items"]} == {s_a}
            # another ISP entirely
            await api.get(f"/subscribers/{s_a}", who="B", code=404)

            # ---- writes outside the subtree are refused
            await sub(cb, zb, "x1", who="FA", code=404)  # customer not visible
            await sub(ca, zb, "x2", who="FA", code=404)  # visible customer, other zone
            await sub(cs, None, "x3", who="FA", code=404)  # no zone -> profile zone B
            ok_new = await sub(ca, za1, "x4", who="FA")
            assert ok_new["id"]
            await api.patch(f"/subscribers/{s_a}", {"zone_id": zb}, who="FA", code=404)
            await api.patch(
                f"/customers/{ca}", {"zone_id": zb}, who="FA", code=(403, 404)
            )

            # ---- exports respect the zone
            r = await c.get(
                f"{w.api}/subscriber-directory/export",
                params={"format": "csv"},
                headers=w.headers["FA"],
            )
            assert r.status_code == 200, r.text[:300]
            assert f"sa{w.tag}" in r.text and f"ssa{w.tag}" in r.text, r.text[:600]
            assert f"sb{w.tag}" not in r.text and f"ssb{w.tag}" not in r.text

            # ---- several zones on one router; placement
            r_cs = await _router(w, cs, 1)
            r_ca = await _router(w, ca, 2)
            got = await api.put(
                f"/workflow/routers/{r_cs}/zones", {"zone_ids": [za, zb]}
            )
            assert {z["id"] for z in got["zones"]} == {za, zb}
            await api.put(
                f"/workflow/routers/{r_cs}/zones",
                {"zone_ids": [za]},
                who="FA",
                code=403,
            )
            await api.put(
                f"/workflow/routers/{r_cs}/zones", {"zone_ids": [zother]}, code=404
            )
            await api.get(f"/workflow/routers/{r_cs}/zones", who="B", code=404)
            pl = await api.get("/workflow/placement", params={"zone_ref": za1})
            assert pl["suggested"]["isp_router_id"] == r_cs, pl  # linked to parent ZA
            assert {i["isp_router_id"] for i in pl["items"]} == {r_cs, r_ca}
            pl_b = await api.get(
                "/workflow/placement", params={"zone_ref": zb}, who="FB"
            )
            assert [i["isp_router_id"] for i in pl_b["items"]] == [r_cs], pl_b
            await api.get(
                "/workflow/placement", params={"zone_ref": zb}, who="FA", code=404
            )
            zr = await api.get(f"/workflow/zones/{za}/routers", who="FA")
            assert [i["isp_router_id"] for i in zr["items"]] == [r_cs]

            # ---- subscriber router: own customer's routers only
            await api.put(
                f"/workflow/subscribers/{s_a}/router", {"isp_router_id": r_cs}, code=404
            )
            got = await api.put(
                f"/workflow/subscribers/{s_a}/router", {"isp_router_id": r_ca}, who="FA"
            )
            assert got["router"]["isp_router_id"] == r_ca
            await api.get(f"/workflow/subscribers/{s_b}/router", who="FA", code=404)

            # ---- zone package allowlist
            await api.put(f"/workflow/zones/{za}/packages", {"package_ids": [p2]})
            await api.put(
                f"/workflow/zones/{za}/packages",
                {"package_ids": [p1]},
                who="FA",
                code=403,
            )
            pk = {
                p["id"]
                for p in (
                    await api.get("/packages", who="FA", params={"page_size": 100})
                )["items"]
            }
            assert pk == {p2}, pk
            await api.get(f"/packages/{p1}", who="FA", code=404)
            pk_b = {
                p["id"]
                for p in (
                    await api.get("/packages", who="FB", params={"page_size": 100})
                )["items"]
            }
            assert {p1, p2} <= pk_b
            await sub(ca, za1, "x5", who="FA", code=404)  # p1 not sellable in ZA
    finally:
        _clear()
        await dispose()
