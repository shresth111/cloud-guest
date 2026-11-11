# ruff: noqa: E501, PLR0915 -- scenario test
"""FR-GENERATE on real PostgreSQL (skipped unless ``ISP_TEST_PG_DSN``). Run
with ``scripts/run_isp_pg_tests.py``. ISP_PROV_FIX_ENABLED=true
ISP_IPLOGS_SELFSERVE_ENABLED=true CLOUDGUEST_DEVICE_LOGS_ENABLED=true

The test switches ISP_WORKFLOW_ENABLED / ISP_ZONES_ENABLED itself.

World: ISP A with zones ZA and ZB; customers cA (profile ZA), cB (profile ZB)
and cS (profile ZB, with a ZA subscriber: a shared site FA can *see*), one
router each; ISP B with its own router. Franchisee FA holds ZA.

Covers:
* FA mints a provisioning token on cA's router (201, audited with its role),
  gets its IP-logs script, and ``setup/access`` says ``can_generate``;
* FA on cB's router (other zone), cS's router (shared site, no ZA link) and
  ISP B's router: token / agent-credential / check-in / IP-logs script are
  all 404, never 403; ``setup/access`` is ``outside_zones`` for cS and 404 for
  the other two;
* check-in: FA passes role + scope on its router (a token of another router
  is refused 409 ISP_SETUP_TOKEN_MISMATCH, i.e. not 403/404);
* once the owner links cS's router to ZA, FA may mint its token;
* owner and technician unchanged (token on every own-ISP router, access
  true); a viewer's access is ``can_generate: false`` (``role``).
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
            name=f"FG Site{n}",
            slug=f"fg{n}{w.tag}",
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
            name=f"FG R{n}",
            serial_number=f"SNFG{n}{w.tag}",
            mac_address=f"06:3{n}:{w.tag[0:2]}:{w.tag[2:4]}:{w.tag[4:6]}:{w.tag[6:8]}",
            model="hEX",
            vendor="mikrotik",
            status="pending_provisioning",
            settings={},
        )
        s.add(r)
        await s.commit()
        return str(r.id)


async def test_franchisee_generate_own_zone_only(monkeypatch) -> None:  # noqa: ANN001, C901
    import httpx
    from sqlalchemy import select

    from app.database.session import SessionLocal
    from app.domains.rbac.models import AuditLogEntry

    from .isp_small_pg_helpers import Api, customer, dispose, make_world, package

    monkeypatch.setenv("ISP_PROV_FIX_ENABLED", "true")
    monkeypatch.setenv("ISP_WORKFLOW_ENABLED", "true")
    monkeypatch.setenv("ISP_ZONES_ENABLED", "true")
    _clear()
    try:
        w = await make_world(
            extra_users_on_a={
                "FA": "isp-franchisee",
                "tech": "isp-technician",
                "view": "isp-viewer",
            }
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=w.app), base_url="http://t"
        ) as c:
            api = Api(c, w)
            za = (await api.post("/zones/tree", {"name": f"FGZA{w.tag}"}))["id"]
            zb = (await api.post("/zones/tree", {"name": f"FGZB{w.tag}"}))["id"]
            ca = await customer(api, "A", "FgA")
            cb = await customer(api, "A", "FgB")
            cs = await customer(api, "A", "FgS")
            cx = await customer(api, "B", "FgX")
            for cid, z in ((ca, za), (cb, zb), (cs, zb)):
                await api.patch(f"/customers/{cid}", {"zone_id": z})
            p1 = await package(api, "A", price=50000, name="FgOne")
            await api.post(
                "/subscribers",
                {
                    "isp_customer_id": cs,
                    "identifier": f"fgs{w.tag}",
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

            # FA can see cS's router (shared-site read rule) but not cB's
            await api.get(f"/routers/{rs}", who="FA")
            await api.get(f"/routers/{rb}", who="FA", code=404)

            # ---- own zone: token, IP-logs script, access
            tok = await api.post(
                f"/routers/{ra}/provisioning-token", who="FA", code=201
            )
            assert tok["token"], tok
            async with SessionLocal() as s:
                row = (
                    (
                        await s.execute(
                            select(AuditLogEntry)
                            .where(
                                AuditLogEntry.entity_id == uuid.UUID(ra),
                                AuditLogEntry.action
                                == "isp_router_setup_provisioning_token",
                            )
                            .order_by(AuditLogEntry.created_at.desc())
                        )
                    )
                    .scalars()
                    .first()
                )
            assert row is not None
            assert row.event_metadata["role"] == "isp-franchisee"
            script = await api.get(f"/routers/{ra}/ip-logs/script", who="FA")
            assert script["isp_router_id"] == ra
            acc = await api.get(f"/routers/{ra}/setup/access", who="FA")
            assert acc == {"isp_router_id": ra, "can_generate": True, "reason": None}

            # ---- other zone / shared site / other ISP: 404, never 403
            for rid in (rb, rs, rx):
                await api.post(f"/routers/{rid}/provisioning-token", who="FA", code=404)
                await api.post(
                    f"/routers/{rid}/agent-credential/regenerate", who="FA", code=404
                )
                await api.post(
                    f"/routers/{rid}/setup/check-in",
                    {"token": "x" * 20},
                    who="FA",
                    code=404,
                )
                await api.get(f"/routers/{rid}/ip-logs/script", who="FA", code=404)
            acc = await api.get(f"/routers/{rs}/setup/access", who="FA")
            assert acc["can_generate"] is False and acc["reason"] == "outside_zones"
            await api.get(f"/routers/{rb}/setup/access", who="FA", code=404)
            await api.get(f"/routers/{rx}/setup/access", who="FA", code=404)

            # ---- check-in on its own router passes role + scope: another
            #      router's token is refused as a mismatch (409), not 403/404
            tok_b = (await api.post(f"/routers/{rb}/provisioning-token", code=201))[
                "token"
            ]
            body = await api.post(
                f"/routers/{ra}/setup/check-in", {"token": tok_b}, who="FA", code=409
            )
            assert "ISP_SETUP_TOKEN_MISMATCH" in str(body), body

            # ---- the owner links cS's router to ZA: now inside FA's zones
            await api.put(f"/workflow/routers/{rs}/zones", {"zone_ids": [za, zb]})
            await api.post(f"/routers/{rs}/provisioning-token", who="FA", code=201)
            acc = await api.get(f"/routers/{rs}/setup/access", who="FA")
            assert acc["can_generate"] is True
            # still nothing on cB / ISP B
            await api.post(f"/routers/{rb}/provisioning-token", who="FA", code=404)

            # ---- owner / technician unchanged, viewer cannot
            for rid in (ra, rb, rs):
                await api.post(f"/routers/{rid}/provisioning-token", code=201)
                await api.post(
                    f"/routers/{rid}/provisioning-token", who="tech", code=201
                )
                assert (await api.get(f"/routers/{rid}/setup/access"))[
                    "can_generate"
                ] is True
            await api.post(f"/routers/{rx}/provisioning-token", code=404)
            await api.post(f"/routers/{rx}/provisioning-token", who="B", code=201)
            acc = await api.get(f"/routers/{ra}/setup/access", who="view")
            assert acc["can_generate"] is False and acc["reason"] == "role"
            await api.post(f"/routers/{ra}/provisioning-token", who="view", code=403)
    finally:
        _clear()
        await dispose()
