# ruff: noqa: E501, PLR0915 -- scenario test
"""DEFAULT-LOGS on real PostgreSQL (skipped unless ``ISP_TEST_PG_DSN``). Run
with ``scripts/run_isp_pg_tests.py``. ISP_IPLOGS_SELFSERVE_ENABLED=true

The test switches ISP_WORKFLOW_ENABLED / ISP_ZONES_ENABLED itself.

Covers:
* ``GET /ip-logs/features`` answers while the flag is on (404 while off);
* owner Add router with ``ip_logs: true`` / ``false`` / not sent records
  wanted True / False / nothing, and the status row says ``wanted`` and
  ``switch_on``; with the flag off the field is accepted and nothing is
  written;
* enable / disable on a router WITHOUT a management connection record the
  choice (200, no intent rows, audited) instead of the old 409;
* once the router has its management connection the script carries
  ``setup_lines`` with its own address, and enable writes the intent rows;
* **ISP B** cannot add a router at A's location (404), cannot enable / disable
  A's routers (404, A's choice unchanged), and does not see them in its list;
* franchisee FA adds a router at its own site with ``ip_logs: true``
  (recorded), switches its own router; **franchisee FB** (other zone) gets 404
  on FA's router and cannot add one at FA's site.
"""

from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)


def _clear() -> None:
    from app.domains.isp_partner.iplogs_router import get_iplogs_settings
    from app.domains.isp_partner.workflow_config import get_workflow_settings
    from app.domains.isp_partner.zones_config import get_zones_settings

    get_workflow_settings.cache_clear()
    get_zones_settings.cache_clear()
    get_iplogs_settings.cache_clear()


def _loc_body(name: str, tag: str) -> dict:
    return {
        "name": name,
        "slug": f"{name.lower()}-{tag}",
        "address_line1": "1 Main Rd",
        "city": "Noida",
        "state_province": "UP",
        "postal_code": "201301",
    }


async def test_default_logs(monkeypatch) -> None:  # noqa: ANN001, C901
    import httpx
    from sqlalchemy import func, select

    from app.database.session import SessionLocal
    from app.domains.device_logs.models import RouterRemoteLogging
    from app.domains.isp_partner.iplogs_default import IspRouterIpLogsDefault
    from app.domains.rbac.models import AuditLogEntry
    from app.domains.traffic_flow.models import RouterTrafficFlowExport
    from app.domains.wireguard.models import WireGuardPeer, WireGuardServer

    from .isp_small_pg_helpers import Api, customer, dispose, make_world

    monkeypatch.setenv("ISP_IPLOGS_SELFSERVE_ENABLED", "true")
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

            def rbody(**extra):  # noqa: ANN003, ANN202
                i = next(n)
                t = w.tag
                return {
                    "name": f"DL R{i}",
                    "serial_number": f"SNDL{i}{t}",
                    "mac_address": f"0a:{i:02d}:{t[0:2]}:{t[2:4]}:{t[4:6]}:{t[6:8]}",
                    "model": "hEX",
                    **extra,
                }

            async def choice(rid: str) -> bool | None:
                async with SessionLocal() as s:
                    row = (
                        await s.execute(
                            select(IspRouterIpLogsDefault).where(
                                IspRouterIpLogsDefault.router_id == uuid.UUID(rid)
                            )
                        )
                    ).scalar_one_or_none()
                    return None if row is None else row.wanted

            async def intent_rows(rid: str) -> int:
                async with SessionLocal() as s:
                    return (
                        await s.execute(
                            select(func.count()).where(
                                RouterTrafficFlowExport.router_id == uuid.UUID(rid)
                            )
                        )
                    ).scalar_one()

            # ---- probe
            f = await api.get("/ip-logs/features")
            assert (
                f["default_on_add_router"] is True and f["setup_script_lines"] is True
            )
            assert (await api.get("/ip-logs/features", who="B"))["switch"] is True

            # ---- world: zones, customers, sites
            za = (await api.post("/zones/tree", {"name": f"DZA{w.tag}"}))["id"]
            zb = (await api.post("/zones/tree", {"name": f"DZB{w.tag}"}))["id"]
            ca = await customer(api, "A", "DLa")
            cb = await customer(api, "A", "DLb")
            await api.patch(f"/customers/{ca}", {"zone_id": za})
            await api.patch(f"/customers/{cb}", {"zone_id": zb})
            la = (
                await api.post(f"/customers/{ca}/locations", _loc_body("Dla", w.tag))
            )["id"]
            lb = (
                await api.post(f"/customers/{cb}/locations", _loc_body("Dlb", w.tag))
            )["id"]
            fa, fb = str(w.users["FA"]), str(w.users["FB"])
            await api.put(f"/workflow/franchisees/{fa}/zones", {"zone_ids": [za]})
            await api.put(f"/workflow/franchisees/{fb}/zones", {"zone_ids": [zb]})

            # ---- owner Add router: on / off / not sent
            r_on = await api.post(f"/locations/{la}/routers", rbody(ip_logs=True))
            assert r_on["ip_logs_wanted"] is True
            r_off = await api.post(f"/locations/{la}/routers", rbody(ip_logs=False))
            assert r_off["ip_logs_wanted"] is False
            r_old = await api.post(f"/locations/{la}/routers", rbody())
            assert "ip_logs_wanted" not in r_old  # response exactly as before
            assert await choice(r_on["id"]) is True
            assert await choice(r_off["id"]) is False
            assert await choice(r_old["id"]) is None

            d = await api.get(f"/routers/{r_on['id']}/ip-logs")
            assert d["wanted"] is True and d["switch_on"] is True
            assert d["set_up"] is False and d["blocker"] == "needs_link"
            d = await api.get(f"/routers/{r_off['id']}/ip-logs")
            assert d["wanted"] is False and d["switch_on"] is False
            d = await api.get(f"/routers/{r_old['id']}/ip-logs")
            assert d["wanted"] is None and d["switch_on"] is False
            sc = await api.get(f"/routers/{r_on['id']}/ip-logs/script")
            assert sc["available"] is False and sc["setup_lines"] is None

            # ---- flag off: the field is accepted, nothing is written
            monkeypatch.setenv("ISP_IPLOGS_SELFSERVE_ENABLED", "false")
            _clear()
            await api.get("/ip-logs/features", code=404)
            r_flag = await api.post(f"/locations/{la}/routers", rbody(ip_logs=True))
            assert "ip_logs_wanted" not in r_flag
            assert await choice(r_flag["id"]) is None
            monkeypatch.setenv("ISP_IPLOGS_SELFSERVE_ENABLED", "true")
            _clear()

            # ---- switch on a router without a management connection: recorded
            d = await api.post(f"/routers/{r_old['id']}/ip-logs/enable")
            assert d["wanted"] is True and d["switch_on"] is True
            assert d["set_up"] is False and d["state"] == "needs_link"
            assert await intent_rows(r_old["id"]) == 0
            async with SessionLocal() as s:
                meta = (
                    await s.execute(
                        select(AuditLogEntry.event_metadata).where(
                            AuditLogEntry.action == "isp_ip_logs_enabled",
                            AuditLogEntry.entity_id == uuid.UUID(r_old["id"]),
                        )
                    )
                ).scalar_one()
                assert meta["recorded_for_setup_script"] is True
            d = await api.post(f"/routers/{r_on['id']}/ip-logs/disable")
            assert d["wanted"] is False and d["switch_on"] is False
            assert await choice(r_on["id"]) is False

            # ---- management connection arrives: setup lines + real enable
            async with SessionLocal() as s:
                server = WireGuardServer(
                    name=f"hub dl {w.tag}",
                    endpoint_host="hub.example.com",
                    endpoint_port=51820,
                    public_key=f"srvdl{w.tag}".ljust(44, "A"),
                    private_key_encrypted="x",
                    tunnel_network_cidr="10.66.0.0/24",
                )
                s.add(server)
                await s.flush()
                s.add(
                    WireGuardPeer(
                        router_id=uuid.UUID(r_old["id"]),
                        server_id=server.id,
                        tunnel_ip_address="10.66.0.88",
                        public_key=f"peerdl{w.tag}".ljust(44, "A"),
                        private_key_encrypted="x",
                    )
                )
                await s.commit()
            sc = await api.get(f"/routers/{r_old['id']}/ip-logs/script")
            text = "\n".join(sc["setup_lines"])
            assert "src-address=10.66.0.88" in text and "nat-events=yes" in text
            assert ":error" not in text and "add-topics-string=yes" in text
            d = await api.get(f"/routers/{r_old['id']}/ip-logs")
            assert (
                d["switch_on"] is True and d["set_up"] is False
            )  # wanted, not yet written
            d = await api.post(f"/routers/{r_old['id']}/ip-logs/enable")
            assert d["set_up"] is True and d["switch_on"] is True
            assert await intent_rows(r_old["id"]) == 1
            async with SessionLocal() as s:
                rl = (
                    await s.execute(
                        select(RouterRemoteLogging).where(
                            RouterRemoteLogging.router_id == uuid.UUID(r_old["id"])
                        )
                    )
                ).scalar_one()
                assert rl.enabled and rl.src_address == "10.66.0.88"

            # ---- fleet list carries the choice
            fl = await api.get("/ip-logs/routers", params={"isp_customer_id": ca})
            by = {i["isp_router_id"]: i for i in fl["items"]}
            assert by[r_on["id"]]["wanted"] is False
            assert by[r_off["id"]]["switch_on"] is False
            assert by[r_old["id"]]["switch_on"] is True
            assert by[r_flag["id"]]["wanted"] is None

            # ---- ISP B: 404 everywhere, A's choice unchanged
            await api.post(
                f"/locations/{la}/routers", rbody(ip_logs=True), who="B", code=404
            )
            for rid in (r_on["id"], r_old["id"]):
                await api.post(f"/routers/{rid}/ip-logs/enable", who="B", code=404)
                await api.post(f"/routers/{rid}/ip-logs/disable", who="B", code=404)
                await api.get(f"/routers/{rid}/ip-logs", who="B", code=404)
                await api.get(f"/routers/{rid}/ip-logs/script", who="B", code=404)
            assert await choice(r_on["id"]) is False
            assert await choice(r_old["id"]) is True
            assert (await api.get("/ip-logs/routers", who="B"))["items"] == []

            # ---- franchisees
            fr = await api.post(
                f"/workflow/franchisee/sites/{la}/routers",
                rbody(ip_logs=True),
                who="FA",
            )
            assert fr["ip_logs_wanted"] is True and await choice(fr["id"]) is True
            d = await api.get(f"/routers/{fr['id']}/ip-logs", who="FA")
            assert d["switch_on"] is True
            await api.post(f"/routers/{fr['id']}/ip-logs/disable", who="FA")
            assert await choice(fr["id"]) is False
            # FB (zone B) cannot see, switch or add at FA's site
            await api.get(f"/routers/{fr['id']}/ip-logs", who="FB", code=404)
            await api.post(f"/routers/{fr['id']}/ip-logs/enable", who="FB", code=404)
            await api.post(f"/routers/{fr['id']}/ip-logs/disable", who="FB", code=404)
            await api.post(
                f"/workflow/franchisee/sites/{la}/routers",
                rbody(ip_logs=True),
                who="FB",
                code=404,
            )
            assert await choice(fr["id"]) is False
            # FB adds at its own site with the switch off
            frb = await api.post(
                f"/workflow/franchisee/sites/{lb}/routers",
                rbody(ip_logs=False),
                who="FB",
            )
            assert await choice(frb["id"]) is False
            # FA cannot reach FB's router
            await api.post(f"/routers/{frb['id']}/ip-logs/enable", who="FA", code=404)
            assert await choice(frb["id"]) is False
    finally:
        _clear()
        await dispose()
