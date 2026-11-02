# ruff: noqa: E501, PLR0915 -- scenario test
"""SMALL-5: incidents auto-opened from router DOWN, on real PostgreSQL + Redis
(skipped unless ``ISP_TEST_PG_DSN``). Run with ``scripts/run_isp_pg_tests.py``.
The test switches ISP_INCIDENTS_ENABLED itself (env + cache_clear) and drives
the job with an explicit clock.

Covers: flag off -> 404 on the settings routes and the job does nothing;
per-ISP switch default off (nothing opens); a router DOWN shorter than
down_minutes opens nothing (debounce), longer opens exactly one incident
started at the DOWN moment; re-runs never open a second one; a flap back UP
for less than up_minutes does not resolve; UP long enough resolves with RFO
auto_restored + note, auto_grace_allowed false; a router in a venue with a
controller-managed (Omada) row never auto-opens; an open manual incident on
the router blocks an auto one; staff resolving by hand closes the auto row
and a later DOWN can open a new one; viewer 403 on PUT; confined technician
sees only marks for routers of their customer; ISP B sees nothing and its
switch is its own.
"""

from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)


def _clear() -> None:
    from app.domains.isp_partner.incidents_config import get_incidents_settings

    get_incidents_settings.cache_clear()


async def test_auto_incidents(monkeypatch) -> None:  # noqa: ANN001, C901
    from datetime import UTC, datetime, timedelta

    import httpx
    from sqlalchemy import func, select

    from app.database.session import SessionLocal
    from app.domains.isp_partner.incident_auto import (
        AUTO_RFO,
        auto_grace_allowed,
        run_incident_auto,
    )
    from app.domains.isp_partner.incident_auto_models import IspIncidentAuto
    from app.domains.isp_partner.incidents_models import IspIncident
    from app.domains.router.models import Router
    from app.domains.router.vendor_capabilities import is_controller_managed_row

    from .isp_small_pg_helpers import (
        Api,
        confine,
        customer,
        dispose,
        make_world,
    )

    monkeypatch.setenv("ISP_INCIDENTS_ENABLED", "false")
    _clear()
    try:
        w = await make_world({"tech": "isp-technician", "view": "isp-viewer"})
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=w.app), base_url="http://t"
        ) as c:
            api = Api(c, w)
            rtr: dict[str, str] = {}
            cust: dict[str, str] = {}
            for i, n in enumerate(("c1", "c2", "c3")):
                cust[n] = await customer(api, "A", n.upper())
                loc = (
                    await api.post(
                        f"/customers/{cust[n]}/locations",
                        {
                            "name": "Main",
                            "address_line1": "1",
                            "city": "c",
                            "state_province": "s",
                            "postal_code": "1",
                        },
                    )
                )["id"]
                rtr[n] = (
                    await api.post(
                        f"/locations/{loc}/routers",
                        {
                            "name": f"hEX-{n}",
                            "serial_number": f"SM{n}{w.tag}",
                            "mac_address": f"02:2{i}:"
                            + ":".join(w.tag[j : j + 2] for j in (0, 2, 4, 6)),
                            "model": "hEX",
                        },
                    )
                )["id"]
                if n == "c3":  # a second, controller-managed row in venue c3
                    rtr["c3omada"] = (
                        await api.post(
                            f"/locations/{loc}/routers",
                            {
                                "name": "omada",
                                "serial_number": f"SMO{w.tag}",
                                "mac_address": "02:3f:"
                                + ":".join(w.tag[j : j + 2] for j in (0, 2, 4, 6)),
                                "model": "EAP",
                            },
                        )
                    )["id"]

            async def set_status(**st: str) -> None:
                async with SessionLocal() as s:
                    for k, v in st.items():
                        r = await s.get(Router, uuid.UUID(rtr[k]))
                        r.status = v
                    await s.commit()

            async with SessionLocal() as s:
                o = await s.get(Router, uuid.UUID(rtr["c3omada"]))
                o.vendor = "tplink_omada"
                await s.commit()
                await s.refresh(o)
                assert is_controller_managed_row(o), "test setup: omada row"

            async def autos(router: str | None = None) -> list:
                async with SessionLocal() as s:
                    q = select(IspIncidentAuto).where(
                        IspIncidentAuto.isp_organization_id == w.isps["A"]
                    )
                    if router:
                        q = q.where(IspIncidentAuto.router_id == uuid.UUID(rtr[router]))
                    return list(
                        (
                            await s.execute(q.order_by(IspIncidentAuto.opened_at))
                        ).scalars()
                    )

            async def n_incidents() -> int:
                async with SessionLocal() as s:
                    return int(
                        (
                            await s.execute(
                                select(func.count())
                                .select_from(IspIncident)
                                .where(IspIncident.isp_organization_id == w.isps["A"])
                            )
                        ).scalar_one()
                    )

            # the job clock runs in the past so every step stays before 'now'
            t0 = datetime.now(UTC) - timedelta(hours=3)
            at = lambda m: t0 + timedelta(minutes=m)  # noqa: E731

            # ---- flag off: routes 404, job no-op
            await api.get("/incident-auto/settings", code=404)
            assert (await run_incident_auto(now=at(0)))["isps"] == 0
            monkeypatch.setenv("ISP_INCIDENTS_ENABLED", "true")
            _clear()

            # ---- per-ISP switch defaults off
            st = await api.get("/incident-auto/settings")
            assert st == {"enabled": False, "down_minutes": 10, "up_minutes": 15}, st
            await set_status(c1="offline", c2="online", c3="offline")
            assert (await run_incident_auto(now=at(0)))["isps"] == 0
            await api.put(
                "/incident-auto/settings", {"enabled": True}, who="view", code=403
            )
            st = await api.put(
                "/incident-auto/settings",
                {"enabled": True, "down_minutes": 10, "up_minutes": 15},
            )
            assert st["enabled"] is True

            # ---- debounce: first sight starts the clock; 5 min is not enough
            await run_incident_auto(now=at(0))
            await run_incident_auto(now=at(5))
            assert await autos() == [] and await n_incidents() == 0
            # 11 min down -> one incident on c1, none on c3 (controller venue)
            r = await run_incident_auto(now=at(11))
            assert r["opened"] == 1, r
            (a1,) = await autos("c1")
            assert await autos("c3") == []
            async with SessionLocal() as s:
                inc = await s.get(IspIncident, a1.incident_id)
                assert inc.status == "investigating" and inc.router_id == uuid.UUID(
                    rtr["c1"]
                )
                assert abs((inc.started_at - at(0)).total_seconds()) < 1
            # re-runs: still exactly one
            await run_incident_auto(now=at(12))
            await run_incident_auto(now=at(30))
            assert len(await autos("c1")) == 1 and await n_incidents() == 1

            # ---- flap: up 5 min, down again -> not resolved
            await set_status(c1="online")
            await run_incident_auto(now=at(31))
            await run_incident_auto(now=at(36))
            await set_status(c1="offline")
            await run_incident_auto(now=at(37))
            async with SessionLocal() as s:
                assert (
                    await s.get(IspIncident, a1.incident_id)
                ).status == "investigating"
            # ---- up for 15 min -> auto-resolved
            await set_status(c1="online")
            await run_incident_auto(now=at(40))
            r = await run_incident_auto(now=at(56))
            assert r["resolved"] == 1, r
            async with SessionLocal() as s:
                inc = await s.get(IspIncident, a1.incident_id)
                assert inc.status == "resolved" and inc.rfo_reason == AUTO_RFO
                assert "restored" in (inc.rfo_note or "") and "auto" in inc.rfo_note
                assert abs((inc.resolved_at - at(40)).total_seconds()) < 1
                assert await auto_grace_allowed(s, inc.id) is False
            d = await api.get(f"/incidents/{a1.incident_id}")
            assert d["status"] == "resolved", d

            # ---- a manual open incident on c2 blocks an auto one
            man = await api.post(
                "/incidents",
                {"scope_kind": "router", "isp_router_id": rtr["c2"], "note": "x"},
            )
            await set_status(c2="offline")
            await run_incident_auto(now=at(60))
            await run_incident_auto(now=at(75))
            assert await autos("c2") == []
            await api.post(
                f"/incidents/{man['id']}/status",
                {"status": "resolved", "rfo_reason": "other"},
            )
            r = await run_incident_auto(now=at(76))
            assert r["opened"] == 1
            (a2,) = await autos("c2")
            # staff resolve the auto one by hand -> row closed, not auto_resolved
            await api.post(
                f"/incidents/{a2.incident_id}/status",
                {"status": "resolved", "rfo_reason": "fiber_cut"},
            )
            r = await run_incident_auto(now=at(77))
            assert r["closed"] == 1
            (a2,) = await autos("c2")
            assert a2.closed_at is not None and a2.auto_resolved is False
            async with SessionLocal() as s:
                assert await auto_grace_allowed(s, a2.incident_id) is True
            # still down -> a NEW auto incident may open (the old one is closed)
            r = await run_incident_auto(now=at(78))
            assert r["opened"] == 1 and len(await autos("c2")) == 2

            # ---- marks: owner sees all, confined technician only c1, ISP B nothing
            marks = (await api.get("/incident-auto/marks"))["items"]
            assert len(marks) == 3
            await confine(w, "tech", [cust["c1"]])
            tm = (await api.get("/incident-auto/marks", who="tech"))["items"]
            assert [m["router_id"] for m in tm] == [rtr["c1"]]
            assert (
                tm[0]["auto_resolved"] is True and tm[0]["auto_grace_allowed"] is False
            )
            assert (await api.get("/incident-auto/marks", who="B"))["items"] == []
            assert (await api.get("/incident-auto/settings", who="B"))[
                "enabled"
            ] is False
    finally:
        _clear()
        await dispose()
