# ruff: noqa: E501, PLR0915 -- scenario test
"""CI-INTEG's four controller-venue behaviours on real router rows, real
PostgreSQL + Redis and real HTTP (skipped unless ``ISP_TEST_PG_DSN``; run with
``scripts/run_isp_pg_tests.py``). ISP_INCIDENTS_ENABLED=true ISP_NETMON_ENABLED=true

``test_isp_controller_venue_reads.py`` covers the same logic with fake rows.
Here the rows are real, so the database defaults, the queries and the response
keys are all in the path:

* J14 Telegram UP/DOWN skips a controller venue (``_device_statuses``);
* the NAT feed gives it ``not_applicable``, which never raises the banner;
* incidents ``/health`` leaves it out of up/down and counts it separately;
* the netmon traffic card says ``controller_managed``.

A MikroTik mislabelled as Omada that has checked in stays a real router in all
four, and a real offline MikroTik stays down.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)


async def test_controller_venues_on_real_rows() -> None:
    import httpx

    from app.database.session import SessionLocal
    from app.domains.isp_partner.automation import _device_statuses
    from app.domains.isp_partner.config import get_isp_partner_settings
    from app.domains.isp_partner.incidents_config import get_incidents_settings
    from app.domains.isp_partner.netmon_router import get_netmon_settings
    from app.domains.location.models import Location
    from app.domains.router.models import Router

    from .isp_small_pg_helpers import Api, customer, dispose, make_world

    for getter in (
        get_isp_partner_settings,
        get_incidents_settings,
        get_netmon_settings,
    ):
        getter.cache_clear()
    w = await make_world()
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=w.app), base_url="http://t"
        ) as c:
            api = Api(c, w)
            cust = await customer(api, "A", "Venue")
            seen = datetime.now(UTC) - timedelta(days=1)
            async with SessionLocal() as s:
                loc = Location(
                    organization_id=uuid.UUID(cust),
                    name="Cafe",
                    slug=f"cafe{w.tag}",
                    address_line1="1",
                    city="c",
                    state_province="s",
                    postal_code="1",
                    country="IN",
                    settings={},
                )
                s.add(loc)
                await s.flush()

                def router(
                    n: int, name: str, vendor: str, status: str, evidence: bool
                ) -> Router:
                    return Router(
                        location_id=loc.id,
                        organization_id=uuid.UUID(cust),
                        name=name,
                        serial_number=f"SN{n}{w.tag}",
                        mac_address=f"06:0{n}:{w.tag[0:2]}:{w.tag[2:4]}:{w.tag[4:6]}:{w.tag[6:8]}",
                        model="m",
                        vendor=vendor,
                        status=status,
                        settings={},
                        last_seen_at=seen if evidence else None,
                        routeros_version="7.16" if evidence else None,
                    )

                s.add_all(
                    [
                        router(1, "hEX", "mikrotik", "offline", True),
                        router(2, "Omada ctl", "tplink_omada", "offline", False),
                        router(3, "Instant On", "aruba_instant_on", "online", False),
                        router(
                            4, "RB750 typed as Omada", "tplink_omada", "offline", True
                        ),
                    ]
                )
                await s.commit()
            controller = {"Omada ctl", "Instant On"}
            real = {"hEX", "RB750 typed as Omada"}

            # 1. Telegram
            async with SessionLocal() as s:
                out = await _device_statuses(s, [uuid.UUID(cust)], include_aps=False)
            assert {name: state for _k, _i, name, state, _c in out} == {
                "hEX": "down",
                "RB750 typed as Omada": "down",
            }

            # 2. NAT feed
            feed = await api.get("/compliance/nat-feed")
            items = {i["router_name"]: i for i in feed["routers"]}
            assert set(items) == controller | real
            for name in controller:
                assert items[name]["state"] == "not_applicable", items[name]
                assert items[name]["alerting"] is False, items[name]
            for name in real:
                assert items[name]["state"] != "not_applicable", items[name]

            # 3. Incidents health
            h = await api.get("/incidents/health")
            assert h["routers_controller_managed"] == 2, h
            assert (h["routers_up"], h["routers_down"], h["routers_total"]) == (
                0,
                2,
                2,
            ), h
            assert h["health_percent"] == 0.0, h

            # 4. Netmon traffic cards
            traffic = await api.get("/netmon/traffic", params={"range": "day"})
            cards = {card["name"]: card for card in traffic["routers"]}
            assert set(cards) == controller | real
            for name in controller:
                assert cards[name]["reason"] == "controller_managed", cards[name]
                assert cards[name]["readable"] is False, cards[name]
            for name in real:
                assert cards[name]["reason"] != "controller_managed", cards[name]
    finally:
        await dispose()
