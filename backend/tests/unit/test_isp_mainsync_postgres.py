# ruff: noqa: E501, PLR0915 -- scenario test
"""MAIN-SYNC twins on real PostgreSQL + Redis (skipped unless ``ISP_TEST_PG_DSN``;
run with ``scripts/run_isp_pg_tests.py``).

ISP A's venue is reachable through every twin added for main's customer pages.
ISP B naming A's customer/location/router gets a 404 from every one of them,
and A naming a guest session of another organization is refused by the
original service (403), with nothing changed.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)


async def test_mainsync_twins_are_scoped() -> None:
    import httpx

    from app.database.session import SessionLocal
    from app.domains.guest.models import Guest, GuestSession
    from app.domains.isp_partner.config import get_isp_partner_settings
    from app.domains.location.models import Location
    from app.domains.organization.models import Organization
    from app.domains.router.models import Router

    from .isp_small_pg_helpers import Api, customer, dispose, make_world

    get_isp_partner_settings.cache_clear()
    w = await make_world()
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=w.app), base_url="http://t"
        ) as c:
            api = Api(c, w)
            cust = await customer(api, "A", "Venue")
            now = datetime.now(UTC)
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
                rtr = Router(
                    location_id=loc.id,
                    organization_id=uuid.UUID(cust),
                    name="r",
                    serial_number=f"SN{w.tag}",
                    mac_address=f"06:00:{w.tag[0:2]}:{w.tag[2:4]}:{w.tag[4:6]}:{w.tag[6:8]}",
                    model="m",
                    settings={},
                )
                s.add(rtr)
                other = Organization(
                    name=f"Other {w.tag}",
                    slug=f"other{w.tag}",
                    org_type="standard",
                    status="active",
                    contact_email=f"other{w.tag}@e.com",
                    timezone="Asia/Kolkata",
                    settings={},
                )
                s.add(other)
                await s.flush()
                oloc = Location(
                    organization_id=other.id,
                    name="O",
                    slug=f"o{w.tag}",
                    address_line1="1",
                    city="c",
                    state_province="s",
                    postal_code="1",
                    country="IN",
                    settings={},
                )
                s.add(oloc)
                await s.flush()
                ortr = Router(
                    location_id=oloc.id,
                    organization_id=other.id,
                    name="o",
                    serial_number=f"OSN{w.tag}",
                    mac_address=f"06:01:{w.tag[0:2]}:{w.tag[2:4]}:{w.tag[4:6]}:{w.tag[6:8]}",
                    model="m",
                    settings={},
                )
                g = Guest(
                    organization_id=other.id,
                    identifier=f"g{w.tag}@e.com",
                    display_name="G",
                    first_seen_at=now,
                    last_seen_at=now,
                )
                s.add_all([ortr, g])
                await s.flush()
                gs = GuestSession(
                    guest_id=g.id,
                    router_id=ortr.id,
                    location_id=oloc.id,
                    organization_id=other.id,
                    auth_method="otp_sms",
                    status="active",
                    started_at=now,
                    last_activity_at=now,
                    bytes_uploaded=0,
                    bytes_downloaded=0,
                )
                s.add(gs)
                await s.commit()
                loc_id, rtr_id, foreign_session = str(loc.id), str(rtr.id), str(gs.id)
                foreign_router = str(ortr.id)

            venue = {"X-Isp-Customer-Id": cust, "X-Isp-Location-Id": loc_id}
            w.headers["A@venue"] = {**w.headers["A"], **venue}
            w.headers["B@venue"] = {**w.headers["B"], **venue}

            # A's own venue answers on the rows that need no device round trip.
            for path in (
                f"/venue/network-integrations/locations/{loc_id}/speed-control",
                f"/venue/locations/{loc_id}/ssid-tiers",
                "/venue/hotspot-profiles",
                "/venue/otp/requests/sms-daily-consumption",
            ):
                await api.get(path, who="A@venue")
            await api.put(
                f"/venue/locations/{loc_id}/ssid-tiers",
                {"items": []},
                who="A@venue",
            )

            # B naming A's venue: 404 everywhere, before any handler runs.
            for method, path, body in (
                (
                    "GET",
                    f"/venue/network-integrations/locations/{loc_id}/speed-control",
                    None,
                ),
                ("GET", f"/venue/locations/{loc_id}/ssid-tiers", None),
                ("PUT", f"/venue/locations/{loc_id}/ssid-tiers", {"items": []}),
                ("GET", "/venue/hotspot-profiles", None),
                ("POST", "/venue/hotspot-profiles", {"router_id": rtr_id, "name": "x"}),
                ("GET", f"/venue/hotspot-profiles/{uuid.uuid4()}", None),
                ("PUT", f"/venue/hotspot-profiles/{uuid.uuid4()}", {"name": "x"}),
                ("DELETE", f"/venue/hotspot-profiles/{uuid.uuid4()}", None),
                ("GET", f"/venue/vlans/device-interfaces?isp_router_id={rtr_id}", None),
                ("GET", f"/venue/routers/{rtr_id}/device-interfaces", None),
                ("GET", f"/venue/dhcp-pools/routers/{rtr_id}/live-pools", None),
                (
                    "PUT",
                    f"/venue/dhcp-pools/routers/{rtr_id}/live-pools/p1",
                    {"range_start": "10.0.0.2", "range_end": "10.0.0.9"},
                ),
                ("POST", f"/venue/guest-sessions/{foreign_session}/terminate", {}),
                ("GET", "/venue/otp/requests/sms-daily-consumption", None),
            ):
                await api.call(method, path, body, who="B@venue", code=404)

            # A's own venue, another org's guest session: the original service's 403.
            await api.call(
                "POST",
                f"/venue/guest-sessions/{foreign_session}/terminate",
                {},
                who="A@venue",
                code=403,
            )
            # A cannot point the router-scoped rows at another org's router.
            for path in (
                f"/venue/routers/{foreign_router}/device-interfaces",
                f"/venue/dhcp-pools/routers/{foreign_router}/live-pools",
                f"/venue/vlans/device-interfaces?isp_router_id={foreign_router}",
            ):
                await api.call("GET", path, who="A@venue", code=404)
    finally:
        await dispose()
