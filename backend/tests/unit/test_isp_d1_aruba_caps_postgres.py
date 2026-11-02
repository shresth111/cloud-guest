# ruff: noqa: PLR0915 -- scenario test
"""D-1 gaps on main's Aruba authorize: Session-Timeout, FUP and Open-Hours caps,
WISPr bandwidth. Regular tenant, real PostgreSQL + Redis, real HTTP (skipped
unless ``ISP_TEST_PG_DSN``; run with ``scripts/run_isp_pg_tests.py``).

Compares the reply bytes with the ISP flags off, with ISP_PARTNER_ENABLED on,
and with enforcement on and the real JAZE-2 gate registered (cache miss, then
hit). A Session-Timeout that counts down is compared after checking the value
is the time left, within a few seconds.

STUBBED INPUTS, stated plainly: the FUP allowance, the Open Hours closing time
and the WISPr rates are stubbed where main reads them
(``_fup_time_remaining_seconds``, ``_open_hours_standing``,
``_nas_only_bandwidth_attributes``). What runs for real is everything after
them: ``nas_only_authorize_standing``'s cap, ``authorize``, the ISP hook and the
JSON reply. The test answers "does the hook change these replies", not "is the
FUP arithmetic right" (main's own suites cover that). FreeRADIUS and an AP are
not in the loop.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from datetime import UTC, datetime

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)
FLAGS = ("ISP_PARTNER_ENABLED", "ISP_PARTNER_ENFORCEMENT_ENABLED")
SECRET = "s3cret"


async def test_aruba_capped_replies_are_byte_identical(monkeypatch) -> None:  # noqa: ANN001
    import httpx

    from app.database.session import SessionLocal, engine
    from app.domains.guest import service as guest_service
    from app.domains.guest.models import Guest, GuestSession, RadiusNasClient
    from app.domains.isp_partner import hotspot_hooks as hh
    from app.domains.isp_partner.config import get_isp_partner_settings
    from app.domains.isp_partner.enforcement_hotspot import jaze2_hotspot_gate
    from app.domains.isp_partner.rate_limit import _isp_customer_cache
    from app.domains.location.models import Location
    from app.domains.organization.models import Organization
    from app.domains.router.crypto import encrypt_secret
    from app.domains.router.models import Router
    from app.main import create_app

    tag = uuid.uuid4().hex[:8]
    now = datetime.now(UTC)
    nas_id = f"nas-ar{tag}"
    sessions: dict[str, uuid.UUID] = {}
    async with SessionLocal() as s:
        org = Organization(
            name=f"Reg {tag}",
            slug=f"reg{tag}",
            org_type="standard",
            status="active",
            contact_email=f"reg{tag}@e.com",
            timezone="Asia/Kolkata",
            settings={},
        )
        s.add(org)
        await s.flush()
        loc = Location(
            organization_id=org.id,
            name="v",
            slug=f"v{tag}",
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
            organization_id=org.id,
            name="ap",
            serial_number=f"SN{tag}",
            mac_address=f"54:F0:B1:{tag[0:2]}:{tag[2:4]}:{tag[4:6]}".upper(),
            model="AP21",
            vendor="aruba_instant_on",
            settings={},
        )
        s.add(rtr)
        await s.flush()
        s.add(
            RadiusNasClient(
                router_id=rtr.id,
                organization_id=org.id,
                location_id=loc.id,
                nas_identifier=nas_id,
                vendor=rtr.vendor,
                status="active",
                is_active=True,
                shared_secret_encrypted=encrypt_secret(SECRET),
            )
        )
        specs = {
            "session-timeout": {
                "session_timeout_minutes": 120,
                "idle_timeout_minutes": 30,
            },
            "fup": {"idle_timeout_minutes": 30},
            "open-hours": {"session_timeout_minutes": 120},
            "wispr": {"idle_timeout_minutes": 30},
            "data-used-up": {"data_limit_mb": 1, "bytes_downloaded": 5_000_000},
        }
        for key, kw in specs.items():
            g = Guest(
                organization_id=org.id,
                identifier=f"{key}{tag}@e.com",
                display_name="T",
                first_seen_at=now,
                last_seen_at=now,
            )
            s.add(g)
            await s.flush()
            row = GuestSession(
                guest_id=g.id,
                router_id=rtr.id,
                location_id=loc.id,
                organization_id=org.id,
                auth_method="otp_sms",
                status="active",
                started_at=now,
                last_activity_at=now,
                bytes_uploaded=0,
                bytes_downloaded=kw.pop("bytes_downloaded", 0),
                **kw,
            )
            s.add(row)
            await s.flush()
            sessions[key] = row.id
        await s.commit()

    async def fup(self, session, access_tier=None):  # noqa: ANN001, ANN202
        return 1800 if session.id == sessions["fup"] else None

    async def open_hours(self, session):  # noqa: ANN001, ANN202
        return 900 if session.id == sessions["open-hours"] else None

    async def bandwidth(self, router, session):  # noqa: ANN001, ANN202
        if session.id == sessions["wispr"]:
            return 5_000_000, 1_000_000
        return None, None

    monkeypatch.setattr(guest_service.GuestService, "_fup_time_remaining_seconds", fup)
    monkeypatch.setattr(guest_service.GuestService, "_open_hours_standing", open_hours)
    monkeypatch.setattr(
        guest_service.RadiusService, "_nas_only_bandwidth_attributes", bandwidth
    )

    # One device per guest, as in real life: authorize binds the MAC.
    macs = {
        key: f"AA:E{i}:{tag[0:2]}:{tag[2:4]}:{tag[4:6]}:{tag[6:8]}".upper()
        for i, key in enumerate(specs)
    }
    app = create_app()

    def set_flags(*on: str) -> None:
        for name in FLAGS:
            monkeypatch.delenv(name, raising=False)
        for name in on:
            monkeypatch.setenv(name, "true")
        get_isp_partner_settings.cache_clear()
        _isp_customer_cache.clear()

    try:
        hh.clear_hotspot_gates()
        hh.register_hotspot_gate(jaze2_hotspot_gate)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t"
        ) as c:

            async def sweep() -> dict[str, bytes]:
                out: dict[str, bytes] = {}
                for key in specs:
                    r = await c.post(
                        "/api/v1/radius/authorize",
                        json={
                            "username": f"{key}{tag}@e.com",
                            "calling_station_id": macs[key],
                        },
                        headers={
                            "X-RADIUS-NAS-Identifier": nas_id,
                            "X-RADIUS-Shared-Secret": SECRET,
                        },
                    )
                    assert r.status_code == 200, (key, r.text)
                    out[key] = r.content
                return out

            def counted_down(replies: dict[str, bytes]) -> dict[str, bytes]:
                """The two session-limit replies count down: check the value,
                then blank it so the rest of the bytes can compare."""
                out = dict(replies)
                left = 7200 - (datetime.now(UTC) - now).total_seconds()
                body = replies["session-timeout"]
                got = int(re.search(rb'"Session-Timeout":(\d+)', body).group(1))
                assert abs(got - left) < 60, (got, left)
                out["session-timeout"] = re.sub(
                    rb'"Session-Timeout":\d+', b'"Session-Timeout":"N"', body
                )
                return out

            set_flags()
            base = await sweep()
            print("D-1 Aruba capped baseline:")
            for key, body in base.items():
                print(f"  {key}: {body.decode()}")
            parsed = {k: json.loads(v) for k, v in base.items()}
            for key in ("session-timeout", "fup", "open-hours", "wispr"):
                assert parsed[key]["control:Auth-Type"] == "Accept", (key, parsed[key])
            assert parsed["fup"]["Session-Timeout"] == 1800
            assert parsed["open-hours"]["Session-Timeout"] == 900
            wispr = base["wispr"].decode()
            assert "5000000" in wispr and "1000000" in wispr, wispr
            assert parsed["data-used-up"]["control:Auth-Type"] == "Reject"
            base = counted_down(base)

            set_flags("ISP_PARTNER_ENABLED")
            assert counted_down(await sweep()) == base, "ISP_PARTNER_ENABLED"
            set_flags("ISP_PARTNER_ENABLED", "ISP_PARTNER_ENFORCEMENT_ENABLED")
            assert counted_down(await sweep()) == base, "enforcement, cache miss"
            assert counted_down(await sweep()) == base, "enforcement, cached"
    finally:
        hh.clear_hotspot_gates()
        get_isp_partner_settings.cache_clear()
        await engine.dispose()
