# ruff: noqa: PLR0915 -- scenario test
"""D-1 evidence: regular tenants' RADIUS replies are byte-identical whatever the
ISP flags say, on main's Aruba-aware authorize plus the ENFORCE-2 hook.

Real PostgreSQL + Redis (skipped unless ``ISP_TEST_PG_DSN``; run with
``scripts/run_isp_pg_tests.py``). Real HTTP through the whole app, so the full
DI and reply serialisation run. Compares ``response.content`` -- bytes, not
parsed JSON -- across three states:

  off      ISP_PARTNER_ENABLED off, enforcement off (the first prod deploy)
  partner  ISP_PARTNER_ENABLED on, enforcement off
  enforce  ISP_PARTNER_ENABLED on, enforcement on, the real JAZE-2 gate
           registered (twice: the first call misses the is-ISP cache)

Scenarios, all non-ISP tenants:

  * MikroTik venue, per-venue listener: accept and unknown-guest reject;
  * Aruba Instant On venue, per-venue listener: accept and reject;
  * Aruba Instant On venue, shared listener (Called-Station-Id, NAS-Identifier
    from inside the packet): accept on an open SSID, refusal on an
    entitlement-only SSID (main's speed-tier gate), reject on a wrong AP MAC.

A control swaps in a gate that shortens Idle-Timeout and asserts the bytes DO
change, so a comparison that cannot see a difference fails instead of passing.

What this does NOT prove: what an AP does on the wire. FreeRADIUS and the AP
are not in the loop (see RELEASE_RUNBOOK Z5 for the radclient compare).
"""

from __future__ import annotations

import dataclasses
import os
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

needs_pg = pytest.mark.skipif(
    not os.environ.get("ISP_TEST_PG_DSN"), reason="set ISP_TEST_PG_DSN to run"
)

AGENT = "d1-hub-agent-secret"
RADIUS_SECRET = "d1-shared-radius-secret"
NAS_SECRET = "s3cret"
FLAGS = ("ISP_PARTNER_ENABLED", "ISP_PARTNER_ENFORCEMENT_ENABLED")


def test_a_verdict_keeps_mains_aruba_reply_fields() -> None:
    """The one place the hook rebuilds a reply: an ISP rule that shortens a
    timeout must not drop main's WISPr bandwidth fields."""
    from app.domains.guest.service import RadiusAuthorizeResult
    from app.domains.isp_partner.hotspot_hooks import (
        HotspotGateResult,
        apply_hotspot_verdict,
    )

    accepted = RadiusAuthorizeResult(
        authorized=True,
        session_timeout_seconds=3600,
        data_limit_mb=None,
        idle_timeout_seconds=1800,
        rate_limit=None,
        bandwidth_max_down_bps=5_000_000,
        bandwidth_max_up_bps=1_000_000,
    )
    assert apply_hotspot_verdict(None, accepted) is accepted
    shorter = apply_hotspot_verdict(HotspotGateResult(idle_timeout_cap=60), accepted)
    assert dataclasses.asdict(shorter) == {
        **dataclasses.asdict(accepted),
        "idle_timeout_seconds": 60,
    }


@needs_pg
async def test_regular_tenant_replies_are_byte_identical(monkeypatch) -> None:  # noqa: ANN001
    import httpx

    from app.database.session import SessionLocal, engine
    from app.domains.guest import aruba_shared
    from app.domains.guest.models import (
        Guest,
        GuestSession,
        LocationSsidTier,
        RadiusNasClient,
    )
    from app.domains.isp_partner import hotspot_hooks as hh
    from app.domains.isp_partner.config import get_isp_partner_settings
    from app.domains.isp_partner.enforcement_hotspot import jaze2_hotspot_gate
    from app.domains.isp_partner.rate_limit import _isp_customer_cache
    from app.domains.location.models import Location
    from app.domains.organization.models import Organization
    from app.domains.router.crypto import encrypt_secret
    from app.domains.router.models import Router
    from app.domains.system_settings.constants import SystemSettingKey
    from app.domains.system_settings.repository import SystemSettingsRepository
    from app.main import create_app

    monkeypatch.setattr(
        aruba_shared,
        "get_settings",
        lambda: SimpleNamespace(
            hub_radius_agent_secret=AGENT,
            hub_radius_aruba_shared_agent_url="http://agent/radius/shared-client",
        ),
    )
    backend_secret = aruba_shared.backend_secret_for(RADIUS_SECRET, AGENT)

    tag = uuid.uuid4().hex[:8]
    now = datetime.now(UTC)
    ap_mac = f"54:F0:B1:{tag[0:2]}:{tag[2:4]}:{tag[4:6]}".upper()

    async with SessionLocal() as s:
        await SystemSettingsRepository(s).upsert(
            SystemSettingKey.ARUBA_SHARED_RADIUS.value,
            {"secret_encrypted": encrypt_secret(RADIUS_SECRET)},
        )

        async def venue(key: str, vendor: str, mac: str):  # noqa: ANN202
            org = Organization(
                name=f"Reg {key} {tag}",
                slug=f"reg{key}{tag}",
                org_type="standard",
                status="active",
                contact_email=f"reg{key}{tag}@e.com",
                timezone="Asia/Kolkata",
                settings={},
            )
            s.add(org)
            await s.flush()
            loc = Location(
                organization_id=org.id,
                name=key,
                slug=f"{key}{tag}",
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
                name=key,
                serial_number=f"SN{key}{tag}",
                mac_address=mac,
                model="m",
                vendor=vendor,
                settings={},
            )
            s.add(rtr)
            await s.flush()
            return org, loc, rtr

        def add_guest(org, ident: str) -> Guest:  # noqa: ANN001
            g = Guest(
                organization_id=org.id,
                identifier=ident,
                display_name="Test",
                first_seen_at=now,
                last_seen_at=now,
            )
            s.add(g)
            return g

        mt_org, mt_loc, mt_rtr = await venue(
            "mt", "mikrotik", f"06:00:{tag[0:2]}:{tag[2:4]}:{tag[4:6]}:{tag[6:8]}"
        )
        ar_org, ar_loc, ar_rtr = await venue("ar", "aruba_instant_on", ap_mac)
        mt_nas = f"nas-mt{tag}"
        ar_nas = aruba_shared.would_be_nas_identifier(ar_rtr.id)
        for rtr, org, loc, ident in (
            (mt_rtr, mt_org, mt_loc, mt_nas),
            (ar_rtr, ar_org, ar_loc, ar_nas),
        ):
            s.add(
                RadiusNasClient(
                    router_id=rtr.id,
                    organization_id=org.id,
                    location_id=loc.id,
                    nas_identifier=ident,
                    vendor=rtr.vendor,
                    status="active",
                    is_active=True,
                    shared_secret_encrypted=encrypt_secret(NAS_SECRET),
                )
            )
        guests = {
            "mt": add_guest(mt_org, f"mt{tag}@e.com"),
            "ar": add_guest(ar_org, f"ar{tag}@e.com"),
        }
        await s.flush()
        for g, rtr, org, loc in (
            (guests["mt"], mt_rtr, mt_org, mt_loc),
            (guests["ar"], ar_rtr, ar_org, ar_loc),
        ):
            # No Session-Timeout: it counts down, so replies could not compare.
            s.add(
                GuestSession(
                    guest_id=g.id,
                    router_id=rtr.id,
                    location_id=loc.id,
                    organization_id=org.id,
                    auth_method="otp_sms",
                    status="active",
                    started_at=now,
                    last_activity_at=now,
                    bytes_uploaded=0,
                    bytes_downloaded=0,
                    idle_timeout_minutes=30,
                )
            )
        for ssid, paid in (("WYFY_FREE", False), ("WYFY_PREMIUM", True)):
            s.add(
                LocationSsidTier(
                    organization_id=ar_org.id,
                    location_id=ar_loc.id,
                    ssid=ssid,
                    tier_name=ssid,
                    requires_entitlement=paid,
                    voucher_plan_ids=[],
                    sort_order=1 if paid else 0,
                )
            )
        await s.commit()

    gmac = f"AA:E2:{tag[0:2]}:{tag[2:4]}:{tag[4:6]}:{tag[6:8]}".upper()
    app = create_app()

    def per_venue(nas: str, user: str) -> dict:
        return {
            "url": "/api/v1/radius/authorize",
            "json": {"username": user, "calling_station_id": gmac},
            "headers": {
                "X-RADIUS-NAS-Identifier": nas,
                "X-RADIUS-Shared-Secret": NAS_SECRET,
            },
        }

    def shared(user: str, called: str, essid: str) -> dict:
        return {
            "url": "/api/v1/radius/aruba-shared/authorize",
            "json": {"username": user, "calling_station_id": gmac},
            "headers": {
                "X-RADIUS-Shared-Secret": backend_secret,
                "X-RADIUS-Packet-NAS-Identifier": ar_nas,
                "X-RADIUS-Called-Station-Id": called,
                "X-RADIUS-Aruba-Essid-Name": essid,
            },
        }

    ap_dash = ap_mac.replace(":", "-")
    scenarios: dict[str, tuple[dict, str]] = {
        "mikrotik accept": (per_venue(mt_nas, f"mt{tag}@e.com"), "Accept"),
        "mikrotik reject": (per_venue(mt_nas, f"nobody{tag}@e.com"), "Reject"),
        "aruba per-venue accept": (per_venue(ar_nas, f"ar{tag}@e.com"), "Accept"),
        "aruba per-venue reject": (per_venue(ar_nas, f"nobody{tag}@e.com"), "Reject"),
        "aruba shared open ssid": (
            shared(f"ar{tag}@e.com", ap_dash, "WYFY_FREE"),
            "Accept",
        ),
        "aruba shared entitlement ssid refused": (
            shared(f"ar{tag}@e.com", ap_dash, "WYFY_PREMIUM"),
            "Reject",
        ),
        "aruba shared wrong ap": (
            shared(f"ar{tag}@e.com", "00-11-22-33-44-55", "WYFY_FREE"),
            "Reject",
        ),
    }

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
                for name, (req, _want) in scenarios.items():
                    r = await c.post(**req)
                    assert r.status_code == 200, (name, r.status_code, r.text)
                    out[name] = r.content
                return out

            set_flags()
            off = await sweep()
            for name, (_req, want) in scenarios.items():
                assert f'"control:Auth-Type":"{want}"'.encode() in off[name].replace(
                    b": ", b":"
                ), (name, off[name])
            print("D-1 baseline replies:")
            for name, body in off.items():
                print(f"  {name}: {body.decode()}")

            set_flags("ISP_PARTNER_ENABLED")
            assert await sweep() == off, "ISP_PARTNER_ENABLED changed a reply"

            set_flags("ISP_PARTNER_ENABLED", "ISP_PARTNER_ENFORCEMENT_ENABLED")
            assert await sweep() == off, "enforcement changed a reply (cache miss)"
            assert await sweep() == off, "enforcement changed a reply (cached)"

            # Control: the comparison can see a change. A hook verdict that
            # shortens Idle-Timeout must alter exactly the accepts.
            async def shorter(**_kw):  # noqa: ANN003, ANN202
                return hh.HotspotGateResult(idle_timeout_cap=60)

            monkeypatch.setattr(hh, "run_hotspot_gates", shorter)
            changed = await sweep()
            for name, (_req, want) in scenarios.items():
                if want == "Accept":
                    assert changed[name] != off[name], name
                else:
                    assert changed[name] == off[name], name
    finally:
        hh.clear_hotspot_gates()
        get_isp_partner_settings.cache_clear()
        await engine.dispose()
