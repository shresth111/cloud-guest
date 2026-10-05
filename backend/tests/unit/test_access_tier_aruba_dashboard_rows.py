"""Access Tiers at an Aruba Instant On venue, from the rows the dashboard
writes to what the guest gets -- through the REAL ``PolicyService``.

``test_access_tier_enforcement.py`` proves each tier field against a stub
policy lookup, and ``test_access_tier.py`` proves ``resolve_access_tier``
against real assignment rows. This file joins the two: the Access Tiers tab
(``CreateGroup.tsx``) saves a BANDWIDTH policy with the exact rules body the
Aruba form sends, "Map tier" maps it to the location for everyone
(``target_type=none``), "Map users" maps a guest into it
(``target_type=guest``) -- and the portal sign-in and the RADIUS
Access-Request at an Instant On venue then resolve it with the production
resolver, alongside the venue's own Guest WiFi Limits policies.

It also pins down WHY the dashboard must not map a tier's *paired*
SESSION/DEVICE policies for everyone at an Aruba venue (fixed in the
frontend, ``mirrorsPairedAt`` in CreateGroup.tsx): a location-wide paired
SESSION policy ties with the venue's own and the newest assignment wins, so
every guest at the venue -- not just the tier's guests -- would get the
tier's session length.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.domains.guest.exceptions import (
    AccessTierOutsideLoginHoursError,
    GuestDeviceLimitExceededError,
)
from app.domains.guest.validators import canonicalize_calling_station_id
from app.domains.policy.constants import PolicyAssignmentTargetType, PolicyType
from app.domains.policy.schemas import BandwidthPolicyRules
from app.domains.rbac.enums import ScopeType
from tests.unit.test_aruba_access_rules import (
    _authorize,
    _fixture,
    _register_nas,
    _set_minutes_used,
    _sign_in,
)
from tests.unit.test_policy import _build_service

_PHONE_2 = "+919800000002"
_MAC_2 = "aa:bb:cc:dd:ee:02"
_MAC_3 = "aa:bb:cc:dd:ee:03"

#: What the Aruba tier form sends (scripts/test-access-tiers-aruba.mjs pins the
#: same body on the frontend side): speed held, not applied; Unlimited
#: devices as the explicit 9999; "No Limit" daily as 0.
_DASHBOARD_TIER_RULES: dict[str, object] = {
    "download_rate_kbps": 5120,
    "upload_rate_kbps": 5120,
    "burst_download_kbps": None,
    "burst_upload_kbps": None,
    "burst_threshold_kbps": None,
    "burst_time_seconds": None,
    "priority": None,
    "session_timeout_minutes": 60,
    "idle_timeout_minutes": 10,
    "devices_per_user": 9999,
    "daily_limit_minutes": 0,
    "login_hours": {
        "days": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
        "start_time": "00:00",
        "end_time": "00:00",
    },
    "data_limit": {"quota": 3, "unit": "GB", "resets": "Weekly"},
}

_VENUE_SESSION = {
    "session_timeout_minutes": 240,
    "idle_timeout_minutes": 30,
    "max_concurrent_sessions_per_guest": 20,
    "termination_reconnect_cooldown_minutes": 60,
    "reconnect_grace_minutes": 30,
}


async def _published(service, org_id, policy_type: PolicyType, name: str, rules):  # noqa: ANN001, ANN202
    policy = await service.create_policy(
        actor_user_id=None,
        requesting_organization_id=org_id,
        organization_id=org_id,
        policy_type=policy_type,
        name=name,
        description=None,
    )
    version = await service.create_version(
        policy_id=policy.id,
        requesting_organization_id=org_id,
        actor_user_id=None,
        rules=rules,
    )
    await service.publish_version(
        policy_id=policy.id,
        version_id=version.id,
        requesting_organization_id=org_id,
        actor_user_id=None,
    )
    return policy


async def _assign(service, policy, org_id, loc_id, guest_id=None):  # noqa: ANN001, ANN202
    return await service.create_assignment(
        policy_id=policy.id,
        requesting_organization_id=org_id,
        actor_user_id=None,
        scope_type=ScopeType.LOCATION.value,
        scope_id=loc_id,
        priority=0,
        target_type=(
            PolicyAssignmentTargetType.GUEST.value
            if guest_id
            else PolicyAssignmentTargetType.NONE.value
        ),
        target_id=guest_id,
    )


async def _aruba_venue(**tier_overrides: object):  # noqa: ANN202
    """An Instant On venue on the real PolicyService: Guest WiFi Limits
    (SESSION 240/30, DEVICE 3) mapped for everyone, one tier saved from the
    dashboard and mapped to the location, and one guest mapped into it."""
    service, _, org_lookup, _ = _build_service()
    fx = _fixture(policy_lookup=service)
    org = org_lookup.add()
    org_lookup.organizations.pop(org.id)
    org.id = fx.organization_id
    org_lookup.organizations[org.id] = org
    service.location_lookup.add(organization_id=org.id, location_id=fx.location_id)

    venue_session = await _published(
        service, org.id, PolicyType.SESSION, "Office", _VENUE_SESSION
    )
    venue_device = await _published(
        service, org.id, PolicyType.DEVICE, "Office", {"max_devices_per_guest": 3}
    )
    await _assign(service, venue_session, org.id, fx.location_id)
    await _assign(service, venue_device, org.id, fx.location_id)

    rules = {**_DASHBOARD_TIER_RULES, **tier_overrides}
    BandwidthPolicyRules.model_validate(rules)  # the save the dashboard makes
    tier = await _published(service, org.id, PolicyType.BANDWIDTH, "Gold", rules)
    await _assign(service, tier, org.id, fx.location_id)  # "Map tier"

    nas = await _register_nas(fx)
    first = await _sign_in(fx)  # a guest must exist before they can be mapped
    await _assign(service, tier, org.id, fx.location_id, first.guest.id)  # "Map users"
    return fx, nas, service, org.id, first


class TestTheDashboardsTierReachesTheMappedGuest:
    async def test_the_form_body_validates(self) -> None:
        BandwidthPolicyRules.model_validate(_DASHBOARD_TIER_RULES)

    async def test_session_and_idle_timeout_come_from_the_tier(self) -> None:
        fx, nas, _, _, _ = await _aruba_venue()
        second = await _sign_in(fx)
        assert second.session.session_timeout_minutes == 60
        authz = await _authorize(fx, nas)
        assert authz.authorized is True
        assert 3590 <= authz.session_timeout_seconds <= 3600
        assert authz.idle_timeout_seconds == 600

    async def test_unlimited_devices_lifts_the_venues_three(self) -> None:
        fx, _, _, _, _ = await _aruba_venue()
        await _sign_in(fx, mac=_MAC_2)
        await _sign_in(fx, mac=_MAC_3)
        fourth = await _sign_in(fx, mac="aa:bb:cc:dd:ee:04")
        assert fourth.session is not None

    async def test_a_stricter_device_count_refuses_the_extra_device(self) -> None:
        fx, _, _, _, _ = await _aruba_venue(devices_per_user=1)
        with pytest.raises(GuestDeviceLimitExceededError):
            await _sign_in(fx, mac=_MAC_2)

    async def test_a_daily_limit_used_up_refuses_the_access_request(self) -> None:
        fx, nas, _, _, first = await _aruba_venue(daily_limit_minutes=30)
        await _set_minutes_used(fx, first.guest.id, 30)
        assert (await _authorize(fx, nas)).authorized is False

    async def test_login_hours_outside_the_window_refuse_sign_in(self) -> None:
        day = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][
            (datetime.now(UTC).weekday() + 3) % 7
        ]
        fx, nas, _, _, _ = await _aruba_venue(
            login_hours={"days": [day], "start_time": "10:00", "end_time": "11:00"}
        )
        with pytest.raises(AccessTierOutsideLoginHoursError):
            await _sign_in(fx)
        assert (await _authorize(fx, nas)).authorized is False

    async def test_the_tier_data_cap_replaces_the_venues(self) -> None:
        _, _, service, org_id, first = await _aruba_venue()
        tier = await service.resolve_access_tier(
            organization_id=org_id,
            location_id=first.session.location_id,
            guest_id=first.guest.id,
        )
        assert tier is not None
        assert (tier.data_limit_mb, tier.data_limit_period) == (3072, "weekly")


class TestMapTierChangesNobodyElse:
    async def test_a_guest_not_mapped_in_keeps_guest_wifi_limits(self) -> None:
        """ "Map tier" (target none) is not membership: another guest at the
        same venue still gets the venue's 240 minutes and 30-minute idle."""
        fx, nas, _, _, _ = await _aruba_venue()
        other = await _sign_in(fx, identifier=_PHONE_2, mac=_MAC_2)
        assert other.session.session_timeout_minutes == 240
        authz = await fx.radius_service.authorize(
            nas_client=nas,
            username=_PHONE_2,
            calling_station_id=canonicalize_calling_station_id(_MAC_2.replace(":", "")),
        )
        assert authz.authorized is True
        assert 14390 <= authz.session_timeout_seconds <= 14400
        assert authz.idle_timeout_seconds == 1800

    async def test_a_paired_session_policy_mapped_for_everyone_would_hijack_the_venue(
        self,
    ) -> None:
        """Why the dashboard stopped doing this at Aruba (CreateGroup.tsx,
        ``mirrorsPairedAt``): the tier's paired SESSION policy, mapped to the
        location for everyone, ties with Guest WiFi Limits' own and -- being
        newer -- wins for EVERY guest, including one never mapped in."""
        fx, nas, service, org_id, _ = await _aruba_venue()
        paired = await _published(
            service,
            org_id,
            PolicyType.SESSION,
            "Gold",
            {**_VENUE_SESSION, "session_timeout_minutes": 60},
        )
        await _assign(service, paired, org_id, fx.location_id)
        other = await _sign_in(fx, identifier=_PHONE_2, mac=_MAC_2)
        # An unmapped guest, all the same.
        assert other.session.session_timeout_minutes == 60
