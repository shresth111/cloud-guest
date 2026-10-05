"""Trusted Devices at an Aruba Instant On venue.

Instant On has no MAC authentication on a guest network, so the AP only asks
RADIUS after the portal's login POST. ``GuestService
.trusted_device_login_identifier`` tells the portal a device is trusted so it
can make that POST without a sign-in form; ``RadiusService.authorize`` is
still the only place the device is admitted, on the AP-asserted MAC.
"""

from __future__ import annotations

import uuid

from app.domains.guest.constants import GuestAuthMethod
from app.domains.guest.validators import canonicalize_calling_station_id
from app.domains.router.vendor_capabilities import ARUBA_INSTANT_ON_VENDOR
from tests.unit.test_guest import FakeMacAuthorizationHook, make_fixture

TRUSTED = "60:F4:45:0B:28:66"
OTHER = "11:22:33:44:55:66"


def _aruba_fixture(*, hook: FakeMacAuthorizationHook | None = None):  # noqa: ANN202
    fx = make_fixture(
        mac_authorization_hook=hook
        if hook is not None
        else FakeMacAuthorizationHook(whitelisted={TRUSTED})
    )
    fx.router.vendor = ARUBA_INSTANT_ON_VENDOR
    return fx


async def _nas(fx):  # noqa: ANN001, ANN202
    await fx.radius_service.register_nas(
        actor_user_id=uuid.uuid4(),
        router_id=fx.router.id,
        nas_identifier="cg-aruba-test",
        shared_secret="supersecret123",
    )
    return await fx.radius_service.authenticate_nas(
        nas_identifier="cg-aruba-test", shared_secret="supersecret123"
    )


class TestTrustedDeviceLoginIdentifier:
    async def test_a_trusted_device_at_an_aruba_venue_gets_its_identifier(self) -> None:
        fx = _aruba_fixture()
        assert (
            await fx.guest_service.trusted_device_login_identifier(
                router_id=fx.router.id, device_mac="60:f4:45:0b:28:66"
            )
            == f"mac:{TRUSTED}"
        )

    async def test_any_mac_spelling_is_accepted(self) -> None:
        fx = _aruba_fixture()
        for spelling in ("60f4450b2866", "60-F4-45-0B-28-66", " 60:F4:45:0B:28:66 "):
            assert (
                await fx.guest_service.trusted_device_login_identifier(
                    router_id=fx.router.id, device_mac=spelling
                )
                == f"mac:{TRUSTED}"
            )

    async def test_the_lookup_is_scoped_to_the_routers_venue(self) -> None:
        hook = FakeMacAuthorizationHook(whitelisted={TRUSTED})
        fx = _aruba_fixture(hook=hook)
        await fx.guest_service.trusted_device_login_identifier(
            router_id=fx.router.id, device_mac=TRUSTED
        )
        assert hook.calls[-1]["organization_id"] == fx.router.organization_id
        assert hook.calls[-1]["location_id"] == fx.router.location_id

    async def test_an_untrusted_device_gets_nothing(self) -> None:
        fx = _aruba_fixture()
        assert (
            await fx.guest_service.trusted_device_login_identifier(
                router_id=fx.router.id, device_mac=OTHER
            )
            is None
        )

    async def test_a_malformed_mac_gets_nothing(self) -> None:
        hook = FakeMacAuthorizationHook(whitelisted={TRUSTED})
        fx = _aruba_fixture(hook=hook)
        assert (
            await fx.guest_service.trusted_device_login_identifier(
                router_id=fx.router.id, device_mac="not-a-mac"
            )
            is None
        )
        assert hook.calls == []

    async def test_a_mikrotik_router_is_unchanged(self) -> None:
        """MikroTik admits a trusted device in RADIUS on connect; the portal
        never sees it, so this answer is never needed there."""
        fx = make_fixture(
            mac_authorization_hook=FakeMacAuthorizationHook(whitelisted={TRUSTED})
        )
        assert (
            await fx.guest_service.trusted_device_login_identifier(
                router_id=fx.router.id, device_mac=TRUSTED
            )
            is None
        )

    async def test_no_hook_wired_gets_nothing(self) -> None:
        fx = make_fixture()
        fx.router.vendor = ARUBA_INSTANT_ON_VENDOR
        assert (
            await fx.guest_service.trusted_device_login_identifier(
                router_id=fx.router.id, device_mac=TRUSTED
            )
            is None
        )

    async def test_an_unknown_router_gets_nothing(self) -> None:
        fx = _aruba_fixture()
        assert (
            await fx.guest_service.trusted_device_login_identifier(
                router_id=uuid.uuid4(), device_mac=TRUSTED
            )
            is None
        )

    async def test_a_blocked_trusted_device_gets_nothing(self) -> None:
        """Its sign-in page is where the refusal is shown; an auto-submit
        would only land it on the AP's own error page."""
        fx = _aruba_fixture()
        nas = await _nas(fx)
        authz = await fx.radius_service.authorize(
            nas_client=nas,
            username=f"mac:{TRUSTED}",
            calling_station_id=canonicalize_calling_station_id("60f4450b2866"),
        )
        assert authz.authorized is True
        guest = await fx.repository.get_guest_by_identifier(
            fx.router.organization_id, f"mac:{TRUSTED}"
        )
        guest.is_blocked = True
        assert (
            await fx.guest_service.trusted_device_login_identifier(
                router_id=fx.router.id, device_mac=TRUSTED
            )
            is None
        )


class TestTheApLoginAdmitsOnlyTheRealDevice:
    async def test_the_portal_identifier_and_the_aps_mac_admit_a_trusted_device(
        self,
    ) -> None:
        """The whole Aruba path: the portal posts ``user=mac:<MAC>``, the AP
        sends that as User-Name with its own bare-hex Calling-Station-Id."""
        fx = _aruba_fixture()
        nas = await _nas(fx)
        authz = await fx.radius_service.authorize(
            nas_client=nas,
            username=f"mac:{TRUSTED}",
            calling_station_id=canonicalize_calling_station_id("60f4450b2866"),
        )
        assert authz.authorized is True
        assert authz.session_timeout_seconds is not None
        guest = await fx.repository.get_guest_by_identifier(
            fx.router.organization_id, f"mac:{TRUSTED}"
        )
        sessions = await fx.repository.list_active_sessions_for_guest(guest.id)
        assert [s.auth_method for s in sessions] == [
            GuestAuthMethod.MAC_WHITELIST.value
        ]

    async def test_the_aps_reauthorize_reuses_the_session(self) -> None:
        fx = _aruba_fixture()
        nas = await _nas(fx)
        for _ in range(2):
            authz = await fx.radius_service.authorize(
                nas_client=nas,
                username=f"mac:{TRUSTED}",
                calling_station_id=canonicalize_calling_station_id("60f4450b2866"),
            )
            assert authz.authorized is True
        guest = await fx.repository.get_guest_by_identifier(
            fx.router.organization_id, f"mac:{TRUSTED}"
        )
        assert len(await fx.repository.list_active_sessions_for_guest(guest.id)) == 1

    async def test_naming_a_trusted_mac_from_another_device_is_refused(self) -> None:
        """A browser can POST any User-Name; the AP still reports its real MAC."""
        fx = _aruba_fixture()
        nas = await _nas(fx)
        authz = await fx.radius_service.authorize(
            nas_client=nas,
            username=f"mac:{TRUSTED}",
            calling_station_id=canonicalize_calling_station_id("112233445566"),
        )
        assert authz.authorized is False

    async def test_riding_an_online_trusted_devices_session_is_refused(self) -> None:
        fx = _aruba_fixture()
        nas = await _nas(fx)
        first = await fx.radius_service.authorize(
            nas_client=nas,
            username=f"mac:{TRUSTED}",
            calling_station_id=canonicalize_calling_station_id("60f4450b2866"),
        )
        assert first.authorized is True
        second = await fx.radius_service.authorize(
            nas_client=nas,
            username=f"mac:{TRUSTED}",
            calling_station_id=canonicalize_calling_station_id("112233445566"),
        )
        assert second.authorized is False
