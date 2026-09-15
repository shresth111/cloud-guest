"""A guest blocked while already online stops being re-admitted.

The defect: the login gate (``GuestService._enforce_access_control``)
refuses a blocked guest only when they *sign in*. Three other paths keep
an already-admitted guest online, and each read ``session.status`` and
nothing else:

* RADIUS ``authorize`` -- Accepted any guest with an ``ACTIVE`` row;
* ``GET /agent/authorized-macs`` -- kept a ``type=bypassed`` binding for
  every MAC with an ``ACTIVE`` row;
* ``get_active_session_for_device`` -- told the portal the guest was
  "already connected", skipping the sign-in step where the refusal shows.

A block's device-side removal (``guest_access.enforcement``) deliberately
leaves the row ``ACTIVE`` when the router cannot be made to agree -- which
happened in production when a router refused its stored API credentials.
So every one of those paths kept re-admitting the blocked guest.

These tests log a guest in, block them *afterwards* (the order that
matters), and assert each path now says no -- and that an unrelated guest
is untouched.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from app.domains.guest.constants import GuestAuthMethod, GuestSessionStatus
from app.domains.guest_access.service import AccessDecision, is_blocklisted
from app.domains.router_agent.dependencies import AgentIdentity
from app.domains.router_agent.router import agent_authorized_macs

from .test_guest import FakeAccessControlHook, Fixture, make_fixture

GUEST = "+15553334444"
OTHER_GUEST = "+15553335555"
MAC = "AA:BB:CC:DD:EE:01"
OTHER_MAC = "AA:BB:CC:DD:EE:02"


async def _login(fx: Fixture, identifier: str, mac: str):
    return await fx.guest_service.login_via_otp(
        identifier=identifier,
        code="GOOD",
        auth_method=GuestAuthMethod.OTP_SMS,
        organization_id=None,
        location_id=fx.location_id,
        router_id=fx.router.id,
        device_mac=mac,
    )


async def _nas(fx: Fixture):
    await fx.radius_service.register_nas(
        actor_user_id=uuid.uuid4(),
        router_id=fx.router.id,
        nas_identifier="nas-1",
        shared_secret="supersecret123",
    )
    return await fx.radius_service.authenticate_nas(
        nas_identifier="nas-1", shared_secret="supersecret123"
    )


@dataclass
class _NoTrustedDevices:
    async def list_active_entries_for_router(
        self, router_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> list[object]:
        return []


@dataclass
class _RaisingHook:
    calls: list[dict[str, object]] = field(default_factory=list)

    async def check_access(self, **kwargs: object) -> AccessDecision:
        self.calls.append(kwargs)
        raise RuntimeError("rule lookup unavailable")


async def _authorized_macs(fx: Fixture, hook: object) -> list[str]:
    identity = AgentIdentity(router=fx.router, credential=None)  # type: ignore[arg-type]
    response = await agent_authorized_macs(
        identity=identity,
        guest_repository=fx.repository,
        mac_authorization_service=_NoTrustedDevices(),  # type: ignore[arg-type]
        access_decision_service=hook,  # type: ignore[arg-type]
    )
    return response.mac_addresses


class TestRadiusAuthorize:
    async def test_a_guest_blocked_after_login_is_rejected_on_re_authorize(
        self,
    ) -> None:
        hook = FakeAccessControlHook()
        fx = make_fixture(access_control_hook=hook)
        login = await _login(fx, GUEST, MAC)
        nas = await _nas(fx)
        before = await fx.radius_service.authorize(nas_client=nas, username=GUEST)
        assert before.authorized is True

        hook.deny(identifier=GUEST)
        after = await fx.radius_service.authorize(nas_client=nas, username=GUEST)

        assert after.authorized is False
        # Deciding "no" is not the same as claiming the session ended.
        assert login.session.status == GuestSessionStatus.ACTIVE.value

    async def test_a_blocked_device_mac_is_rejected_on_re_authorize(self) -> None:
        hook = FakeAccessControlHook()
        fx = make_fixture(access_control_hook=hook)
        await _login(fx, GUEST, MAC)
        nas = await _nas(fx)

        hook.deny(mac_address=MAC)
        result = await fx.radius_service.authorize(
            nas_client=nas, username=GUEST, calling_station_id=MAC
        )

        assert result.authorized is False

    async def test_the_block_is_checked_at_the_sessions_own_location(self) -> None:
        hook = FakeAccessControlHook()
        fx = make_fixture(access_control_hook=hook)
        await _login(fx, GUEST, MAC)
        nas = await _nas(fx)
        hook.deny(identifier=GUEST)

        await fx.radius_service.authorize(nas_client=nas, username=GUEST)

        call = hook.calls[-1]
        assert call["location_id"] == fx.location_id
        assert call["organization_id"] == fx.organization_id
        assert call["whitelist_only_enabled"] is False

    async def test_an_unblocked_guest_is_still_authorized(self) -> None:
        hook = FakeAccessControlHook()
        fx = make_fixture(access_control_hook=hook)
        await _login(fx, GUEST, MAC)
        await _login(fx, OTHER_GUEST, OTHER_MAC)
        nas = await _nas(fx)

        hook.deny(identifier=OTHER_GUEST)
        result = await fx.radius_service.authorize(nas_client=nas, username=GUEST)

        assert result.authorized is True

    async def test_a_rule_lookup_failure_does_not_reject_connected_guests(
        self,
    ) -> None:
        hook = FakeAccessControlHook()
        fx = make_fixture(access_control_hook=hook)
        await _login(fx, GUEST, MAC)
        nas = await _nas(fx)

        hook.raises = RuntimeError("database blip")
        result = await fx.radius_service.authorize(nas_client=nas, username=GUEST)

        assert result.authorized is True


class TestAgentAuthorizedMacs:
    async def test_a_blocked_guests_mac_is_withdrawn_from_the_bypass_list(
        self,
    ) -> None:
        hook = FakeAccessControlHook()
        fx = make_fixture(access_control_hook=hook)
        await _login(fx, GUEST, MAC)
        await _login(fx, OTHER_GUEST, OTHER_MAC)
        assert await _authorized_macs(fx, hook) == sorted([MAC, OTHER_MAC])

        hook.deny(identifier=GUEST)

        assert await _authorized_macs(fx, hook) == [OTHER_MAC]

    async def test_a_blocked_device_mac_is_withdrawn_from_the_bypass_list(
        self,
    ) -> None:
        hook = FakeAccessControlHook()
        fx = make_fixture(access_control_hook=hook)
        await _login(fx, GUEST, MAC)

        hook.deny(mac_address=MAC)

        assert await _authorized_macs(fx, hook) == []

    async def test_a_rule_lookup_failure_keeps_every_binding(self) -> None:
        """Fail open: a database blip must not strip every guest at a venue
        of their bypass binding at once."""
        fx = make_fixture(access_control_hook=FakeAccessControlHook())
        await _login(fx, GUEST, MAC)

        assert await _authorized_macs(fx, _RaisingHook()) == [MAC]


class TestPortalAlreadyConnected:
    async def test_a_blocked_guest_is_not_told_they_are_already_connected(
        self,
    ) -> None:
        hook = FakeAccessControlHook()
        fx = make_fixture(access_control_hook=hook)
        await _login(fx, GUEST, MAC)
        assert (
            await fx.guest_service.get_active_session_for_device(
                router_id=fx.router.id, device_mac=MAC
            )
            is not None
        )

        hook.deny(identifier=GUEST)

        assert (
            await fx.guest_service.get_active_session_for_device(
                router_id=fx.router.id, device_mac=MAC
            )
            is None
        )


class TestIsBlocklisted:
    async def test_only_a_blocklist_decision_counts(self) -> None:
        """Whitelist-only mode refuses new sign-ins; it must never withdraw
        access from guests already online, so it is not a block here."""

        class WhitelistOnlyDenial:
            async def check_access(self, **kwargs: object) -> AccessDecision:
                return AccessDecision(
                    allowed=False, rule_type=None, matched_rule_id=None, reason="x"
                )

        assert (
            await is_blocklisted(
                WhitelistOnlyDenial(),
                organization_id=uuid.uuid4(),
                location_id=None,
                identifier=GUEST,
                mac_address=None,
            )
            is False
        )

    async def test_a_mac_identity_is_checked_by_mac_not_as_an_identifier(
        self,
    ) -> None:
        hook = FakeAccessControlHook()
        hook.deny(mac_address=MAC)

        blocked = await is_blocklisted(
            hook,
            organization_id=uuid.uuid4(),
            location_id=None,
            identifier=f"mac:{MAC}",
            mac_address=MAC,
        )

        assert blocked is True
        assert hook.calls[-1]["identifier"] is None

    async def test_nothing_to_check_asks_nothing(self) -> None:
        hook = FakeAccessControlHook()

        assert (
            await is_blocklisted(
                hook,
                organization_id=uuid.uuid4(),
                location_id=None,
                identifier=None,
                mac_address=None,
            )
            is False
        )
        assert hook.calls == []

    async def test_a_blocklist_decision_counts(self) -> None:
        hook = FakeAccessControlHook()
        hook.deny(identifier=GUEST)

        assert (
            await is_blocklisted(
                hook,
                organization_id=uuid.uuid4(),
                location_id=None,
                identifier=GUEST,
                mac_address=None,
            )
            is True
        )
