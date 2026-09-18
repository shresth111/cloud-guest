"""Per-client management at an Omada venue: capabilities, tenancy, and the
two ordering bugs that made a controller-managed venue fail with a sentence
about credentials it does not have.

## What these tests are guarding

**Tenancy.** The customer-facing client routes are keyed on a location and a
MAC -- never on an integration id or a site id -- and the integration is
resolved with the caller's organization *in the query*. That is what makes a
cross-tenant action structurally impossible rather than merely checked, and
what makes "not yours" and "does not exist" the same answer. Every write has
a test here that an admin of one organization cannot reach another's venue,
and that the refusal is the same one they would get for a location of their
own with no controller.

**Honesty about what the controller can do.** A ``legacy`` integration is
reported unsupported up front, with a reason, rather than failing at call
time; and ``list_blocked`` is reported unsupported on *both* modes, because
the block flag is not readable through the connection this platform holds and
an empty list would be a false statement about the venue.

**MikroTik is untouched.** ``TestMikroTikPathIsUnchanged`` is the proof
obligation for the whole change: the RouterOS branch of both reordered call
sites must resolve the same credentials, reach the same adapter and make the
same calls, in the same order.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

import pytest

from app.domains.network_integration.constants import ControllerAuthMode
from app.domains.network_integration.exceptions import (
    ClientActionUnavailableError,
    LocationHasNoControllerError,
    ProviderUnsupportedApiError,
)
from app.domains.network_integration.providers.base import (
    CONTROLLER_RATE_LIMIT_MAX_KBPS,
    ProviderConnectionConfig,
)
from app.domains.network_integration.providers.omada import OmadaProvider

from .test_network_integration import (
    FakeProvider,
    FakeRepository,
    _integration,
    _service,
)

pytestmark = pytest.mark.asyncio

CLIENT_MAC = "AA:BB:CC:DD:EE:FF"


def _config(auth_mode: str) -> ProviderConnectionConfig:
    return ProviderConnectionConfig(
        provider="omada",
        base_url="https://controller.example.com:8043",
        auth_mode=auth_mode,
        credentials={"client_id": "cid", "client_secret": "shh"},
    )


def _venue(
    *,
    auth_mode: str = ControllerAuthMode.OPENAPI.value,
    provider: FakeProvider | None = None,
):
    """One organization, one location, one controller -- and a second
    organization with neither."""
    organization_id = uuid.uuid4()
    location_id = uuid.uuid4()
    repo = FakeRepository()
    repo.add(
        _integration(
            organization_id=organization_id,
            location_id=location_id,
            auth_mode=auth_mode,
            external_site_id="a" * 24,
        )
    )
    service = _service(repo, provider=provider or FakeProvider())
    return service, organization_id, location_id


# ===========================================================================
# Capabilities: declared per auth mode, before anything is called
# ===========================================================================


class TestCapabilitiesAreDeclaredNotDiscovered:
    def test_open_api_can_do_the_per_client_writes(self) -> None:
        capabilities = OmadaProvider().client_capabilities(
            _config(ControllerAuthMode.OPENAPI.value)
        )
        assert capabilities.set_rate_limit.supported is True
        assert capabilities.block.supported is True
        assert capabilities.unblock.supported is True
        assert capabilities.set_rate_limit.reason is None

    def test_a_hotspot_operator_venue_reports_them_unsupported_with_a_reason(
        self,
    ) -> None:
        """Not a failure at click time. A ``legacy`` integration provably
        cannot reach the client record -- that lives in the site tree and a
        hotspot-operator session reaches the portal tree only -- so the
        console is told up front and can disable the control."""
        capabilities = OmadaProvider().client_capabilities(
            _config(ControllerAuthMode.LEGACY.value)
        )
        assert capabilities.set_rate_limit.supported is False
        assert capabilities.block.supported is False
        assert "Open API" in (capabilities.block.reason or "")

    def test_disconnect_survives_legacy_mode_because_it_rides_the_portal(
        self,
    ) -> None:
        """The one client action a hotspot-operator venue keeps. If this ever
        flips to unsupported, every legacy venue silently loses its only way
        to remove a guest."""
        for mode in (ControllerAuthMode.OPENAPI, ControllerAuthMode.LEGACY):
            capabilities = OmadaProvider().client_capabilities(_config(mode.value))
            assert capabilities.disconnect.supported is True

    def test_listing_blocked_clients_is_unsupported_in_both_modes(self) -> None:
        """Measured: ``filters.blocked=true`` is silently ignored by the
        controller (it returned all six rows, every one unblocked), and the
        client grid this platform reads carries no block field at all. So
        there is no honest way to answer, on either surface."""
        for mode in (ControllerAuthMode.OPENAPI, ControllerAuthMode.LEGACY):
            capabilities = OmadaProvider().client_capabilities(_config(mode.value))
            assert capabilities.list_blocked.supported is False
            assert capabilities.list_blocked.reason

    async def test_listing_blocked_clients_raises_rather_than_returning_empty(
        self,
    ) -> None:
        """An empty list is this platform asserting the venue has blocked
        nobody, on the strength of a question it could not ask."""
        with pytest.raises(ProviderUnsupportedApiError):
            await OmadaProvider().list_blocked_clients(
                _config(ControllerAuthMode.OPENAPI.value), "a" * 24
            )

    async def test_a_legacy_venue_is_refused_before_the_controller_is_called(
        self,
    ) -> None:
        provider = FakeProvider()
        service, organization_id, location_id = _venue(
            auth_mode=ControllerAuthMode.LEGACY.value, provider=provider
        )
        with pytest.raises(ClientActionUnavailableError):
            await service.block_client(
                location_id=location_id,
                organization_id=organization_id,
                client_mac=CLIENT_MAC,
                actor_user_id=None,
            )
        assert provider.client_actions == []

    def test_the_clamp_ceiling_is_the_documented_one_not_the_stored_one(self) -> None:
        """The controller accepted and stored 5000 Mbps when asked. The
        documented contract is 1-1024 and nothing shows an access point
        honours more, so this platform's ceiling is the documented one."""
        assert CONTROLLER_RATE_LIMIT_MAX_KBPS == 1024 * 1000


# ===========================================================================
# Tenancy
# ===========================================================================


class TestAVenueAdminCannotReachAnotherTenant:
    """One test per write, plus the read.

    The refusal must be identical to the one a caller gets for a location of
    their own that has no controller -- otherwise the response is a probe for
    other tenants' locations.
    """

    async def _act(self, service, action: str, organization_id, location_id):
        if action == "capabilities":
            return await service.get_client_capabilities(
                location_id=location_id, organization_id=organization_id
            )
        if action == "set_speed":
            return await service.set_client_speed(
                location_id=location_id,
                organization_id=organization_id,
                client_mac=CLIENT_MAC,
                down_kbps=5_000,
                up_kbps=1_000,
                actor_user_id=None,
            )
        if action == "clear_speed":
            return await service.clear_client_speed(
                location_id=location_id,
                organization_id=organization_id,
                client_mac=CLIENT_MAC,
                actor_user_id=None,
            )
        return await getattr(service, f"{action}_client")(
            location_id=location_id,
            organization_id=organization_id,
            client_mac=CLIENT_MAC,
            actor_user_id=None,
        )

    @pytest.mark.parametrize(
        "action",
        ["capabilities", "block", "unblock", "set_speed", "clear_speed"],
    )
    async def test_another_organizations_location_is_not_found(
        self, action: str
    ) -> None:
        provider = FakeProvider()
        service, _owner_org, location_id = _venue(provider=provider)
        intruder_org = uuid.uuid4()

        with pytest.raises(LocationHasNoControllerError):
            await self._act(service, action, intruder_org, location_id)

        # And nothing reached the controller on the way to being refused.
        assert provider.client_actions == []

    @pytest.mark.parametrize(
        "action", ["capabilities", "block", "unblock", "set_speed", "clear_speed"]
    )
    async def test_the_refusal_is_the_same_as_for_a_location_with_no_controller(
        self, action: str
    ) -> None:
        """"Not yours" and "does not exist" must be indistinguishable. If
        these two messages ever diverge, the response becomes an oracle for
        enumerating another tenant's locations."""
        service, owner_org, location_id = _venue()
        intruder_org = uuid.uuid4()

        with pytest.raises(LocationHasNoControllerError) as cross_tenant:
            await self._act(service, action, intruder_org, location_id)
        with pytest.raises(LocationHasNoControllerError) as own_empty:
            await self._act(service, action, owner_org, uuid.uuid4())

        assert str(cross_tenant.value) == str(own_empty.value)
        assert cross_tenant.value.status_code == own_empty.value.status_code

    async def test_the_owner_of_the_venue_is_allowed_through(self) -> None:
        """The negative tests above are worthless if the positive case is
        also refused for some unrelated reason."""
        provider = FakeProvider()
        service, organization_id, location_id = _venue(provider=provider)
        result = await service.block_client(
            location_id=location_id,
            organization_id=organization_id,
            client_mac=CLIENT_MAC,
            actor_user_id=None,
        )
        assert result.performed is True
        assert [call[0] for call in provider.client_actions] == ["block_client"]

    async def test_the_site_comes_from_the_resolved_row_not_the_caller(self) -> None:
        """No route takes a site id, so the only site a caller can act on is
        the one on their own integration."""
        provider = FakeProvider()
        service, organization_id, location_id = _venue(provider=provider)
        await service.set_client_speed(
            location_id=location_id,
            organization_id=organization_id,
            client_mac=CLIENT_MAC,
            down_kbps=10_000,
            up_kbps=None,
            actor_user_id=None,
        )
        assert provider.client_actions[0][1] == "a" * 24

    async def test_an_anonymous_caller_reaches_no_controller_at_all(self) -> None:
        """``organization_id`` is ``None`` for a caller with no organization
        header. That must never mean "every organization" -- the known Global
        Super Admin failure shape."""
        provider = FakeProvider()
        service, _owner_org, location_id = _venue(provider=provider)
        with pytest.raises(LocationHasNoControllerError):
            await service.block_client(
                location_id=location_id,
                organization_id=None,
                client_mac=CLIENT_MAC,
                actor_user_id=None,
            )
        assert provider.client_actions == []


# ===========================================================================
# The ordering bug, and the MikroTik path it must not disturb
# ===========================================================================


@dataclass
class _Router:
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    vendor: str = "mikrotik"
    api_username: str | None = "admin"
    management_ip_address: str | None = "10.20.0.2"
    public_ip_address: str | None = None
    location_id: uuid.UUID | None = field(default_factory=uuid.uuid4)


@dataclass
class _RouterLookup:
    router: _Router

    async def get_router(self, router_id, *, requesting_organization_id=None):
        return self.router

    def get_decrypted_api_secret(self, router) -> str | None:
        return "secret" if router.api_username else None


@dataclass
class _DeviceLookup:
    async def get_device_by_id(self, device_id):
        return None


@dataclass
class _Session:
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    router_id: uuid.UUID = field(default_factory=uuid.uuid4)
    organization_id: uuid.UUID = field(default_factory=uuid.uuid4)
    device_id: uuid.UUID | None = None


@dataclass
class _RecordingAdapter:
    """Records what the RouterOS path did, so the MikroTik proof is about
    real calls rather than about the absence of an exception."""

    calls: list[tuple[str, Any]] = field(default_factory=list)
    vendor: str = "mikrotik"

    async def end_sessions(self, credentials, *, mac_address, username):
        from app.domains.guest_access.device_adapters import (
            SessionControlSnapshot,
            SessionEndOutcome,
        )

        self.calls.append(("end_sessions", credentials.host, username))
        return SessionEndOutcome(
            control=SessionControlSnapshot(
                hotspot_servers=1, coa_accept=True, coa_port=3799
            ),
            matched=1,
            removed=1,
            still_active=0,
        )


class TestEndOnRouterAsksTheVendorFirst:
    async def test_a_controller_managed_row_no_longer_fails_on_credentials(
        self,
    ) -> None:
        """The bug. A synthetic Omada router has NULL credentials by
        construction, and the old ordering resolved them one line before it
        resolved the adapter -- so a venue admin blocking a guest got "this
        router is missing device connection credentials", a 400 asking them
        to supply something that does not exist.
        """
        from app.domains.guest_access.enforcement import LiveSessionTerminator
        from app.domains.guest_access.exceptions import (
            BlockEnforcementMissingCredentialsError,
        )

        reached: list[dict] = []

        async def controller_terminator(**kwargs):
            reached.append(kwargs)
            return True

        router = _Router(
            vendor="tplink_omada",
            api_username=None,
            management_ip_address=None,
        )
        terminator = LiveSessionTerminator(
            router_lookup=_RouterLookup(router),
            device_lookup=_DeviceLookup(),
            controller_terminator=controller_terminator,
        )

        organization_id = uuid.uuid4()
        try:
            outcome = await terminator.end_on_router(
                session=_Session(),
                identifier=CLIENT_MAC,
                organization_id=organization_id,
            )
        except BlockEnforcementMissingCredentialsError:  # pragma: no cover
            pytest.fail(
                "the credential question was asked before the vendor question"
            )

        assert outcome.ended_cleanly is True
        assert reached == [
            {
                "location_id": router.location_id,
                "organization_id": organization_id,
                "client_mac": CLIENT_MAC,
            }
        ]

    async def test_a_controller_that_could_not_be_reached_is_not_reported_as_success(
        self,
    ) -> None:
        """The caller refuses a block it did not enforce, so a controller
        path that did nothing must raise rather than return an outcome that
        reads as clean."""
        from app.domains.guest_access.enforcement import LiveSessionTerminator
        from app.domains.guest_access.exceptions import (
            ControllerSessionTerminationUnavailableError,
        )

        async def controller_terminator(**_kwargs):
            return False

        terminator = LiveSessionTerminator(
            router_lookup=_RouterLookup(
                _Router(
                    vendor="tplink_omada",
                    api_username=None,
                    management_ip_address=None,
                )
            ),
            device_lookup=_DeviceLookup(),
            controller_terminator=controller_terminator,
        )
        with pytest.raises(ControllerSessionTerminationUnavailableError):
            await terminator.end_on_router(
                session=_Session(), identifier=CLIENT_MAC, organization_id=uuid.uuid4()
            )

    async def test_an_unwired_controller_path_says_so_rather_than_naming_credentials(
        self,
    ) -> None:
        from app.domains.guest_access.enforcement import LiveSessionTerminator
        from app.domains.guest_access.exceptions import (
            ControllerSessionTerminationUnavailableError,
        )

        terminator = LiveSessionTerminator(
            router_lookup=_RouterLookup(
                _Router(
                    vendor="tplink_omada",
                    api_username=None,
                    management_ip_address=None,
                )
            ),
            device_lookup=_DeviceLookup(),
        )
        with pytest.raises(ControllerSessionTerminationUnavailableError) as excinfo:
            await terminator.end_on_router(
                session=_Session(), identifier=CLIENT_MAC, organization_id=uuid.uuid4()
            )
        assert "credential" not in str(excinfo.value).lower()


class TestMikroTikPathIsUnchanged:
    """The proof obligation for this whole change.

    Two call sites were reordered so the vendor question comes first. On a
    MikroTik row both must reach the same credentials, the same adapter and
    the same calls they always did -- one branch later, and otherwise
    identically.
    """

    async def test_a_mikrotik_session_end_still_reaches_the_adapter(
        self,
    ) -> None:
        from app.domains.guest_access.enforcement import LiveSessionTerminator

        adapter = _RecordingAdapter()
        terminator = LiveSessionTerminator(
            router_lookup=_RouterLookup(_Router()),
            device_lookup=_DeviceLookup(),
            adapter_factory=lambda _vendor: adapter,
            # Wired, and deliberately so: the MikroTik branch must not consult
            # it even when it is available.
            controller_terminator=_unreachable_controller,
        )
        outcome = await terminator.end_on_router(
            session=_Session(), identifier="+919999999999", organization_id=uuid.uuid4()
        )
        assert outcome.ended_cleanly is True
        assert adapter.calls == [("end_sessions", "10.20.0.2", "+919999999999")]

    async def test_a_mikrotik_row_with_no_credentials_still_gets_the_old_error(
        self,
    ) -> None:
        """The credential error was never wrong for a MikroTik -- a RouterOS
        device really does need a host, a username and a secret, and "add
        them" really is the fix. Only the controller case was misdiagnosed,
        and only the controller case changed."""
        from app.domains.guest_access.enforcement import LiveSessionTerminator
        from app.domains.guest_access.exceptions import (
            BlockEnforcementMissingCredentialsError,
        )

        terminator = LiveSessionTerminator(
            router_lookup=_RouterLookup(
                _Router(api_username=None, management_ip_address=None)
            ),
            device_lookup=_DeviceLookup(),
            adapter_factory=lambda _vendor: _RecordingAdapter(),
        )
        with pytest.raises(BlockEnforcementMissingCredentialsError):
            await terminator.end_on_router(
                session=_Session(), identifier="x", organization_id=uuid.uuid4()
            )


async def _unreachable_controller(**_kwargs):  # pragma: no cover - never called
    raise AssertionError("the MikroTik path must not reach the controller hook")


# ===========================================================================
# Speed profiles at a controller-managed venue
# ===========================================================================


@dataclass
class _SpeedHook:
    """Records what reached the controller, and can be made to fail."""

    calls: list[tuple[str, Any, Any, int | None, int | None]] = field(
        default_factory=list
    )
    error: Exception | None = None

    async def set_client_speed(
        self,
        *,
        location_id,
        organization_id,
        client_mac,
        down_kbps,
        up_kbps,
        actor_user_id=None,
    ):
        if self.error is not None:
            raise self.error
        self.calls.append(
            ("set", location_id, client_mac, down_kbps, up_kbps)
        )
        return object()

    async def clear_client_speed(
        self, *, location_id, organization_id, client_mac, actor_user_id=None
    ):
        self.calls.append(("clear", location_id, client_mac, None, None))
        return object()


class TestSpeedProfilesReachAControllerVenue:
    """``QueueProfile`` is reused, not duplicated: the same profile rows, the
    same kbps, a different transport."""

    async def _setup(self, *, hook: _SpeedHook | None = None, vendor: str):
        from tests.unit.test_queue_management import _make_router, make_harness

        speed_hook = hook if hook is not None else _SpeedHook()
        harness = make_harness()
        harness.service.controller_speed_hook = speed_hook
        router = harness.router_lookup.add(_make_router())
        router.vendor = vendor
        profile = await harness.service.create_profile(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            name="5 Mbps",
            download_rate_kbps=5000,
            upload_rate_kbps=1000,
        )
        from app.domains.queue_management.constants import QueueTargetType

        assignment = await harness.service.create_assignment(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            target_type=QueueTargetType.SESSION,
            target_id=uuid.uuid4(),
            router_id=router.id,
            device_target=CLIENT_MAC,
            queue_profile_id=profile.id,
        )
        return harness, router, assignment, speed_hook

    async def test_a_controller_venue_gets_the_profiles_rates_on_the_controller(
        self,
    ) -> None:
        harness, _router, assignment, hook = await self._setup(vendor="tplink_omada")
        applied = await harness.service.apply_queue(
            assignment.id,
            actor_user_id=None,
            requesting_organization_id=assignment.organization_id,
        )
        assert applied.status == "active"
        assert [(c[0], c[3], c[4]) for c in hook.calls] == [("set", 5000, 1000)]
        # And nothing was pushed to a RouterOS queue.
        assert harness.device_adapter.created_ids == []

    async def test_a_controller_failure_is_recorded_on_the_row_and_re_raised(
        self,
    ) -> None:
        """Never a silent success. A limit this platform recorded and the
        venue never received is the exact failure this work exists to
        prevent."""
        hook = _SpeedHook(error=RuntimeError("controller refused"))
        harness, _router, assignment, _hook = await self._setup(
            hook=hook, vendor="tplink_omada"
        )
        with pytest.raises(RuntimeError):
            await harness.service.apply_queue(
                assignment.id,
                actor_user_id=None,
                requesting_organization_id=assignment.organization_id,
            )
        stored = await harness.service.get_assignment(
            assignment.id, requesting_organization_id=assignment.organization_id
        )
        assert stored.status != "active"
        assert "controller refused" in (stored.error_message or "")

    async def test_removing_the_queue_clears_the_limit_on_the_controller(
        self,
    ) -> None:
        harness, _router, assignment, hook = await self._setup(vendor="tplink_omada")
        await harness.service.apply_queue(
            assignment.id,
            actor_user_id=None,
            requesting_organization_id=assignment.organization_id,
        )
        await harness.service.remove_queue(
            assignment.id,
            actor_user_id=None,
            requesting_organization_id=assignment.organization_id,
        )
        assert [c[0] for c in hook.calls] == ["set", "clear"]

    async def test_a_mikrotik_venue_still_uses_queue_simple_and_never_the_hook(
        self,
    ) -> None:
        """The MikroTik half of the reorder. Same adapter, same call, and the
        controller hook is wired and must stay untouched."""
        harness, _router, assignment, hook = await self._setup(vendor="mikrotik")
        applied = await harness.service.apply_queue(
            assignment.id,
            actor_user_id=None,
            requesting_organization_id=assignment.organization_id,
        )
        assert applied.status == "active"
        assert len(harness.device_adapter.created_ids) == 1
        assert hook.calls == []
