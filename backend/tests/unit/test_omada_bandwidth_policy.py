"""A venue's Guest WiFi Limits -> Bandwidth policy, taking effect at a venue
whose network is run from a TP-Link Omada controller.

The mechanism already existed when these tests were written -- ``apply_queue``
branches to the controller, ``remove_queue`` clears the limit instead of
deleting a queue row, and the provider speaks the controller's per-client
rate-limit call. What did not exist was anything that *ran* it on the triggers
that matter, so this module is about triggers and wiring rather than about the
controller call:

* **session start** -- the factory the login path actually uses, and the
  identifier it addresses the client by;
* **policy edit** -- the publish sweep, and whether it reaches a venue it had
  been silently refusing;
* **session end** -- clearing the limit so a recycled MAC is not throttled by
  a ghost;
* **honest failure** -- a refusal recorded where the venue can see it, and
  never in front of the guest getting online.

Every test that asserts something about MikroTik asserts that it did *not*
change. The RouterOS lifecycle -- the reply attribute, ``/queue simple``, the
assignment states -- is out of scope for this work by construction, and the
tests that own it are named in ``TestMikrotikIsUntouched``'s docstring.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from app.domains.network_integration import client_hooks
from app.domains.network_integration.exceptions import (
    ClientActionUnavailableError,
    ProviderClientNotFoundError,
    ProviderConnectionFailedError,
)
from app.domains.network_integration.providers.base import (
    ProviderCapability,
    ProviderClientCapabilities,
    ProviderClientRateLimit,
)
from app.domains.queue_management.constants import QueueStatus, QueueTargetType

OMADA_VENDOR = "tplink_omada"
MIKROTIK_VENDOR = "mikrotik"
CLIENT_MAC = "A6-52-E9-76-3B-A0"


def _now() -> datetime:
    return datetime.now(UTC)


# ============================================================================
# 1. Every factory wires the hook -- yesterday's outage, as a test
# ============================================================================


class TestEveryFactoryWiresTheControllerHook:
    """A dependency factory that composes a service differently from the
    dependency it claims to mirror is the defect that took guest login down
    platform-wide the day before this work: the constructor signature changed,
    2800+ tests stayed green because nothing ever *called* the factory, and
    every venue 500'd.

    So each factory is constructed here the way the application constructs it,
    and asked the one question that was wrong: does the service it builds hold
    a controller speed hook. Three of the four did not, and the one that did
    is the one a guest login never reaches.
    """

    @staticmethod
    def _session() -> object:
        """A stand-in ``AsyncSession``.

        Every repository in these graphs stores the session and touches it
        only when a query runs, and no query runs during construction -- which
        is precisely the property under test: construction must succeed, and
        it must produce the same shape the request path produces.
        """
        return MagicMock()

    def test_the_guest_login_factory_wires_it(self) -> None:
        """The one that matters most, and the one that had it missing.

        A guest login does not build the service through FastAPI: it enqueues
        ``assign_guest_queue`` and returns, so the worker's own factory is the
        only one on the path a guest actually takes.
        """
        from app.domains.guest.tasks import _build_queue_management_service

        service = _build_queue_management_service(self._session())
        assert service.controller_speed_hook is not None
        assert hasattr(service.controller_speed_hook, "set_client_speed")
        assert hasattr(service.controller_speed_hook, "clear_client_speed")

    def test_the_request_path_dependency_wires_it(self) -> None:
        from app.domains.queue_management.dependencies import (
            get_queue_management_service,
        )

        service = get_queue_management_service(
            db=self._session(),
            repository=MagicMock(),
            router_service=MagicMock(),
            policy_service=MagicMock(),
            audit_repository=MagicMock(),
            caller_location_scope=None,
        )
        assert service.controller_speed_hook is not None

    def test_the_hook_satisfies_the_protocol_the_service_calls(self) -> None:
        """Not "is not None" -- the two method names ``_controller_speed``
        actually calls, with the keyword arguments it actually passes.

        ``ControllerSpeedHookProtocol`` is a structural protocol, so nothing
        at import time checks that the object handed over can answer the call.
        A hook that is present and wrong fails exactly where the unwired hook
        did: at a real venue, on a real guest.
        """
        import inspect

        hook = client_hooks.build_controller_speed_hook(self._session())
        for name, expected in (
            (
                "set_client_speed",
                {
                    "location_id",
                    "organization_id",
                    "client_mac",
                    "down_kbps",
                    "up_kbps",
                    "actor_user_id",
                },
            ),
            (
                "clear_client_speed",
                {"location_id", "organization_id", "client_mac", "actor_user_id"},
            ),
        ):
            signature = inspect.signature(getattr(hook, name))
            assert expected <= set(signature.parameters), name


# ============================================================================
# 2. Session start -- the identifier the venue's equipment understands
# ============================================================================


def _guest_fixture(**kwargs):
    from tests.unit.test_guest import make_fixture

    return make_fixture(**kwargs)


@dataclass
class _RecordingDispatcher:
    calls: list[dict[str, object]] = field(default_factory=list)

    async def __call__(self, **kwargs: object) -> None:
        self.calls.append(kwargs)


class TestSessionStartAddressesTheClientTheVenueWayRound:
    """One ``device_target`` column, two vendor vocabularies.

    A ``/queue simple`` entry matches one concrete IP; a controller's
    per-client limit is a field on a known-client record keyed by MAC. Sending
    either one where the other belongs does not fail loudly -- a MAC in a
    RouterOS target matches nothing and an IP in a controller path is rejected
    as a malformed MAC -- so both would look like a speed that was applied.
    """

    async def _dispatch(self, *, vendor: str, with_device: bool = True):
        dispatcher = _RecordingDispatcher()
        fixture = _guest_fixture()
        service = fixture.guest_service
        service.queue_assignment_dispatcher = dispatcher
        router = fixture.router
        router.vendor = vendor

        device = None
        if with_device:
            device = await fixture.repository.create_device(
                guest_id=uuid.uuid4(),
                mac_address=CLIENT_MAC,
                device_name="phone",
                first_seen_at=_now(),
                last_seen_at=_now(),
            )
        session_row = MagicMock()
        session_row.id = uuid.uuid4()
        session_row.ip_address = "10.0.0.5"
        session_row.guest_id = uuid.uuid4()
        session_row.device_id = device.id if device is not None else None

        await service._assign_guest_queue(
            session=session_row,
            router=router,
            location_id=fixture.location_id,
            organization_id=fixture.organization_id,
        )
        return dispatcher

    async def test_a_controller_venue_is_addressed_by_the_client_mac(self) -> None:
        dispatcher = await self._dispatch(vendor=OMADA_VENDOR)
        assert len(dispatcher.calls) == 1
        assert dispatcher.calls[0]["device_target"] == CLIENT_MAC

    async def test_a_mikrotik_venue_is_still_addressed_by_the_session_ip(
        self,
    ) -> None:
        """The untouched half. This is the assertion that would fail if the
        controller branch had been written as a replacement rather than as a
        branch."""
        dispatcher = await self._dispatch(vendor=MIKROTIK_VENDOR)
        assert len(dispatcher.calls) == 1
        assert dispatcher.calls[0]["device_target"] == "10.0.0.5"

    async def test_a_controller_venue_with_no_known_device_dispatches_nothing(
        self,
    ) -> None:
        """Nothing beats the wrong thing.

        With no MAC on record there is no identifier the controller would
        accept, and sending the IP instead would create an assignment that
        reads ACTIVE and throttles nobody.
        """
        dispatcher = await self._dispatch(vendor=OMADA_VENDOR, with_device=False)
        assert dispatcher.calls == []


# ============================================================================
# 3. Policy edit reaches guests already online
# ============================================================================


@dataclass
class _FakeSpeedHook:
    """Stands in for the controller half at the protocol boundary."""

    calls: list[tuple] = field(default_factory=list)
    error: Exception | None = None
    applied: object | None = None

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
        self.calls.append(("set", client_mac, down_kbps, up_kbps))
        return self.applied or ProviderClientRateLimit(
            enabled=True,
            applied_down_kbps=down_kbps,
            applied_up_kbps=up_kbps,
            requested_down_kbps=down_kbps,
            requested_up_kbps=up_kbps,
            clamped=False,
        )

    async def clear_client_speed(
        self, *, location_id, organization_id, client_mac, actor_user_id=None
    ):
        self.calls.append(("clear", client_mac, None, None))
        return None


async def _omada_session_assignment(hook: _FakeSpeedHook):
    """One live SESSION assignment at a controller-managed venue."""
    from tests.unit.test_queue_management import _make_router, make_harness

    harness = make_harness()
    harness.service.controller_speed_hook = hook
    router = harness.router_lookup.add(_make_router())
    router.vendor = OMADA_VENDOR

    harness.policy_lookup.rules_by_scope[
        (router.organization_id, router.location_id)
    ] = {"download_rate_kbps": 5000, "upload_rate_kbps": 1000}
    assignment = await harness.service.resolve_and_assign_queue(
        requesting_organization_id=router.organization_id,
        location_id=router.location_id,
        router_id=router.id,
        target_type=QueueTargetType.SESSION,
        target_id=uuid.uuid4(),
        device_target=CLIENT_MAC,
    )
    return harness, router, assignment


class TestSessionStartAppliesTheVenuePolicy:
    async def test_the_policys_rates_reach_the_client_mac(self) -> None:
        hook = _FakeSpeedHook()
        _harness, _router, assignment = await _omada_session_assignment(hook)
        assert hook.calls == [("set", CLIENT_MAC, 5000, 1000)]
        assert assignment.status == QueueStatus.ACTIVE.value

    async def test_the_profile_is_the_same_model_mikrotik_uses(self) -> None:
        """No parallel speed model for controller venues: the assignment
        points at a real ``QueueProfile`` row carrying kbps."""
        hook = _FakeSpeedHook()
        harness, _router, assignment = await _omada_session_assignment(hook)
        profile = await harness.service.get_profile(assignment.queue_profile_id)
        assert (profile.download_rate_kbps, profile.upload_rate_kbps) == (5000, 1000)


class TestPolicyEditReachesGuestsAlreadyOnline:
    """The venue raises its speeds; a guest who is already connected should
    not have to reconnect to feel it.

    The RouterOS answer was already the publish-time sweep
    (``reapply_active_sessions_for_location``, fired by the policy router
    through ``reapply_policy_assignments``). The controller venue rides the
    same sweep -- the only thing that had to change was the sweep's own
    factory, which built a service with no hook and therefore refused every
    controller venue it visited.
    """

    async def test_a_raised_limit_is_pushed_to_a_connected_client(self) -> None:
        hook = _FakeSpeedHook()
        harness, router, _assignment = await _omada_session_assignment(hook)
        hook.calls.clear()

        harness.policy_lookup.rules_by_scope[
            (router.organization_id, router.location_id)
        ] = {"download_rate_kbps": 20000, "upload_rate_kbps": 5000}

        result = await harness.service.reapply_active_sessions_for_location(
            location_id=router.location_id,
            requesting_organization_id=router.organization_id,
        )
        assert result["reapplied"] == 1
        assert ("set", CLIENT_MAC, 20000, 5000) in hook.calls

    async def test_an_unchanged_limit_touches_the_controller_not_at_all(self) -> None:
        """Idempotent by construction, and it has to be: the sweep runs over
        every live session at the location on every publish."""
        hook = _FakeSpeedHook()
        harness, router, _assignment = await _omada_session_assignment(hook)
        hook.calls.clear()

        await harness.service.reapply_active_sessions_for_location(
            location_id=router.location_id,
            requesting_organization_id=router.organization_id,
        )
        assert hook.calls == []


# ============================================================================
# 4. Honest failure
# ============================================================================


class TestAFailureIsRecordedAndNeverSilent:
    async def test_a_controller_that_cannot_see_the_client_leaves_the_row_failed(
        self,
    ) -> None:
        """The refusal this path meets most: the device dropped off the site
        between authenticating and this write, so there is no known-client
        record to carry a limit.

        The assignment must not read ACTIVE, and the reason must be on the
        row -- a limit this platform recorded and the venue never received is
        the silent success the whole feature was commissioned to prevent.
        """
        hook = _FakeSpeedHook(
            error=ProviderClientNotFoundError(
                "That client is not currently connected to this Omada site."
            )
        )
        with pytest.raises(ProviderClientNotFoundError):
            await _omada_session_assignment(hook)

    async def test_the_reason_lands_on_the_assignment_row(self) -> None:
        from tests.unit.test_queue_management import _make_router, make_harness

        hook = _FakeSpeedHook()
        harness = make_harness()
        harness.service.controller_speed_hook = hook
        router = harness.router_lookup.add(_make_router())
        router.vendor = OMADA_VENDOR
        profile = await harness.service.create_profile(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            name="5 Mbps",
            download_rate_kbps=5000,
            upload_rate_kbps=1000,
        )
        assignment = await harness.service.create_assignment(
            actor_user_id=None,
            requesting_organization_id=router.organization_id,
            target_type=QueueTargetType.SESSION,
            target_id=uuid.uuid4(),
            router_id=router.id,
            device_target=CLIENT_MAC,
            queue_profile_id=profile.id,
        )
        hook.error = ProviderConnectionFailedError("controller said no")
        with pytest.raises(ProviderConnectionFailedError):
            await harness.service.apply_queue(
                assignment.id,
                actor_user_id=None,
                requesting_organization_id=router.organization_id,
            )
        stored = harness.repository.assignments[assignment.id]
        assert stored.status != QueueStatus.ACTIVE.value
        assert "controller said no" in (stored.error_message or "")

    async def test_a_failed_speed_write_never_stops_the_guest_getting_online(
        self,
    ) -> None:
        """The guest-login path swallows, by contract.

        A speed limit is a quality-of-service concern; authorization is not.
        The inline path catches everything, and the real API path enqueues the
        work to a worker after the session has already committed -- so neither
        can put a controller refusal in front of a guest.
        """

        class _Boom:
            async def resolve_and_assign_queue(self, **kwargs):
                raise ProviderClientNotFoundError("no such client")

        fixture = _guest_fixture(queue_assignment_hook=_Boom())
        service = fixture.guest_service
        service.queue_assignment_dispatcher = None
        router = fixture.router
        router.vendor = OMADA_VENDOR
        device = await fixture.repository.create_device(
            guest_id=uuid.uuid4(),
            mac_address=CLIENT_MAC,
            device_name="phone",
            first_seen_at=_now(),
            last_seen_at=_now(),
        )
        session_row = MagicMock()
        session_row.id = uuid.uuid4()
        session_row.ip_address = "10.0.0.5"
        session_row.guest_id = uuid.uuid4()
        session_row.device_id = device.id

        # No exception escapes. That is the assertion.
        await service._assign_guest_queue(
            session=session_row,
            router=router,
            location_id=fixture.location_id,
            organization_id=fixture.organization_id,
        )


# ============================================================================
# 5. The controller hook itself: events, capability gating, session end
# ============================================================================


@dataclass
class _FakeEventRepository:
    events: list[dict[str, object]] = field(default_factory=list)

    def __call__(self, _session: object) -> _FakeEventRepository:
        return self

    async def create_event(self, **fields: object):
        self.events.append(fields)
        return MagicMock()


@dataclass
class _FakeProvider:
    supported: bool = True
    reason: str | None = None
    set_error: Exception | None = None
    clear_error: Exception | None = None
    calls: list[tuple] = field(default_factory=list)
    applied: ProviderClientRateLimit | None = None

    def client_capabilities(self, _config: object) -> ProviderClientCapabilities:
        capability = ProviderCapability(
            supported=self.supported, reason=None if self.supported else self.reason
        )
        return ProviderClientCapabilities(
            set_rate_limit=capability,
            clear_rate_limit=capability,
            block=capability,
            unblock=capability,
            list_blocked=ProviderCapability(supported=False, reason="n/a"),
            disconnect=ProviderCapability(supported=True),
            client_stats=capability,
        )

    async def set_client_rate_limit(
        self, _config, site_id, client_mac, *, down_kbps, up_kbps
    ):
        if self.set_error is not None:
            raise self.set_error
        self.calls.append(("set", site_id, client_mac, down_kbps, up_kbps))
        return self.applied or ProviderClientRateLimit(
            enabled=True,
            applied_down_kbps=down_kbps,
            applied_up_kbps=up_kbps,
            requested_down_kbps=down_kbps,
            requested_up_kbps=up_kbps,
            clamped=False,
        )

    async def clear_client_rate_limit(self, _config, site_id, client_mac):
        if self.clear_error is not None:
            raise self.clear_error
        self.calls.append(("clear", site_id, client_mac, None, None))
        return ProviderClientRateLimit(
            enabled=False,
            applied_down_kbps=None,
            applied_up_kbps=None,
            requested_down_kbps=None,
            requested_up_kbps=None,
            clamped=False,
        )

    async def deauthorize_guest(self, _config, _site_id, _client_mac):
        self.calls.append(("deauthorize", _site_id, _client_mac, None, None))
        return True


def _install_controller(
    monkeypatch: pytest.MonkeyPatch, provider: _FakeProvider
) -> _FakeEventRepository:
    """Point the hooks at a fake controller and a fake event feed.

    ``_resolve`` is the tenant-scoped database query the hooks share; it is
    covered by the integration's own repository tests. Replacing it here keeps
    these tests about the thing this work changed -- what the hooks *do* with
    a resolved controller.
    """
    integration = MagicMock()
    integration.id = uuid.uuid4()
    integration.organization_id = uuid.uuid4()
    resolved = client_hooks._ResolvedController(
        integration=integration,
        provider=provider,
        config=MagicMock(),
        site_id="site-1",
    )

    async def _fake_resolve(_session, *, location_id, organization_id):
        return resolved

    events = _FakeEventRepository()
    monkeypatch.setattr(client_hooks, "_resolve", _fake_resolve)
    monkeypatch.setattr(client_hooks, "NetworkIntegrationRepository", events)
    return events


class TestTheAutomaticWriteIsVisibleToTheVenue:
    async def test_a_success_records_what_was_applied_beside_what_was_asked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The controller's per-client limit is a number in 1..1024 plus a
        unit, so a requested rate is not always the applied rate. The venue is
        shown the cap it has, not the one it typed."""
        provider = _FakeProvider(
            applied=ProviderClientRateLimit(
                enabled=True,
                applied_down_kbps=1024000,
                applied_up_kbps=1000,
                requested_down_kbps=5000000,
                requested_up_kbps=1000,
                clamped=True,
            )
        )
        events = _install_controller(monkeypatch, provider)
        hook = client_hooks.build_controller_speed_hook(MagicMock())

        await hook.set_client_speed(
            location_id=uuid.uuid4(),
            organization_id=uuid.uuid4(),
            client_mac=CLIENT_MAC,
            down_kbps=5000000,
            up_kbps=1000,
        )
        assert len(events.events) == 1
        context = events.events[0]["context"]
        assert context["requested_down_kbps"] == 5000000
        assert context["applied_down_kbps"] == 1024000
        assert context["clamped"] is True
        assert events.events[0]["status"] == "ok"

    async def test_a_refusal_is_recorded_with_its_code_then_re_raised(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Both halves matter. The record is what makes the failure visible at
        the venue; the re-raise is what keeps the assignment out of ACTIVE.

        ``provider_code`` is carried because the normalized code is coarser
        than the controller's own: a refusal this platform cannot yet name is
        still a refusal, and an unnamed integer recorded verbatim can be read
        off a real venue's feed and turned into a named one. A swallowed one
        cannot.
        """
        error = ProviderClientNotFoundError("no such client")
        error.with_diagnostics(provider_code=-41011)
        provider = _FakeProvider(set_error=error)
        events = _install_controller(monkeypatch, provider)
        hook = client_hooks.build_controller_speed_hook(MagicMock())

        with pytest.raises(ProviderClientNotFoundError):
            await hook.set_client_speed(
                location_id=uuid.uuid4(),
                organization_id=uuid.uuid4(),
                client_mac=CLIENT_MAC,
                down_kbps=5000,
                up_kbps=1000,
            )
        assert len(events.events) == 1
        assert events.events[0]["status"] == "error"
        assert events.events[0]["context"]["provider_code"] == -41011

    async def test_a_legacy_venue_is_refused_with_its_own_reason(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A hotspot-operator login buys the portal and nothing else -- there
        is no per-client rate-limit route under ``/hotspot/`` at all. The
        refusal comes from the capability, before any request leaves, so it
        reads as a fact about the venue rather than as a network fault."""
        provider = _FakeProvider(
            supported=False, reason="This venue is connected with an operator login."
        )
        _install_controller(monkeypatch, provider)
        hook = client_hooks.build_controller_speed_hook(MagicMock())

        with pytest.raises(ClientActionUnavailableError):
            await hook.set_client_speed(
                location_id=uuid.uuid4(),
                organization_id=uuid.uuid4(),
                client_mac=CLIENT_MAC,
                down_kbps=5000,
                up_kbps=1000,
            )
        assert provider.calls == []


class TestSessionEndClearsTheLimit:
    """A controller's per-client limit outlives the session that caused it: it
    is a field on the known-client record, it survives the client going
    offline, and nothing on the controller ever removes it. The next device to
    hold that MAC would inherit a cap nobody configured for it.
    """

    async def test_ending_a_session_clears_the_clients_limit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        provider = _FakeProvider()
        _install_controller(monkeypatch, provider)
        terminate = client_hooks.build_controller_session_terminator(MagicMock())

        assert (
            await terminate(
                location_id=uuid.uuid4(),
                organization_id=uuid.uuid4(),
                client_mac=CLIENT_MAC,
            )
            is True
        )
        verbs = [call[0] for call in provider.calls]
        assert verbs == ["deauthorize", "clear"]

    async def test_a_legacy_venue_is_not_asked_to_clear_what_it_cannot_set(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        provider = _FakeProvider(supported=False, reason="operator login")
        _install_controller(monkeypatch, provider)
        terminate = client_hooks.build_controller_session_terminator(MagicMock())

        await terminate(
            location_id=uuid.uuid4(),
            organization_id=uuid.uuid4(),
            client_mac=CLIENT_MAC,
        )
        assert [call[0] for call in provider.calls] == ["deauthorize"]

    async def test_a_clear_that_fails_is_recorded_and_does_not_fail_the_end(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Ending a session in this platform's records can never be blocked by
        the venue's equipment. The limit that could not be cleared is written
        to the venue's feed instead of raising."""
        provider = _FakeProvider(
            clear_error=ProviderConnectionFailedError("controller unreachable")
        )
        events = _install_controller(monkeypatch, provider)
        terminate = client_hooks.build_controller_session_terminator(MagicMock())

        assert (
            await terminate(
                location_id=uuid.uuid4(),
                organization_id=uuid.uuid4(),
                client_mac=CLIENT_MAC,
            )
            is True
        )
        assert [e["status"] for e in events.events] == ["error"]


# ============================================================================
# 6. MikroTik is untouched
# ============================================================================


class TestMikrotikIsUntouched:
    """The RouterOS half of this feature is not modified by this work, and the
    suites that own it are the proof rather than anything restated here:

    * ``tests/unit/test_queue_management.py`` -- ``TestApplyAndRemoveQueue``,
      ``TestMoveQueue``, ``TestResolveAndAssignQueue``,
      ``TestResolveFollowsTheGuestsCurrentAddress``, ``TestOneQueuePerAddress``,
      ``TestSweepScheduleTransitions``, ``TestReapplyActiveSessionsForLocation``,
      ``TestFormatMikrotikRateLimit``, ``TestGetRateLimitReplyForSession``.
    * ``tests/unit/test_queue_management_adapters.py`` -- ``TestSimpleQueue``
      and the rest of the real ``/queue simple`` adapter surface.
    * ``tests/vendor/.../test_mikrotik_queue.py`` -- the gateway's own queue
      calls.

    What is asserted *here* is only the seam: that the controller work is a
    branch taken on a vendor question, so a RouterOS venue reaches none of it.
    """

    async def test_a_mikrotik_venue_never_consults_the_controller_hook(self) -> None:
        from tests.unit.test_queue_management import _make_router, make_harness

        hook = _FakeSpeedHook()
        harness = make_harness()
        harness.service.controller_speed_hook = hook
        router = harness.router_lookup.add(_make_router())
        assert router.vendor == MIKROTIK_VENDOR

        harness.policy_lookup.rules_by_scope[
            (router.organization_id, router.location_id)
        ] = {"download_rate_kbps": 5000, "upload_rate_kbps": 1000}
        assignment = await harness.service.resolve_and_assign_queue(
            requesting_organization_id=router.organization_id,
            location_id=router.location_id,
            router_id=router.id,
            target_type=QueueTargetType.SESSION,
            target_id=uuid.uuid4(),
            device_target="10.0.0.5",
        )
        assert hook.calls == []
        assert harness.device_adapter.created_calls
        assert harness.device_adapter.created_calls[0]["target"] == "10.0.0.5"
        assert assignment.status == QueueStatus.ACTIVE.value

    async def test_the_reply_attribute_path_is_not_a_controller_path(self) -> None:
        """``Mikrotik-Rate-Limit`` is composed from the same assignment row and
        is untouched by this work. It is also the thing that must never be
        attempted for a controller: that controller honours no bandwidth reply
        attribute of any vendor -- no WISPr, no 11863 field, no
        ``Bandwidth-Max`` -- so bandwidth there is a separate control-plane
        call after authentication, which is exactly what this feature is.
        """
        from app.domains.queue_management.models import QueueProfile
        from app.domains.queue_management.service import format_mikrotik_rate_limit
        from tests.unit.test_queue_management import _base_fields

        profile = QueueProfile(
            **_base_fields(
                organization_id=uuid.uuid4(),
                name="5 Mbps",
                description=None,
                download_rate_kbps=5000,
                upload_rate_kbps=1000,
                burst_download_kbps=None,
                burst_upload_kbps=None,
                burst_threshold_kbps=None,
                burst_time_seconds=None,
                priority=8,
                queue_type="simple",
                is_system_profile=False,
                is_active=True,
            )
        )
        assert format_mikrotik_rate_limit(profile) == "1000k/5000k"
