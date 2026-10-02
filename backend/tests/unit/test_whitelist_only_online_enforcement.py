"""Only Allowed: the sessions a whitelist-only property has already stopped
admitting.

The defect these tests pin down: ``captive_portal_configs
.whitelist_only_enabled`` was answered once, at sign-in, and never re-asked.
Switching it on therefore stopped admitting *new* guests and left every guest
already online exactly where they were -- the venue believes it is running
closed, its dashboard says so, and the people the feature exists to refuse
are the ones holding a session. Founder QA: "Always allowed not working" /
"turning it on doesn't cut off guests already online".

Every test here asserts an observable outcome: a session row moved to
``TERMINATED``, that same guest left ``ACTIVE``, or a device that was actually
told to drop them. A test that only asserted "``check_access`` was called"
would have passed against the bug, because the bug was that nothing asked it
again at all.

Follows this project's plain-``assert``/native-``async def`` style
(``tests/unit/test_guest_access_block_enforcement.py``); ``asyncio_mode =
"auto"`` runs async tests directly. Everything is exercised against small
hand-rolled in-memory fakes -- there is no live Postgres, router or Celery
broker in this environment.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.domains.guest.repository import ActiveGuestOrgPair
from app.domains.guest.service import (
    WHITELIST_ONLY_DISCONNECT_REASON,
    enforce_whitelist_only_online_guests,
    whitelist_only_refusal_stands,
)
from app.domains.guest_access.service import AccessDecision

# The value ``GuestSessionStatus.TERMINATED`` holds in the running app.
# Hard-coded rather than imported so a silent rename of the guest domain's own
# enum cannot make these tests agree with a broken wiring.
TERMINATED = "terminated"
ACTIVE = "active"


def _now() -> datetime:
    return datetime.now(UTC)


# ============================================================================
# Test doubles
# ============================================================================


@dataclass
class FakeGuest:
    id: uuid.UUID
    identifier: str = "+919876543210"


@dataclass
class FakeDevice:
    mac_address: str


@dataclass
class FakeSession:
    id: uuid.UUID
    guest_id: uuid.UUID
    location_id: uuid.UUID
    organization_id: uuid.UUID
    router_id: uuid.UUID = field(default_factory=uuid.uuid4)
    device_id: uuid.UUID | None = None
    status: str = ACTIVE
    ended_at: datetime | None = None
    disconnect_reason: str | None = None
    disconnect_enforced: bool | None = None


@dataclass
class FakeConfig:
    whitelist_only_enabled: bool
    whitelist_only_denied_message: str | None = "Ask reception to add you."


@dataclass
class FakeResolvedConfig:
    config: FakeConfig


@dataclass
class FakePortalLookup:
    """Structurally satisfies ``CaptivePortalLookupProtocol`` for the one
    method this sweep calls."""

    #: ``location_id`` -> resolved config. A location that is absent raises,
    #: which is the "no portal config for this venue at all" case.
    configs: dict[uuid.UUID, FakeConfig] = field(default_factory=dict)
    raises: bool = False
    calls: list[uuid.UUID] = field(default_factory=list)

    async def resolve_portal_config(
        self, *, organization_id: uuid.UUID | None, location_id: uuid.UUID | None
    ) -> FakeResolvedConfig:
        if self.raises:
            raise RuntimeError("config lookup exploded")
        assert location_id is not None
        self.calls.append(location_id)
        return FakeResolvedConfig(self.configs[location_id])


@dataclass
class FakeAccessHook:
    """Structurally satisfies ``AccessDecisionProtocol``.

    ``denied`` lists the ``(identifier, mac)`` pairs this property refuses.
    Everything else is allowed, so each test states only the refusal it is
    about.
    """

    denied: set[tuple[str, str]] = field(default_factory=set)
    raises: bool = False
    whitelist_only_seen: list[bool] = field(default_factory=list)

    async def check_access(
        self,
        *,
        organization_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        identifier: str | None,
        mac_address: str | None,
        whitelist_only_enabled: bool = False,
    ) -> AccessDecision:
        if self.raises:
            raise RuntimeError("access lookup exploded")
        self.whitelist_only_seen.append(whitelist_only_enabled)
        if (identifier or "", mac_address or "") in self.denied:
            # No matched rule -> ``AccessDecision.is_whitelist_only_denial``.
            return AccessDecision(
                allowed=False, rule_type=None, matched_rule_id=None, reason=None
            )
        return AccessDecision(
            allowed=True, rule_type=None, matched_rule_id=None, reason=None
        )


@dataclass
class FakeMacHook:
    """Structurally satisfies ``MacAuthorizationLookupProtocol``."""

    authorized: set[str] = field(default_factory=set)
    calls: list[str] = field(default_factory=list)

    async def is_mac_authorized(
        self,
        mac_address: str,
        *,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None = None,
    ) -> bool:
        self.calls.append(mac_address)
        return mac_address in self.authorized


@dataclass
class FakeTerminator:
    """Structurally satisfies ``LiveSessionTerminatorProtocol`` for the one
    method ``issue_live_disconnect`` calls."""

    ended: list[tuple[uuid.UUID, str]] = field(default_factory=list)
    raises: bool = False

    async def end_on_router(
        self,
        *,
        session: object,
        identifier: str,
        organization_id: uuid.UUID | None = None,
    ) -> object:
        if self.raises:
            raise RuntimeError("router unreachable")
        self.ended.append((session.id, identifier))  # type: ignore[attr-defined]
        return object()


@dataclass
class FakeGuestRepository:
    """Structurally satisfies ``GuestRepositoryProtocol`` for the subset this
    sweep uses."""

    guests: dict[uuid.UUID, FakeGuest] = field(default_factory=dict)
    sessions: dict[uuid.UUID, list[FakeSession]] = field(default_factory=dict)
    devices: dict[uuid.UUID, FakeDevice] = field(default_factory=dict)

    async def list_active_guest_org_pairs(self) -> list[ActiveGuestOrgPair]:
        seen: dict[tuple[uuid.UUID, uuid.UUID, uuid.UUID], ActiveGuestOrgPair] = {}
        for sessions in self.sessions.values():
            for session in sessions:
                if session.status != ACTIVE:
                    continue
                key = (session.guest_id, session.organization_id, session.location_id)
                seen[key] = ActiveGuestOrgPair(
                    guest_id=session.guest_id,
                    organization_id=session.organization_id,
                    location_id=session.location_id,
                )
        return list(seen.values())

    async def get_guest_by_id(self, guest_id: uuid.UUID) -> FakeGuest | None:
        return self.guests.get(guest_id)

    async def list_active_sessions_for_guest(
        self, guest_id: uuid.UUID
    ) -> list[FakeSession]:
        return [s for s in self.sessions.get(guest_id, []) if s.status == ACTIVE]

    async def get_device_by_id(self, device_id: uuid.UUID) -> FakeDevice | None:
        return self.devices.get(device_id)

    async def update_session(
        self, session: FakeSession, data: dict[str, object]
    ) -> FakeSession:
        for key, value in data.items():
            setattr(session, key, value)
        return session


def _fixture(
    *,
    whitelist_only: bool = True,
    device_mac: str | None = "AA:BB:CC:DD:EE:FF",
    authorized_mac: str | None = None,
) -> tuple[
    FakeGuestRepository,
    FakePortalLookup,
    FakeAccessHook,
    FakeMacHook,
    FakeTerminator,
    FakeSession,
]:
    org_id = uuid.uuid4()
    location_id = uuid.uuid4()
    guest = FakeGuest(id=uuid.uuid4())
    device = FakeDevice(mac_address=device_mac) if device_mac else None
    session = FakeSession(
        id=uuid.uuid4(),
        guest_id=guest.id,
        location_id=location_id,
        organization_id=org_id,
        device_id=uuid.uuid4() if device else None,
    )
    devices = {session.device_id: device} if device is not None else {}
    repository = FakeGuestRepository(
        guests={guest.id: guest},
        sessions={guest.id: [session]},
        devices=devices,
    )
    portal = FakePortalLookup(
        configs={location_id: FakeConfig(whitelist_only_enabled=whitelist_only)}
    )
    mac_hook = FakeMacHook(authorized={authorized_mac} if authorized_mac else set())
    access = FakeAccessHook(denied={(guest.identifier, device_mac or "")})
    return repository, portal, access, mac_hook, FakeTerminator(), session


# ============================================================================
# The trusted-device reconciliation itself
# ============================================================================


async def test_a_mac_that_is_not_shapeable_is_never_consulted() -> None:
    """``whitelist_only_refusal_stands``'s truth table, one row per branch --
    it replaced an inline block in ``_enforce_access_control`` and both the
    login gate and this sweep depend on it agreeing with itself."""
    org_id, location_id = uuid.uuid4(), uuid.uuid4()
    hook = FakeMacHook(authorized={"AA:BB:CC:DD:EE:FF"})

    # No device at all: nothing to reconcile against, refusal stands.
    assert await whitelist_only_refusal_stands(
        hook, organization_id=org_id, location_id=location_id, device_mac=None
    ) == (True, False)

    # The caller already performed the identical check.
    assert await whitelist_only_refusal_stands(
        hook,
        organization_id=org_id,
        location_id=location_id,
        device_mac="AA:BB:CC:DD:EE:FF",
        device_mac_already_authorized=True,
    ) == (False, False)

    # No hook wired: no lookup happened, and the event must not claim one.
    assert await whitelist_only_refusal_stands(
        None,
        organization_id=org_id,
        location_id=location_id,
        device_mac="AA:BB:CC:DD:EE:FF",
    ) == (True, False)

    # Not MAC-shaped: still not consulted.
    assert await whitelist_only_refusal_stands(
        hook, organization_id=org_id, location_id=location_id, device_mac="not-a-mac"
    ) == (True, False)
    assert hook.calls == []

    # A real entry admits the device; its absence leaves the refusal standing.
    assert await whitelist_only_refusal_stands(
        hook,
        organization_id=org_id,
        location_id=location_id,
        device_mac="aa-bb-cc-dd-ee-ff",
    ) == (False, True)
    assert await whitelist_only_refusal_stands(
        hook,
        organization_id=org_id,
        location_id=location_id,
        device_mac="11:22:33:44:55:66",
    ) == (True, True)


# ============================================================================
# The sweep
# ============================================================================


async def test_an_unlisted_guest_already_online_is_ended_and_dropped() -> None:
    """The reported defect, end to end: whitelist-only is on, this guest
    matches nothing, and the sweep both flips the row and tells the router."""
    repository, portal, access, mac_hook, terminator, session = _fixture()
    ended = await enforce_whitelist_only_online_guests(
        repository,
        captive_portal_lookup=portal,
        access_control_hook=access,
        mac_authorization_hook=mac_hook,
        terminator=terminator,
    )

    assert [s.id for s in ended] == [session.id]
    assert session.status == TERMINATED
    assert session.disconnect_reason == WHITELIST_ONLY_DISCONNECT_REASON
    assert session.ended_at is not None
    # Device-level, not merely a status change -- the product rule this whole
    # area is built on.
    assert terminator.ended == [(session.id, "+919876543210")]
    # The decision was made *as* a whitelist-only property, which is the one
    # argument that makes ``check_access`` deny a rule-less guest at all.
    assert access.whitelist_only_seen == [True]


async def test_a_property_that_never_opted_in_is_untouched() -> None:
    """The blast radius of a feature nobody switched on is zero."""
    repository, portal, access, mac_hook, terminator, session = _fixture(
        whitelist_only=False
    )
    ended = await enforce_whitelist_only_online_guests(
        repository,
        captive_portal_lookup=portal,
        access_control_hook=access,
        mac_authorization_hook=mac_hook,
        terminator=terminator,
    )

    assert ended == []
    assert session.status == ACTIVE
    assert terminator.ended == []
    # Not even asked: the flag short-circuits before any decision is made.
    assert access.whitelist_only_seen == []


async def test_a_listed_guest_keeps_their_session() -> None:
    repository, portal, access, mac_hook, terminator, session = _fixture()
    access.denied = set()
    ended = await enforce_whitelist_only_online_guests(
        repository,
        captive_portal_lookup=portal,
        access_control_hook=access,
        mac_authorization_hook=mac_hook,
        terminator=terminator,
    )

    assert ended == []
    assert session.status == ACTIVE
    assert terminator.ended == []


async def test_a_trusted_device_is_kept_online_even_though_nothing_matched() -> None:
    """The front-desk tablet case: it is on the Trusted Devices list, not the
    Only Allowed list, and an operator must not have to add it twice or watch
    it drop off the WiFi every five minutes."""
    repository, portal, access, mac_hook, terminator, session = _fixture(
        device_mac="AA:BB:CC:DD:EE:FF", authorized_mac="AA:BB:CC:DD:EE:FF"
    )
    ended = await enforce_whitelist_only_online_guests(
        repository,
        captive_portal_lookup=portal,
        access_control_hook=access,
        mac_authorization_hook=mac_hook,
        terminator=terminator,
    )

    assert ended == []
    assert session.status == ACTIVE
    assert terminator.ended == []
    assert mac_hook.calls  # the reconciliation really ran


async def test_a_guest_with_one_device_each_gets_one_answer_each() -> None:
    """Admission at a whitelist-only property is per device: a trusted tablet
    and an untrusted laptop belong to the same guest and must not share a
    verdict."""
    repository, portal, access, mac_hook, terminator, session = _fixture(
        device_mac="AA:BB:CC:DD:EE:FF", authorized_mac="AA:BB:CC:DD:EE:FF"
    )
    untrusted = FakeDevice(mac_address="11:22:33:44:55:66")
    repository.devices[session.device_id] = untrusted  # type: ignore[index]
    access.denied = {
        (repository.guests[session.guest_id].identifier, untrusted.mac_address)
    }

    ended = await enforce_whitelist_only_online_guests(
        repository,
        captive_portal_lookup=portal,
        access_control_hook=access,
        mac_authorization_hook=mac_hook,
        terminator=terminator,
    )

    assert [s.id for s in ended] == [session.id]
    assert session.status == TERMINATED


async def test_a_failing_decision_lookup_leaves_the_guest_online() -> None:
    """Fail open, and say so.

    Uncomfortable and deliberate, for the same reason the login gate is: a
    whitelist-only property that fails closed is a total WiFi outage the
    venue cannot tell from the feature working. This sweep runs unattended
    against live venues, so the failure direction has to be the survivable
    one plus a log line."""
    repository, portal, access, mac_hook, terminator, session = _fixture()
    access.raises = True

    ended = await enforce_whitelist_only_online_guests(
        repository,
        captive_portal_lookup=portal,
        access_control_hook=access,
        mac_authorization_hook=mac_hook,
        terminator=terminator,
    )

    assert ended == []
    assert session.status == ACTIVE
    assert terminator.ended == []


async def test_a_failing_config_lookup_skips_that_venue() -> None:
    repository, portal, access, mac_hook, terminator, session = _fixture()
    portal.raises = True

    ended = await enforce_whitelist_only_online_guests(
        repository,
        captive_portal_lookup=portal,
        access_control_hook=access,
        mac_authorization_hook=mac_hook,
        terminator=terminator,
    )

    assert ended == []
    assert session.status == ACTIVE


async def test_an_unreachable_router_still_ends_the_session() -> None:
    """Honest enforcement: the row moves because that is what the operator
    asked for, and ``disconnect_enforced`` records whether the device half
    actually happened. An unreachable router must never keep a refused guest
    in this platform's records."""
    repository, portal, access, mac_hook, terminator, session = _fixture()
    terminator.raises = True

    ended = await enforce_whitelist_only_online_guests(
        repository,
        captive_portal_lookup=portal,
        access_control_hook=access,
        mac_authorization_hook=mac_hook,
        terminator=terminator,
    )

    assert [s.id for s in ended] == [session.id]
    assert session.status == TERMINATED
    assert session.disconnect_enforced is False


async def test_the_sweep_runs_with_no_hooks_wired_and_says_so() -> None:
    """A mis-composed service graph must not cut anyone off. Nothing is asked,
    nothing is ended, and the WARNING is the loud part."""
    repository, portal, _access, mac_hook, terminator, session = _fixture()

    ended = await enforce_whitelist_only_online_guests(
        repository,
        captive_portal_lookup=portal,
        access_control_hook=None,
        mac_authorization_hook=mac_hook,
        terminator=terminator,
    )

    assert ended == []
    assert session.status == ACTIVE


async def test_one_location_is_resolved_once_however_many_guests_are_online() -> None:
    """The sweep's own cost control: a venue with forty guests online resolves
    its config once, not forty times."""
    repository, portal, access, mac_hook, terminator, first = _fixture()
    second_guest = FakeGuest(id=uuid.uuid4(), identifier="+919000000002")
    second = FakeSession(
        id=uuid.uuid4(),
        guest_id=second_guest.id,
        location_id=first.location_id,
        organization_id=first.organization_id,
    )
    repository.guests[second_guest.id] = second_guest
    repository.sessions[second_guest.id] = [second]
    access.denied = set()

    await enforce_whitelist_only_online_guests(
        repository,
        captive_portal_lookup=portal,
        access_control_hook=access,
        mac_authorization_hook=mac_hook,
        terminator=terminator,
    )

    assert portal.calls == [first.location_id]


async def test_a_second_location_that_is_not_whitelist_only_is_left_alone() -> None:
    """A guest with a session at a second venue of the same organization: the
    sweep genuinely asks about that venue too -- ``list_active_guest_org_pairs``
    yields one row per (guest, organization, location) -- and must respect the
    answer it gets back, because the flag is per property."""
    repository, portal, access, mac_hook, terminator, session = _fixture()
    other_location = uuid.uuid4()
    other = FakeSession(
        id=uuid.uuid4(),
        guest_id=session.guest_id,
        location_id=other_location,
        organization_id=session.organization_id,
    )
    repository.sessions[session.guest_id].append(other)
    portal.configs[other_location] = FakeConfig(whitelist_only_enabled=False)

    ended = await enforce_whitelist_only_online_guests(
        repository,
        captive_portal_lookup=portal,
        access_control_hook=access,
        mac_authorization_hook=mac_hook,
        terminator=terminator,
    )

    assert [s.id for s in ended] == [session.id]
    assert other.status == ACTIVE
    assert other_location in portal.calls
    assert terminator.ended == [(session.id, "+919876543210")]


async def test_the_sweep_asks_about_the_guest_who_is_actually_online() -> None:
    """The identifier handed to ``check_access`` is the guest's own -- the
    value rule matching is string equality against, so a wrong one here would
    quietly admit or refuse everyone."""
    repository, portal, access, mac_hook, terminator, session = _fixture()
    seen: list[tuple[str | None, str | None]] = []

    original = access.check_access

    async def _recording(**kwargs: object) -> AccessDecision:
        seen.append((kwargs["identifier"], kwargs["mac_address"]))  # type: ignore[arg-type]
        return await original(**kwargs)  # type: ignore[arg-type]

    access.check_access = _recording  # type: ignore[method-assign]
    await enforce_whitelist_only_online_guests(
        repository,
        captive_portal_lookup=portal,
        access_control_hook=access,
        mac_authorization_hook=mac_hook,
        terminator=terminator,
    )

    guest = repository.guests[session.guest_id]
    device = repository.devices[session.device_id]  # type: ignore[index]
    assert seen == [(guest.identifier, device.mac_address)]


# ============================================================================
# Wiring: a sweep nothing schedules is a callable, not a fix
# ============================================================================


def test_the_sweep_is_beat_scheduled_and_registered() -> None:
    # Importing the task module is what registers the task on the app --
    # ``include=[...]`` does that at worker start, which no test process ever
    # performs. Done here rather than relying on another test in the session
    # having imported it first, so this suite passes in isolation.
    import app.domains.guest.tasks  # noqa: F401
    from app.core.celery_app import celery_app
    from app.domains.guest.constants import (
        TASK_RUN_WHITELIST_ONLY_ENFORCEMENT_SWEEP,
        WHITELIST_ONLY_ENFORCEMENT_SWEEP_INTERVAL_SECONDS,
    )

    entry = celery_app.conf.beat_schedule["guest-whitelist-only-enforcement-sweep"]
    assert entry["task"] == TASK_RUN_WHITELIST_ONLY_ENFORCEMENT_SWEEP
    assert entry["schedule"] == WHITELIST_ONLY_ENFORCEMENT_SWEEP_INTERVAL_SECONDS
    assert TASK_RUN_WHITELIST_ONLY_ENFORCEMENT_SWEEP in celery_app.tasks


def test_the_sweep_task_bridges_into_async(monkeypatch) -> None:
    """Mirrors ``test_run_session_timeout_sweep_task_bridges_into_async``:
    the async bridge is monkeypatched, so this runs with no Celery worker,
    broker or Postgres, and only the sync task's own wiring is under test."""
    from app.domains.guest import tasks as tasks_module

    async def _fake_sweep_async() -> int:
        return 4

    monkeypatch.setattr(
        tasks_module,
        "_run_whitelist_only_enforcement_sweep_async",
        _fake_sweep_async,
    )

    assert tasks_module.run_whitelist_only_enforcement_sweep() == {"ended_count": 4}


def test_a_closed_venue_refusal_carries_a_machine_readable_code() -> None:
    """Open Hours' refusal has to be distinguishable on the wire from any
    other 403, or the portal cannot route it to its own closed screen -- the
    venue's message is free text an operator can type anything into."""
    from app.domains.guest.exceptions import VenueClosedError

    error = VenueClosedError("Back at 8am")
    assert error.status_code == 403
    assert error.message == "Back at 8am"
    assert error.data == {"code": "venue_closed"}
    # The venue's own words when it has them, the platform default when not.
    assert VenueClosedError().message == "This WiFi network is closed right now."
