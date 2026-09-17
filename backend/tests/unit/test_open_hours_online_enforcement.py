"""Open Hours: the sessions a venue keeps serving after it has closed.

Open Hours was a *sign-in* gate only. ``GuestService._require_venue_open``
refuses a login outside the venue's own schedule, and nothing ever revisited a
guest who was already connected -- so a venue that closes at 22:00 stops
admitting anyone at 22:00 and keeps serving everyone who was already online.
From the venue's side that is the feature not working. Founder QA: "Open Hours
not working, internet still working".

Every test here asserts an observable outcome: a session row moved to
``TERMINATED``, a guest left alone, or a device actually told to drop someone.
A test that only asserted ``is_open_now`` was called would have passed against
the bug, because the bug was that nothing called it after sign-in.

Follows this project's plain-``assert``/native-``async def`` style
(``tests/unit/test_whitelist_only_online_enforcement.py``); ``asyncio_mode =
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
    OPEN_HOURS_DISCONNECT_REASON,
    enforce_open_hours_online_guests,
)

# The value ``GuestSessionStatus.TERMINATED`` holds in the running app.
# Hard-coded rather than imported so a silent rename of the guest domain's own
# enum cannot make these tests agree with a broken wiring.
TERMINATED = "terminated"
ACTIVE = "active"

_WEEKDAYS = (
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
)

#: The only two spellings that do not depend on which day the suite runs on --
#: `is_open_now` reads the *current* weekday's entry.
CLOSED_EVERY_DAY = {day: {"open": False} for day in _WEEKDAYS}
OPEN_EVERY_DAY = {
    day: {"open": True, "start": "00:00", "end": "23:59"} for day in _WEEKDAYS
}


def _now() -> datetime:
    return datetime.now(UTC)


# ============================================================================
# Test doubles
# ============================================================================


@dataclass
class FakeSession:
    id: uuid.UUID
    guest_id: uuid.UUID
    location_id: uuid.UUID
    organization_id: uuid.UUID
    router_id: uuid.UUID = field(default_factory=uuid.uuid4)
    device_id: uuid.UUID | None = None
    status: str = ACTIVE
    started_at: datetime = field(default_factory=_now)
    ended_at: datetime | None = None
    disconnect_reason: str | None = None
    disconnect_enforced: bool | None = None


@dataclass
class FakeGuest:
    id: uuid.UUID
    identifier: str = "+919876543210"


@dataclass
class FakeConfig:
    organization_id: uuid.UUID
    business_hours_enabled: bool = False
    business_hours_timezone: str = "UTC"
    business_hours_schedule: dict[str, dict[str, object]] = field(
        default_factory=lambda: dict(OPEN_EVERY_DAY)
    )


@dataclass
class FakeResolvedConfig:
    config: FakeConfig


@dataclass
class FakePortalLookup:
    """Structurally satisfies ``CaptivePortalLookupProtocol`` for the one
    method this sweep calls."""

    configs: dict[uuid.UUID, FakeConfig] = field(default_factory=dict)
    #: When set, the venues in here raise instead of resolving.
    broken_locations: set[uuid.UUID] = field(default_factory=set)
    calls: list[uuid.UUID] = field(default_factory=list)

    async def resolve_portal_config(
        self, *, organization_id: uuid.UUID | None, location_id: uuid.UUID | None
    ) -> FakeResolvedConfig:
        assert location_id is not None
        self.calls.append(location_id)
        if location_id in self.broken_locations:
            raise RuntimeError("config lookup exploded")
        return FakeResolvedConfig(self.configs[location_id])


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
    #: Set to make one venue's own read raise, so "one venue must not stop the
    #: rest" is testable.
    broken_reads: set[uuid.UUID] = field(default_factory=set)

    def all_sessions(self) -> list[FakeSession]:
        return [s for sessions in self.sessions.values() for s in sessions]

    async def list_active_guest_org_pairs(self) -> list[ActiveGuestOrgPair]:
        seen: dict[tuple[uuid.UUID, uuid.UUID, uuid.UUID], ActiveGuestOrgPair] = {}
        for session in self.all_sessions():
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

    async def list_active_sessions_for_location(
        self, *, organization_id: uuid.UUID, location_id: uuid.UUID
    ) -> list[FakeSession]:
        if location_id in self.broken_reads:
            raise RuntimeError("session read exploded")
        return [
            s
            for s in self.all_sessions()
            if s.status == ACTIVE
            and s.location_id == location_id
            and s.organization_id == organization_id
        ]

    async def update_session(
        self, session: FakeSession, data: dict[str, object]
    ) -> FakeSession:
        for key, value in data.items():
            setattr(session, key, value)
        return session


def _venue(
    *,
    enabled: bool = True,
    schedule: dict[str, dict[str, object]] | None = None,
    guest_count: int = 2,
) -> tuple[FakeGuestRepository, FakePortalLookup, FakeTerminator, list[FakeSession]]:
    """One venue with ``guest_count`` guests online, and its own config."""
    organization_id = uuid.uuid4()
    location_id = uuid.uuid4()
    sessions: list[FakeSession] = []
    guests: dict[uuid.UUID, FakeGuest] = {}
    by_guest: dict[uuid.UUID, list[FakeSession]] = {}
    for i in range(guest_count):
        guest = FakeGuest(id=uuid.uuid4(), identifier=f"+9198765432{i:02d}")
        guests[guest.id] = guest
        session = FakeSession(
            id=uuid.uuid4(),
            guest_id=guest.id,
            location_id=location_id,
            organization_id=organization_id,
        )
        sessions.append(session)
        by_guest[guest.id] = [session]
    repository = FakeGuestRepository(guests=guests, sessions=by_guest)
    portal = FakePortalLookup(
        configs={
            location_id: FakeConfig(
                organization_id=organization_id,
                business_hours_enabled=enabled,
                business_hours_schedule=(
                    schedule if schedule is not None else dict(OPEN_EVERY_DAY)
                ),
            )
        }
    )
    return repository, portal, FakeTerminator(), sessions


# ============================================================================
# The sweep
# ============================================================================


async def test_a_closed_venue_is_emptied_and_each_device_is_told() -> None:
    """The reported defect, end to end: the venue's own schedule says closed,
    so the guests it is still serving come off -- at the device, not only in
    this platform's records."""
    repository, portal, terminator, sessions = _venue(
        enabled=True, schedule=dict(CLOSED_EVERY_DAY)
    )

    ended = await enforce_open_hours_online_guests(
        repository, captive_portal_lookup=portal, terminator=terminator
    )

    assert sorted(s.id for s in ended) == sorted(s.id for s in sessions)
    for session in sessions:
        assert session.status == TERMINATED
        assert session.disconnect_reason == OPEN_HOURS_DISCONNECT_REASON
        assert session.ended_at is not None
    assert len(terminator.ended) == len(sessions)


async def test_an_open_venue_is_untouched() -> None:
    repository, portal, terminator, sessions = _venue(
        enabled=True, schedule=dict(OPEN_EVERY_DAY)
    )

    ended = await enforce_open_hours_online_guests(
        repository, captive_portal_lookup=portal, terminator=terminator
    )

    assert ended == []
    assert all(s.status == ACTIVE for s in sessions)
    assert terminator.ended == []


async def test_a_venue_with_hours_switched_off_is_never_closed() -> None:
    """`is_open_now`'s own forgiving direction, and the one that protects the
    fleet: enforcement off means open, whatever the stored schedule says. A
    venue that never switched Open Hours on must not have guests dropped by a
    schedule it is not enforcing."""
    repository, portal, terminator, sessions = _venue(
        enabled=False, schedule=dict(CLOSED_EVERY_DAY)
    )

    ended = await enforce_open_hours_online_guests(
        repository, captive_portal_lookup=portal, terminator=terminator
    )

    assert ended == []
    assert all(s.status == ACTIVE for s in sessions)


async def test_a_day_missing_from_the_schedule_is_closed() -> None:
    """The documented meaning of the column: a day absent from the schedule is
    closed all day. That is also the answer the same venue's logins already
    get, so this cannot disagree with the screen the guest lands on."""
    repository, portal, terminator, sessions = _venue(enabled=True, schedule={})

    ended = await enforce_open_hours_online_guests(
        repository, captive_portal_lookup=portal, terminator=terminator
    )

    assert len(ended) == len(sessions)
    assert all(s.status == TERMINATED for s in sessions)


async def test_a_failing_config_lookup_leaves_that_venue_online() -> None:
    """Fail open, and say so. Uncomfortable and deliberate: this sweep runs
    unattended, and one that acted on a failed lookup would empty venues on a
    database hiccup. Last week's behaviour plus a WARNING is the survivable
    answer."""
    repository, portal, terminator, sessions = _venue(enabled=True, schedule={})
    portal.broken_locations = {sessions[0].location_id}

    ended = await enforce_open_hours_online_guests(
        repository, captive_portal_lookup=portal, terminator=terminator
    )

    assert ended == []
    assert all(s.status == ACTIVE for s in sessions)
    assert terminator.ended == []


async def test_one_broken_venue_does_not_stop_the_rest() -> None:
    """Two closed venues, one of whose session read explodes. The other must
    still be emptied -- a sweep that stops at the first bad row protects
    nobody."""
    repo_a, portal_a, terminator, sessions_a = _venue(schedule=dict(CLOSED_EVERY_DAY))
    repo_b, portal_b, _terminator_b, sessions_b = _venue(
        schedule=dict(CLOSED_EVERY_DAY)
    )
    repository = FakeGuestRepository(
        guests={**repo_a.guests, **repo_b.guests},
        sessions={**repo_a.sessions, **repo_b.sessions},
        broken_reads={sessions_b[0].location_id},
    )
    portal = FakePortalLookup(configs={**portal_a.configs, **portal_b.configs})

    ended = await enforce_open_hours_online_guests(
        repository, captive_portal_lookup=portal, terminator=terminator
    )

    assert sorted(s.id for s in ended) == sorted(s.id for s in sessions_a)
    assert all(s.status == TERMINATED for s in sessions_a)
    assert all(s.status == ACTIVE for s in sessions_b)


async def test_an_unreachable_router_still_ends_the_session() -> None:
    """Honest enforcement: the row moves because that is what the venue's own
    configuration asks for, and ``disconnect_enforced`` records whether the
    device half actually happened. A router that is down must not keep a
    closed venue's guests in this platform's records."""
    repository, portal, terminator, sessions = _venue(schedule=dict(CLOSED_EVERY_DAY))
    terminator.raises = True

    ended = await enforce_open_hours_online_guests(
        repository, captive_portal_lookup=portal, terminator=terminator
    )

    assert len(ended) == len(sessions)
    assert all(s.status == TERMINATED for s in sessions)
    assert all(s.disconnect_enforced is False for s in sessions)


async def test_the_sweep_runs_with_no_lookup_wired_and_says_so() -> None:
    """A mis-composed service graph must not empty anything: with no way to
    read a schedule, there is no answer to act on."""
    repository, _portal, terminator, sessions = _venue(schedule=dict(CLOSED_EVERY_DAY))

    ended = await enforce_open_hours_online_guests(
        repository, captive_portal_lookup=None, terminator=terminator
    )

    assert ended == []
    assert all(s.status == ACTIVE for s in sessions)


async def test_the_venue_is_read_once_however_many_guests_are_on_it() -> None:
    """The sweep's own cost control, shared with its sibling: a venue with
    forty guests online resolves its config once."""
    repository, portal, terminator, _sessions = _venue(
        schedule=dict(CLOSED_EVERY_DAY), guest_count=6
    )

    await enforce_open_hours_online_guests(
        repository, captive_portal_lookup=portal, terminator=terminator
    )

    assert len(portal.calls) == 1


# ============================================================================
# Wiring: a sweep nothing schedules is a callable, not a fix
# ============================================================================


def test_the_sweep_is_beat_scheduled_and_registered() -> None:
    # Importing the task module is what registers the task on the app --
    # ``include=[...]`` does that at worker start, which no test process ever
    # performs.
    import app.domains.guest.tasks  # noqa: F401
    from app.core.celery_app import celery_app
    from app.domains.guest.constants import (
        OPEN_HOURS_ENFORCEMENT_SWEEP_INTERVAL_SECONDS,
        TASK_RUN_OPEN_HOURS_ENFORCEMENT_SWEEP,
    )

    entry = celery_app.conf.beat_schedule["guest-open-hours-enforcement-sweep"]
    assert entry["task"] == TASK_RUN_OPEN_HOURS_ENFORCEMENT_SWEEP
    assert entry["schedule"] == OPEN_HOURS_ENFORCEMENT_SWEEP_INTERVAL_SECONDS
    assert TASK_RUN_OPEN_HOURS_ENFORCEMENT_SWEEP in celery_app.tasks


def test_the_sweep_task_bridges_into_async(monkeypatch) -> None:
    """Mirrors the sibling sweeps' bridge tests: the async bridge is
    monkeypatched, so this runs with no Celery worker, broker or Postgres."""
    from app.domains.guest import tasks as tasks_module

    async def _fake_sweep_async() -> int:
        return 7

    monkeypatch.setattr(
        tasks_module,
        "_run_open_hours_enforcement_sweep_async",
        _fake_sweep_async,
    )

    assert tasks_module.run_open_hours_enforcement_sweep() == {"ended_count": 7}
