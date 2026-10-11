"""A live guest session whose login never got a queue onto the router is
given one -- and nothing else is disturbed in the process.

What this pins, observed at one live RouterOS venue: the router's API did
not answer while guests were signing in. Each login's ``assign_guest_queue``
task retried three times, gave up and rolled back, leaving ACTIVE sessions
with no ``QueueAssignment`` at all -- unlimited. The API then became
reachable again and nothing came back for those guests: the venue's saved
speed was published and the re-apply reported ``reapplied: 0``, because it
walks existing assignments and these sessions had none.

Everything here runs against the in-memory fakes from
``test_queue_management``. Nothing talks to a router or a database: the
query that finds such sessions is compiled, not run, and the savepoint the
task wraps each attempt in is stood in for by a snapshot of the fake
repository.
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.core.celery_app import DEVICE_IO_QUEUE_NAME, celery_app
from app.core.config import Settings
from app.domains.location.service import LocationService
from app.domains.organization.service import OrganizationService
from app.domains.queue_management import tasks as queue_tasks
from app.domains.queue_management.constants import (
    BACKFILL_UNASSIGNED_SESSION_QUEUES_INTERVAL_SECONDS,
    BACKFILL_UNASSIGNED_SESSION_QUEUES_MIN_AGE_SECONDS,
    TASK_BACKFILL_UNASSIGNED_SESSION_QUEUES,
    QueueStatus,
    QueueTargetType,
)
from app.domains.queue_management.exceptions import QueueDeviceConnectionError
from app.domains.queue_management.service import SessionWithoutQueue
from app.domains.router.models import Router
from app.domains.router.vendor_capabilities import CONTROLLER_MANAGED_VENDORS
from tests.unit.test_queue_management import (
    FakeQueueDeviceAdapter,
    Harness,
    _make_router,
    _now,
    _seed_assignment,
    make_harness,
)
from tests.unit.test_queue_release_on_session_end import (
    FakeSessionLiveness,
    _policy,
    _profile,
)

OLD = timedelta(minutes=30)
EMPTY = {
    "assigned": 0,
    "failed": 0,
    "skipped_unreachable": 0,
    "skipped_no_target": 0,
    "skipped_address_in_use": 0,
}


@dataclass
class FakeSessionsWithoutQueue:
    """Stands in for the guest-side query. It answers from ``sessions`` and
    the fake repository's own rows, so "has no queue" means here what the
    real statement means: no ACTIVE, SUSPENDED or DISABLED SESSION row."""

    h: Harness
    sessions: list[SessionWithoutQueue] = field(default_factory=list)
    asked: list[dict[str, object]] = field(default_factory=list)

    async def list_sessions_without_queue(
        self, *, started_before, location_id=None, limit
    ) -> list[SessionWithoutQueue]:
        self.asked.append(
            {
                "started_before": started_before,
                "location_id": location_id,
                "limit": limit,
            }
        )
        holding = {
            a.target_id
            for a in self.h.repository.assignments.values()
            if a.target_type == QueueTargetType.SESSION.value
            and not a.is_deleted
            and a.status
            in (
                QueueStatus.ACTIVE.value,
                QueueStatus.SUSPENDED.value,
                QueueStatus.DISABLED.value,
            )
        }
        found = [
            s
            for s in self.sessions
            if s.started_at <= started_before
            and s.session_id not in holding
            and (location_id is None or s.location_id == location_id)
        ]
        return sorted(found, key=lambda s: s.started_at, reverse=True)[:limit]


@dataclass
class DownAdapter(FakeQueueDeviceAdapter):
    """A router whose API does not answer -- every create times out -- for
    the hosts named in ``down_hosts`` (all hosts when it is ``None``)."""

    down_hosts: set[str] | None = None
    create_attempts: int = 0

    async def create_simple_queue(self, credentials, **kwargs) -> str:
        self.create_attempts += 1
        if self.down_hosts is None or credentials.host in self.down_hosts:
            raise QueueDeviceConnectionError(credentials.host, "timed out")
        return await super().create_simple_queue(credentials, **kwargs)


def _harness(
    adapter: FakeQueueDeviceAdapter | None = None,
) -> tuple[Harness, FakeSessionsWithoutQueue, FakeSessionLiveness]:
    h = make_harness(device_adapter=adapter)
    lookup = FakeSessionsWithoutQueue(h)
    liveness = FakeSessionLiveness()
    h.service.sessions_without_queue_lookup = lookup
    h.service.session_liveness_lookup = liveness
    return h, lookup, liveness


def _session(
    lookup: FakeSessionsWithoutQueue,
    liveness: FakeSessionLiveness,
    router: Router,
    *,
    address: str | None = "10.5.50.20",
    age: timedelta = OLD,
    live: bool = True,
) -> SessionWithoutQueue:
    session = SessionWithoutQueue(
        session_id=uuid.uuid4(),
        organization_id=router.organization_id,
        location_id=router.location_id,
        router_id=router.id,
        ip_address=address,
        guest_id=None,
        started_at=_now() - age,
    )
    lookup.sessions.append(session)
    if live:
        liveness.live.add(session.session_id)
    return session


def _rows_for(h: Harness, session: SessionWithoutQueue) -> list:
    return [
        a
        for a in h.repository.assignments.values()
        if a.target_id == session.session_id and a.status != QueueStatus.EXPIRED.value
    ]


def _savepoint(h: Harness):
    """What ``AsyncSession.begin_nested`` does for the task, for the fake
    repository: a failed attempt's rows are gone again."""

    @asynccontextmanager
    async def unit_of_work():
        before = dict(h.repository.assignments)
        try:
            yield
        except BaseException:
            h.repository.assignments.clear()
            h.repository.assignments.update(before)
            raise

    return unit_of_work


class TestBackfillQueuesForUnassignedSessions:
    async def test_a_live_session_with_no_queue_gets_the_venues_rate(self) -> None:
        h, lookup, liveness = _harness()
        router = h.router_lookup.add(_make_router())
        _policy(h, router, 40960)
        session = _session(lookup, liveness, router)

        result = await h.service.backfill_queues_for_unassigned_sessions()

        assert result == {**EMPTY, "assigned": 1}
        (row,) = _rows_for(h, session)
        assert row.status == QueueStatus.ACTIVE.value
        assert row.device_target == "10.5.50.20"
        assert row.target_type == QueueTargetType.SESSION.value
        (call,) = h.device_adapter.created_calls
        assert call["target"] == "10.5.50.20"
        assert call["download_rate_kbps"] == 40960
        assert call["upload_rate_kbps"] == 40960

    async def test_a_session_that_already_has_a_queue_is_untouched(self) -> None:
        h, lookup, liveness = _harness()
        router = h.router_lookup.add(_make_router())
        _policy(h, router, 40960)
        session = _session(lookup, liveness, router)
        existing = _seed_assignment(
            h,
            router=router,
            target_id=session.session_id,
            device_target="10.5.50.20",
            queue_profile_id=(await _profile(h, 20480)).id,
            device_queue_id="*9",
        )

        result = await h.service.backfill_queues_for_unassigned_sessions()

        assert result == EMPTY
        assert _rows_for(h, session) == [existing]
        assert existing.device_queue_id == "*9"
        assert h.device_adapter.created_calls == []
        assert h.device_adapter.updated_calls == []
        assert h.device_adapter.removed_ids == []

    async def test_an_ended_session_is_not_given_a_queue(self) -> None:
        """The lookup returned it (it ended between the read and the
        write); liveness, asked again just before the write, says no."""
        h, lookup, liveness = _harness()
        router = h.router_lookup.add(_make_router())
        ended = _session(lookup, liveness, router, live=False)

        result = await h.service.backfill_queues_for_unassigned_sessions()

        assert result == EMPTY
        assert _rows_for(h, ended) == []
        assert h.device_adapter.created_calls == []

    async def test_an_address_that_is_not_on_the_lan_is_refused(self) -> None:
        h, lookup, liveness = _harness()
        router = h.router_lookup.add(_make_router())
        public = _session(lookup, liveness, router, address="203.0.113.7")
        missing = _session(lookup, liveness, router, address=None)
        own = _session(lookup, liveness, router, address=router.management_ip_address)

        result = await h.service.backfill_queues_for_unassigned_sessions()

        assert result == {**EMPTY, "skipped_no_target": 3}
        for session in (public, missing, own):
            assert _rows_for(h, session) == []
        assert h.device_adapter.created_calls == []

    @pytest.mark.parametrize("vendor", sorted(CONTROLLER_MANAGED_VENDORS))
    async def test_a_controller_run_venue_is_left_alone(self, vendor: str) -> None:
        h, lookup, liveness = _harness()
        router = _make_router()
        router.vendor = vendor
        h.router_lookup.add(router)
        session = _session(lookup, liveness, router)

        result = await h.service.backfill_queues_for_unassigned_sessions()

        assert result == {**EMPTY, "skipped_no_target": 1}
        assert _rows_for(h, session) == []
        assert h.device_adapter.created_calls == []

    async def test_an_unreachable_router_is_tried_once_and_leaves_no_row(self) -> None:
        adapter = DownAdapter()
        h, lookup, liveness = _harness(adapter)
        router = h.router_lookup.add(_make_router())
        sessions = [
            _session(lookup, liveness, router, address=f"10.5.50.{n}")
            for n in (10, 11, 12)
        ]

        result = await h.service.backfill_queues_for_unassigned_sessions(
            unit_of_work=_savepoint(h)
        )

        assert result == {**EMPTY, "failed": 1, "skipped_unreachable": 2}
        assert adapter.create_attempts == 1
        assert h.repository.assignments == {}
        for session in sessions:
            assert _rows_for(h, session) == []

    async def test_one_routers_outage_does_not_stop_another_routers_backfill(
        self,
    ) -> None:
        adapter = DownAdapter(down_hosts={"10.20.0.9"})
        h, lookup, liveness = _harness(adapter)
        down = _make_router()
        down.management_ip_address = "10.20.0.9"
        h.router_lookup.add(down)
        up = h.router_lookup.add(_make_router())
        on_down = _session(lookup, liveness, down, address="10.5.50.10")
        on_up = _session(lookup, liveness, up, address="10.5.50.11", age=OLD * 2)

        result = await h.service.backfill_queues_for_unassigned_sessions(
            unit_of_work=_savepoint(h)
        )

        assert result == {**EMPTY, "assigned": 1, "failed": 1}
        assert _rows_for(h, on_down) == []
        (row,) = _rows_for(h, on_up)
        assert row.status == QueueStatus.ACTIVE.value

    async def test_a_second_run_does_nothing(self) -> None:
        h, lookup, liveness = _harness()
        router = h.router_lookup.add(_make_router())
        session = _session(lookup, liveness, router)

        first = await h.service.backfill_queues_for_unassigned_sessions()
        second = await h.service.backfill_queues_for_unassigned_sessions()

        assert first == {**EMPTY, "assigned": 1}
        assert second == EMPTY
        assert len(_rows_for(h, session)) == 1
        assert len(h.device_adapter.created_calls) == 1

    async def test_a_session_still_inside_the_logins_retry_window_is_skipped(
        self,
    ) -> None:
        h, lookup, liveness = _harness()
        router = h.router_lookup.add(_make_router())
        young = _session(lookup, liveness, router, age=timedelta(seconds=60))
        now = _now()

        result = await h.service.backfill_queues_for_unassigned_sessions(now=now)

        assert result == EMPTY
        assert _rows_for(h, young) == []
        assert lookup.asked[0]["started_before"] == now - timedelta(
            seconds=BACKFILL_UNASSIGNED_SESSION_QUEUES_MIN_AGE_SECONDS
        )

    async def test_it_does_not_take_an_address_from_the_guest_who_holds_it(
        self,
    ) -> None:
        """Two ACTIVE sessions record one address. The one with a queue
        keeps it; giving the other a queue would retire that row, and the
        next run would take it back, for ever."""
        h, lookup, liveness = _harness()
        router = h.router_lookup.add(_make_router())
        holder_id = uuid.uuid4()
        liveness.live.add(holder_id)
        holders = _seed_assignment(
            h,
            router=router,
            target_id=holder_id,
            device_target="10.5.50.20",
            queue_profile_id=(await _profile(h, 0)).id,
            device_queue_id="*4",
        )
        stale = _session(lookup, liveness, router, address="10.5.50.20")

        result = await h.service.backfill_queues_for_unassigned_sessions()

        assert result == {**EMPTY, "skipped_address_in_use": 1}
        assert _rows_for(h, stale) == []
        assert holders.status == QueueStatus.ACTIVE.value
        assert h.device_adapter.removed_ids == []

    async def test_an_ended_sessions_row_on_the_address_does_not_block_it(
        self,
    ) -> None:
        h, lookup, liveness = _harness()
        router = h.router_lookup.add(_make_router())
        left_behind = _seed_assignment(
            h,
            router=router,
            target_id=uuid.uuid4(),
            device_target="10.5.50.20",
            queue_profile_id=(await _profile(h, 0)).id,
            device_queue_id="*4",
        )
        session = _session(lookup, liveness, router, address="10.5.50.20")

        result = await h.service.backfill_queues_for_unassigned_sessions()

        assert result == {**EMPTY, "assigned": 1}
        assert left_behind.status == QueueStatus.EXPIRED.value
        assert h.device_adapter.removed_ids == ["*4"]
        assert len(_rows_for(h, session)) == 1

    async def test_two_unassigned_sessions_on_one_address_only_the_newest_is_served(
        self,
    ) -> None:
        h, lookup, liveness = _harness()
        router = h.router_lookup.add(_make_router())
        older = _session(lookup, liveness, router, address="10.5.50.20", age=OLD * 2)
        newer = _session(lookup, liveness, router, address="10.5.50.20")

        result = await h.service.backfill_queues_for_unassigned_sessions()

        assert result == {**EMPTY, "assigned": 1, "skipped_address_in_use": 1}
        assert len(_rows_for(h, newer)) == 1
        assert _rows_for(h, older) == []

    async def test_a_pending_row_left_by_a_failed_attempt_is_applied_not_duplicated(
        self,
    ) -> None:
        h, lookup, liveness = _harness()
        router = h.router_lookup.add(_make_router())
        session = _session(lookup, liveness, router)
        unlimited = await h.service._get_or_create_system_profile(
            download_rate_kbps=0, upload_rate_kbps=0
        )
        pending = _seed_assignment(
            h,
            router=router,
            target_id=session.session_id,
            device_target="10.5.50.20",
            queue_profile_id=unlimited.id,
            status=QueueStatus.PENDING.value,
        )

        result = await h.service.backfill_queues_for_unassigned_sessions()

        assert result == {**EMPTY, "assigned": 1}
        assert _rows_for(h, session) == [pending]
        assert pending.status == QueueStatus.ACTIVE.value
        assert len(h.device_adapter.created_calls) == 1

    async def test_the_cap_bounds_device_attempts_not_sessions_examined(self) -> None:
        h, lookup, liveness = _harness()
        router = h.router_lookup.add(_make_router())
        for n in range(5):
            _session(lookup, liveness, router, address=f"203.0.113.{n}")
        for n in range(4):
            _session(
                lookup, liveness, router, address=f"10.5.50.{30 + n}", age=OLD * 2
            )

        result = await h.service.backfill_queues_for_unassigned_sessions(max_per_run=3)

        assert result == {**EMPTY, "assigned": 3, "skipped_no_target": 5}
        assert len(h.device_adapter.created_calls) == 3

    async def test_a_router_outside_the_allow_list_is_not_touched(self) -> None:
        h, lookup, liveness = _harness()
        wanted = h.router_lookup.add(_make_router())
        other = h.router_lookup.add(_make_router())
        on_wanted = _session(lookup, liveness, wanted, address="10.5.50.10")
        on_other = _session(lookup, liveness, other, address="10.5.50.11")

        result = await h.service.backfill_queues_for_unassigned_sessions(
            router_allowed=lambda router_id: router_id == wanted.id
        )

        assert result == {**EMPTY, "assigned": 1}
        assert len(_rows_for(h, on_wanted)) == 1
        assert _rows_for(h, on_other) == []

    async def test_a_location_filter_is_passed_to_the_lookup(self) -> None:
        h, lookup, liveness = _harness()
        here = h.router_lookup.add(_make_router())
        elsewhere = h.router_lookup.add(_make_router())
        _session(lookup, liveness, here, address="10.5.50.10")
        there = _session(lookup, liveness, elsewhere, address="10.5.50.11")

        result = await h.service.backfill_queues_for_unassigned_sessions(
            location_id=here.location_id
        )

        assert result == {**EMPTY, "assigned": 1}
        assert lookup.asked[0]["location_id"] == here.location_id
        assert _rows_for(h, there) == []

    async def test_without_a_lookup_nothing_is_assigned(self) -> None:
        h = make_harness()

        assert await h.service.backfill_queues_for_unassigned_sessions() == EMPTY


class TestTheSwitch:
    def _settings(self, **overrides: object) -> SimpleNamespace:
        return SimpleNamespace(
            **{
                "guest_queue_backfill_enabled": False,
                "guest_queue_backfill_router_ids": "",
                "guest_queue_backfill_max_per_run": 25,
                **overrides,
            }
        )

    def test_it_is_off_by_default(self) -> None:
        fields = Settings.model_fields
        assert fields["guest_queue_backfill_enabled"].default is False
        assert fields["guest_queue_backfill_router_ids"].default == ""
        assert not queue_tasks._queue_backfill_is_on_anywhere(self._settings())

    def test_the_allow_list_names_single_routers_and_never_widens(self) -> None:
        wanted, other = uuid.uuid4(), uuid.uuid4()
        settings = self._settings(
            guest_queue_backfill_router_ids=f" {str(wanted).upper()} , not-a-uuid,"
        )

        assert queue_tasks._queue_backfill_is_on_anywhere(settings)
        assert queue_tasks.queue_backfill_applies(wanted, settings)
        assert not queue_tasks.queue_backfill_applies(other, settings)

    def test_enabled_means_every_router(self) -> None:
        settings = self._settings(guest_queue_backfill_enabled=True)

        assert queue_tasks.queue_backfill_applies(uuid.uuid4(), settings)

    async def test_switched_off_the_task_opens_no_database_session(
        self, monkeypatch
    ) -> None:
        def _no_session():
            raise AssertionError("the backfill opened a session while switched off")

        monkeypatch.setattr(queue_tasks, "get_settings", self._settings)
        monkeypatch.setattr(queue_tasks, "SessionLocal", _no_session)

        assert await queue_tasks._backfill_unassigned_session_queues_async() == EMPTY


class TestTheWiringIsReal:
    def test_the_backfill_is_registered_scheduled_and_routed(self) -> None:
        assert TASK_BACKFILL_UNASSIGNED_SESSION_QUEUES in celery_app.tasks
        entries = [
            entry
            for entry in celery_app.conf.beat_schedule.values()
            if entry["task"] == TASK_BACKFILL_UNASSIGNED_SESSION_QUEUES
        ]
        assert len(entries) == 1
        assert (
            entries[0]["schedule"]
            == BACKFILL_UNASSIGNED_SESSION_QUEUES_INTERVAL_SECONDS
        )
        assert celery_app.conf.task_routes[TASK_BACKFILL_UNASSIGNED_SESSION_QUEUES] == {
            "queue": DEVICE_IO_QUEUE_NAME
        }

    def test_the_query_selects_active_sessions_with_no_applied_queue(self) -> None:
        """No database here, so the statement is compiled, not run."""
        cutoff = datetime(2026, 10, 11, 18, 0, tzinfo=UTC)
        location_id = uuid.uuid4()
        compiled = queue_tasks.GuestSessionsWithoutQueue.statement(
            started_before=cutoff, location_id=location_id, limit=50
        ).compile()
        sql = " ".join(str(compiled).split())

        assert "FROM guest_sessions" in sql
        assert "guest_sessions.is_deleted IS false" in sql
        assert "guest_sessions.router_id IS NOT NULL" in sql
        assert "guest_sessions.started_at <=" in sql
        assert "guest_sessions.location_id =" in sql
        assert "NOT (EXISTS (SELECT queue_assignments.id FROM queue_assignments" in sql
        assert "queue_assignments.target_id = guest_sessions.id" in sql
        assert "ORDER BY guest_sessions.started_at DESC" in sql
        params = compiled.params
        assert "active" in params.values()
        assert "session" in params.values()
        assert cutoff in params.values()
        assert location_id in params.values()
        assert 50 in params.values()
        statuses = [v for v in params.values() if isinstance(v, list)]
        assert statuses == [["active", "suspended", "disabled"]]

    async def test_the_lookup_maps_rows_to_sessions(self) -> None:
        started = datetime(2026, 10, 11, 17, 31, tzinfo=UTC)
        ids = [uuid.uuid4() for _ in range(4)]
        row = (*ids, "10.5.50.9", None, started)

        class _Session:
            async def execute(self, statement):
                return SimpleNamespace(all=lambda: [row])

        (found,) = await queue_tasks.GuestSessionsWithoutQueue(
            _Session()
        ).list_sessions_without_queue(started_before=started, limit=10)

        assert found == SessionWithoutQueue(
            session_id=row[0],
            organization_id=row[1],
            location_id=row[2],
            router_id=row[3],
            ip_address="10.5.50.9",
            guest_id=None,
            started_at=started,
        )


class TestTheLoginFactoriesPassLookupsInTheRightOrder:
    """``RouterService(repository, location_lookup, organization_lookup)``.
    Two hand-built factories in ``guest.tasks`` passed the last two the
    other way round. It went unnoticed because ``get_router`` on a
    same-organisation call consults neither."""

    def test_the_queue_factory(self) -> None:
        from app.domains.guest.tasks import _build_queue_management_service

        router_service = _build_queue_management_service(MagicMock()).router_lookup

        assert isinstance(router_service.location_lookup, LocationService)
        assert isinstance(router_service.organization_lookup, OrganizationService)

    def test_the_session_terminator_factory(self) -> None:
        from app.domains.guest.tasks import _build_session_terminator

        terminator = _build_session_terminator(MagicMock(), MagicMock())
        router_service = terminator.router_lookup

        assert isinstance(router_service.location_lookup, LocationService)
        assert isinstance(router_service.organization_lookup, OrganizationService)
