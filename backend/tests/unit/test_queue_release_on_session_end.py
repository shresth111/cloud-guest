"""A guest session's speed-limit row leaves the router when the session ends,
and a policy change reaches the guests it should -- and only them.

What these pin, all observed on one live RouterOS venue:

* An ``0/0`` (unlimited) ``/queue simple`` row belonging to a session that
  had been disconnected for over twenty minutes was still on the router,
  still ACTIVE in the database, and still first in the list. RouterOS
  applies the first matching row for an address, so any later, correct row
  for that address would have been inert. No code path removed a session's
  queue when the session ended.
* The venue's speed was saved while that guest was online and did not
  reach them: the dashboard publishes the policy version and *then* maps
  the policy to the location, and only the publish asked for a re-apply --
  against a policy that was, at that instant, mapped to no location.

Everything here runs against the in-memory fakes from
``test_queue_management``. Nothing talks to a router: that RouterOS answers
a remove of a missing id with ``no such item`` is asserted about this
code's handling of that text, not about the device.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from types import SimpleNamespace

import pytest

from app.core.celery_app import DEVICE_IO_QUEUE_NAME, celery_app
from app.domains.policy import router as policy_router
from app.domains.queue_management import tasks as queue_tasks
from app.domains.queue_management.constants import (
    RELEASE_ENDED_SESSION_QUEUES_INTERVAL_SECONDS,
    TASK_RELEASE_ENDED_SESSION_QUEUES,
    QueueStatus,
    QueueTargetType,
)
from app.domains.queue_management.exceptions import (
    QueueDeviceConnectionError,
    QueueDeviceOperationError,
)
from app.domains.queue_management.models import QueueAssignment, QueueProfile
from app.domains.router.models import Router
from tests.unit.test_queue_management import (
    FakeQueueDeviceAdapter,
    Harness,
    _make_router,
    _now,
    _seed_assignment,
    make_harness,
)

ADDRESS = "10.5.50.254"
OLD = timedelta(minutes=30)


@dataclass
class FakeSessionLiveness:
    live: set[uuid.UUID] = field(default_factory=set)
    asked: list[set[uuid.UUID]] = field(default_factory=list)

    async def live_session_ids(self, session_ids) -> set[uuid.UUID]:
        self.asked.append(set(session_ids))
        return {s for s in session_ids if s in self.live}


@dataclass
class FailingRemoveAdapter(FakeQueueDeviceAdapter):
    """Fails removals on request, to stand in for a router that is
    unreachable or that no longer holds the row."""

    remove_error: Exception | None = None
    remove_attempts: int = 0

    async def remove_queue(self, credentials, *, device_queue_id, **kwargs) -> None:
        self.remove_attempts += 1
        if self.remove_error is not None:
            raise self.remove_error
        await super().remove_queue(
            credentials, device_queue_id=device_queue_id, **kwargs
        )


def _harness(
    adapter: FakeQueueDeviceAdapter | None = None,
) -> tuple[Harness, FakeSessionLiveness]:
    h = make_harness(device_adapter=adapter)
    liveness = FakeSessionLiveness()
    h.service.session_liveness_lookup = liveness
    return h, liveness


async def _profile(h: Harness, kbps: int) -> QueueProfile:
    return await h.service.create_profile(
        actor_user_id=None,
        requesting_organization_id=None,
        name=f"System {kbps}k/{kbps}k",
        download_rate_kbps=kbps,
        upload_rate_kbps=kbps,
        is_system_profile=True,
    )


def _policy(h: Harness, router: Router, kbps: int) -> None:
    h.policy_lookup.rules_by_scope[(router.organization_id, router.location_id)] = {
        "download_rate_kbps": kbps,
        "upload_rate_kbps": kbps,
        "burst_download_kbps": None,
        "burst_upload_kbps": None,
        "burst_threshold_kbps": None,
        "burst_time_seconds": None,
        "priority": None,
    }


def _row(
    h: Harness,
    router: Router,
    profile: QueueProfile,
    *,
    session_id: uuid.UUID | None = None,
    address: str = ADDRESS,
    device_queue_id: str | None = "*1",
    status: str = QueueStatus.ACTIVE.value,
    age: timedelta = OLD,
) -> QueueAssignment:
    return _seed_assignment(
        h,
        router=router,
        target_id=session_id or uuid.uuid4(),
        device_target=address,
        queue_profile_id=profile.id,
        device_queue_id=device_queue_id,
        status=status,
        created_at=_now() - age,
    )


class TestReleaseQueuesForEndedSessions:
    async def test_an_ended_sessions_row_comes_off_the_router(self) -> None:
        h, liveness = _harness()
        router = h.router_lookup.add(_make_router())
        unlimited = await _profile(h, 0)
        ended = _row(h, router, unlimited, device_queue_id="*1")
        still_here = _row(
            h, router, unlimited, address="10.5.50.7", device_queue_id="*2"
        )
        liveness.live = {still_here.target_id}

        result = await h.service.release_queues_for_ended_sessions()

        assert result == {"released": 1, "failed": 0, "skipped_unreachable": 0}
        assert h.device_adapter.removed_ids == ["*1"]
        assert h.repository.assignments[ended.id].status == QueueStatus.EXPIRED.value
        assert h.repository.assignments[ended.id].device_queue_id is None
        kept = h.repository.assignments[still_here.id]
        assert kept.status == QueueStatus.ACTIVE.value
        assert kept.device_queue_id == "*2"

    async def test_it_asks_about_sessions_and_never_about_other_targets(self) -> None:
        """An admin's router- or guest-level assignment is an instruction,
        not a session's leftover; it is not this sweep's to judge."""
        h, liveness = _harness()
        router = h.router_lookup.add(_make_router())
        profile = await _profile(h, 20480)
        admin_row = _row(h, router, profile, device_queue_id="*9")
        admin_row.target_type = QueueTargetType.GUEST.value

        result = await h.service.release_queues_for_ended_sessions()

        assert result["released"] == 0
        assert liveness.asked == []
        assert h.device_adapter.removed_ids == []

    async def test_a_brand_new_assignment_is_not_judged(self) -> None:
        """The worker can create the assignment before the login request
        has committed the session row, so for a moment no live session has
        this id -- for a guest who is signing in right now."""
        h, liveness = _harness()
        router = h.router_lookup.add(_make_router())
        profile = await _profile(h, 20480)
        fresh = _row(h, router, profile, age=timedelta(seconds=20))

        result = await h.service.release_queues_for_ended_sessions()

        assert result["released"] == 0
        assert liveness.asked == []
        assert h.repository.assignments[fresh.id].status == QueueStatus.ACTIVE.value

    async def test_rows_that_never_reached_the_device_are_closed_without_a_call(
        self,
    ) -> None:
        h, _ = _harness()
        router = h.router_lookup.add(_make_router())
        profile = await _profile(h, 20480)
        pending = _row(
            h, router, profile, device_queue_id=None, status=QueueStatus.PENDING.value
        )

        result = await h.service.release_queues_for_ended_sessions()

        assert result["released"] == 1
        assert h.device_adapter.removed_ids == []
        assert h.repository.assignments[pending.id].status == QueueStatus.EXPIRED.value

    async def test_without_a_lookup_nothing_is_released(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        row = _row(h, router, await _profile(h, 0))

        result = await h.service.release_queues_for_ended_sessions()

        assert result == {"released": 0, "failed": 0, "skipped_unreachable": 0}
        assert h.repository.assignments[row.id].status == QueueStatus.ACTIVE.value

    async def test_an_unreachable_router_is_tried_once_and_left_as_it_was(
        self,
    ) -> None:
        adapter = FailingRemoveAdapter(
            remove_error=QueueDeviceConnectionError("router", "timed out")
        )
        h, _ = _harness(adapter)
        router = h.router_lookup.add(_make_router())
        profile = await _profile(h, 0)
        rows = [
            _row(h, router, profile, address=f"10.5.50.{n}", device_queue_id=f"*{n}")
            for n in (10, 11, 12)
        ]

        result = await h.service.release_queues_for_ended_sessions()

        assert result == {"released": 0, "failed": 1, "skipped_unreachable": 2}
        assert adapter.remove_attempts == 1
        for row in rows:
            stored = h.repository.assignments[row.id]
            assert stored.status == QueueStatus.ACTIVE.value
            assert stored.device_queue_id == row.device_queue_id

    async def test_one_routers_outage_does_not_stop_another_routers_release(
        self,
    ) -> None:
        @dataclass
        class DownForOneHost(FakeQueueDeviceAdapter):
            down_host: str = ""

            async def remove_queue(
                self, credentials, *, device_queue_id, **kwargs
            ) -> None:
                if credentials.host == self.down_host:
                    raise QueueDeviceConnectionError(credentials.host, "timed out")
                await super().remove_queue(
                    credentials, device_queue_id=device_queue_id, **kwargs
                )

        adapter = DownForOneHost(down_host="10.20.0.9")
        h, _ = _harness(adapter)
        down = _make_router()
        down.management_ip_address = "10.20.0.9"
        h.router_lookup.add(down)
        up = h.router_lookup.add(_make_router())
        profile = await _profile(h, 0)
        on_down = _row(h, down, profile, device_queue_id="*1", age=OLD * 2)
        on_up = _row(h, up, profile, device_queue_id="*5")

        result = await h.service.release_queues_for_ended_sessions()

        assert result == {"released": 1, "failed": 1, "skipped_unreachable": 0}
        assert adapter.removed_ids == ["*5"]
        assert h.repository.assignments[on_up.id].status == QueueStatus.EXPIRED.value
        assert h.repository.assignments[on_down.id].status == QueueStatus.ACTIVE.value

    async def test_a_row_the_router_no_longer_holds_is_released_cleanly(self) -> None:
        """Removed by hand, or lost with a reset. The router saying "no
        such item" is the end state, not a failure -- treated as one, the
        assignment would stay ACTIVE and be retried for ever."""
        adapter = FailingRemoveAdapter(
            remove_error=QueueDeviceOperationError("remove_queue", "no such item")
        )
        h, _ = _harness(adapter)
        router = h.router_lookup.add(_make_router())
        row = _row(h, router, await _profile(h, 0))

        result = await h.service.release_queues_for_ended_sessions()

        assert result == {"released": 1, "failed": 0, "skipped_unreachable": 0}
        assert h.repository.assignments[row.id].status == QueueStatus.EXPIRED.value

    async def test_any_other_device_refusal_is_still_a_failure(self) -> None:
        adapter = FailingRemoveAdapter(
            remove_error=QueueDeviceOperationError("remove_queue", "not permitted")
        )
        h, _ = _harness(adapter)
        router = h.router_lookup.add(_make_router())
        row = _row(h, router, await _profile(h, 0))

        result = await h.service.release_queues_for_ended_sessions()

        assert result == {"released": 0, "failed": 1, "skipped_unreachable": 0}
        assert h.repository.assignments[row.id].status == QueueStatus.ACTIVE.value


class TestTheObservedSequence:
    """Unlimited row from a session that ended, then the same device signs
    in again at 30 Mbps: one row for the address, and it is the new one."""

    async def test_release_then_sign_in_leaves_exactly_the_new_row(self) -> None:
        h, liveness = _harness()
        router = h.router_lookup.add(_make_router())
        stale = _row(h, router, await _profile(h, 0), device_queue_id="*old")

        await h.service.release_queues_for_ended_sessions()

        _policy(h, router, 30720)
        new_session = uuid.uuid4()
        liveness.live = {new_session}
        applied = await h.service.resolve_and_assign_queue(
            requesting_organization_id=router.organization_id,
            location_id=router.location_id,
            router_id=router.id,
            target_type=QueueTargetType.SESSION,
            target_id=new_session,
            device_target=ADDRESS,
        )

        assert h.device_adapter.removed_ids == ["*old"]
        assert h.repository.assignments[stale.id].status == QueueStatus.EXPIRED.value
        live_rows = [
            a
            for a in h.repository.assignments.values()
            if a.status == QueueStatus.ACTIVE.value and a.device_target == ADDRESS
        ]
        assert [a.id for a in live_rows] == [applied.id]
        assert h.device_adapter.created_calls[-1]["download_rate_kbps"] == 30720


class TestReapplyReachesLiveSessionsOnly:
    async def test_an_ended_session_is_not_given_a_new_queue(self) -> None:
        h, liveness = _harness()
        router = h.router_lookup.add(_make_router())
        ended = _row(h, router, await _profile(h, 0), device_queue_id="*1")
        _policy(h, router, 30720)

        result = await h.service.reapply_active_sessions_for_location(
            location_id=router.location_id,
            requesting_organization_id=router.organization_id,
        )

        assert result == {"reapplied": 0, "failed": 0}
        assert h.device_adapter.created_calls == []
        assert list(h.repository.assignments) == [ended.id]

    async def test_a_live_session_gets_the_new_rate(self) -> None:
        h, liveness = _harness()
        router = h.router_lookup.add(_make_router())
        online = _row(h, router, await _profile(h, 0), device_queue_id="*1")
        liveness.live = {online.target_id}
        _policy(h, router, 30720)

        result = await h.service.reapply_active_sessions_for_location(
            location_id=router.location_id,
            requesting_organization_id=router.organization_id,
        )

        assert result == {"reapplied": 1, "failed": 0}
        assert h.device_adapter.created_calls[-1]["target"] == ADDRESS
        assert h.device_adapter.created_calls[-1]["download_rate_kbps"] == 30720
        assert h.device_adapter.removed_ids == ["*1"]

    @pytest.mark.parametrize("seed_newest_first", [True, False])
    async def test_two_rows_on_one_address_the_newest_sign_in_keeps_it(
        self, seed_newest_first: bool
    ) -> None:
        """Legacy data: two live sessions' rows naming one address. Whatever
        order the repository lists them in, the survivor must belong to the
        most recent sign-in -- it used to be whichever was iterated last."""
        h, liveness = _harness()
        router = h.router_lookup.add(_make_router())
        unlimited = await _profile(h, 0)
        ages = [("new", timedelta(minutes=10)), ("old", timedelta(hours=3))]
        if not seed_newest_first:
            ages.reverse()
        rows = {
            name: _row(h, router, unlimited, device_queue_id=f"*{name}", age=age)
            for name, age in ages
        }
        liveness.live = {r.target_id for r in rows.values()}
        _policy(h, router, 30720)

        result = await h.service.reapply_active_sessions_for_location(
            location_id=router.location_id,
            requesting_organization_id=router.organization_id,
        )

        assert result == {"reapplied": 1, "failed": 0}
        live_rows = [
            a
            for a in h.repository.assignments.values()
            if a.status == QueueStatus.ACTIVE.value
        ]
        assert len(live_rows) == 1
        assert live_rows[0].target_id == rows["new"].target_id
        assert sorted(h.device_adapter.removed_ids) == ["*new", "*old"]
        assert len(h.device_adapter.created_calls) == 1

    async def test_without_a_lookup_every_active_row_is_reapplied_as_before(
        self,
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        _row(h, router, await _profile(h, 0), device_queue_id="*1")
        _policy(h, router, 30720)

        result = await h.service.reapply_active_sessions_for_location(
            location_id=router.location_id,
            requesting_organization_id=router.organization_id,
        )

        assert result == {"reapplied": 1, "failed": 0}


class TestMappingAPolicyToALocationAsksForAReapply:
    async def test_create_assignment_dispatches_the_reapply(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        dispatched: list[dict[str, object]] = []
        monkeypatch.setattr(
            queue_tasks.reapply_policy_assignments,
            "apply_async",
            lambda **kwargs: dispatched.append(kwargs),
        )
        policy_id = uuid.uuid4()
        location_id = uuid.uuid4()

        class _Service:
            async def create_assignment(self, **fields):
                return SimpleNamespace(
                    id=uuid.uuid4(),
                    policy_id=fields["policy_id"],
                    scope_type="location",
                    scope_id=fields["scope_id"],
                    priority=0,
                    target_type="none",
                    target_id=None,
                    is_active=True,
                    created_at=_now(),
                )

        await policy_router.create_policy_assignment(
            request=SimpleNamespace(state=SimpleNamespace(request_id="t")),
            policy_id=policy_id,
            payload=SimpleNamespace(
                scope_type="location",
                scope_id=location_id,
                priority=0,
                target_type="none",
                target_id=None,
            ),
            user=SimpleNamespace(id=str(uuid.uuid4())),
            requesting_organization_id=uuid.uuid4(),
            service=_Service(),
        )

        assert len(dispatched) == 1
        assert dispatched[0]["kwargs"]["policy_id"] == str(policy_id)
        # After the request's own commit, not racing it.
        assert dispatched[0]["countdown"] > 0

    async def test_a_broker_failure_does_not_fail_the_request(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _boom(**kwargs):
            raise RuntimeError("broker down")

        monkeypatch.setattr(
            queue_tasks.reapply_policy_assignments, "apply_async", _boom
        )

        policy_router._dispatch_bandwidth_reapply(uuid.uuid4())


class TestTheWiringIsReal:
    def test_the_release_sweep_is_registered_scheduled_and_routed(self) -> None:
        assert TASK_RELEASE_ENDED_SESSION_QUEUES in celery_app.tasks
        entries = [
            entry
            for entry in celery_app.conf.beat_schedule.values()
            if entry["task"] == TASK_RELEASE_ENDED_SESSION_QUEUES
        ]
        assert len(entries) == 1
        assert entries[0]["schedule"] == RELEASE_ENDED_SESSION_QUEUES_INTERVAL_SECONDS
        assert celery_app.conf.task_routes[TASK_RELEASE_ENDED_SESSION_QUEUES] == {
            "queue": DEVICE_IO_QUEUE_NAME
        }

    def test_the_liveness_query_selects_active_and_paused_sessions(self) -> None:
        """No database here, so the statement is compiled, not run: it must
        be a query on ``guest_sessions`` filtered by id, status and the
        soft-delete flag, binding exactly ``active`` and ``paused``."""
        ids = [uuid.uuid4(), uuid.uuid4()]
        compiled = queue_tasks.GuestSessionLiveness.statement(ids).compile()
        sql = str(compiled)

        assert "FROM guest_sessions" in sql
        assert "guest_sessions.status IN" in sql
        assert "guest_sessions.is_deleted IS false" in sql
        bound = [
            value
            for values in compiled.params.values()
            if isinstance(values, list)
            for value in values
        ]
        assert {"active", "paused"} <= set(bound)
        assert set(ids) <= set(bound)

    async def test_the_lookup_returns_what_the_query_returns(self) -> None:
        live = uuid.uuid4()

        class _Session:
            async def execute(self, statement):
                return SimpleNamespace(
                    scalars=lambda: SimpleNamespace(all=lambda: [live])
                )

        lookup = queue_tasks.GuestSessionLiveness(_Session())

        assert await lookup.live_session_ids([live, uuid.uuid4()]) == {live}
