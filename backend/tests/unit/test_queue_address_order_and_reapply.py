"""Three ways a venue's saved speed did not reach a guest who was online,
all observed on one live RouterOS venue in the same half hour.

* **The address was the guest's word.** A laptop holding one LAN address
  signed in through a portal URL left over from an earlier visit, carrying
  a different private address. The queue was written against the claimed
  one: the dashboard showed an active limit and the guest ran unshaped.
  The claim is a private address, so the LAN check did not catch it, and
  anyone can do it on purpose. The router is now asked, by MAC, what
  address the device has.
* **One save, three re-applies.** The venue's policy screen publishes
  several policies per save and each dispatched a re-apply for the same
  location within a second. One was aborted mid-run ("current transaction
  is aborted") and retried, and each recreated the same assignments.
  Re-apply is now single-flight per location and one assignment's failure
  is rolled back on its own.
* **The row was not first.** Covered in the gateway's own suite
  (``vendor/wyfy-device-gateway/tests/test_mikrotik_queue.py``): the
  platform's row is moved to the top of ``/queue simple`` after it is
  written.

In-memory fakes from ``test_queue_management`` throughout; nothing here
talks to a router or a database.
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from datetime import timedelta
from types import SimpleNamespace

import pytest

from app.domains.guest import tasks as guest_tasks
from app.domains.guest.service import GuestService
from app.domains.queue_management import tasks as queue_tasks
from app.domains.queue_management.constants import QueueStatus, QueueTargetType
from app.domains.queue_management.exceptions import (
    QueueDeviceConnectionError,
    QueueDeviceOperationError,
    QueueTargetNotLanAddressError,
    QueueTargetNotOnRouterError,
)
from tests.unit.test_queue_backfill_unassigned_sessions import (
    EMPTY,
    _rows_for,
    _savepoint,
    _session,
)
from tests.unit.test_queue_backfill_unassigned_sessions import (
    _harness as _backfill_harness,
)
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

MAC = "9C:69:D3:00:00:17"
HELD = "192.168.88.254"  # what the router has for the device
CLAIMED = "10.5.50.10"  # what the portal URL said
PUBLIC = "203.0.113.24"  # RFC 5737 -- never a real venue's address


async def _resolve(h: Harness, router, *, session_id, address, mac=None):
    return await h.service.resolve_and_assign_queue(
        requesting_organization_id=router.organization_id,
        location_id=router.location_id,
        router_id=router.id,
        target_type=QueueTargetType.SESSION,
        target_id=session_id,
        device_target=address,
        device_mac=mac,
    )


class TestTheRouterSaysWhatTheAddressIs:
    async def test_a_stale_claimed_address_is_replaced_by_the_routers(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        h.device_adapter.client_addresses[MAC] = HELD

        row = await _resolve(
            h, router, session_id=uuid.uuid4(), address=CLAIMED, mac=MAC
        )

        assert row.device_target == HELD
        assert row.status == QueueStatus.ACTIVE.value
        (call,) = h.device_adapter.created_calls
        assert call["target"] == HELD
        assert h.device_adapter.resolve_calls == [MAC]

    async def test_a_login_that_recorded_the_venues_public_address_still_gets_a_queue(
        self,
    ) -> None:
        """The refusal ``guest_queue_target_not_lan_address`` used to be the
        end of it. With the device's MAC the router supplies the address
        the login could not."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        h.device_adapter.client_addresses[MAC] = HELD

        for claimed in (PUBLIC, ""):
            row = await _resolve(
                h, router, session_id=uuid.uuid4(), address=claimed, mac=MAC
            )
            assert row.device_target == HELD

    async def test_a_device_the_router_has_never_seen_gets_no_queue(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())

        with caplog.at_level("WARNING"), pytest.raises(QueueTargetNotOnRouterError):
            await _resolve(h, router, session_id=uuid.uuid4(), address=CLAIMED, mac=MAC)

        assert h.repository.assignments == {}
        assert h.device_adapter.created_calls == []
        wanted = "queue_assignment_device_not_on_router"
        (record,) = [r for r in caplog.records if r.msg == wanted]
        assert record.speed_limit_applied is False
        assert CLAIMED not in caplog.text
        assert MAC not in caplog.text

    async def test_refusing_does_not_disturb_the_addresss_real_holder(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        holder = _seed_assignment(
            h,
            router=router,
            target_id=uuid.uuid4(),
            device_target=CLAIMED,
            queue_profile_id=(await _profile(h, 0)).id,
            device_queue_id="*4",
        )

        with pytest.raises(QueueTargetNotOnRouterError):
            await _resolve(h, router, session_id=uuid.uuid4(), address=CLAIMED, mac=MAC)

        assert holder.status == QueueStatus.ACTIVE.value
        assert h.device_adapter.removed_ids == []

    async def test_an_address_the_router_reports_is_still_checked(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        h.device_adapter.client_addresses[MAC] = PUBLIC

        with pytest.raises(QueueTargetNotLanAddressError):
            await _resolve(h, router, session_id=uuid.uuid4(), address=CLAIMED, mac=MAC)

        assert h.repository.assignments == {}

    async def test_the_routers_own_slash_32_spelling_is_the_same_address(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        h.device_adapter.client_addresses[MAC] = f"{HELD}/32"
        session_id = uuid.uuid4()

        first = await _resolve(h, router, session_id=session_id, address=HELD, mac=MAC)
        second = await _resolve(h, router, session_id=session_id, address=HELD, mac=MAC)

        assert first.device_target == HELD
        assert second.id == first.id
        assert len(h.device_adapter.created_calls) == 1

    async def test_without_a_mac_the_claimed_address_is_used_and_nothing_is_asked(
        self,
    ) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())

        row = await _resolve(h, router, session_id=uuid.uuid4(), address=CLAIMED)

        assert row.device_target == CLAIMED
        assert h.device_adapter.resolve_calls == []

    async def test_an_unreachable_router_fails_before_any_row_exists(self) -> None:
        class Down(FakeQueueDeviceAdapter):
            async def resolve_client_address(self, credentials, *, mac_address):
                raise QueueDeviceConnectionError(credentials.host, "timed out")

        h = make_harness(device_adapter=Down())
        router = h.router_lookup.add(_make_router())

        with pytest.raises(QueueDeviceConnectionError):
            await _resolve(h, router, session_id=uuid.uuid4(), address=CLAIMED, mac=MAC)

        assert h.repository.assignments == {}


class TestTheLoginHandsTheMacToTheWorker:
    def _service(self, mac: str | None):
        async def get_device_by_id(device_id):
            return SimpleNamespace(mac_address=mac) if mac else None

        dispatched: list[dict] = []

        async def dispatcher(**kwargs):
            dispatched.append(kwargs)

        service = SimpleNamespace(
            repository=SimpleNamespace(get_device_by_id=get_device_by_id),
            queue_assignment_dispatcher=dispatcher,
            queue_assignment_hook=None,
        )
        service._queue_device_target = lambda **kw: GuestService._queue_device_target(
            service, **kw
        )
        service._session_device_mac = lambda s: GuestService._session_device_mac(
            service, s
        )
        return service, dispatched

    async def _login(self, service, *, address, has_device=True, router=None):
        router = router or _make_router()
        session = SimpleNamespace(
            id=uuid.uuid4(),
            ip_address=address,
            device_id=uuid.uuid4() if has_device else None,
            guest_id=None,
        )
        await GuestService._assign_guest_queue(
            service,
            session=session,
            router=router,
            location_id=router.location_id,
            organization_id=router.organization_id,
        )
        return session

    async def test_the_mac_travels_with_the_claimed_address(self) -> None:
        service, dispatched = self._service(MAC)

        await self._login(service, address=CLAIMED)

        (sent,) = dispatched
        assert sent["device_target"] == CLAIMED
        assert sent["device_mac"] == MAC

    async def test_an_unusable_address_is_still_handed_on_when_the_device_is_known(
        self,
    ) -> None:
        service, dispatched = self._service(MAC)

        await self._login(service, address=PUBLIC)

        (sent,) = dispatched
        assert sent["device_target"] == ""
        assert sent["device_mac"] == MAC

    async def test_no_address_and_no_device_dispatches_nothing(self) -> None:
        service, dispatched = self._service(None)

        await self._login(service, address=PUBLIC, has_device=False)

        assert dispatched == []

    async def test_a_controller_venue_is_addressed_by_mac_as_before(self) -> None:
        from app.domains.router.vendor_capabilities import (
            CONTROLLER_MANAGED_VENDORS,
            NAS_ONLY_VENDORS,
        )

        service, dispatched = self._service(MAC)
        router = _make_router()
        router.vendor = sorted(CONTROLLER_MANAGED_VENDORS - NAS_ONLY_VENDORS)[0]

        await self._login(service, address=CLAIMED, router=router)

        (sent,) = dispatched
        assert sent["device_target"] == MAC
        assert sent["device_mac"] is None

    def test_a_device_not_on_the_router_is_not_retried(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The router answered; it has no entry for the device. Three
        retries thirty seconds apart would ask the same question and the
        backfill is what comes back for it."""
        router_id = uuid.uuid4()

        def _refuse(coroutine):
            coroutine.close()
            raise QueueTargetNotOnRouterError(router_id)

        monkeypatch.setattr(guest_tasks, "run_celery_task", _refuse)
        session_id = str(uuid.uuid4())

        result = guest_tasks.assign_guest_queue.run(
            organization_id=None,
            location_id=str(uuid.uuid4()),
            router_id=str(router_id),
            session_id=session_id,
            device_target=CLAIMED,
            device_mac=MAC,
        )

        assert result == {"session_id": session_id, "assigned": False}


class TestTheBackfillAsksTheRouterToo:
    async def test_it_targets_the_address_the_router_has(self) -> None:
        h, lookup, liveness = _backfill_harness()
        router = h.router_lookup.add(_make_router())
        h.device_adapter.client_addresses[MAC] = HELD
        session = _session(lookup, liveness, router, address=CLAIMED)
        lookup.sessions[0] = session = _with_mac(session)

        result = await h.service.backfill_queues_for_unassigned_sessions()

        assert result == {**EMPTY, "assigned": 1}
        (row,) = _rows_for(h, session)
        assert row.device_target == HELD
        # Asked once: the assignment itself is not asked a second time.
        assert h.device_adapter.resolve_calls == [MAC]

    async def test_a_device_the_router_does_not_have_is_left_for_the_next_run(
        self,
    ) -> None:
        h, lookup, liveness = _backfill_harness()
        router = h.router_lookup.add(_make_router())
        session = _with_mac(_session(lookup, liveness, router, address=CLAIMED))
        lookup.sessions[0] = session

        result = await h.service.backfill_queues_for_unassigned_sessions()

        assert result == {**EMPTY, "skipped_no_target": 1}
        assert _rows_for(h, session) == []
        assert h.device_adapter.created_calls == []

    async def test_a_router_that_does_not_answer_the_lookup_is_tried_once(self) -> None:
        class Down(FakeQueueDeviceAdapter):
            async def resolve_client_address(self, credentials, *, mac_address):
                self.resolve_calls.append(mac_address)
                raise QueueDeviceConnectionError(credentials.host, "timed out")

        h, lookup, liveness = _backfill_harness(Down())
        router = h.router_lookup.add(_make_router())
        for n in (10, 11, 12):
            _session(lookup, liveness, router, address=f"10.5.50.{n}")
        lookup.sessions[:] = [_with_mac(s) for s in lookup.sessions]

        result = await h.service.backfill_queues_for_unassigned_sessions(
            unit_of_work=_savepoint(h)
        )

        assert result == {**EMPTY, "failed": 1, "skipped_unreachable": 2}
        assert len(h.device_adapter.resolve_calls) == 1
        assert h.repository.assignments == {}

    async def test_the_address_guard_uses_the_resolved_address(self) -> None:
        """The claimed address is free; the one the device really holds
        already carries a live guest's queue."""
        h, lookup, liveness = _backfill_harness()
        router = h.router_lookup.add(_make_router())
        h.device_adapter.client_addresses[MAC] = HELD
        holder_id = uuid.uuid4()
        liveness.live.add(holder_id)
        holders = _seed_assignment(
            h,
            router=router,
            target_id=holder_id,
            device_target=HELD,
            queue_profile_id=(await _profile(h, 0)).id,
            device_queue_id="*4",
        )
        session = _with_mac(_session(lookup, liveness, router, address=CLAIMED))
        lookup.sessions[0] = session

        result = await h.service.backfill_queues_for_unassigned_sessions()

        assert result == {**EMPTY, "skipped_address_in_use": 1}
        assert holders.status == QueueStatus.ACTIVE.value
        assert _rows_for(h, session) == []


def _with_mac(session):
    from dataclasses import replace

    return replace(session, device_mac=MAC)


def _reapply_harness() -> tuple[Harness, FakeSessionLiveness]:
    h = make_harness()
    liveness = FakeSessionLiveness()
    h.service.session_liveness_lookup = liveness
    return h, liveness


async def _live_row(h: Harness, liveness, router, *, address: str, kbps: int):
    session_id = uuid.uuid4()
    liveness.live.add(session_id)
    return _seed_assignment(
        h,
        router=router,
        target_id=session_id,
        device_target=address,
        queue_profile_id=(
            await h.service._get_or_create_system_profile(
                download_rate_kbps=kbps, upload_rate_kbps=kbps
            )
        ).id,
        device_queue_id=f"*{address.rsplit('.', 1)[1]}",
        created_at=_now() - timedelta(minutes=30),
    )


class TestReapplyIsSingleFlightPerLocation:
    async def test_the_location_lock_is_taken_before_anything_is_read(self) -> None:
        h, _ = _reapply_harness()
        router = h.router_lookup.add(_make_router())
        order: list[str] = []
        lock = h.repository.acquire_location_reapply_lock
        listing = h.repository.list_assignments

        async def _lock(**kwargs):
            order.append("lock")
            await lock(**kwargs)

        async def _list(**kwargs):
            order.append("read")
            return await listing(**kwargs)

        h.repository.acquire_location_reapply_lock = _lock
        h.repository.list_assignments = _list

        await h.service.reapply_active_sessions_for_location(
            location_id=router.location_id,
            requesting_organization_id=router.organization_id,
        )

        assert order[:2] == ["lock", "read"]
        assert h.repository.location_reapply_locks == [router.location_id]

    async def test_a_second_reapply_of_the_same_publish_writes_nothing(self) -> None:
        """What the later two of the three tasks now find once the first
        has committed: every assignment already at the published rate."""
        h, liveness = _reapply_harness()
        router = h.router_lookup.add(_make_router())
        _policy(h, router, 20480)
        for n in (251, 252, 254):
            await _live_row(h, liveness, router, address=f"192.168.88.{n}", kbps=40960)

        first = await h.service.reapply_active_sessions_for_location(
            location_id=router.location_id,
            requesting_organization_id=router.organization_id,
        )
        rows_after_first = dict(h.repository.assignments)
        statuses = {k: v.status for k, v in rows_after_first.items()}
        created = len(h.device_adapter.created_calls)
        removed = list(h.device_adapter.removed_ids)

        second = await h.service.reapply_active_sessions_for_location(
            location_id=router.location_id,
            requesting_organization_id=router.organization_id,
        )

        assert first == {"reapplied": 3, "failed": 0}
        assert created == 3
        assert second == {"reapplied": 3, "failed": 0}
        assert h.repository.assignments.keys() == rows_after_first.keys()
        assert {k: v.status for k, v in h.repository.assignments.items()} == statuses
        assert len(h.device_adapter.created_calls) == created
        assert h.device_adapter.removed_ids == removed
        assert h.device_adapter.updated_calls == []

    async def test_one_assignments_failure_is_rolled_back_and_the_rest_go_on(
        self,
    ) -> None:
        class FailsForOne(FakeQueueDeviceAdapter):
            async def create_simple_queue(self, credentials, **kwargs) -> str:
                if kwargs["target"] == "192.168.88.252":
                    raise QueueDeviceOperationError("create_simple_queue", "boom")
                return await super().create_simple_queue(credentials, **kwargs)

        h = make_harness(device_adapter=FailsForOne())
        liveness = FakeSessionLiveness()
        h.service.session_liveness_lookup = liveness
        router = h.router_lookup.add(_make_router())
        _policy(h, router, 20480)
        rows = {
            n: await _live_row(
                h, liveness, router, address=f"192.168.88.{n}", kbps=40960
            )
            for n in (251, 252, 254)
        }
        entered: list[int] = []
        inner = _savepoint(h)

        @asynccontextmanager
        async def unit_of_work():
            entered.append(1)
            async with inner():
                yield

        result = await h.service.reapply_active_sessions_for_location(
            location_id=router.location_id,
            requesting_organization_id=router.organization_id,
            unit_of_work=unit_of_work,
        )

        assert result == {"reapplied": 2, "failed": 1}
        assert len(entered) == 3
        # The failed one is exactly as it was: no half-made replacement row.
        failed = rows[252]
        assert failed.status == QueueStatus.ACTIVE.value
        live_for_failed = [
            a
            for a in h.repository.assignments.values()
            if a.target_id == failed.target_id and a.status != QueueStatus.EXPIRED.value
        ]
        assert live_for_failed == [failed]
        for n in (251, 254):
            assert rows[n].status == QueueStatus.EXPIRED.value

    def test_the_real_lock_is_a_transaction_scoped_advisory_lock(self) -> None:
        import inspect

        from app.domains.queue_management.repository import QueueManagementRepository

        source = inspect.getsource(
            QueueManagementRepository.acquire_location_reapply_lock
        )
        assert "_acquire_advisory_lock" in source
        assert 'b"queue_reapply_location"' in source

    def test_the_task_reapplies_locations_in_one_order_inside_savepoints(self) -> None:
        import inspect

        source = inspect.getsource(queue_tasks._reapply_policy_assignments_async)
        assert "sorted(location_ids, key=str)" in source
        assert "unit_of_work=session.begin_nested" in source


MAC_B = "F2:A8:84:00:00:D7"


def _moved_harness():
    h, lookup, liveness = _backfill_harness()
    router = h.router_lookup.add(_make_router())
    return h, lookup, router


async def _applied_row(h, lookup, router, *, address, queue_id, mac=MAC):
    session_id = uuid.uuid4()
    if mac is not None:
        lookup.macs[session_id] = mac
    return _seed_assignment(
        h,
        router=router,
        target_id=session_id,
        device_target=address,
        queue_profile_id=(await _profile(h, 20480)).id,
        device_queue_id=queue_id,
        created_at=_now() - timedelta(minutes=12),
    )


RETARGET_EMPTY = {
    "retargeted": 0,
    "failed": 0,
    "skipped_unreachable": 0,
    "skipped_absent": 0,
    "skipped_address_in_use": 0,
    "unchanged": 0,
}


class TestAQueueFollowsItsDeviceToANewAddress:
    """Observed live: a device signed in on ``.254`` and got its queue
    there; twelve minutes later the router had the same MAC on ``.253``
    carrying the traffic, and the queue on ``.254`` idle."""

    async def test_a_changed_address_is_retargeted_once_and_then_left_alone(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        h, lookup, router = _moved_harness()
        row = await _applied_row(
            h, lookup, router, address="10.5.50.254", queue_id="*5"
        )
        h.device_adapter.client_addresses[MAC] = "10.5.50.253"

        with caplog.at_level("INFO"):
            first = await h.service.retarget_queues_for_moved_devices()
        second = await h.service.retarget_queues_for_moved_devices()

        assert first == {**RETARGET_EMPTY, "retargeted": 1}
        assert second == {**RETARGET_EMPTY, "unchanged": 1}
        assert h.device_adapter.retarget_calls == [("*5", "10.5.50.253")]
        assert row.device_target == "10.5.50.253"
        assert row.device_queue_id == "*5"
        assert row.status == QueueStatus.ACTIVE.value
        # Never a second row, never a new device row, never a removal.
        assert list(h.repository.assignments) == [row.id]
        assert h.device_adapter.created_calls == []
        assert h.device_adapter.removed_ids == []
        (event,) = [r for r in caplog.records if r.msg == "queue_assignment_retargeted"]
        assert event.old_address == "10.5.50.254"
        assert event.new_address == "10.5.50.253"

    async def test_an_unchanged_address_is_not_written(self) -> None:
        h, lookup, router = _moved_harness()
        row = await _applied_row(
            h, lookup, router, address="10.5.50.254", queue_id="*5"
        )
        h.device_adapter.client_addresses[MAC.lower().replace(":", "-")] = "ignored"
        h.device_adapter.client_addresses[MAC] = "10.5.50.254/32"

        result = await h.service.retarget_queues_for_moved_devices()

        assert result == {**RETARGET_EMPTY, "unchanged": 1}
        assert h.device_adapter.retarget_calls == []
        assert row.device_target == "10.5.50.254"

    async def test_a_device_the_router_no_longer_has_is_untouched(self) -> None:
        h, lookup, router = _moved_harness()
        row = await _applied_row(
            h, lookup, router, address="10.5.50.254", queue_id="*5"
        )

        result = await h.service.retarget_queues_for_moved_devices()

        assert result == {**RETARGET_EMPTY, "skipped_absent": 1}
        assert h.device_adapter.retarget_calls == []
        assert row.device_target == "10.5.50.254"
        assert row.status == QueueStatus.ACTIVE.value

    async def test_two_devices_that_swapped_addresses_keep_their_own_queues(
        self,
    ) -> None:
        h, lookup, router = _moved_harness()
        a = await _applied_row(h, lookup, router, address="10.5.50.10", queue_id="*1")
        b = await _applied_row(
            h, lookup, router, address="10.5.50.11", queue_id="*2", mac=MAC_B
        )
        h.device_adapter.client_addresses[MAC] = "10.5.50.11"
        h.device_adapter.client_addresses[MAC_B] = "10.5.50.10"

        result = await h.service.retarget_queues_for_moved_devices()

        assert result == {**RETARGET_EMPTY, "retargeted": 2}
        assert sorted(h.device_adapter.retarget_calls) == [
            ("*1", "10.5.50.11"),
            ("*2", "10.5.50.10"),
        ]
        assert (a.device_target, a.device_queue_id) == ("10.5.50.11", "*1")
        assert (b.device_target, b.device_queue_id) == ("10.5.50.10", "*2")
        assert len(h.repository.assignments) == 2
        assert h.device_adapter.removed_ids == []

    async def test_an_address_another_row_still_holds_is_not_taken(self) -> None:
        h, lookup, router = _moved_harness()
        mover = await _applied_row(
            h, lookup, router, address="10.5.50.10", queue_id="*1"
        )
        holder = await _applied_row(
            h, lookup, router, address="10.5.50.11", queue_id="*2", mac=MAC_B
        )
        unknown = await _applied_row(
            h, lookup, router, address="10.5.50.12", queue_id="*3", mac=None
        )
        h.device_adapter.client_addresses[MAC_B] = "10.5.50.11"

        for wanted in ("10.5.50.11", "10.5.50.12"):
            h.device_adapter.client_addresses[MAC] = wanted
            result = await h.service.retarget_queues_for_moved_devices()
            assert result == {
                **RETARGET_EMPTY,
                "skipped_address_in_use": 1,
                "unchanged": 1,
            }

        assert h.device_adapter.retarget_calls == []
        assert mover.device_target == "10.5.50.10"
        assert holder.device_target == "10.5.50.11"
        assert unknown.device_target == "10.5.50.12"

    async def test_the_router_is_read_once_however_many_sessions_it_has(self) -> None:
        h, lookup, router = _moved_harness()
        for n in range(6):
            mac = f"AA:BB:CC:00:00:{n:02X}"
            await _applied_row(
                h,
                lookup,
                router,
                address=f"10.5.50.{20 + n}",
                queue_id=f"*{n}",
                mac=mac,
            )
            h.device_adapter.client_addresses[mac] = f"10.5.50.{40 + n}"

        result = await h.service.retarget_queues_for_moved_devices(max_per_run=4)

        assert h.device_adapter.list_address_calls == 1
        assert result == {**RETARGET_EMPTY, "retargeted": 4}
        assert len(h.device_adapter.retarget_calls) == 4

    async def test_a_router_that_cannot_be_read_is_skipped_whole(self) -> None:
        class Down(FakeQueueDeviceAdapter):
            async def list_client_addresses(self, credentials):
                self.list_address_calls += 1
                raise QueueDeviceConnectionError(credentials.host, "timed out")

        h, lookup, _ = _backfill_harness(Down())
        router = h.router_lookup.add(_make_router())
        rows = [
            await _applied_row(
                h,
                lookup,
                router,
                address=f"10.5.50.{n}",
                queue_id=f"*{n}",
                mac=f"AA:BB:CC:00:00:{n:02X}",
            )
            for n in (10, 11)
        ]

        result = await h.service.retarget_queues_for_moved_devices()

        assert result == {**RETARGET_EMPTY, "skipped_unreachable": 2}
        assert h.device_adapter.list_address_calls == 1
        assert [r.device_target for r in rows] == ["10.5.50.10", "10.5.50.11"]

    async def test_a_failed_device_write_leaves_the_record_as_it_was(self) -> None:
        class Refuses(FakeQueueDeviceAdapter):
            async def retarget_simple_queue(
                self, credentials, *, device_queue_id, target
            ) -> None:
                raise QueueDeviceOperationError("retarget_simple_queue", "no such item")

        h, lookup, _ = _backfill_harness(Refuses())
        router = h.router_lookup.add(_make_router())
        row = await _applied_row(
            h, lookup, router, address="10.5.50.254", queue_id="*5"
        )
        h.device_adapter.client_addresses[MAC] = "10.5.50.253"

        result = await h.service.retarget_queues_for_moved_devices(
            unit_of_work=_savepoint(h)
        )

        assert result == {**RETARGET_EMPTY, "failed": 1}
        assert row.device_target == "10.5.50.254"

    async def test_it_holds_the_locations_reapply_lock_and_respects_the_allow_list(
        self,
    ) -> None:
        h, lookup, router = _moved_harness()
        other = h.router_lookup.add(_make_router())
        await _applied_row(h, lookup, router, address="10.5.50.254", queue_id="*5")
        elsewhere = await _applied_row(
            h, lookup, other, address="10.5.50.254", queue_id="*6", mac=MAC_B
        )
        h.device_adapter.client_addresses[MAC] = "10.5.50.253"
        h.device_adapter.client_addresses[MAC_B] = "10.5.50.252"

        result = await h.service.retarget_queues_for_moved_devices(
            router_allowed=lambda router_id: router_id == router.id
        )

        assert result == {**RETARGET_EMPTY, "retargeted": 1}
        assert h.repository.location_reapply_locks == [router.location_id]
        assert elsewhere.device_target == "10.5.50.254"

    async def test_a_controller_run_venue_is_not_read(self) -> None:
        from app.domains.router.vendor_capabilities import CONTROLLER_MANAGED_VENDORS

        h, lookup, _ = _backfill_harness()
        router = _make_router()
        router.vendor = sorted(CONTROLLER_MANAGED_VENDORS)[0]
        h.router_lookup.add(router)
        await _applied_row(h, lookup, router, address=MAC, queue_id="x")

        result = await h.service.retarget_queues_for_moved_devices()

        assert result == RETARGET_EMPTY
        assert h.device_adapter.list_address_calls == 0

    def test_the_mac_query_reads_active_sessions_with_a_device(self) -> None:
        ids = [uuid.uuid4()]
        compiled = queue_tasks.GuestSessionsWithoutQueue.device_macs_statement(
            ids
        ).compile()
        sql = " ".join(str(compiled).split())

        assert "SELECT guest_sessions.id, guest_devices.mac_address" in sql
        assert (
            "FROM guest_sessions JOIN guest_devices "
            "ON guest_devices.id = guest_sessions.device_id" in sql
        )
        assert "guest_sessions.is_deleted IS false" in sql
        assert "active" in compiled.params.values()

    def test_the_sweep_runs_it_after_the_backfill_under_the_same_switch(self) -> None:
        import inspect

        source = inspect.getsource(
            queue_tasks._backfill_unassigned_session_queues_async
        )
        assert source.index("backfill_queues_for_unassigned_sessions") < source.index(
            "retarget_queues_for_moved_devices"
        )
        assert source.index("_queue_backfill_is_on_anywhere") < source.index(
            "SessionLocal()"
        )
