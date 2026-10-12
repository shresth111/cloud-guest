"""A venue's total speed: what all of its guests share.

Every guest already has a ``/queue simple`` row of their own. The venue's
total is a row above those -- one parent per router, targeting the guest
subnet, with each guest's row as its child -- and it is stated in the
venue's bandwidth policy as ``venue_download_rate_kbps`` /
``venue_upload_rate_kbps``.

What is pinned here:

* the two keys are validated, persisted and read back through the request
  schema the Guest WiFi Limits screen actually posts;
* a policy that states a total puts one parent on each router and every
  guest row under it, once, and a second run writes nothing;
* a changed total is one update; a removed total returns the guests' rows
  to the top level *before* the parent is removed;
* a router that reports no guest subnet gets nothing written and the guests
  keep their own limits;
* a router that does not answer never stops another, and never stops the
  guests' own re-apply;
* a sign-in under an existing total creates the guest's row under it, and a
  session ending leaves the parent where it is;
* the RADIUS reply carries no rate limit while a total is in force, so the
  hotspot does not put a row above the parent;
* a venue without a total is called exactly as it always was.

In-memory fakes from ``test_queue_management`` throughout. The fake device
keeps a list of rows and does what it is told; what a real RouterOS does
with ``parent`` is in the pull request's hardware plan, not here.
"""

from __future__ import annotations

import inspect
import uuid
from dataclasses import dataclass, field
from types import SimpleNamespace

import pytest

from app.domains.network_integration.schemas import (
    ClientCapabilitiesResponse,
    ClientCapabilityView,
)
from app.domains.policy.constants import PolicyType
from app.domains.policy.exceptions import PolicyRulesValidationError
from app.domains.policy.router import _version_response
from app.domains.policy.schemas import (
    PolicyVersionCreateRequest,
    with_venue_rate_keys,
)
from app.domains.policy.validators import validate_rules
from app.domains.queue_management import router as queue_router
from app.domains.queue_management import tasks as queue_tasks
from app.domains.queue_management.constants import (
    VENUE_QUEUE_COMMENT,
    QueueStatus,
    QueueTargetType,
)
from app.domains.queue_management.device_adapters import (
    MikroTikQueueAdapter,
    QueueCredentials,
    VenueQueueState,
)
from app.domains.queue_management.exceptions import (
    QueueDeviceConnectionError,
    QueueDeviceOperationError,
    QueueTargetTypeNotEnforcedError,
)
from app.domains.queue_management.schemas import QueueAssignmentCreateRequest
from app.domains.queue_management.service import (
    VenueCap,
    venue_cap_from_rules,
    venue_queue_name,
)
from tests.unit.test_policy import _build_service as _policy_service
from tests.unit.test_queue_management import (
    FakeQueueDeviceAdapter,
    Harness,
    _make_router,
    _seed_assignment,
    make_harness,
)
from tests.unit.test_queue_release_on_session_end import (
    FakeSessionLiveness,
    _profile,
)


@pytest.fixture(autouse=True)
def _info_logging_on(caplog: pytest.LogCaptureFixture) -> None:
    """Every test here runs with INFO records actually built, as they are in
    the worker. Run on its own this module had INFO off, so an ``extra`` key
    that collides with a ``LogRecord`` attribute (``created``) raised only in
    the full suite -- and would have raised on every venue-cap write in
    production."""
    caplog.set_level("INFO", logger="app.domains.queue_management.service")


GUEST_NET = "192.168.88.0/24"
PER_GUEST = 40960
TOTAL_DOWN = 81920
TOTAL_UP = 61440


@dataclass
class VenueDevice(FakeQueueDeviceAdapter):
    """A router that can hold a venue's parent row.

    ``rows`` is its ``/queue simple`` list, by id; ``ops`` is every write
    in the order it was made, which is what the ordering rules are asserted
    against. ``networks`` is what it reports for its hotspot interface --
    empty for a router that reports none."""

    networks: tuple[str, ...] = (GUEST_NET,)
    rows: dict[str, dict[str, object]] = field(default_factory=dict)
    ops: list[tuple] = field(default_factory=list)
    sync_calls: list[dict[str, object]] = field(default_factory=list)
    clear_calls: list[str] = field(default_factory=list)
    venue_error: Exception | None = None

    async def create_simple_queue(self, credentials, **kwargs) -> str:
        device_id = await super().create_simple_queue(credentials, **kwargs)
        self.rows[device_id] = {
            "name": kwargs["name"],
            "target": kwargs["target"],
            "parent": kwargs.get("parent") or "none",
        }
        self.ops.append(("create", kwargs["name"], kwargs.get("parent")))
        return device_id

    async def remove_queue(self, credentials, *, device_queue_id, **kwargs) -> None:
        await super().remove_queue(
            credentials, device_queue_id=device_queue_id, **kwargs
        )
        self.rows.pop(device_queue_id, None)
        self.ops.append(("remove", device_queue_id))

    def _parent_id(self, name: str) -> str | None:
        return next((i for i, r in self.rows.items() if r["name"] == name), None)

    async def sync_venue_queue(
        self,
        credentials,
        *,
        name,
        download_rate_kbps,
        upload_rate_kbps,
        child_queue_ids=(),
    ) -> VenueQueueState:
        self.sync_calls.append(
            {
                "name": name,
                "download_rate_kbps": download_rate_kbps,
                "upload_rate_kbps": upload_rate_kbps,
                "child_queue_ids": tuple(child_queue_ids),
            }
        )
        if self.venue_error is not None:
            raise self.venue_error
        if not self.networks:
            return VenueQueueState(
                name=name, in_sync=False, problems=("guest_subnet_unresolved",)
            )
        wanted = {
            "name": name,
            "target": ",".join(self.networks),
            "rates": (download_rate_kbps, upload_rate_kbps),
            "parent": "none",
        }
        parent_id = self._parent_id(name)
        created = updated = False
        if parent_id is None:
            parent_id = f"*V{len(self.sync_calls)}"
            self.rows[parent_id] = wanted
            self.ops.append(("venue_create", name, wanted["rates"]))
            created = True
        elif self.rows[parent_id] != wanted:
            self.rows[parent_id] = wanted
            self.ops.append(("venue_update", name, wanted["rates"]))
            updated = True
        reparented = 0
        for child_id in child_queue_ids:
            row = self.rows.get(child_id)
            if row is not None and row["parent"] != name:
                row["parent"] = name
                self.ops.append(("reparent", child_id, name))
                reparented += 1
        return VenueQueueState(
            name=name,
            device_queue_id=parent_id,
            targets=self.networks,
            created=created,
            updated=updated,
            reparented=reparented,
            wrote=created or updated or bool(reparented),
        )

    async def clear_venue_queue(self, credentials, *, name) -> VenueQueueState:
        self.clear_calls.append(name)
        if self.venue_error is not None:
            raise self.venue_error
        unparented = 0
        for child_id, row in self.rows.items():
            if row["parent"] == name:
                row["parent"] = "none"
                self.ops.append(("unparent", child_id))
                unparented += 1
        parent_id = self._parent_id(name)
        removed = parent_id is not None
        if removed:
            del self.rows[parent_id]
            self.ops.append(("venue_remove", name))
        return VenueQueueState(
            name=name,
            reparented=unparented,
            removed=removed,
            wrote=removed or bool(unparented),
        )

    def writes(self) -> list[tuple]:
        return list(self.ops)


def _rules(*, total_down=TOTAL_DOWN, total_up=TOTAL_UP, per_guest=PER_GUEST) -> dict:
    return {
        "download_rate_kbps": per_guest,
        "upload_rate_kbps": per_guest,
        "venue_download_rate_kbps": total_down,
        "venue_upload_rate_kbps": total_up,
    }


def _set_policy(h: Harness, router, **kwargs) -> None:
    h.policy_lookup.rules_by_scope[(router.organization_id, router.location_id)] = (
        _rules(**kwargs)
    )


def _can_list_routers(h: Harness) -> None:
    """Gives the fake router lookup the one extra thing the real
    ``RouterService`` has that a venue cap uses: listing a location's
    routers. A venue's parent row has to exist with nobody online, and
    with nobody online there is no guest row to learn the router from."""

    async def list_routers(*, location_id, requesting_organization_id, **kwargs):
        rows = [
            router
            for router in h.router_lookup.routers.values()
            if router.location_id == location_id
        ]
        return rows, None

    h.router_lookup.list_routers = list_routers


def _venue() -> tuple[Harness, VenueDevice, object]:
    device = VenueDevice()
    h = make_harness(device_adapter=device)
    _can_list_routers(h)
    router = h.router_lookup.add(_make_router())
    return h, device, router


async def _sign_in(h: Harness, router, *, address: str, session_id=None):
    return await h.service.resolve_and_assign_queue(
        requesting_organization_id=router.organization_id,
        location_id=router.location_id,
        router_id=router.id,
        target_type=QueueTargetType.SESSION,
        target_id=session_id or uuid.uuid4(),
        device_target=address,
    )


async def _sync(h: Harness, router, **kwargs) -> dict[str, int]:
    return await h.service.sync_venue_cap_for_location(
        location_id=router.location_id,
        requesting_organization_id=router.organization_id,
        **kwargs,
    )


# ============================================================================
# The two keys: validation, persistence, read-back
# ============================================================================


class TestTheTwoKeys:
    def test_they_survive_the_request_schema_the_screen_posts(self) -> None:
        """The body ``POST /policies/{id}/versions`` receives, parsed by the
        model that route declares, then by the validator the service calls
        -- not a dict built by hand in the shape this test hopes for."""
        body = {"rules": _rules()}

        request = PolicyVersionCreateRequest.model_validate(body)
        stored = validate_rules(PolicyType.BANDWIDTH, request.rules)

        assert stored["venue_download_rate_kbps"] == TOTAL_DOWN
        assert stored["venue_upload_rate_kbps"] == TOTAL_UP

    async def test_they_are_stored_on_the_version_and_come_back_in_its_response(
        self,
    ) -> None:
        service, repo, _, _ = _policy_service()
        policy = await service.create_policy(
            actor_user_id=None,
            requesting_organization_id=None,
            organization_id=None,
            policy_type=PolicyType.BANDWIDTH,
            name="Venue",
            description=None,
        )
        request = PolicyVersionCreateRequest.model_validate({"rules": _rules()})

        version = await service.create_version(
            policy_id=policy.id,
            requesting_organization_id=None,
            actor_user_id=None,
            rules=request.rules,
        )

        assert repo.versions[version.id].rules["venue_download_rate_kbps"] == TOTAL_DOWN
        assert repo.versions[version.id].rules["venue_upload_rate_kbps"] == TOTAL_UP
        response = _version_response(version).model_dump()
        assert response["rules"]["venue_download_rate_kbps"] == TOTAL_DOWN
        assert response["rules"]["venue_upload_rate_kbps"] == TOTAL_UP

    def test_unset_is_null_and_each_direction_stands_alone(self) -> None:
        plain = validate_rules(
            PolicyType.BANDWIDTH,
            {"download_rate_kbps": PER_GUEST, "upload_rate_kbps": PER_GUEST},
        )
        assert plain["venue_download_rate_kbps"] is None
        assert plain["venue_upload_rate_kbps"] is None

        one = validate_rules(PolicyType.BANDWIDTH, _rules(total_up=None))
        assert one["venue_download_rate_kbps"] == TOTAL_DOWN
        assert one["venue_upload_rate_kbps"] is None

    def test_a_version_saved_before_the_keys_existed_reads_back_with_them_null(
        self,
    ) -> None:
        old = {"download_rate_kbps": PER_GUEST, "upload_rate_kbps": PER_GUEST}

        assert with_venue_rate_keys(old) == {
            **old,
            "venue_download_rate_kbps": None,
            "venue_upload_rate_kbps": None,
        }
        # ...and the stored dict is not the thing that was changed.
        assert "venue_download_rate_kbps" not in old

    def test_another_policy_types_rules_are_not_given_the_keys(self) -> None:
        session_rules = {"session_timeout_minutes": 60}
        assert with_venue_rate_keys(session_rules) is session_rules

    @pytest.mark.parametrize(
        ("field_name", "value"),
        [
            ("venue_download_rate_kbps", 1023),
            ("venue_upload_rate_kbps", 0),
            ("venue_download_rate_kbps", 10_000_001),
            ("venue_upload_rate_kbps", -5),
        ],
    )
    def test_a_total_outside_the_range_is_refused_naming_the_field(
        self, field_name: str, value: int
    ) -> None:
        rules = {**_rules(), field_name: value}
        with pytest.raises(PolicyRulesValidationError) as refused:
            validate_rules(PolicyType.BANDWIDTH, rules)
        assert field_name in str(refused.value)

    def test_the_bounds_themselves_are_accepted(self) -> None:
        low = validate_rules(
            PolicyType.BANDWIDTH,
            _rules(total_down=1024, total_up=1024, per_guest=512),
        )
        high = validate_rules(
            PolicyType.BANDWIDTH, _rules(total_down=10_000_000, total_up=10_000_000)
        )
        assert low["venue_download_rate_kbps"] == 1024
        assert high["venue_upload_rate_kbps"] == 10_000_000

    @pytest.mark.parametrize(
        ("field_name", "direction"),
        [
            ("venue_download_rate_kbps", "download"),
            ("venue_upload_rate_kbps", "upload"),
        ],
    )
    def test_a_total_below_one_guests_rate_is_refused_naming_the_field(
        self, field_name: str, direction: str
    ) -> None:
        rules = {**_rules(), field_name: PER_GUEST - 1}
        with pytest.raises(PolicyRulesValidationError) as refused:
            validate_rules(PolicyType.BANDWIDTH, rules)
        message = str(refused.value)
        assert field_name in message
        assert f"total {direction} speed" in message
        assert refused.value.status_code == 400
        # ...and once more as data, for a form to put beside the input.
        (entry,) = refused.value.data["field_errors"]
        assert entry["field"] == field_name
        assert entry["message"].startswith(f"the venue's total {direction} speed")

    def test_a_total_equal_to_one_guests_rate_is_allowed(self) -> None:
        stored = validate_rules(
            PolicyType.BANDWIDTH, _rules(total_down=PER_GUEST, total_up=PER_GUEST)
        )
        assert stored["venue_download_rate_kbps"] == PER_GUEST

    def test_an_unlimited_guest_rate_is_not_compared(self) -> None:
        """``0`` is this codebase's "unlimited" for one guest. A venue may
        cap the total and leave each guest unlimited within it."""
        stored = validate_rules(
            PolicyType.BANDWIDTH, _rules(total_down=2048, total_up=2048, per_guest=0)
        )
        assert stored["venue_download_rate_kbps"] == 2048

    def test_a_misspelt_key_is_refused_not_dropped(self) -> None:
        with pytest.raises(PolicyRulesValidationError):
            validate_rules(
                PolicyType.BANDWIDTH, {**_rules(), "venue_download_kbps": 81920}
            )

    @pytest.mark.parametrize(
        ("rules", "expected"),
        [
            (None, None),
            ({}, None),
            ({"download_rate_kbps": 1, "upload_rate_kbps": 1}, None),
            (_rules(total_down=None, total_up=None), None),
            (_rules(), VenueCap(TOTAL_DOWN, TOTAL_UP)),
            (_rules(total_up=None), VenueCap(TOTAL_DOWN, None)),
            ({"venue_download_rate_kbps": "81920"}, None),
            ({"venue_download_rate_kbps": True}, None),
            ({"venue_upload_rate_kbps": 0}, None),
        ],
    )
    def test_reading_a_cap_out_of_rules(self, rules, expected) -> None:
        assert venue_cap_from_rules(rules) == expected


# ============================================================================
# A total is stated: one parent, the guests' rows under it
# ============================================================================


class TestATotalIsStated:
    async def test_one_parent_is_created_and_every_guest_row_goes_under_it(
        self,
    ) -> None:
        h, device, router = _venue()
        a = await _sign_in(h, router, address="192.168.88.254")
        b = await _sign_in(h, router, address="192.168.88.249")
        _set_policy(h, router)

        result = await _sync(h, router)

        name = venue_queue_name(router.location_id)
        assert name == f"cloudguest-venue-{str(router.location_id)[:8]}"
        parents = [r for r in device.rows.values() if r["name"] == name]
        assert len(parents) == 1
        assert parents[0]["target"] == GUEST_NET
        assert parents[0]["rates"] == (TOTAL_DOWN, TOTAL_UP)
        assert device.rows[a.device_queue_id]["parent"] == name
        assert device.rows[b.device_queue_id]["parent"] == name
        assert result == {
            "routers": 1,
            "synced": 1,
            "cleared": 0,
            "wrote": 1,
            "failed": 0,
            "skipped": 0,
        }

    async def test_a_second_run_writes_nothing(self) -> None:
        h, device, router = _venue()
        await _sign_in(h, router, address="192.168.88.254")
        _set_policy(h, router)
        await _sync(h, router)
        before = device.writes()

        result = await _sync(h, router)

        assert device.writes() == before
        assert result["wrote"] == 0 and result["synced"] == 1

    async def test_a_changed_total_is_one_update_of_the_same_row(self) -> None:
        h, device, router = _venue()
        await _sign_in(h, router, address="192.168.88.254")
        _set_policy(h, router)
        await _sync(h, router)
        name = venue_queue_name(router.location_id)
        parent_id = device._parent_id(name)
        device.ops.clear()

        _set_policy(h, router, total_down=102400)
        await _sync(h, router)

        assert device.writes() == [("venue_update", name, (102400, TOTAL_UP))]
        assert device._parent_id(name) == parent_id

    async def test_the_parent_exists_even_when_nobody_is_online(self) -> None:
        """A bypassed or trusted device has no row of its own. The parent is
        what holds it, so the parent cannot wait for a guest to sign in."""
        h, device, router = _venue()
        _set_policy(h, router)

        result = await _sync(h, router)

        assert device._parent_id(venue_queue_name(router.location_id)) is not None
        assert device.sync_calls[-1]["child_queue_ids"] == ()
        assert result["wrote"] == 1

    async def test_one_direction_alone_is_passed_through_as_it_is(self) -> None:
        h, device, router = _venue()
        _set_policy(h, router, total_up=None)

        await _sync(h, router)

        assert device.sync_calls[-1]["download_rate_kbps"] == TOTAL_DOWN
        assert device.sync_calls[-1]["upload_rate_kbps"] is None

    async def test_a_guests_group_does_not_set_what_everybody_shares(self) -> None:
        """A guest mapped to a group gets that group's own rate. The
        venue's total is the location's, whoever is asking."""
        h, device, router = _venue()
        _set_policy(h, router)
        guest_id = uuid.uuid4()
        h.policy_lookup.rules_by_guest[guest_id] = _rules(
            total_down=999_999, total_up=999_999, per_guest=20480
        )

        await h.service.resolve_and_assign_queue(
            requesting_organization_id=router.organization_id,
            location_id=router.location_id,
            router_id=router.id,
            target_type=QueueTargetType.SESSION,
            target_id=uuid.uuid4(),
            device_target="192.168.88.254",
            guest_id=guest_id,
        )

        assert device.sync_calls[-1]["download_rate_kbps"] == TOTAL_DOWN
        assert device.created_calls[-1]["download_rate_kbps"] == 20480


# ============================================================================
# A total is taken away
# ============================================================================


class TestATotalIsTakenAway:
    async def test_the_guests_rows_leave_the_parent_before_it_is_removed(
        self,
    ) -> None:
        h, device, router = _venue()
        a = await _sign_in(h, router, address="192.168.88.254")
        b = await _sign_in(h, router, address="192.168.88.249")
        _set_policy(h, router)
        await _sync(h, router)
        name = venue_queue_name(router.location_id)
        device.ops.clear()

        _set_policy(h, router, total_down=None, total_up=None)
        result = await _sync(h, router)

        kinds = [op[0] for op in device.writes()]
        assert kinds == ["unparent", "unparent", "venue_remove"]
        assert device._parent_id(name) is None
        assert device.rows[a.device_queue_id]["parent"] == "none"
        assert device.rows[b.device_queue_id]["parent"] == "none"
        assert result["cleared"] == 1 and result["wrote"] == 1

    async def test_clearing_twice_writes_nothing_the_second_time(self) -> None:
        h, device, router = _venue()
        _set_policy(h, router)
        await _sync(h, router)
        _set_policy(h, router, total_down=None, total_up=None)
        await _sync(h, router)
        device.ops.clear()

        result = await _sync(h, router)

        assert device.writes() == []
        assert result["wrote"] == 0

    async def test_a_venue_that_never_had_a_total_is_not_contacted(self) -> None:
        """``clear_when_uncapped=False`` is what a publish passes for a
        policy that has never stated a total: no parent can be there, so
        the router is not read to look for one."""
        h, device, router = _venue()
        await _sign_in(h, router, address="192.168.88.254")

        result = await _sync(h, router, clear_when_uncapped=False)

        assert device.clear_calls == [] and device.sync_calls == []
        assert result["routers"] == 0


# ============================================================================
# Failure: the venue cap's, never the guests'
# ============================================================================


class TestFailure:
    async def test_a_router_that_reports_no_guest_subnet_gets_nothing_written(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        h, device, router = _venue()
        device.networks = ()
        _set_policy(h, router)

        with caplog.at_level("WARNING"):
            row = await _sign_in(h, router, address="192.168.88.254")
            await _sync(h, router)

        # The guest's own limit is exactly what it would have been.
        assert row.status == QueueStatus.ACTIVE.value
        assert "parent" not in device.created_calls[-1]
        assert device.rows[row.device_queue_id]["parent"] == "none"
        assert device._parent_id(venue_queue_name(router.location_id)) is None
        assert [op[0] for op in device.writes()] == ["create"]
        events = [r for r in caplog.records if r.msg == "venue_queue_subnet_unresolved"]
        assert events and events[0].problems == ["guest_subnet_unresolved"]

    async def test_a_router_that_refuses_the_parent_still_limits_the_guest(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        h, device, router = _venue()
        device.venue_error = QueueDeviceOperationError(
            "sync_venue_queue", "input does not match any value of parent"
        )
        _set_policy(h, router)

        with caplog.at_level("WARNING"):
            row = await _sign_in(h, router, address="192.168.88.254")

        assert row.status == QueueStatus.ACTIVE.value
        assert "parent" not in device.created_calls[-1]
        assert any(r.msg == "venue_queue_sync_failed" for r in caplog.records)

    async def test_an_unreachable_router_fails_the_sign_in_as_it_always_did(
        self,
    ) -> None:
        h, device, router = _venue()
        device.venue_error = QueueDeviceConnectionError("10.0.0.1", "timed out")
        _set_policy(h, router)

        with pytest.raises(QueueDeviceConnectionError):
            await _sign_in(h, router, address="192.168.88.254")

        assert device.created_calls == []

    async def test_one_router_that_does_not_answer_does_not_stop_the_other(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        @dataclass
        class OneDown(VenueDevice):
            down_host: str = "10.0.0.2"

            async def sync_venue_queue(self, credentials, **kwargs):
                if credentials.host == self.down_host:
                    self.sync_calls.append({"unreachable": credentials.host})
                    raise QueueDeviceConnectionError(credentials.host, "timed out")
                return await super().sync_venue_queue(credentials, **kwargs)

        device = OneDown()
        h = make_harness(device_adapter=device)
        _can_list_routers(h)
        location_id, org = uuid.uuid4(), uuid.uuid4()
        for host in ("10.0.0.1", "10.0.0.2"):
            router = _make_router(organization_id=org, location_id=location_id)
            router.management_ip_address = host
            h.router_lookup.add(router)
        h.policy_lookup.rules_by_scope[(org, location_id)] = _rules()

        with caplog.at_level("WARNING"):
            result = await h.service.sync_venue_cap_for_location(
                location_id=location_id, requesting_organization_id=org
            )

        assert result["routers"] == 2
        assert result["synced"] == 1 and result["failed"] == 1
        assert len(device.sync_calls) == 2
        assert device._parent_id(venue_queue_name(location_id)) is not None
        assert any(r.msg == "venue_queue_router_unreachable" for r in caplog.records)

    async def test_a_failing_venue_cap_does_not_stop_the_guests_own_reapply(
        self,
    ) -> None:
        h, device, router = _venue()
        row = await _sign_in(h, router, address="192.168.88.254")
        _set_policy(h, router, per_guest=20480, total_down=81920, total_up=81920)

        async def _boom(**kwargs):
            raise RuntimeError("the venue cap blew up")

        h.service._sync_venue_cap_under_lock = _boom
        h.service._ensure_venue_parent = _no_parent

        result = await h.service.reapply_active_sessions_for_location(
            location_id=router.location_id,
            requesting_organization_id=router.organization_id,
        )

        assert result == {"reapplied": 1, "failed": 0}
        assert h.repository.assignments[row.id].status == QueueStatus.EXPIRED.value
        assert device.created_calls[-1]["download_rate_kbps"] == 20480


async def _no_parent(*args, **kwargs):
    return None


def _listing(*routers):
    async def _routers_at_location(location_id, **kwargs):
        return list(routers)

    return _routers_at_location


# ============================================================================
# Sign-in, session end, re-apply, the sweep
# ============================================================================


class TestTheTriggers:
    async def test_a_sign_in_under_a_total_creates_the_guests_row_under_it(
        self,
    ) -> None:
        h, device, router = _venue()
        _set_policy(h, router)
        name = venue_queue_name(router.location_id)

        row = await _sign_in(h, router, address="192.168.88.254")

        # The parent first, then the guest's row, already naming it.
        assert [op[0] for op in device.writes()] == ["venue_create", "create"]
        assert device.created_calls[-1]["parent"] == name
        assert device.rows[row.device_queue_id]["parent"] == name
        assert row.status == QueueStatus.ACTIVE.value

    async def test_a_second_sign_in_does_not_remake_the_parent(self) -> None:
        h, device, router = _venue()
        _set_policy(h, router)
        await _sign_in(h, router, address="192.168.88.254")
        device.ops.clear()

        await _sign_in(h, router, address="192.168.88.249")

        assert [op[0] for op in device.writes()] == ["create"]

    async def test_a_venue_without_a_total_is_called_exactly_as_before(self) -> None:
        h, device, router = _venue()
        h.policy_lookup.rules_by_scope[(router.organization_id, router.location_id)] = {
            "download_rate_kbps": PER_GUEST,
            "upload_rate_kbps": PER_GUEST,
        }

        await _sign_in(h, router, address="192.168.88.254")

        assert device.sync_calls == [] and device.clear_calls == []
        assert "parent" not in device.created_calls[-1]

    async def test_an_adapter_that_has_never_heard_of_venue_caps_still_works(
        self,
    ) -> None:
        """``FakeQueueDeviceAdapter`` has no ``sync_venue_queue``. A cap in
        the policy must not pass it a ``parent`` it does not take."""
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        _set_policy(h, router)

        row = await _sign_in(h, router, address="192.168.88.254")
        result = await _sync(h, router)

        assert row.status == QueueStatus.ACTIVE.value
        assert "parent" not in h.device_adapter.created_calls[-1]
        assert result["skipped"] == 1 and result["synced"] == 0

    async def test_a_session_ending_takes_its_own_row_and_leaves_the_parent(
        self,
    ) -> None:
        h, device, router = _venue()
        h.service.session_liveness_lookup = FakeSessionLiveness()
        _set_policy(h, router)
        row = await _sign_in(h, router, address="192.168.88.254")
        guest_row_id = row.device_queue_id
        name = venue_queue_name(router.location_id)
        device.ops.clear()

        released = await h.service.release_queues_for_ended_sessions(grace_seconds=0)

        assert released["released"] == 1
        assert device.writes() == [("remove", guest_row_id)]
        assert device._parent_id(name) is not None
        assert device.clear_calls == []

    async def test_a_publish_brings_the_total_in_before_the_guests_are_reapplied(
        self,
    ) -> None:
        h, device, router = _venue()
        _set_policy(h, router, total_down=None, total_up=None)
        row = await _sign_in(h, router, address="192.168.88.254")
        _set_policy(h, router)
        name = venue_queue_name(router.location_id)

        result = await h.service.reapply_active_sessions_for_location(
            location_id=router.location_id,
            requesting_organization_id=router.organization_id,
        )

        assert result == {"reapplied": 1, "failed": 0}
        assert [op[0] for op in device.writes()][1:3] == ["venue_create", "reparent"]
        assert device.rows[row.device_queue_id]["parent"] == name

    async def test_a_publish_that_removes_the_total_clears_it_when_told_it_had_one(
        self,
    ) -> None:
        h, device, router = _venue()
        _set_policy(h, router)
        row = await _sign_in(h, router, address="192.168.88.254")
        _set_policy(h, router, total_down=None, total_up=None)

        await h.service.reapply_active_sessions_for_location(
            location_id=router.location_id,
            requesting_organization_id=router.organization_id,
            clear_venue_cap_when_uncapped=True,
        )

        assert device._parent_id(venue_queue_name(router.location_id)) is None
        assert device.rows[row.device_queue_id]["parent"] == "none"

    async def test_a_publish_for_a_policy_that_never_had_a_total_reads_no_router(
        self,
    ) -> None:
        h, device, router = _venue()
        await _sign_in(h, router, address="192.168.88.254")

        await h.service.reapply_active_sessions_for_location(
            location_id=router.location_id,
            requesting_organization_id=router.organization_id,
        )

        assert device.clear_calls == [] and device.sync_calls == []

    async def test_a_rate_change_under_a_total_puts_the_new_row_under_it_too(
        self,
    ) -> None:
        """A changed per-guest rate replaces the guest's row (new row
        applied, then the old one removed). The replacement must not come
        out from under the parent."""
        h, device, router = _venue()
        _set_policy(h, router)
        old = await _sign_in(h, router, address="192.168.88.254")
        name = venue_queue_name(router.location_id)

        _set_policy(h, router, per_guest=20480)
        await h.service.reapply_active_sessions_for_location(
            location_id=router.location_id,
            requesting_organization_id=router.organization_id,
        )

        assert old.device_queue_id not in device.rows
        (new_id,) = [i for i, r in device.rows.items() if r["name"] != name]
        assert device.rows[new_id]["parent"] == name

    async def test_the_sweep_repairs_a_parent_that_went_missing(self) -> None:
        h, device, router = _venue()
        _set_policy(h, router)
        row = await _sign_in(h, router, address="192.168.88.254")
        name = venue_queue_name(router.location_id)
        del device.rows[device._parent_id(name)]
        device.rows[row.device_queue_id]["parent"] = "none"

        result = await h.service.sync_venue_caps_for_live_locations()

        assert result["locations"] == 1 and result["wrote"] == 1
        assert device._parent_id(name) is not None
        assert device.rows[row.device_queue_id]["parent"] == name

    async def test_the_sweep_only_visits_routers_the_switch_allows(self) -> None:
        h, device, router = _venue()
        _set_policy(h, router)
        await _sign_in(h, router, address="192.168.88.254")
        device.sync_calls.clear()

        result = await h.service.sync_venue_caps_for_live_locations(
            router_allowed=lambda router_id: False
        )

        assert device.sync_calls == []
        assert result["locations"] == 0

    async def test_the_sweep_does_not_visit_a_location_with_nobody_online(
        self,
    ) -> None:
        h, device, router = _venue()
        _set_policy(h, router)

        result = await h.service.sync_venue_caps_for_live_locations()

        assert result["locations"] == 0 and device.sync_calls == []

    async def test_one_locations_failure_does_not_stop_the_sweep(self) -> None:
        h, device, router = _venue()
        other = h.router_lookup.add(_make_router())
        _set_policy(h, router)
        _set_policy(h, other)
        await _sign_in(h, router, address="192.168.88.254")
        await _sign_in(h, other, address="192.168.88.200")
        plain = h.service.sync_venue_cap_for_location
        failing = sorted([router.location_id, other.location_id], key=str)[0]

        async def _sometimes(**kwargs):
            if kwargs["location_id"] == failing:
                raise RuntimeError("boom")
            return await plain(**kwargs)

        h.service.sync_venue_cap_for_location = _sometimes

        result = await h.service.sync_venue_caps_for_live_locations()

        assert result["locations"] == 2
        assert result["failed"] == 1 and result["synced"] == 1


class TestTheTasksAreWired:
    """The two tasks open a real database session, so -- as the re-apply
    task's own ordering test does -- what they pass on is read from their
    source rather than run."""

    def test_a_publish_clears_only_for_a_policy_that_has_ever_stated_a_total(
        self,
    ) -> None:
        source = inspect.getsource(queue_tasks._reapply_policy_assignments_async)

        assert "venue_cap_from_rules(version.rules) is not None" in source
        assert "list_versions_for_policy(policy.id)" in source
        assert "clear_venue_cap_when_uncapped=ever_capped" in source
        # A location the policy is no longer mapped to is brought in line
        # with whatever its policy is now, each in its own savepoint.
        assert "if not a.is_active" in source
        assert source.index("if ever_capped:") < source.index("await session.commit()")

    def test_the_sweep_runs_the_venue_caps_behind_the_backfills_own_switch(
        self,
    ) -> None:
        source = inspect.getsource(
            queue_tasks._backfill_unassigned_session_queues_async
        )

        switched_off = source.index("if not _queue_backfill_is_on_anywhere(settings):")
        venue = source.index("sync_venue_caps_for_live_locations(")
        assert switched_off < venue
        assert "queue_backfill_applies(rid, settings)" in source[venue:]
        assert "unit_of_work=session.begin_nested" in source[venue:]


# ============================================================================
# Where a total is not enforced
# ============================================================================


class TestWhereItIsNotEnforced:
    @pytest.mark.parametrize("vendor", ["tplink_omada", "aruba_instant_on"])
    async def test_a_venue_not_run_from_a_router_we_log_in_to_is_skipped(
        self, vendor: str
    ) -> None:
        h, device, router = _venue()
        router.vendor = vendor
        _set_policy(h, router)

        result = await _sync(h, router)

        assert result == {
            "routers": 1,
            "synced": 0,
            "cleared": 0,
            "wrote": 0,
            "failed": 0,
            "skipped": 1,
        }
        assert device.sync_calls == []

    async def test_a_router_with_no_credentials_is_skipped_not_failed(self) -> None:
        h, device, _ = _venue()
        bare = h.router_lookup.add(_make_router(), secret=None)
        _set_policy(h, bare)
        h.service._routers_at_location = _listing(bare)

        result = await _sync(h, bare)

        assert result["skipped"] == 1 and result["failed"] == 0

    def test_the_capability_answer_says_unsupported_with_a_reason(self) -> None:
        """The one capability answer the Guest WiFi Limits screen already
        reads. Only a venue whose network is run from somewhere else gets an
        answer from it at all, so a total is never supported there."""
        yes = ClientCapabilityView(supported=True, reason=None)

        payload = ClientCapabilitiesResponse(
            set_rate_limit=yes,
            clear_rate_limit=yes,
            block=yes,
            unblock=yes,
            list_blocked=yes,
            disconnect=yes,
            client_stats=yes,
        ).model_dump()

        assert payload["venue_rate_limit"]["supported"] is False
        assert payload["venue_rate_limit"]["reason"]


# ============================================================================
# The RADIUS reply
# ============================================================================


class TestTheRadiusReply:
    async def test_no_rate_limit_is_sent_while_a_total_is_in_force(self) -> None:
        """The attribute makes the hotspot put a row for the guest at the
        top level, above the parent -- outside the total."""
        h, device, router = _venue()
        _set_policy(h, router)
        session_id = uuid.uuid4()
        await _sign_in(h, router, address="192.168.88.254", session_id=session_id)

        assert await h.service.get_rate_limit_reply_for_session(session_id) is None

    async def test_it_is_sent_as_before_where_there_is_no_total(self) -> None:
        h, device, router = _venue()
        h.policy_lookup.rules_by_scope[(router.organization_id, router.location_id)] = {
            "download_rate_kbps": PER_GUEST,
            "upload_rate_kbps": PER_GUEST,
        }
        session_id = uuid.uuid4()
        await _sign_in(h, router, address="192.168.88.254", session_id=session_id)

        reply = await h.service.get_rate_limit_reply_for_session(session_id)

        assert reply is not None and "40960k" in reply

    async def test_it_is_still_sent_where_the_total_is_not_enforced(self) -> None:
        h, device, router = _venue()
        profile = await _profile(h, PER_GUEST)
        session_id = uuid.uuid4()
        _seed_assignment(
            h,
            router=router,
            target_id=session_id,
            device_target="192.168.88.254",
            queue_profile_id=profile.id,
            device_queue_id="*1",
        )
        router.vendor = "tplink_omada"
        _set_policy(h, router)

        assert await h.service.get_rate_limit_reply_for_session(session_id) is not None

    async def test_a_lookup_that_fails_sends_the_limit_rather_than_nothing(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        h, device, router = _venue()
        h.policy_lookup.rules_by_scope[(router.organization_id, router.location_id)] = {
            "download_rate_kbps": PER_GUEST,
            "upload_rate_kbps": PER_GUEST,
        }
        session_id = uuid.uuid4()
        await _sign_in(h, router, address="192.168.88.254", session_id=session_id)

        async def _boom(**kwargs):
            raise RuntimeError("policy lookup down")

        h.service._venue_cap_for_location = _boom

        with caplog.at_level("WARNING"):
            reply = await h.service.get_rate_limit_reply_for_session(session_id)

        assert reply is not None
        assert any(r.msg == "venue_cap_lookup_failed" for r in caplog.records)


# ============================================================================
# The adapter and the door
# ============================================================================


class TestTheAdapter:
    async def test_it_asks_the_gateway_for_the_parent_with_the_platform_comment(
        self, monkeypatch
    ) -> None:
        seen: dict[str, object] = {}

        class Gateway:
            async def sync_venue_simple_queue(self, creds, **kwargs):
                seen.update(kwargs, host=creds.host)
                return SimpleNamespace(
                    name=kwargs["name"],
                    device_queue_id="*9",
                    targets=(GUEST_NET,),
                    created=True,
                    updated=False,
                    reparented=1,
                    moved_to_top=True,
                    removed=False,
                    wrote=True,
                    in_sync=True,
                    problems=(),
                )

        monkeypatch.setattr(
            "app.domains.queue_management.device_adapters.get_adapter",
            lambda vendor: Gateway(),
        )

        state = await MikroTikQueueAdapter().sync_venue_queue(
            QueueCredentials(host="10.20.0.46", username="u", password="p"),
            name="cloudguest-venue-72425fa0",
            download_rate_kbps=TOTAL_DOWN,
            upload_rate_kbps=None,
            child_queue_ids=["*2"],
        )

        assert seen == {
            "host": "10.20.0.46",
            "name": "cloudguest-venue-72425fa0",
            "download_rate_kbps": TOTAL_DOWN,
            "upload_rate_kbps": None,
            "child_queue_ids": ("*2",),
            "comment": VENUE_QUEUE_COMMENT,
        }
        assert state == VenueQueueState(
            name="cloudguest-venue-72425fa0",
            device_queue_id="*9",
            targets=(GUEST_NET,),
            created=True,
            reparented=1,
            moved_to_top=True,
            wrote=True,
        )


class TestTheDoor:
    """``POST /queue/assign`` no longer accepts a new organization, location
    or router assignment: they were saved and never enforced."""

    @staticmethod
    def _request():
        return SimpleNamespace(state=SimpleNamespace(request_id="r"))

    @pytest.mark.parametrize("target_type", ["organization", "location", "router"])
    async def test_a_target_nothing_enforces_is_refused_before_anything_is_saved(
        self, target_type: str
    ) -> None:
        h = make_harness()
        payload = QueueAssignmentCreateRequest.model_validate(
            {
                "target_type": target_type,
                "target_id": None
                if target_type == "organization"
                else str(uuid.uuid4()),
                "router_id": str(uuid.uuid4()),
            }
        )

        with pytest.raises(QueueTargetTypeNotEnforcedError) as refused:
            await queue_router.create_queue_assignment(
                self._request(),
                payload,
                actor=SimpleNamespace(id=str(uuid.uuid4())),
                requesting_organization_id=uuid.uuid4(),
                service=h.service,
            )

        assert refused.value.status_code == 422
        assert "not supported on this venue's hardware yet" in str(refused.value)
        assert "Guest WiFi Limits" in str(refused.value)
        assert h.repository.assignments == {}

    async def test_a_guest_session_assignment_is_still_accepted(self) -> None:
        h = make_harness()
        router = h.router_lookup.add(_make_router())
        payload = QueueAssignmentCreateRequest.model_validate(
            {
                "target_type": "session",
                "target_id": str(uuid.uuid4()),
                "router_id": str(router.id),
                "device_target": "192.168.88.254",
            }
        )

        await queue_router.create_queue_assignment(
            self._request(),
            payload,
            actor=SimpleNamespace(id=str(uuid.uuid4())),
            requesting_organization_id=router.organization_id,
            service=h.service,
        )

        assert len(h.repository.assignments) == 1
