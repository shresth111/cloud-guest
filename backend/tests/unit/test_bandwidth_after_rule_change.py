"""A changed bandwidth rule reaches every guest who is online, at one rate,
and a rule that was removed and set again does not leave a guest unlimited.

Two things were wrong, and they share one fact about RouterOS: a packet goes
to the **first** ``/queue simple`` row whose target matches it.

* **Two rows per guest.** The RADIUS reply carried ``Mikrotik-Rate-Limit``
  whenever the session had a queue assignment -- exactly when this
  platform's own ``cloudguest-...`` row was on the router too. The hotspot
  turns the attribute into a dynamic row, puts it first, and never changes
  it. A rule changed afterwards rewrote the platform's row and reached
  nobody who had logged in through RADIUS; a guest admitted without a
  hotspot login has no dynamic row and changed at once.
* **A leftover row.** A changed limit is a new row; the old one is removed
  in a second device call. "No limit" is itself a row (``0/0``). When that
  removal failed, the sequence *limit -> no limit -> limit* left an
  unlimited row for the address, and where it sat above the new one the
  guest ran at full speed with the new limit showing as applied.

What is pinned here, against a fake router that keeps its rows **in order**
and answers "which row governs this address" the way RouterOS does:

* limit A -> no limit -> limit B, for a guest who logged in through RADIUS
  and for one admitted without a login: what rows exist after each step and
  which one governs;
* the same when the router will not reorder rows and will not remove the
  old one;
* the RADIUS reply: nothing while the platform's row is on the router, the
  rate when it is not, and the policy's rate for a session with no
  assignment at all;
* a tier member, a venue with a total cap, a second re-apply, a failed
  write.

In-memory fakes from ``test_queue_management``; nothing here talks to a
router or a database. What a real RouterOS does with ``move`` across a
dynamic row is in the pull request's hardware plan, not here -- which is
why the fake can be told to refuse it.
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from types import SimpleNamespace

import pytest

from app.domains.guest.service import RadiusService
from app.domains.queue_management import tasks as queue_tasks
from app.domains.queue_management.constants import (
    GUEST_QUEUE_NAME_PREFIX,
    RADIUS_RATE_FALLBACK_MIN_SESSION_AGE_SECONDS,
    QueueStatus,
    QueueTargetType,
)
from app.domains.queue_management.exceptions import (
    QueueDeviceConnectionError,
    QueueDeviceOperationError,
)
from tests.unit.test_queue_management import (
    FakeQueueDeviceAdapter,
    Harness,
    _make_router,
    _now,
    _seed_assignment,
    make_harness,
)
from tests.unit.test_queue_release_on_session_end import _profile
from tests.unit.test_venue_wide_speed_cap import (
    _set_policy as _set_capped_policy,
)
from tests.unit.test_venue_wide_speed_cap import (
    _sign_in as _sign_in_at_capped_venue,
)
from tests.unit.test_venue_wide_speed_cap import (
    _venue as _capped_venue,
)


@pytest.fixture(autouse=True)
def _info_logging_on(caplog: pytest.LogCaptureFixture) -> None:
    """INFO records are built here as they are in the worker, so an
    ``extra`` key that collides with a ``LogRecord`` attribute raises in
    this module on its own and not only in the full suite."""
    caplog.set_level("INFO", logger="app.domains.queue_management.service")


LIMIT_A = 20480
LIMIT_B = 81920
UNLIMITED = 0
RADIUS_GUEST = "10.5.50.251"
BYPASS_GUEST = "10.5.50.252"


# ============================================================================
# A router whose rows are in order
# ============================================================================


@dataclass
class FirstMatchRouter(FakeQueueDeviceAdapter):
    """``/queue simple`` as a list, in the order RouterOS would print it.

    * A new row is added at the bottom, then moved to the top -- unless
      ``refuses_move``, which is the router nobody has been able to rule
      out: one that will not put a static row above a dynamic one.
    * The hotspot puts its dynamic row first (``hotspot_login``), and only
      when the RADIUS reply carried a rate.
    * ``governing`` is the first row matching an address: what the guest
      actually gets.
    * ``supersede_name_prefix`` is honoured the way the gateway honours it:
      once the new row is in, every other static ``<prefix><uuid>`` row for
      exactly that address goes, except ``keep_queue_ids``.
    """

    rows: list[dict[str, object]] = field(default_factory=list)
    refuses_move: bool = False
    remove_error: Exception | None = None
    create_error: Exception | None = None
    create_attempts: int = 0

    # -- what the platform does -------------------------------------------

    async def create_simple_queue(self, credentials, **kwargs) -> str:
        self.create_attempts += 1
        if self.create_error is not None:
            raise self.create_error
        device_id = await super().create_simple_queue(credentials, **kwargs)
        row = {
            "id": device_id,
            "name": kwargs["name"],
            "target": str(kwargs["target"]).removesuffix("/32"),
            "kbps": kwargs["download_rate_kbps"],
            "dynamic": False,
        }
        self.rows.append(row)
        if not self.refuses_move:
            self.rows.remove(row)
            self.rows.insert(0, row)
        prefix = kwargs.get("supersede_name_prefix")
        if prefix:
            keep = set(kwargs.get("keep_queue_ids") or ())
            self.rows[:] = [
                r
                for r in self.rows
                if r is row
                or r["dynamic"]
                or r["id"] in keep
                or r["target"] != row["target"]
                or not _is_guest_row_name(str(r["name"]), prefix)
            ]
        return device_id

    async def remove_queue(self, credentials, *, device_queue_id, **kwargs) -> None:
        if not any(r["id"] == device_queue_id for r in self.rows):
            raise QueueDeviceOperationError("remove_queue", "no such item")
        if self.remove_error is not None:
            raise self.remove_error
        await super().remove_queue(
            credentials, device_queue_id=device_queue_id, **kwargs
        )
        self.rows[:] = [r for r in self.rows if r["id"] != device_queue_id]

    # -- what the router does on its own ----------------------------------

    def hotspot_login(self, address: str, rate_limit_reply: str | None) -> None:
        """A hotspot login: the previous login's dynamic row goes with the
        previous hotspot session, and a new one is made, first in the list,
        only if RADIUS sent a rate (``<up>k/<down>k``)."""
        self.rows[:] = [
            r for r in self.rows if not (r["dynamic"] and r["target"] == address)
        ]
        if rate_limit_reply:
            down = rate_limit_reply.split()[0].split("/")[1]
            self.rows.insert(
                0,
                {
                    "id": f"*D{len(self.rows)}",
                    "name": f"<hotspot-{address}>",
                    "target": address,
                    "kbps": int(down.removesuffix("k")),
                    "dynamic": True,
                },
            )

    # -- what the guest gets ----------------------------------------------

    def for_address(self, address: str) -> list[dict[str, object]]:
        return [r for r in self.rows if _matches(str(r["target"]), address)]

    def governing(self, address: str) -> dict[str, object] | None:
        """The first row that matches: the one that shapes the guest. ``None``
        is no row at all, which is unlimited."""
        matching = self.for_address(address)
        return matching[0] if matching else None

    def speed(self, address: str) -> int:
        """Download kbps the guest is held to; ``0`` is unlimited."""
        row = self.governing(address)
        return 0 if row is None else int(row["kbps"])  # type: ignore[call-overload]


def _is_guest_row_name(name: str, prefix: str) -> bool:
    if not name.startswith(prefix):
        return False
    try:
        uuid.UUID(name[len(prefix) :])
    except ValueError:
        return False
    return True


def _matches(target: str, address: str) -> bool:
    try:
        return ipaddress.ip_address(address) in ipaddress.ip_network(
            target, strict=False
        )
    except ValueError:
        return False


@dataclass
class OnlineSessions:
    """Which sessions are live, and whose each one is."""

    guests: dict[uuid.UUID, uuid.UUID | None] = field(default_factory=dict)

    async def live_session_ids(self, session_ids) -> set[uuid.UUID]:
        return {s for s in session_ids if s in self.guests}

    async def guest_ids_for_sessions(self, session_ids):
        return {s: self.guests[s] for s in session_ids if s in self.guests}


@dataclass
class Venue:
    h: Harness
    device: FirstMatchRouter
    router: object
    online: OnlineSessions

    def set_limit(self, kbps: int | None) -> None:
        """The location's bandwidth rule: a limit, or -- ``None`` -- no
        rule at all, which is what removing it leaves."""
        scope = (self.router.organization_id, self.router.location_id)
        if kbps is None:
            self.h.policy_lookup.rules_by_scope.pop(scope, None)
        else:
            self.h.policy_lookup.rules_by_scope[scope] = {
                "download_rate_kbps": kbps,
                "upload_rate_kbps": kbps,
            }

    async def publish(self, kbps: int | None) -> dict[str, int]:
        """Change the rule and run what a publish dispatches."""
        self.set_limit(kbps)
        return await self.reapply()

    async def reapply(self) -> dict[str, int]:
        return await self.h.service.reapply_active_sessions_for_location(
            location_id=self.router.location_id,
            requesting_organization_id=self.router.organization_id,
        )

    async def radius_reply(self, session_id: uuid.UUID, **overrides) -> str | None:
        context = {
            "organization_id": self.router.organization_id,
            "location_id": self.router.location_id,
            "router_id": self.router.id,
            "guest_id": self.online.guests.get(session_id),
            "session_started_at": _now(),
        }
        context.update(overrides)
        return await self.h.service.rate_limit_reply_for_authorize(
            session_id, **context
        )

    async def sign_in(
        self,
        address: str,
        *,
        through_radius: bool,
        guest_id: uuid.UUID | None = None,
        session_id: uuid.UUID | None = None,
    ) -> uuid.UUID:
        """The login's queue write, then -- for a guest who logs in to the
        hotspot -- the authorize and what the hotspot makes of its reply. A
        guest admitted by a bypass binding never reaches the second half."""
        session_id = session_id or uuid.uuid4()
        self.online.guests[session_id] = guest_id
        await self.h.service.resolve_and_assign_queue(
            requesting_organization_id=self.router.organization_id,
            location_id=self.router.location_id,
            router_id=self.router.id,
            target_type=QueueTargetType.SESSION,
            target_id=session_id,
            device_target=address,
            guest_id=guest_id,
        )
        if through_radius:
            await self.hotspot_login(session_id, address)
        return session_id

    async def hotspot_login(self, session_id: uuid.UUID, address: str) -> None:
        self.device.hotspot_login(address, await self.radius_reply(session_id))


def _venue(**device_kwargs) -> Venue:
    device = FirstMatchRouter(**device_kwargs)
    h = make_harness(device_adapter=device)
    online = OnlineSessions()
    h.service.session_liveness_lookup = online
    return Venue(
        h=h, device=device, router=h.router_lookup.add(_make_router()), online=online
    )


def _names(rows: list[dict[str, object]]) -> list[tuple[str, int]]:
    """``("platform" | "hotspot", kbps)`` per row, in list order."""
    return [("hotspot" if r["dynamic"] else "platform", int(r["kbps"])) for r in rows]  # type: ignore[call-overload]


# ============================================================================
# Limit A -> no limit -> limit B
# ============================================================================


class TestALimitIsRemovedAndSetAgain:
    """The reported sequence, step by step, for both ways in."""

    @pytest.mark.parametrize(
        ("address", "through_radius"),
        [(RADIUS_GUEST, True), (BYPASS_GUEST, False)],
        ids=["logged-in-through-radius", "admitted-without-a-login"],
    )
    async def test_one_row_per_guest_at_every_step_and_limit_b_governs(
        self, address: str, through_radius: bool
    ) -> None:
        v = _venue()
        v.set_limit(LIMIT_A)
        await v.sign_in(address, through_radius=through_radius)

        # Limit A: the platform's row and nothing else -- no hotspot row,
        # whichever way the guest came in.
        assert _names(v.device.for_address(address)) == [("platform", LIMIT_A)]

        # The limit is removed. "No limit" is a row too.
        await v.publish(None)
        assert _names(v.device.for_address(address)) == [("platform", UNLIMITED)]
        assert v.device.speed(address) == UNLIMITED

        # A limit is set again.
        result = await v.publish(LIMIT_B)
        assert result == {"reapplied": 1, "failed": 0}
        assert _names(v.device.for_address(address)) == [("platform", LIMIT_B)]
        assert v.device.speed(address) == LIMIT_B

    async def test_both_guests_end_at_the_same_rate(self) -> None:
        v = _venue()
        v.set_limit(LIMIT_A)
        await v.sign_in(RADIUS_GUEST, through_radius=True)
        await v.sign_in(BYPASS_GUEST, through_radius=False)

        await v.publish(None)
        await v.publish(LIMIT_B)

        assert v.device.speed(RADIUS_GUEST) == v.device.speed(BYPASS_GUEST) == LIMIT_B
        assert not [r for r in v.device.rows if r["kbps"] == UNLIMITED]

    async def test_a_guest_who_signed_in_while_there_was_no_limit(self) -> None:
        """No rule at sign-in: an ``Unlimited`` assignment, a ``0/0`` row,
        and no hotspot row. Then a limit is published."""
        v = _venue()
        await v.sign_in(RADIUS_GUEST, through_radius=True)
        assert _names(v.device.for_address(RADIUS_GUEST)) == [("platform", UNLIMITED)]

        await v.publish(LIMIT_A)
        await v.publish(LIMIT_B)

        assert _names(v.device.for_address(RADIUS_GUEST)) == [("platform", LIMIT_B)]

    async def test_a_later_hotspot_login_does_not_change_it(self) -> None:
        """The MAC cookie re-admits the guest, or they sign in again: a new
        authorize, and no second row."""
        v = _venue()
        v.set_limit(LIMIT_A)
        session_id = await v.sign_in(RADIUS_GUEST, through_radius=True)
        await v.publish(None)
        await v.publish(LIMIT_B)

        await v.hotspot_login(session_id, RADIUS_GUEST)
        await v.sign_in(RADIUS_GUEST, through_radius=True, session_id=session_id)

        assert _names(v.device.for_address(RADIUS_GUEST)) == [("platform", LIMIT_B)]


class TestTheOldRowCannotOutliveTheNewOne:
    """The same sequence on a router that does the two things the happy
    path depends on badly: it will not reorder rows, and the separate call
    that removes the old row fails."""

    @pytest.mark.parametrize("address", [RADIUS_GUEST, BYPASS_GUEST])
    async def test_limit_b_governs_when_the_old_rows_removal_fails(
        self, address: str
    ) -> None:
        v = _venue(refuses_move=True)
        v.set_limit(LIMIT_A)
        await v.sign_in(address, through_radius=address == RADIUS_GUEST)
        await v.publish(None)
        assert v.device.speed(address) == UNLIMITED

        # From here on the router refuses every separate removal.
        v.device.remove_error = QueueDeviceOperationError("remove_queue", "busy")
        result = await v.publish(LIMIT_B)

        assert result == {"reapplied": 1, "failed": 0}
        assert v.device.speed(address) == LIMIT_B
        assert _names(v.device.for_address(address)) == [("platform", LIMIT_B)]
        live = [
            a
            for a in v.h.repository.assignments.values()
            if a.status == QueueStatus.ACTIVE.value
        ]
        assert len(live) == 1

    async def test_a_row_this_platform_no_longer_has_a_record_of_goes_too(
        self,
    ) -> None:
        """What a rolled-back transaction leaves: a ``0/0`` row on the
        router, above everything, that no assignment names."""
        v = _venue(refuses_move=True)
        v.device.rows.append(
            {
                "id": "*orphan",
                "name": f"{GUEST_QUEUE_NAME_PREFIX}{uuid.uuid4()}",
                "target": BYPASS_GUEST,
                "kbps": UNLIMITED,
                "dynamic": False,
            }
        )
        v.set_limit(LIMIT_B)

        await v.sign_in(BYPASS_GUEST, through_radius=False)

        assert _names(v.device.for_address(BYPASS_GUEST)) == [("platform", LIMIT_B)]

    async def test_the_new_row_is_written_before_any_old_one_goes(self) -> None:
        """Never a moment with no row: a write that fails leaves the guest
        at the limit they had, not unlimited."""
        v = _venue()
        v.set_limit(LIMIT_A)
        await v.sign_in(BYPASS_GUEST, through_radius=False)
        v.device.create_error = QueueDeviceOperationError("create_simple_queue", "no")

        result = await v.publish(LIMIT_B)

        assert result == {"reapplied": 0, "failed": 1}
        assert _names(v.device.for_address(BYPASS_GUEST)) == [("platform", LIMIT_A)]

    async def test_other_rows_for_other_things_are_left_alone(self) -> None:
        """Another guest, a subnet-wide row, a row with another name for
        the same address, and an operator's own assignment for it."""
        v = _venue()
        v.set_limit(LIMIT_A)
        other = await v.sign_in(BYPASS_GUEST, through_radius=False)
        operators = _seed_assignment(
            v.h,
            router=v.router,
            target_id=uuid.uuid4(),
            device_target=RADIUS_GUEST,
            queue_profile_id=(await _profile(v.h, 5120)).id,
            device_queue_id="*operator",
        )
        operators.target_type = QueueTargetType.DEVICE.value
        v.device.rows.extend(
            [
                {
                    "id": "*operator",
                    "name": f"{GUEST_QUEUE_NAME_PREFIX}{operators.id}",
                    "target": RADIUS_GUEST,
                    "kbps": 5120,
                    "dynamic": False,
                },
                {
                    "id": "*qos",
                    "name": f"{GUEST_QUEUE_NAME_PREFIX}qos-{uuid.uuid4()}",
                    "target": RADIUS_GUEST,
                    "kbps": 1024,
                    "dynamic": False,
                },
                {
                    "id": "*subnet",
                    "name": "staff",
                    "target": "10.5.50.0/24",
                    "kbps": 4096,
                    "dynamic": False,
                },
            ]
        )

        await v.sign_in(RADIUS_GUEST, through_radius=False)

        assert {"*operator", "*qos", "*subnet"} <= {r["id"] for r in v.device.rows}
        assert v.device.created_calls[-1]["keep_queue_ids"] == ("*operator",)
        assert other in v.online.guests
        assert [r for r in v.device.rows if r["target"] == BYPASS_GUEST]

    async def test_only_a_guest_sessions_row_supersedes_anything(self) -> None:
        v = _venue()
        profile = await _profile(v.h, LIMIT_A)
        assignment = await v.h.service.create_assignment(
            actor_user_id=None,
            requesting_organization_id=v.router.organization_id,
            target_type=QueueTargetType.DEVICE,
            target_id=uuid.uuid4(),
            router_id=v.router.id,
            device_target=RADIUS_GUEST,
            queue_profile_id=profile.id,
        )

        await v.h.service.apply_queue(
            assignment.id,
            actor_user_id=None,
            requesting_organization_id=v.router.organization_id,
        )

        assert "supersede_name_prefix" not in v.device.created_calls[-1]


class TestAGuestWhoAlreadyHasAHotspotRow:
    """Guests online when this ships logged in under the old reply and
    still hold a dynamic row. Nothing here can change or remove that row;
    what is pinned is what each kind of router then does, and that the next
    hotspot login ends it."""

    async def _signed_in_the_old_way(self, v: Venue) -> uuid.UUID:
        v.set_limit(LIMIT_A)
        session_id = await v.sign_in(RADIUS_GUEST, through_radius=False)
        v.device.hotspot_login(RADIUS_GUEST, f"{LIMIT_A}k/{LIMIT_A}k")
        assert _names(v.device.for_address(RADIUS_GUEST)) == [
            ("hotspot", LIMIT_A),
            ("platform", LIMIT_A),
        ]
        return session_id

    async def test_where_the_router_reorders_the_new_limit_governs_at_once(
        self,
    ) -> None:
        v = _venue()
        await self._signed_in_the_old_way(v)

        await v.publish(LIMIT_B)

        assert v.device.speed(RADIUS_GUEST) == LIMIT_B

    async def test_where_it_will_not_the_old_rate_lasts_until_the_next_login(
        self,
    ) -> None:
        v = _venue(refuses_move=True)
        session_id = await self._signed_in_the_old_way(v)

        await v.publish(LIMIT_B)
        assert v.device.speed(RADIUS_GUEST) == LIMIT_A

        await v.hotspot_login(session_id, RADIUS_GUEST)
        assert _names(v.device.for_address(RADIUS_GUEST)) == [("platform", LIMIT_B)]


# ============================================================================
# The RADIUS reply
# ============================================================================


class TestTheRadiusReplyIsTheFallback:
    async def test_nothing_is_sent_while_the_platforms_row_is_on_the_router(
        self,
    ) -> None:
        v = _venue()
        v.set_limit(LIMIT_A)
        session_id = await v.sign_in(RADIUS_GUEST, through_radius=False)

        assert await v.radius_reply(session_id) is None
        assert await v.h.service.get_rate_limit_reply_for_session(session_id) is None

    @pytest.mark.parametrize(
        "status",
        [QueueStatus.PENDING, QueueStatus.DISABLED, QueueStatus.SUSPENDED],
    )
    async def test_the_rate_is_sent_while_the_row_is_not_on_the_router(
        self, status: QueueStatus
    ) -> None:
        v = _venue()
        session_id = uuid.uuid4()
        _seed_assignment(
            v.h,
            router=v.router,
            target_id=session_id,
            device_target=RADIUS_GUEST,
            queue_profile_id=(await _profile(v.h, LIMIT_A)).id,
            status=status.value,
        )

        assert await v.radius_reply(session_id) == f"{LIMIT_A}k/{LIMIT_A}k"

    async def test_a_session_with_no_assignment_gets_the_policys_rate(self) -> None:
        """The session whose queue write never landed. It used to be sent
        nothing and run unlimited."""
        v = _venue()
        v.set_limit(LIMIT_B)
        old_enough = _now() - timedelta(
            seconds=RADIUS_RATE_FALLBACK_MIN_SESSION_AGE_SECONDS + 1
        )

        reply = await v.radius_reply(uuid.uuid4(), session_started_at=old_enough)

        assert reply == f"{LIMIT_B}k/{LIMIT_B}k"

    async def test_not_while_the_logins_own_write_may_still_be_on_its_way(
        self,
    ) -> None:
        """Answering with a rate here is what gives a guest two rows."""
        v = _venue()
        v.set_limit(LIMIT_B)

        assert await v.radius_reply(uuid.uuid4(), session_started_at=_now()) is None

    async def test_a_tier_members_fallback_is_the_tiers_rate(self) -> None:
        v = _venue()
        v.set_limit(LIMIT_A)
        member = uuid.uuid4()
        v.h.policy_lookup.rules_by_guest[member] = {
            "download_rate_kbps": LIMIT_B,
            "upload_rate_kbps": LIMIT_B,
        }

        reply = await v.radius_reply(
            uuid.uuid4(),
            guest_id=member,
            session_started_at=_now() - timedelta(hours=1),
        )

        assert reply == f"{LIMIT_B}k/{LIMIT_B}k"

    async def test_no_fallback_where_nothing_was_sent_before(self) -> None:
        """No rule, an unlimited rule, a venue total, a venue run from a
        controller, a caller that does not say whose session it is."""
        long_ago = _now() - timedelta(hours=1)
        v = _venue()
        assert await v.radius_reply(uuid.uuid4(), session_started_at=long_ago) is None

        v.set_limit(UNLIMITED)
        assert await v.radius_reply(uuid.uuid4(), session_started_at=long_ago) is None

        v.set_limit(LIMIT_A)
        assert await v.h.service.get_rate_limit_reply_for_session(uuid.uuid4()) is None

        scope = (v.router.organization_id, v.router.location_id)
        v.h.policy_lookup.rules_by_scope[scope]["venue_download_rate_kbps"] = 163840
        assert await v.radius_reply(uuid.uuid4(), session_started_at=long_ago) is None

        del v.h.policy_lookup.rules_by_scope[scope]["venue_download_rate_kbps"]
        v.router.vendor = "tplink_omada"
        assert await v.radius_reply(uuid.uuid4(), session_started_at=long_ago) is None

    async def test_a_lookup_that_fails_sends_nothing_and_says_so(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        v = _venue()
        v.set_limit(LIMIT_A)

        async def _boom(**kwargs):
            raise RuntimeError("policy lookup down")

        v.h.policy_lookup.resolve_effective_policy = _boom

        reply = await v.radius_reply(
            uuid.uuid4(), session_started_at=_now() - timedelta(hours=1)
        )

        assert reply is None
        assert "radius_rate_fallback_lookup_failed" in [r.msg for r in caplog.records]

    async def test_authorize_tells_the_hook_whose_session_it_is(self) -> None:
        asked: dict[str, object] = {}

        class Hook:
            async def rate_limit_reply_for_authorize(self, session_id, **context):
                asked.update(context, session_id=session_id)
                return "1k/1k"

            async def get_rate_limit_reply_for_session(self, session_id):
                raise AssertionError("the older question was asked")

        service = object.__new__(RadiusService)
        service.queue_lookup = Hook()
        session = SimpleNamespace(
            id=uuid.uuid4(),
            organization_id=uuid.uuid4(),
            location_id=uuid.uuid4(),
            router_id=uuid.uuid4(),
            guest_id=uuid.uuid4(),
            started_at=_now(),
        )

        reply = await service._resolve_rate_limit_reply(session.id, session=session)

        assert reply == "1k/1k"
        assert asked == {
            "session_id": session.id,
            "organization_id": session.organization_id,
            "location_id": session.location_id,
            "router_id": session.router_id,
            "guest_id": session.guest_id,
            "session_started_at": session.started_at,
        }

    async def test_a_hook_that_only_knows_the_older_question_is_asked_it(
        self,
    ) -> None:
        class Hook:
            async def get_rate_limit_reply_for_session(self, session_id):
                return "2k/2k"

        service = object.__new__(RadiusService)
        service.queue_lookup = Hook()
        session = SimpleNamespace(id=uuid.uuid4())

        assert (
            await service._resolve_rate_limit_reply(session.id, session=session)
            == "2k/2k"
        )


# ============================================================================
# A tier, a venue total, a second run, a failed write
# ============================================================================


class TestATierChanges:
    async def test_a_member_gets_the_tiers_new_rate_and_nobody_else_does(
        self,
    ) -> None:
        v = _venue()
        v.set_limit(LIMIT_A)
        member = uuid.uuid4()
        v.h.policy_lookup.rules_by_guest[member] = {
            "download_rate_kbps": 40960,
            "upload_rate_kbps": 40960,
        }
        members_session = await v.sign_in(
            RADIUS_GUEST, through_radius=True, guest_id=member
        )
        await v.sign_in(BYPASS_GUEST, through_radius=False)
        assert v.device.speed(RADIUS_GUEST) == 40960

        v.h.policy_lookup.rules_by_guest[member] = {
            "download_rate_kbps": LIMIT_B,
            "upload_rate_kbps": LIMIT_B,
        }
        await v.reapply()

        assert _names(v.device.for_address(RADIUS_GUEST)) == [("platform", LIMIT_B)]
        assert _names(v.device.for_address(BYPASS_GUEST)) == [("platform", LIMIT_A)]
        assert await v.radius_reply(members_session) is None


class TestAVenueWithATotalCap:
    async def test_a_changed_guest_rate_leaves_the_parent_where_it_is(self) -> None:
        h, device, router = _capped_venue()
        _set_capped_policy(h, router)
        session_id = uuid.uuid4()
        await _sign_in_at_capped_venue(
            h, router, address="192.168.88.254", session_id=session_id
        )
        parent_name = next(
            r["name"] for r in device.rows.values() if "venue" in str(r["name"])
        )
        parent_id = device._parent_id(parent_name)
        liveness = OnlineSessions(guests={session_id: None})
        h.service.session_liveness_lookup = liveness

        _set_capped_policy(h, router, per_guest=LIMIT_A)
        result = await h.service.reapply_active_sessions_for_location(
            location_id=router.location_id,
            requesting_organization_id=router.organization_id,
        )

        assert result == {"reapplied": 1, "failed": 0}
        assert device._parent_id(parent_name) == parent_id
        assert ("remove", parent_id) not in device.ops
        guest_rows = [r for r in device.rows.values() if r["name"] != parent_name]
        assert [r["parent"] for r in guest_rows] == [parent_name]
        assert device.created_calls[-1]["download_rate_kbps"] == LIMIT_A
        assert device.created_calls[-1]["supersede_name_prefix"] == "cloudguest-"
        # Under a total nothing is sent, row or no row.
        assert await h.service.get_rate_limit_reply_for_session(session_id) is None


class TestASecondReapply:
    async def test_it_writes_nothing(self) -> None:
        v = _venue()
        v.set_limit(LIMIT_A)
        await v.sign_in(RADIUS_GUEST, through_radius=True)
        await v.sign_in(BYPASS_GUEST, through_radius=False)
        await v.publish(LIMIT_B)
        rows = [dict(r) for r in v.device.rows]
        writes = (len(v.device.created_ids), len(v.device.removed_ids))
        assignments = dict(v.h.repository.assignments)

        again = await v.reapply()

        assert again == {"reapplied": 2, "failed": 0}
        assert [dict(r) for r in v.device.rows] == rows
        assert (len(v.device.created_ids), len(v.device.removed_ids)) == writes
        assert dict(v.h.repository.assignments) == assignments


class TestAFailedWrite:
    async def test_the_guest_keeps_their_limit_and_the_next_run_finishes_it(
        self,
    ) -> None:
        v = _venue()
        v.set_limit(LIMIT_A)
        session_id = await v.sign_in(RADIUS_GUEST, through_radius=True)
        v.device.create_error = QueueDeviceOperationError("create_simple_queue", "no")

        first = await v.publish(LIMIT_B)

        assert first == {"reapplied": 0, "failed": 1}
        assert v.device.speed(RADIUS_GUEST) == LIMIT_A
        # Still this platform's row, so still no second one from RADIUS.
        assert await v.radius_reply(session_id) is None

        v.device.create_error = None
        second = await v.reapply()

        assert second == {"reapplied": 1, "failed": 0}
        assert _names(v.device.for_address(RADIUS_GUEST)) == [("platform", LIMIT_B)]

    async def test_a_router_that_does_not_answer_is_asked_once_per_run(self) -> None:
        v = _venue()
        v.set_limit(LIMIT_A)
        for n in (11, 12, 13):
            await v.sign_in(f"10.5.50.{n}", through_radius=False)
        v.device.create_error = QueueDeviceConnectionError("10.0.0.1", "timed out")
        before = v.device.create_attempts

        result = await v.publish(LIMIT_B)

        assert result == {"reapplied": 0, "failed": 3}
        assert v.device.create_attempts == before + 1
        assert {v.device.speed(f"10.5.50.{n}") for n in (11, 12, 13)} == {LIMIT_A}

    def test_a_run_that_left_a_write_failed_runs_again_while_it_can(self) -> None:
        again = queue_tasks.reapply_should_run_again

        assert again({"reapplied": 4, "failed": 1}, retries=0, max_retries=3)
        assert again({"reapplied": 0, "failed": 2}, retries=2, max_retries=3)
        assert not again({"reapplied": 4, "failed": 1}, retries=3, max_retries=3)
        assert not again({"reapplied": 5, "failed": 0}, retries=0, max_retries=3)
        assert not again({"reapplied": 0, "failed": 1}, retries=0, max_retries=None)
