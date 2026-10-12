"""A guest who is using the network must not be logged out for inactivity
because of *how* they were let on to it.

The production report (2026-10-12): a cabled laptop, admitted by an
``/ip hotspot ip-binding type=bypassed`` row, was expired as
``inactivity_timeout`` 45 minutes after login -- idle timeout 30 plus the
sweep's grace -- with tens of megabytes through its queue in that window.
``last_activity_at`` had never moved off the value the login wrote, and
``bytes_uploaded``/``bytes_downloaded`` were both 0. The same thing had
happened to the same device the evening before.

A bypassed host is never an ``/ip/hotspot/active`` session, so RouterOS sends
no RADIUS accounting for it, and accounting was the only thing that moved
``last_activity_at`` on a RouterOS venue. The idle sweep therefore measured
the session's age and called it silence.

These tests pin the two halves of the fix:

* the presence sweep's existing read of ``/ip/hotspot/host`` now credits each
  listed device with the activity the router itself saw
  (``refresh_session_activity_from_router``), and
* the idle verdict on a session with no accounted bytes stands only if that
  router was read after the session crossed its idle cutoff
  (``idle_verdict_is_evidenced``) -- so a router that cannot be read never
  turns into a guest who was "inactive".
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.domains.guest import tasks as tasks_module
from app.domains.guest.constants import (
    SESSION_ACTIVITY_GRACE_MINUTES,
    SESSION_PRESENCE_DISCONNECT_REASON,
    SESSION_PRESENCE_HOST_DEAD_AFTER_SECONDS,
    SESSION_PRESENCE_READ_AT_REDIS_KEY,
    GuestAuthMethod,
    GuestSessionStatus,
)
from app.domains.guest.service import (
    SESSION_TIME_LIMIT_DISCONNECT_REASON,
    SESSION_TIMEOUT_DISCONNECT_REASON,
    enforce_session_timeouts,
    reconcile_sessions_with_router_presence,
    refresh_session_activity_from_router,
)
from app.domains.guest.validators import (
    RouterActivityRead,
    idle_verdict_is_evidenced,
    last_heard_from_hotspot_hosts,
    later_session_activity,
    parse_routeros_duration_seconds,
)

from .test_guest import Fixture as GuestFixture
from .test_guest import make_fixture

_MAC = "aa:bb:cc:dd:ee:ff"
_MAC_KEY = "AA:BB:CC:DD:EE:FF"
_OTHER_MAC = "11:22:33:44:55:66"
_OTHER_MAC_KEY = "11:22:33:44:55:66"

_IDLE_MINUTES = 30
# What the idle sweep waits for before it will call a session idle.
_IDLE_DEADLINE_MINUTES = _IDLE_MINUTES + SESSION_ACTIVITY_GRACE_MINUTES


def _utcnow() -> datetime:
    return datetime.now(UTC)


async def _login(
    fx: GuestFixture, *, mac: str | None = _MAC, identifier: str = "+15551234567"
):
    result = await fx.guest_service.login_via_otp(
        identifier=identifier,
        code="GOOD",
        auth_method=GuestAuthMethod.OTP_SMS,
        organization_id=None,
        location_id=fx.location_id,
        router_id=fx.router.id,
        device_mac=mac,
    )
    session = result.session
    session.idle_timeout_minutes = _IDLE_MINUTES
    session.session_timeout_minutes = 1440
    return session


def _never_reported(session, *, minutes: float) -> None:
    """The incident's row: logged in ``minutes`` ago, ``last_activity_at``
    still the login's own value, not one accounted byte."""
    then = _utcnow() - timedelta(minutes=minutes)
    session.started_at = then
    session.last_activity_at = then
    session.bytes_uploaded = 0
    session.bytes_downloaded = 0


class _Reads:
    """``RouterActivityReadProtocol`` as a fake. ``asked`` records every
    router the sweep put the question to."""

    def __init__(
        self, read: RouterActivityRead | None = None, raises: bool = False
    ) -> None:
        self.read = read
        self.raises = raises
        self.asked: list[uuid.UUID] = []

    async def router_activity_read(self, *, router_id: uuid.UUID) -> RouterActivityRead:
        self.asked.append(router_id)
        if self.raises:
            raise RuntimeError("redis unavailable")
        assert self.read is not None
        return self.read


def _read_now() -> RouterActivityRead:
    return RouterActivityRead(applies=True, read_at=_utcnow())


# ============================================================================
# Reading activity out of /ip/hotspot/host
# ============================================================================


class TestIdleTimeFormsSeenOnRouterOs7:
    @pytest.mark.parametrize(
        ("raw", "seconds"),
        [
            ("0s", 0),  # a bypassed host passing traffic, hEX lite 7.21.4
            ("7m26s", 446),  # an authorized phone left on a desk
            ("16m43s", 1003),
            ("17m3s", 1023),
            ("1d2h", 86400 + 7200),
            ("1h5s", 3605),
        ],
    )
    def test_parses(self, raw: str, seconds: float) -> None:
        assert parse_routeros_duration_seconds(raw) == pytest.approx(seconds)


class TestLastHeardFromHotspotHosts:
    def test_a_bypassed_host_passing_traffic_was_heard_at_the_read(self) -> None:
        read_at = _utcnow()
        rows = [
            {
                "mac-address": _MAC_KEY,
                "bypassed": True,
                "authorized": False,
                "idle-time": "0s",
                "host-dead-time": "0s",
            }
        ]

        assert last_heard_from_hotspot_hosts(
            rows,
            read_at=read_at,
            dead_after_seconds=SESSION_PRESENCE_HOST_DEAD_AFTER_SECONDS,
        ) == {_MAC_KEY: read_at}

    def test_a_quiet_host_was_heard_idle_time_ago(self) -> None:
        read_at = _utcnow()
        rows = [
            {"mac-address": _MAC_KEY, "authorized": True, "idle-time": "7m26s"},
        ]

        heard = last_heard_from_hotspot_hosts(
            rows, read_at=read_at, dead_after_seconds=900
        )

        assert heard == {_MAC_KEY: read_at - timedelta(seconds=446)}

    @pytest.mark.parametrize("idle", [None, "", "never", "5x"])
    def test_a_row_that_states_no_idle_time_credits_nothing(self, idle) -> None:  # noqa: ANN001
        # "RouterOS did not say" is not "active just now".
        rows = [{"mac-address": _MAC_KEY, "bypassed": True, "idle-time": idle}]

        heard = last_heard_from_hotspot_hosts(
            rows, read_at=_utcnow(), dead_after_seconds=900
        )

        assert heard == {}

    def test_a_long_dead_host_credits_nothing(self) -> None:
        rows = [
            {
                "mac-address": _MAC_KEY,
                "idle-time": "2h45m",
                "host-dead-time": "2h45m",
            }
        ]

        heard = last_heard_from_hotspot_hosts(
            rows, read_at=_utcnow(), dead_after_seconds=900
        )

        assert heard == {}

    def test_macs_are_normalized_and_rows_without_one_ignored(self) -> None:
        read_at = _utcnow()
        rows = [
            {"mac-address": " aa:bb:cc:dd:ee:ff ", "idle-time": "0s"},
            {"address": "10.5.50.2", "idle-time": "0s"},
        ]

        assert last_heard_from_hotspot_hosts(
            rows, read_at=read_at, dead_after_seconds=900
        ) == {_MAC_KEY: read_at}

    def test_two_rows_for_one_mac_keep_the_most_recently_heard(self) -> None:
        # addresses-per-mac=2 on the test router.
        read_at = _utcnow()
        rows = [
            {"mac-address": _MAC_KEY, "idle-time": "9m"},
            {"mac-address": _MAC_KEY, "idle-time": "4s"},
            {"mac-address": _MAC_KEY, "idle-time": "3m"},
        ]

        heard = last_heard_from_hotspot_hosts(
            rows, read_at=read_at, dead_after_seconds=900
        )

        assert heard == {_MAC_KEY: read_at - timedelta(seconds=4)}


class TestLaterSessionActivity:
    async def test_moves_forward(self) -> None:
        fx = make_fixture()
        session = await _login(fx)
        _never_reported(session, minutes=40)
        now = _utcnow()
        heard = now - timedelta(seconds=30)

        assert later_session_activity(session, heard_at=heard, now=now) == heard

    async def test_never_moves_back(self) -> None:
        fx = make_fixture()
        session = await _login(fx)
        now = _utcnow()
        session.last_activity_at = now - timedelta(minutes=1)  # accounting

        assert (
            later_session_activity(
                session, heard_at=now - timedelta(minutes=10), now=now
            )
            is None
        )
        assert (
            later_session_activity(
                session, heard_at=session.last_activity_at, now=now
            )
            is None
        )

    async def test_a_reading_from_the_future_is_clamped_to_now(self) -> None:
        fx = make_fixture()
        session = await _login(fx)
        _never_reported(session, minutes=40)
        now = _utcnow()

        assert (
            later_session_activity(session, heard_at=now + timedelta(hours=1), now=now)
            == now
        )


# ============================================================================
# The refresh
# ============================================================================


class TestRefreshSessionActivityFromRouter:
    async def test_the_incident_an_active_bypassed_guest_survives_the_idle_deadline(
        self,
    ) -> None:
        fx = make_fixture()
        session = await _login(fx)
        _never_reported(session, minutes=_IDLE_DEADLINE_MINUTES + 5)
        now = _utcnow()

        refreshed = await refresh_session_activity_from_router(
            fx.repository,
            router_id=fx.router.id,
            last_heard={_MAC_KEY: now},  # idle-time 0s
            now=now,
        )
        expired = await enforce_session_timeouts(
            fx.repository, activity_reads=_Reads(_read_now())
        )

        assert [s.id for s in refreshed] == [session.id]
        assert session.last_activity_at == now
        assert expired == []
        assert session.status == GuestSessionStatus.ACTIVE.value
        # Still no accounted bytes: the host read credits activity, it does
        # not invent usage.
        assert session.total_bytes() == 0

    async def test_without_the_refresh_that_same_guest_is_expired(self) -> None:
        # The defect, so the test above is known to be testing something.
        fx = make_fixture()
        session = await _login(fx)
        _never_reported(session, minutes=_IDLE_DEADLINE_MINUTES + 5)

        expired = await enforce_session_timeouts(fx.repository)

        assert [s.id for s in expired] == [session.id]
        assert session.disconnect_reason == SESSION_TIMEOUT_DISCONNECT_REASON

    async def test_a_host_idle_longer_than_the_policy_still_expires(self) -> None:
        fx = make_fixture()
        session = await _login(fx)
        _never_reported(session, minutes=120)
        now = _utcnow()
        heard = now - timedelta(minutes=_IDLE_DEADLINE_MINUTES + 5)

        await refresh_session_activity_from_router(
            fx.repository, router_id=fx.router.id, last_heard={_MAC_KEY: heard}, now=now
        )
        expired = await enforce_session_timeouts(
            fx.repository, activity_reads=_Reads(_read_now())
        )

        # Credited with what the router saw -- and that was 45 minutes ago.
        assert session.last_activity_at == heard
        assert [s.id for s in expired] == [session.id]
        assert session.disconnect_reason == SESSION_TIMEOUT_DISCONNECT_REASON

    async def test_a_mac_the_router_does_not_list_is_left_to_the_presence_rule(
        self,
    ) -> None:
        fx = make_fixture()
        session = await _login(fx)
        _never_reported(session, minutes=60)
        before = session.last_activity_at

        refreshed = await refresh_session_activity_from_router(
            fx.repository,
            router_id=fx.router.id,
            last_heard={_OTHER_MAC_KEY: _utcnow()},
        )
        closed = await reconcile_sessions_with_router_presence(
            fx.repository,
            router_id=fx.router.id,
            present_macs=frozenset({_OTHER_MAC_KEY}),
        )

        assert refreshed == []
        assert session.last_activity_at == before
        assert [s.id for s in closed] == [session.id]
        assert session.disconnect_reason == SESSION_PRESENCE_DISCONNECT_REASON

    async def test_the_timestamp_never_regresses(self) -> None:
        fx = make_fixture()
        session = await _login(fx)
        now = _utcnow()
        accounted_at = now - timedelta(minutes=1)
        session.last_activity_at = accounted_at  # an Interim-Update just landed

        refreshed = await refresh_session_activity_from_router(
            fx.repository,
            router_id=fx.router.id,
            last_heard={_MAC_KEY: now - timedelta(minutes=12)},
            now=now,
        )

        assert refreshed == []
        assert session.last_activity_at == accounted_at

    async def test_only_the_device_that_was_heard_is_credited(self) -> None:
        fx = make_fixture()
        busy = await _login(fx, mac=_MAC)
        quiet = await _login(fx, mac=_OTHER_MAC, identifier="+15557654321")
        _never_reported(busy, minutes=35)
        _never_reported(quiet, minutes=35)
        quiet_before = quiet.last_activity_at
        now = _utcnow()

        refreshed = await refresh_session_activity_from_router(
            fx.repository, router_id=fx.router.id, last_heard={_MAC_KEY: now}, now=now
        )

        assert [s.id for s in refreshed] == [busy.id]
        assert quiet.last_activity_at == quiet_before

    async def test_a_session_without_a_device_is_skipped(self) -> None:
        fx = make_fixture()
        session = await _login(fx, mac=None)
        _never_reported(session, minutes=35)
        before = session.last_activity_at

        refreshed = await refresh_session_activity_from_router(
            fx.repository, router_id=fx.router.id, last_heard={_MAC_KEY: _utcnow()}
        )

        assert refreshed == []
        assert session.last_activity_at == before

    async def test_another_routers_sessions_are_never_touched(self) -> None:
        fx = make_fixture()
        session = await _login(fx)
        _never_reported(session, minutes=35)
        before = session.last_activity_at

        refreshed = await refresh_session_activity_from_router(
            fx.repository, router_id=uuid.uuid4(), last_heard={_MAC_KEY: _utcnow()}
        )

        assert refreshed == []
        assert session.last_activity_at == before

    async def test_a_just_credited_device_is_inside_the_presence_grace(self) -> None:
        # Refresh then reconcile is the task's order. A device credited a
        # moment ago must not be closed by a present_macs that disagrees.
        fx = make_fixture()
        session = await _login(fx)
        _never_reported(session, minutes=60)
        now = _utcnow()

        await refresh_session_activity_from_router(
            fx.repository, router_id=fx.router.id, last_heard={_MAC_KEY: now}, now=now
        )
        closed = await reconcile_sessions_with_router_presence(
            fx.repository, router_id=fx.router.id, present_macs=frozenset()
        )

        assert closed == []
        assert session.status == GuestSessionStatus.ACTIVE.value


# ============================================================================
# No expiry on a read that did not happen
# ============================================================================


class TestIdleVerdictIsEvidenced:
    async def _idle_session(self, *, idle_for: float, accounted_bytes: int = 0):
        fx = make_fixture()
        session = await _login(fx)
        _never_reported(session, minutes=idle_for)
        session.bytes_downloaded = accounted_bytes
        return session

    async def test_not_asking_changes_nothing(self) -> None:
        session = await self._idle_session(idle_for=45)

        assert idle_verdict_is_evidenced(session, None) is True

    async def test_a_router_the_presence_sweep_does_not_read_is_left_alone(
        self,
    ) -> None:
        session = await self._idle_session(idle_for=45)

        assert (
            idle_verdict_is_evidenced(session, RouterActivityRead(False, None)) is True
        )

    async def test_an_accounted_session_keeps_the_idle_rule(self) -> None:
        # It has an accounting producer; that producer going silent is the
        # lost-Stop case the idle rule exists for.
        session = await self._idle_session(idle_for=45, accounted_bytes=4096)

        assert (
            idle_verdict_is_evidenced(session, RouterActivityRead(True, None)) is True
        )

    async def test_no_record_of_a_read_is_not_evidence(self) -> None:
        session = await self._idle_session(idle_for=45)

        assert (
            idle_verdict_is_evidenced(session, RouterActivityRead(True, None)) is False
        )

    async def test_a_read_from_before_the_cutoff_saw_nothing_about_it(self) -> None:
        session = await self._idle_session(idle_for=45)
        # Last good read 20 minutes after login; the session crossed its
        # 30-minute cutoff 10 minutes after that, with the router dark.
        read_at = session.last_activity_at + timedelta(minutes=20)

        assert (
            idle_verdict_is_evidenced(session, RouterActivityRead(True, read_at))
            is False
        )

    async def test_a_read_after_the_cutoff_did_look(self) -> None:
        session = await self._idle_session(idle_for=45)
        at_cutoff = session.last_activity_at + timedelta(minutes=_IDLE_MINUTES)

        assert idle_verdict_is_evidenced(
            session, RouterActivityRead(True, at_cutoff)
        )
        assert idle_verdict_is_evidenced(
            session, RouterActivityRead(True, at_cutoff + timedelta(minutes=3))
        )


class TestAnUnreadableRouterDoesNotExpireItsGuests:
    async def test_no_read_since_login_no_idle_expiry(self) -> None:
        fx = make_fixture()
        session = await _login(fx)
        _never_reported(session, minutes=_IDLE_DEADLINE_MINUTES + 5)

        expired = await enforce_session_timeouts(
            fx.repository, activity_reads=_Reads(RouterActivityRead(True, None))
        )

        assert expired == []
        assert session.status == GuestSessionStatus.ACTIVE.value

    async def test_a_router_dark_since_before_the_deadline_no_idle_expiry(
        self,
    ) -> None:
        fx = make_fixture()
        session = await _login(fx)
        _never_reported(session, minutes=_IDLE_DEADLINE_MINUTES + 5)
        last_good_read = session.last_activity_at + timedelta(minutes=10)

        expired = await enforce_session_timeouts(
            fx.repository,
            activity_reads=_Reads(RouterActivityRead(True, last_good_read)),
        )

        assert expired == []
        assert session.status == GuestSessionStatus.ACTIVE.value

    async def test_once_it_is_read_again_and_the_host_is_quiet_it_expires(
        self,
    ) -> None:
        fx = make_fixture()
        session = await _login(fx)
        _never_reported(session, minutes=_IDLE_DEADLINE_MINUTES + 5)

        expired = await enforce_session_timeouts(
            fx.repository, activity_reads=_Reads(_read_now())
        )

        assert [s.id for s in expired] == [session.id]
        assert session.disconnect_reason == SESSION_TIMEOUT_DISCONNECT_REASON

    async def test_the_session_ceiling_still_applies_and_says_so(self) -> None:
        # Nothing becomes immortal -- and the row does not claim inactivity
        # this platform never observed.
        fx = make_fixture()
        session = await _login(fx)
        session.session_timeout_minutes = 60
        _never_reported(session, minutes=60 + SESSION_ACTIVITY_GRACE_MINUTES + 1)

        expired = await enforce_session_timeouts(
            fx.repository, activity_reads=_Reads(RouterActivityRead(True, None))
        )

        assert [s.id for s in expired] == [session.id]
        assert session.disconnect_reason == SESSION_TIME_LIMIT_DISCONNECT_REASON

    async def test_a_lookup_that_fails_does_not_end_the_session(self) -> None:
        fx = make_fixture()
        session = await _login(fx)
        _never_reported(session, minutes=_IDLE_DEADLINE_MINUTES + 5)

        expired = await enforce_session_timeouts(
            fx.repository, activity_reads=_Reads(raises=True)
        )

        assert expired == []
        assert session.status == GuestSessionStatus.ACTIVE.value

    async def test_the_router_is_asked_once_per_run(self) -> None:
        fx = make_fixture()
        first = await _login(fx, mac=_MAC)
        second = await _login(fx, mac=_OTHER_MAC, identifier="+15557654321")
        _never_reported(first, minutes=_IDLE_DEADLINE_MINUTES + 5)
        _never_reported(second, minutes=_IDLE_DEADLINE_MINUTES + 5)
        reads = _Reads(_read_now())

        expired = await enforce_session_timeouts(fx.repository, activity_reads=reads)

        assert len(expired) == 2
        assert reads.asked == [fx.router.id]


class TestEveryoneElseIsJudgedAsBefore:
    async def test_a_radius_accounted_session_still_idles_out_with_no_read(
        self,
    ) -> None:
        fx = make_fixture()
        session = await _login(fx)
        _never_reported(session, minutes=_IDLE_DEADLINE_MINUTES + 5)
        session.bytes_uploaded = 1_000
        session.bytes_downloaded = 250_000  # accounting did report, then stopped

        expired = await enforce_session_timeouts(
            fx.repository, activity_reads=_Reads(RouterActivityRead(True, None))
        )

        assert [s.id for s in expired] == [session.id]
        assert session.disconnect_reason == SESSION_TIMEOUT_DISCONNECT_REASON

    async def test_a_controller_or_nas_only_venue_still_idles_out(self) -> None:
        fx = make_fixture()
        session = await _login(fx)
        _never_reported(session, minutes=_IDLE_DEADLINE_MINUTES + 5)

        expired = await enforce_session_timeouts(
            fx.repository, activity_reads=_Reads(RouterActivityRead(False, None))
        )

        assert [s.id for s in expired] == [session.id]
        assert session.disconnect_reason == SESSION_TIMEOUT_DISCONNECT_REASON

    async def test_a_session_inside_its_idle_window_is_never_looked_up(self) -> None:
        fx = make_fixture()
        session = await _login(fx)
        _never_reported(session, minutes=10)
        reads = _Reads(RouterActivityRead(True, None))

        expired = await enforce_session_timeouts(fx.repository, activity_reads=reads)

        assert expired == []
        assert reads.asked == []
        assert session.status == GuestSessionStatus.ACTIVE.value


# ============================================================================
# The per-router task: credit on a good read, stamp it, nothing on a bad one
# ============================================================================


@dataclass
class _Capture:
    sections: dict = field(default_factory=dict)
    errors: dict = field(default_factory=dict)


class _FakeReader:
    def __init__(
        self, capture: _Capture | None = None, exc: Exception | None = None
    ) -> None:
        self.capture = capture
        self.exc = exc

    async def read_all(self, sections):  # noqa: ANN001, ANN201
        if self.exc is not None:
            raise self.exc
        return self.capture


class _FakeDbSession:
    def __init__(self) -> None:
        self.committed = False

    async def __aenter__(self):  # noqa: ANN204
        return self

    async def __aexit__(self, *exc) -> None:  # noqa: ANN002
        return None

    async def commit(self) -> None:
        self.committed = True

    async def rollback(self) -> None:
        return None


_SERVING = [{"name": "hotspot1", "disabled": False}]


@pytest.fixture
def wired(monkeypatch):  # noqa: ANN001, ANN201
    fx = make_fixture()
    db = _FakeDbSession()
    stamps: list[tuple[uuid.UUID, datetime]] = []

    async def _fake_target(router_id):  # noqa: ANN001, ANN202
        return fx.router, object()

    async def _fake_stamp(router_id, read_at):  # noqa: ANN001, ANN202
        stamps.append((router_id, read_at))

    monkeypatch.setattr(tasks_module, "_load_presence_target", _fake_target)
    monkeypatch.setattr(tasks_module, "SessionLocal", lambda: db)
    monkeypatch.setattr(tasks_module, "GuestRepository", lambda _session: fx.repository)
    monkeypatch.setattr(tasks_module, "_record_presence_read", _fake_stamp)
    return fx, db, stamps


class TestReconcileRouterSessionPresenceTaskCreditsActivity:
    async def test_a_listed_bypassed_host_is_credited_and_the_read_is_stamped(
        self, wired
    ) -> None:  # noqa: ANN001
        fx, db, stamps = wired
        session = await _login(fx)
        _never_reported(session, minutes=_IDLE_DEADLINE_MINUTES + 5)
        login_time = session.last_activity_at
        hosts = [
            {
                "mac-address": _MAC_KEY,
                "bypassed": True,
                "authorized": False,
                "idle-time": "0s",
                "host-dead-time": "0s",
            }
        ]
        reader = _FakeReader(
            _Capture(sections={"hotspot_servers": _SERVING, "hotspot_hosts": hosts})
        )

        result = await tasks_module._reconcile_router_session_presence_async(
            fx.router.id, reader_factory=lambda _creds: reader
        )

        assert result == {
            "router_id": str(fx.router.id),
            "closed": 0,
            "refreshed": 1,
            "skipped": None,
        }
        assert db.committed is True
        assert session.last_activity_at > login_time
        assert session.status == GuestSessionStatus.ACTIVE.value
        assert [router_id for router_id, _at in stamps] == [fx.router.id]
        # The stamp and the credited activity come from the same instant.
        assert stamps[0][1] == session.last_activity_at
        # And the guest the incident logged out is still online afterwards.
        assert await enforce_session_timeouts(fx.repository) == []

    async def test_a_good_read_that_finds_nobody_is_still_stamped(self, wired) -> None:  # noqa: ANN001
        # An empty host table is an answer. The timeout sweep needs to know
        # the router was looked at, not that somebody was there.
        fx, _db, stamps = wired
        reader = _FakeReader(
            _Capture(sections={"hotspot_servers": _SERVING, "hotspot_hosts": []})
        )

        result = await tasks_module._reconcile_router_session_presence_async(
            fx.router.id, reader_factory=lambda _creds: reader
        )

        assert result["skipped"] is None
        assert result["refreshed"] == 0
        assert len(stamps) == 1

    async def test_an_unreachable_router_credits_and_stamps_nothing(
        self, wired
    ) -> None:  # noqa: ANN001
        fx, db, stamps = wired
        session = await _login(fx)
        _never_reported(session, minutes=_IDLE_DEADLINE_MINUTES + 5)
        before = session.last_activity_at
        reader = _FakeReader(exc=TimeoutError("timed out"))

        result = await tasks_module._reconcile_router_session_presence_async(
            fx.router.id, reader_factory=lambda _creds: reader
        )

        assert result["skipped"] == "read_failed"
        assert db.committed is False
        assert stamps == []
        assert session.last_activity_at == before

    async def test_a_refused_section_credits_and_stamps_nothing(self, wired) -> None:  # noqa: ANN001
        fx, _db, stamps = wired
        session = await _login(fx)
        _never_reported(session, minutes=_IDLE_DEADLINE_MINUTES + 5)
        before = session.last_activity_at
        reader = _FakeReader(
            _Capture(
                sections={"hotspot_servers": _SERVING},
                errors={"hotspot_hosts": "no such command"},
            )
        )

        result = await tasks_module._reconcile_router_session_presence_async(
            fx.router.id, reader_factory=lambda _creds: reader
        )

        assert result["skipped"] == "read_failed"
        assert stamps == []
        assert session.last_activity_at == before

    async def test_a_router_with_no_hotspot_is_not_stamped(self, wired) -> None:  # noqa: ANN001
        # Its host table means nothing, so reading it is not looking.
        fx, _db, stamps = wired
        reader = _FakeReader(
            _Capture(
                sections={
                    "hotspot_servers": [{"name": "hs", "disabled": True}],
                    "hotspot_hosts": [],
                }
            )
        )

        result = await tasks_module._reconcile_router_session_presence_async(
            fx.router.id, reader_factory=lambda _creds: reader
        )

        assert result["skipped"] == "no_hotspot"
        assert stamps == []


# ============================================================================
# The stamp and the lookup that reads it back
# ============================================================================


class _FakeRedis:
    store: dict[str, str]

    def __init__(self, store: dict[str, str], fail: bool = False) -> None:
        self.store = store
        self.fail = fail
        self.closed = False
        self.ttl: dict[str, int] = {}

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        if self.fail:
            raise ConnectionError("redis down")
        self.store[key] = value
        if ex is not None:
            self.ttl[key] = ex

    async def get(self, key: str) -> str | None:
        if self.fail:
            raise ConnectionError("redis down")
        return self.store.get(key)

    async def aclose(self) -> None:
        self.closed = True


def _mikrotik_router(**overrides):  # noqa: ANN003, ANN202
    fields = {
        "vendor": "mikrotik",
        "management_ip_address": "10.20.0.9",
        "public_ip_address": None,
        "api_username": "platform-api",
        "api_credentials_encrypted": "ciphertext",
    }
    fields.update(overrides)
    return SimpleNamespace(**fields)


def _install_router(monkeypatch: pytest.MonkeyPatch, router) -> None:  # noqa: ANN001
    from app.domains.router import repository as router_repository

    class _Repo:
        def __init__(self, _session) -> None:  # noqa: ANN001
            pass

        async def get_by_id(self, _router_id):  # noqa: ANN001, ANN202
            return router

    monkeypatch.setattr(router_repository, "RouterRepository", _Repo)


def _install_redis(
    monkeypatch: pytest.MonkeyPatch, store: dict[str, str], *, fail: bool = False
) -> list[_FakeRedis]:
    from app.database import redis as redis_module

    clients: list[_FakeRedis] = []

    def _create() -> _FakeRedis:
        client = _FakeRedis(store, fail=fail)
        clients.append(client)
        return client

    monkeypatch.setattr(redis_module, "create_redis_client", _create)
    return clients


class TestThePresenceReadStamp:
    async def test_what_the_task_stamps_is_what_the_sweep_reads_back(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        router_id = uuid.uuid4()
        store: dict[str, str] = {}
        clients = _install_redis(monkeypatch, store)
        _install_router(monkeypatch, _mikrotik_router())
        read_at = _utcnow()

        await tasks_module._record_presence_read(router_id, read_at)
        read = await tasks_module._build_router_activity_read_lookup(
            MagicMock()
        ).router_activity_read(router_id=router_id)

        assert list(store) == [
            SESSION_PRESENCE_READ_AT_REDIS_KEY.format(router_id=router_id)
        ]
        assert read.applies is True
        assert read.read_at == pytest.approx(read_at, abs=timedelta(milliseconds=1))
        assert all(client.closed for client in clients)
        assert clients[0].ttl  # the key expires; it is not left forever

    async def test_a_stamp_that_cannot_be_written_does_not_fail_the_task(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_redis(monkeypatch, {}, fail=True)

        await tasks_module._record_presence_read(uuid.uuid4(), _utcnow())

    async def test_a_router_never_stamped_has_no_read(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_redis(monkeypatch, {})
        _install_router(monkeypatch, _mikrotik_router())

        read = await tasks_module._build_router_activity_read_lookup(
            MagicMock()
        ).router_activity_read(router_id=uuid.uuid4())

        assert read == RouterActivityRead(applies=True, read_at=None)

    @pytest.mark.parametrize(
        "router",
        [
            None,
            _mikrotik_router(vendor="omada"),
            _mikrotik_router(vendor="aruba_instant_on"),
            _mikrotik_router(management_ip_address=None, public_ip_address=None),
            _mikrotik_router(api_username=None),
            _mikrotik_router(api_credentials_encrypted=None),
        ],
    )
    async def test_a_router_the_presence_sweep_cannot_read_does_not_apply(
        self, monkeypatch: pytest.MonkeyPatch, router
    ) -> None:  # noqa: ANN001
        # Never asks Redis: there is nothing a stamp could say about it.
        from app.database import redis as redis_module

        def _must_not_connect():  # noqa: ANN202
            raise AssertionError("asked Redis about a router that is never read")

        monkeypatch.setattr(redis_module, "create_redis_client", _must_not_connect)
        _install_router(monkeypatch, router)

        read = await tasks_module._build_router_activity_read_lookup(
            MagicMock()
        ).router_activity_read(router_id=uuid.uuid4())

        assert read == RouterActivityRead(applies=False, read_at=None)

    async def test_a_redis_that_cannot_be_asked_is_not_a_read(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_redis(monkeypatch, {}, fail=True)
        _install_router(monkeypatch, _mikrotik_router())

        read = await tasks_module._build_router_activity_read_lookup(
            MagicMock()
        ).router_activity_read(router_id=uuid.uuid4())

        assert read == RouterActivityRead(applies=True, read_at=None)

    async def test_a_value_that_is_not_a_timestamp_is_not_a_read(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        router_id = uuid.uuid4()
        key = SESSION_PRESENCE_READ_AT_REDIS_KEY.format(router_id=router_id)
        _install_redis(monkeypatch, {key: "yesterday"})
        _install_router(monkeypatch, _mikrotik_router())

        read = await tasks_module._build_router_activity_read_lookup(
            MagicMock()
        ).router_activity_read(router_id=router_id)

        assert read == RouterActivityRead(applies=True, read_at=None)
