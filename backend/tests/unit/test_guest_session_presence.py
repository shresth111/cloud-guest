"""A guest who has left the venue must stop being reported as connected.

The production report (2026-09-13, "Noida sector 56"): two sessions
``ACTIVE`` for 2h45m with zero bytes and a ``last_activity_at`` 49 seconds
after ``started_at``, while the router's own device list was empty. The
guest was admitted by an ``/ip hotspot ip-binding type=bypassed`` row from
``GET /agent/authorized-macs``, which never becomes a hotspot session and so
never produces RADIUS accounting -- no Stop, no Interim-Update, and therefore
no exit other than the 240-minute ``session_timeout_minutes``.

These tests pin the replacement exit, ``reconcile_sessions_with_router_presence``
and its task, and above all its fail-closed contract: only a *successful*
read of the router that lacks the MAC may close a session.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from app.domains.guest import tasks as tasks_module
from app.domains.guest.constants import (
    SESSION_PRESENCE_DISCONNECT_REASON,
    SESSION_PRESENCE_GRACE_MINUTES,
    SESSION_PRESENCE_HOST_DEAD_AFTER_SECONDS,
    GuestAuthMethod,
    GuestSessionStatus,
)
from app.domains.guest.service import reconcile_sessions_with_router_presence
from app.domains.guest.validators import (
    hotspot_is_serving,
    is_session_presence_judgeable,
    parse_routeros_duration_seconds,
    present_macs_from_hotspot_hosts,
)

from .test_guest import Fixture as GuestFixture
from .test_guest import make_fixture

_MAC = "aa:bb:cc:dd:ee:ff"
_OTHER_MAC = "11:22:33:44:55:66"


async def _login(
    fx: GuestFixture, *, mac: str | None = _MAC, identifier: str = "+15551234567"
):
    return await fx.guest_service.login_via_otp(
        identifier=identifier,
        code="GOOD",
        auth_method=GuestAuthMethod.OTP_SMS,
        organization_id=None,
        location_id=fx.location_id,
        router_id=fx.router.id,
        device_mac=mac,
    )


def _age(session, *, minutes: float) -> None:
    """Back-date a session the way the incident's rows looked: started long
    ago, and never refreshed since (no accounting ever arrived)."""
    then = datetime.now(UTC) - timedelta(minutes=minutes)
    session.started_at = then
    session.last_activity_at = then


# ============================================================================
# Pure interpretation of RouterOS rows
# ============================================================================


class TestParseRouterOsDuration:
    @pytest.mark.parametrize(
        ("raw", "seconds"),
        [
            ("0s", 0),
            ("5m32s", 332),
            ("1h", 3600),
            ("1w2d3h4m5s", 7 * 86400 + 2 * 86400 + 3 * 3600 + 4 * 60 + 5),
            ("250ms", 0.25),
            ("00:05:32", 332),
            ("1d02:00:00", 86400 + 7200),
        ],
    )
    def test_parses_routeros_forms(self, raw: str, seconds: float) -> None:
        assert parse_routeros_duration_seconds(raw) == pytest.approx(seconds)

    @pytest.mark.parametrize("raw", [None, "", "   ", "never", "5x", "5m junk"])
    def test_unparseable_is_none_not_zero(self, raw) -> None:  # noqa: ANN001
        # "RouterOS did not say" must stay distinguishable from "zero".
        assert parse_routeros_duration_seconds(raw) is None


class TestHotspotIsServing:
    def test_enabled_server(self) -> None:
        assert hotspot_is_serving([{"name": "hotspot1", "disabled": False}])

    def test_string_flags_are_understood(self) -> None:
        assert hotspot_is_serving([{"name": "hotspot1", "disabled": "false"}])
        assert not hotspot_is_serving([{"name": "hotspot1", "disabled": "true"}])

    def test_no_server_or_all_disabled_is_not_serving(self) -> None:
        # An empty host table on such a router means nothing -- it must
        # never be read as "every guest has left".
        assert not hotspot_is_serving([])
        assert not hotspot_is_serving([{"name": "hotspot1", "disabled": True}])


class TestPresentMacsFromHotspotHosts:
    def test_bypassed_and_authorized_hosts_both_count(self) -> None:
        rows = [
            {
                "mac-address": "AA:BB:CC:DD:EE:FF",
                "bypassed": True,
                "host-dead-time": "3s",
            },
            {
                "mac-address": "11:22:33:44:55:66",
                "authorized": True,
                "host-dead-time": "0s",
            },
        ]
        assert present_macs_from_hotspot_hosts(
            rows, dead_after_seconds=SESSION_PRESENCE_HOST_DEAD_AFTER_SECONDS
        ) == frozenset({"AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"})

    def test_macs_are_normalized(self) -> None:
        rows = [{"mac-address": " aa:bb:cc:dd:ee:ff "}]
        assert present_macs_from_hotspot_hosts(rows, dead_after_seconds=900) == {
            "AA:BB:CC:DD:EE:FF"
        }

    def test_long_dead_host_is_not_present(self) -> None:
        rows = [{"mac-address": "AA:BB:CC:DD:EE:FF", "host-dead-time": "2h45m"}]
        assert (
            present_macs_from_hotspot_hosts(rows, dead_after_seconds=900) == frozenset()
        )

    def test_missing_dead_time_counts_as_present(self) -> None:
        rows = [{"mac-address": "AA:BB:CC:DD:EE:FF"}]
        assert present_macs_from_hotspot_hosts(rows, dead_after_seconds=900) == {
            "AA:BB:CC:DD:EE:FF"
        }

    def test_row_without_mac_is_ignored(self) -> None:
        assert (
            present_macs_from_hotspot_hosts(
                [{"address": "10.5.50.2"}], dead_after_seconds=900
            )
            == frozenset()
        )


class TestIsSessionPresenceJudgeable:
    async def test_grace_applies_to_both_timestamps(self) -> None:
        fx = make_fixture()
        session = (await _login(fx)).session
        now = datetime.now(UTC)

        _age(session, minutes=SESSION_PRESENCE_GRACE_MINUTES + 1)
        assert is_session_presence_judgeable(
            session, now=now, grace_minutes=SESSION_PRESENCE_GRACE_MINUTES
        )

        # A portal re-POST just refreshed the row: not judged yet.
        session.last_activity_at = now - timedelta(minutes=1)
        assert not is_session_presence_judgeable(
            session, now=now, grace_minutes=SESSION_PRESENCE_GRACE_MINUTES
        )


# ============================================================================
# The reconciliation itself
# ============================================================================


class TestReconcileSessionsWithRouterPresence:
    async def test_the_incident_departed_guest_is_disconnected(self) -> None:
        fx = make_fixture()
        session = (await _login(fx)).session
        _age(session, minutes=165)  # 2h45m, zero bytes, as measured

        closed = await reconcile_sessions_with_router_presence(
            fx.repository, router_id=fx.router.id, present_macs=frozenset()
        )

        assert [s.id for s in closed] == [session.id]
        assert session.status == GuestSessionStatus.DISCONNECTED.value
        assert session.disconnect_reason == SESSION_PRESENCE_DISCONNECT_REASON
        assert session.ended_at is not None
        # This is what withdraws the router-side bypass: the authorized-MAC
        # endpoint is built from exactly this list.
        assert await fx.repository.list_active_sessions_for_router(fx.router.id) == []

    async def test_guest_still_on_the_network_is_untouched(self) -> None:
        fx = make_fixture()
        session = (await _login(fx)).session
        _age(session, minutes=165)

        closed = await reconcile_sessions_with_router_presence(
            fx.repository,
            router_id=fx.router.id,
            present_macs=frozenset({"AA:BB:CC:DD:EE:FF"}),
        )

        assert closed == []
        assert session.status == GuestSessionStatus.ACTIVE.value

    async def test_fresh_session_is_never_judged(self) -> None:
        fx = make_fixture()
        session = (await _login(fx)).session  # just logged in

        closed = await reconcile_sessions_with_router_presence(
            fx.repository, router_id=fx.router.id, present_macs=frozenset()
        )

        assert closed == []
        assert session.status == GuestSessionStatus.ACTIVE.value

    async def test_session_without_a_device_is_never_judged(self) -> None:
        fx = make_fixture()
        session = (await _login(fx, mac=None)).session
        assert session.device_id is None
        _age(session, minutes=165)

        closed = await reconcile_sessions_with_router_presence(
            fx.repository, router_id=fx.router.id, present_macs=frozenset()
        )

        assert closed == []
        assert session.status == GuestSessionStatus.ACTIVE.value

    async def test_only_the_departed_device_is_closed(self) -> None:
        fx = make_fixture()
        gone = (await _login(fx, mac=_MAC)).session
        here = (await _login(fx, mac=_OTHER_MAC, identifier="+15557654321")).session
        _age(gone, minutes=60)
        _age(here, minutes=60)

        closed = await reconcile_sessions_with_router_presence(
            fx.repository,
            router_id=fx.router.id,
            present_macs=frozenset({"11:22:33:44:55:66"}),
        )

        assert [s.id for s in closed] == [gone.id]
        assert here.status == GuestSessionStatus.ACTIVE.value

    async def test_other_routers_sessions_are_never_touched(self) -> None:
        fx = make_fixture()
        session = (await _login(fx)).session
        _age(session, minutes=165)

        closed = await reconcile_sessions_with_router_presence(
            fx.repository, router_id=uuid.uuid4(), present_macs=frozenset()
        )

        assert closed == []
        assert session.status == GuestSessionStatus.ACTIVE.value


# ============================================================================
# The per-router task: fail closed on every read failure
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
        self.requested: tuple[str, ...] | None = None

    async def read_all(self, sections):  # noqa: ANN001, ANN201
        self.requested = tuple(sections)
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
    """The task wired to the in-memory guest fixture: no Postgres, no
    RouterOS, one departed guest aged well past the grace window."""
    fx = make_fixture()
    db = _FakeDbSession()

    async def _fake_target(router_id):  # noqa: ANN001, ANN202
        return fx.router, object()

    monkeypatch.setattr(tasks_module, "_load_presence_target", _fake_target)
    monkeypatch.setattr(tasks_module, "SessionLocal", lambda: db)
    monkeypatch.setattr(tasks_module, "GuestRepository", lambda _session: fx.repository)
    return fx, db


async def _aged_session(fx: GuestFixture):
    session = (await _login(fx)).session
    _age(session, minutes=165)
    return session


class TestReconcileRouterSessionPresenceTask:
    async def test_successful_read_without_the_mac_closes_the_session(
        self, wired
    ) -> None:  # noqa: ANN001
        fx, db = wired
        session = await _aged_session(fx)
        reader = _FakeReader(
            _Capture(sections={"hotspot_servers": _SERVING, "hotspot_hosts": []})
        )

        result = await tasks_module._reconcile_router_session_presence_async(
            fx.router.id, reader_factory=lambda _creds: reader
        )

        assert result["closed"] == 1
        assert result["skipped"] is None
        assert reader.requested == ("hotspot_servers", "hotspot_hosts")
        assert db.committed is True
        assert session.status == GuestSessionStatus.DISCONNECTED.value

    async def test_successful_read_with_the_mac_keeps_the_session(self, wired) -> None:  # noqa: ANN001
        fx, _db = wired
        session = await _aged_session(fx)
        hosts = [
            {
                "mac-address": "AA:BB:CC:DD:EE:FF",
                "bypassed": True,
                "host-dead-time": "4s",
            }
        ]
        reader = _FakeReader(
            _Capture(sections={"hotspot_servers": _SERVING, "hotspot_hosts": hosts})
        )

        result = await tasks_module._reconcile_router_session_presence_async(
            fx.router.id, reader_factory=lambda _creds: reader
        )

        assert result["closed"] == 0
        assert session.status == GuestSessionStatus.ACTIVE.value

    async def test_unreachable_router_changes_nothing(self, wired) -> None:  # noqa: ANN001
        fx, db = wired
        session = await _aged_session(fx)
        reader = _FakeReader(exc=TimeoutError("timed out"))

        result = await tasks_module._reconcile_router_session_presence_async(
            fx.router.id, reader_factory=lambda _creds: reader
        )

        assert result == {
            "router_id": str(fx.router.id),
            "closed": 0,
            "skipped": "read_failed",
        }
        assert db.committed is False
        assert session.status == GuestSessionStatus.ACTIVE.value

    async def test_section_error_changes_nothing(self, wired) -> None:  # noqa: ANN001
        # read_all records a refused menu in `errors` and leaves the section
        # out. A missing hotspot_hosts must not read as an empty one.
        fx, _db = wired
        session = await _aged_session(fx)
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
        assert session.status == GuestSessionStatus.ACTIVE.value

    async def test_router_without_an_enabled_hotspot_changes_nothing(
        self, wired
    ) -> None:  # noqa: ANN001
        fx, _db = wired
        session = await _aged_session(fx)
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
        assert session.status == GuestSessionStatus.ACTIVE.value

    async def test_router_without_credentials_is_never_dialled(
        self, monkeypatch
    ) -> None:  # noqa: ANN001
        fx = make_fixture()

        async def _no_creds(router_id):  # noqa: ANN001, ANN202
            return fx.router, None

        monkeypatch.setattr(tasks_module, "_load_presence_target", _no_creds)

        def _must_not_dial(_creds):  # noqa: ANN001, ANN202
            raise AssertionError("dialled a router with no usable credentials")

        result = await tasks_module._reconcile_router_session_presence_async(
            fx.router.id, reader_factory=_must_not_dial
        )

        assert result["skipped"] == "unreadable"


def test_run_session_presence_sweep_task_bridges_into_async(monkeypatch) -> None:  # noqa: ANN001
    async def _fake_dispatch() -> dict[str, object]:
        return {"dispatched": 2, "skipped_locked": False}

    monkeypatch.setattr(
        tasks_module, "_dispatch_session_presence_sweep_async", _fake_dispatch
    )

    assert tasks_module.run_session_presence_sweep() == {
        "dispatched": 2,
        "skipped_locked": False,
    }


def test_presence_sweep_is_beat_scheduled() -> None:
    from app.core.celery_app import celery_app
    from app.domains.guest.constants import (
        SESSION_PRESENCE_SWEEP_INTERVAL_SECONDS,
        TASK_RUN_SESSION_PRESENCE_SWEEP,
    )

    entry = celery_app.conf.beat_schedule["guest-session-presence-sweep"]
    assert entry["task"] == TASK_RUN_SESSION_PRESENCE_SWEEP
    assert entry["schedule"] == SESSION_PRESENCE_SWEEP_INTERVAL_SECONDS
    assert TASK_RUN_SESSION_PRESENCE_SWEEP in celery_app.tasks
