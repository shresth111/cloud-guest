"""The idle half of the session-timeout sweep, and the venues where it was
measuring nothing.

## The defect

``last_activity_at`` is written by exactly one method
(``GuestService.record_usage``) with exactly two producers: RADIUS accounting
Interim-Updates, and the Omada Open-API usage sweep
(``network_integration.usage_tasks``, which selects ``auth_mode == openapi``
in SQL). At an Omada venue in ``legacy`` (hotspot-operator) auth mode there is
neither -- a hotspot-operator credential provably cannot read the controller's
client table at all (contract CR-002) -- so the column stays frozen at the
value the login wrote.

The sweep then measured ``now - last_activity_at`` against the idle cutoff and
called the answer idleness. It is not idleness; it is the session's age. Every
guest at such a venue was expired mid-browse, on schedule, and told they had
been inactive.

## The rule these tests pin

**We do not end a session because we cannot see it.** Where activity cannot be
reported, the idle half is dropped and only the absolute
``session_timeout_minutes`` ceiling applies -- it measures ``started_at``, which
needs no reporting to be true -- and the row carries
``session_time_limit_reached`` rather than ``inactivity_timeout``, because only
one of those is a claim this platform can support there.

Nothing about a RouterOS venue changes: see ``TestMikrotikIsUntouched``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from app.domains.guest.constants import (
    SESSION_ACTIVITY_GRACE_MINUTES,
    VENUE_ACTIVITY_REPORTING_WINDOW_MINUTES,
    GuestAuthMethod,
    GuestSessionStatus,
)
from app.domains.guest.service import (
    SESSION_TIME_LIMIT_DISCONNECT_REASON,
    SESSION_TIMEOUT_DISCONNECT_REASON,
    enforce_session_timeouts,
)
from app.domains.network_integration import client_hooks
from app.domains.network_integration.constants import ControllerAuthMode
from app.domains.network_integration.crypto import (
    NetworkIntegrationCredentialDecryptionError,
)
from tests.unit.test_guest import _now, make_fixture


class _ActivityReporting:
    """The venue half of the sweep, as a fake. ``reports`` is the answer;
    ``asked`` records every venue the sweep put the question to, which is how
    the memoization is checked."""

    def __init__(self, reports: bool = True, raises: bool = False) -> None:
        self.reports = reports
        self.raises = raises
        self.asked: list[tuple[uuid.UUID | None, uuid.UUID | None]] = []

    async def venue_reports_guest_activity(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
    ) -> bool:
        self.asked.append((organization_id, location_id))
        if self.raises:
            raise RuntimeError("controller row unreadable")
        return self.reports


async def _session(
    fx,
    identifier: str,
    *,
    idle_timeout_minutes: int | None = 30,
    session_timeout_minutes: int | None = 240,
    idle_for: int,
    open_for: int | None = None,
):
    """One ACTIVE session, aged. Mirrors ``test_guest.py``'s own
    ``_sweep_candidate``: ``idle_for`` moves ``last_activity_at`` back,
    ``open_for`` moves ``started_at`` back independently."""
    result = await fx.guest_service.login_via_otp(
        identifier=identifier,
        code="GOOD",
        auth_method=GuestAuthMethod.OTP_SMS,
        organization_id=None,
        location_id=fx.location_id,
        router_id=fx.router.id,
    )
    session = result.session
    session.idle_timeout_minutes = idle_timeout_minutes
    session.session_timeout_minutes = session_timeout_minutes
    now = _now()
    session.started_at = now - timedelta(minutes=open_for or idle_for)
    session.last_activity_at = now - timedelta(minutes=idle_for)
    return session


class TestAVenueThatCannotReportActivityIsNotAskedToProveIt:
    async def test_a_guest_who_is_streaming_is_not_expired_for_idleness(
        self,
    ) -> None:
        """The defect, as a test. Idle cutoff 30 + grace, session ceiling 240,
        and a guest 45 minutes in with a frozen ``last_activity_at`` -- which
        at a legacy venue is what *every* guest looks like, including the one
        on a video call. Before this change the sweep expired them."""
        fx = make_fixture()
        streaming = await _session(fx, "+15553330001", idle_for=45)
        reporting = _ActivityReporting(reports=False)

        expired = await enforce_session_timeouts(
            fx.repository, None, reporting
        )

        assert expired == []
        assert streaming.status == GuestSessionStatus.ACTIVE.value
        assert streaming.ended_at is None

    async def test_the_same_guest_is_still_expired_at_the_session_ceiling(
        self,
    ) -> None:
        """Not an exemption. ``session_timeout_minutes`` is measured from
        ``started_at`` and needs nobody to report anything, so it still ends
        the session -- which is what keeps a legacy venue's rows from living
        forever."""
        fx = make_fixture()
        overrun = await _session(
            fx,
            "+15553330002",
            session_timeout_minutes=240,
            idle_for=45,
            open_for=240 + SESSION_ACTIVITY_GRACE_MINUTES + 1,
        )
        reporting = _ActivityReporting(reports=False)

        expired = await enforce_session_timeouts(
            fx.repository, None, reporting
        )

        assert [s.id for s in expired] == [overrun.id]
        assert overrun.status == GuestSessionStatus.EXPIRED.value

    async def test_that_ending_says_time_limit_not_inactivity(self) -> None:
        """A venue admin reading their guest history is told what happened,
        not what we guessed. "Inactivity" on a venue that cannot observe
        activity is an assertion with nothing behind it."""
        fx = make_fixture()
        overrun = await _session(
            fx,
            "+15553330003",
            session_timeout_minutes=60,
            idle_for=90,
            open_for=60 + SESSION_ACTIVITY_GRACE_MINUTES + 1,
        )

        await enforce_session_timeouts(
            fx.repository, None, _ActivityReporting(reports=False)
        )

        assert overrun.disconnect_reason == SESSION_TIME_LIMIT_DISCONNECT_REASON

    async def test_the_guest_is_still_told_their_time_ran_out(self) -> None:
        """The new reason must not fall through the portal's allowlist and
        leave a guest staring at an unexplained sign-in page."""
        from app.domains.guest.constants import GuestSessionEndedReason
        from app.domains.guest.service import _ended_session_reason

        session = MagicMock()
        session.status = GuestSessionStatus.EXPIRED.value
        session.disconnect_reason = SESSION_TIME_LIMIT_DISCONNECT_REASON
        assert _ended_session_reason(session) is GuestSessionEndedReason.TIMED_OUT

    async def test_a_reporting_venue_keeps_the_idle_rule_exactly(self) -> None:
        """The other half of the guarantee: where activity *is* reported,
        silence still means idleness and the reason is unchanged."""
        fx = make_fixture()
        idle = await _session(fx, "+15553330004", idle_for=45)

        expired = await enforce_session_timeouts(
            fx.repository, None, _ActivityReporting(reports=True)
        )

        assert [s.id for s in expired] == [idle.id]
        assert idle.disconnect_reason == SESSION_TIMEOUT_DISCONNECT_REASON

    async def test_omitting_the_lookup_changes_nothing(self) -> None:
        """Every caller that does not ask the question -- including
        ``GuestService.enforce_timeouts`` -- gets the pre-existing
        behaviour, which is what makes this parameter additive."""
        fx = make_fixture()
        idle = await _session(fx, "+15553330005", idle_for=45)

        expired = await enforce_session_timeouts(fx.repository)

        assert [s.id for s in expired] == [idle.id]
        assert idle.disconnect_reason == SESSION_TIMEOUT_DISCONNECT_REASON

    async def test_the_venue_is_asked_once_per_run_not_once_per_session(
        self,
    ) -> None:
        """Candidates cluster onto a handful of locations and the answer
        cannot change within a tick. A controller row read per expiring row
        would be a query per guest for a constant."""
        fx = make_fixture()
        await _session(fx, "+15553330006", idle_for=45)
        await _session(fx, "+15553330007", idle_for=50)
        await _session(fx, "+15553330008", idle_for=55)
        reporting = _ActivityReporting(reports=False)

        await enforce_session_timeouts(fx.repository, None, reporting)

        assert len(reporting.asked) == 1

    async def test_a_lookup_that_fails_does_not_end_the_session(self) -> None:
        """A question that could not be answered has not been answered
        "yes". Expiring a guest on the strength of a failed read is the
        exact move this work exists to stop."""
        fx = make_fixture()
        streaming = await _session(fx, "+15553330009", idle_for=45)

        expired = await enforce_session_timeouts(
            fx.repository, None, _ActivityReporting(raises=True)
        )

        assert expired == []
        assert streaming.status == GuestSessionStatus.ACTIVE.value


class _Integration:
    """The handful of fields the capability question reads off a real
    ``NetworkIntegration`` row."""

    def __init__(self, auth_mode: str, *, credentials: str | None = "cipher") -> None:
        self.id = uuid.uuid4()
        self.provider = "omada"
        self.auth_mode = auth_mode
        self.base_url = "https://controller.example:8043"
        self.controller_id = "c" * 32
        self.tls_mode = "strict"
        self.tls_pinned_sha256 = None
        self.credentials_encrypted = credentials


def _install_integration(monkeypatch: pytest.MonkeyPatch, integration) -> None:
    class _Repository:
        def __init__(self, _session) -> None:
            pass

        async def get_omada_integration_for_location(
            self, *, location_id, organization_id
        ):
            return integration

    monkeypatch.setattr(client_hooks, "NetworkIntegrationRepository", _Repository)
    monkeypatch.setattr(
        client_hooks, "decrypt_credentials", lambda *_a, **_k: {"username": "op"}
    )
    monkeypatch.setattr(
        client_hooks, "get_settings", lambda: MagicMock(omada_api_timeout_seconds=15.0)
    )


def _install_observed_activity(
    monkeypatch: pytest.MonkeyPatch, *, reported: bool
) -> list[dict]:
    """Stand in for the one query that answers "is anything reporting here".

    Patched on the guest repository module rather than on ``client_hooks``
    because the lookup imports it at call time; the name is resolved off the
    module either way. Returns the list of calls, so a test can assert the
    question was asked at all -- an implementation that answers from the
    integration row alone would leave it empty, which is exactly the defect.
    """
    import app.domains.guest.repository as guest_repository

    asked: list[dict] = []

    class _GuestRepository:
        def __init__(self, _session) -> None:
            pass

        async def venue_activity_was_reported_since(
            self, *, organization_id, location_id, since
        ) -> bool:
            asked.append(
                {
                    "organization_id": organization_id,
                    "location_id": location_id,
                    "since": since,
                }
            )
            return reported

    monkeypatch.setattr(guest_repository, "GuestRepository", _GuestRepository)
    return asked


class TestTheAnswerComesFromTheExistingCapabilityGate:
    """Deliberately driven through the **real** Omada provider rather than a
    fake one: the thing under test is that the sweep's question and the
    console's disabled-button question are answered by the same gate, so they
    cannot drift into disagreeing about the same venue.

    The capability gate is only half of it now -- see
    ``TestACapabilityIsNotAnObservation`` below for why, and for the tests
    that would have caught the guard being inert.
    """

    async def _ask(self, session=None) -> bool:
        lookup = client_hooks.build_controller_activity_reporting_lookup(
            session or MagicMock()
        )
        return await lookup.venue_reports_guest_activity(
            organization_id=uuid.uuid4(), location_id=uuid.uuid4()
        )

    async def test_a_legacy_venue_cannot_report_activity(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_integration(
            monkeypatch, _Integration(ControllerAuthMode.LEGACY.value)
        )
        assert await self._ask() is False

    async def test_an_openapi_venue_can_and_is(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Because the usage sweep polls it -- ``client_stats`` supported and
        ``list_omada_openapi_for_usage_sync`` selecting it are the same fact
        about the same venue -- **and** because something has actually
        reported here lately."""
        _install_integration(
            monkeypatch, _Integration(ControllerAuthMode.OPENAPI.value)
        )
        _install_observed_activity(monkeypatch, reported=True)
        assert await self._ask() is True

    async def test_a_venue_with_no_controller_at_all_can(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The MikroTik/RADIUS fleet. Not "unknown" -- known to hold: the NAS
        sends Interim-Updates every 300s and ``last_activity_at`` moves."""
        _install_integration(monkeypatch, None)
        assert await self._ask() is True

    async def test_a_venue_with_no_resolvable_tenant_is_left_alone(self) -> None:
        lookup = client_hooks.build_controller_activity_reporting_lookup(MagicMock())
        assert (
            await lookup.venue_reports_guest_activity(
                organization_id=None, location_id=None
            )
            is True
        )

    async def test_an_integration_with_no_credentials_cannot_be_polled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_integration(
            monkeypatch,
            _Integration(ControllerAuthMode.OPENAPI.value, credentials=None),
        )
        assert await self._ask() is False

    async def test_credentials_that_will_not_decrypt_cannot_be_polled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``auth_mode`` says openapi, but nothing can actually reach this
        controller, so no producer exists for its sessions either. Answering
        "yes" off the column alone would resume ending sessions on evidence
        we do not have."""
        integration = _Integration(ControllerAuthMode.OPENAPI.value)
        _install_integration(monkeypatch, integration)

        def _boom(*_a, **_k):
            raise NetworkIntegrationCredentialDecryptionError("key rotated")

        monkeypatch.setattr(client_hooks, "decrypt_credentials", _boom)
        assert await self._ask() is False


class TestACapabilityIsNotAnObservation:
    """The test that would have caught the guard being inert.

    The first version of this lookup ended at
    ``client_capabilities(config).client_stats.supported``, which is computed
    from ``auth_mode`` and contacts nothing. So every ``openapi`` venue
    answered ``True`` whether its controller was alive, unreachable or
    switched off -- and the guard read as working while guests went on being
    expired on a clock nothing was advancing. Measured at the real venue on
    2026-09-18: zero Interim-Updates that day, four of five expiries still
    written as ``inactivity_timeout``.

    Every test here pins the same distinction: *can* is not *does*.
    """

    async def _ask(self) -> bool:
        lookup = client_hooks.build_controller_activity_reporting_lookup(MagicMock())
        return await lookup.venue_reports_guest_activity(
            organization_id=uuid.uuid4(), location_id=uuid.uuid4()
        )

    async def test_a_capable_controller_that_reports_nothing_answers_no(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An ``openapi`` venue -- every capability supported, by
        construction -- whose column nothing has moved inside the window.
        The old implementation said ``True`` here."""
        _install_integration(
            monkeypatch, _Integration(ControllerAuthMode.OPENAPI.value)
        )
        _install_observed_activity(monkeypatch, reported=False)
        assert await self._ask() is False

    async def test_the_observation_is_actually_made(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Not just that the answer is right, but that it came from looking.
        An implementation that reads the integration row and stops asks
        nothing here, and this is the assertion it fails."""
        _install_integration(
            monkeypatch, _Integration(ControllerAuthMode.OPENAPI.value)
        )
        asked = _install_observed_activity(monkeypatch, reported=True)
        await self._ask()
        assert len(asked) == 1

    async def test_the_window_is_the_one_the_producers_report_on(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Both producers report every 300 s, so the window has to be wide
        enough for a missed tick and narrow enough that a controller that
        died an hour ago is not still counted as reporting."""
        _install_integration(
            monkeypatch, _Integration(ControllerAuthMode.OPENAPI.value)
        )
        asked = _install_observed_activity(monkeypatch, reported=True)
        await self._ask()
        age = datetime.now(UTC) - asked[0]["since"]
        assert abs(
            age - timedelta(minutes=VENUE_ACTIVITY_REPORTING_WINDOW_MINUTES)
        ) < timedelta(seconds=5)

    async def test_a_legacy_venue_is_still_refused_without_a_query(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Question one still short-circuits. A venue that provably cannot
        report is not worth observing, and the observation is a query."""
        _install_integration(
            monkeypatch, _Integration(ControllerAuthMode.LEGACY.value)
        )
        asked = _install_observed_activity(monkeypatch, reported=True)
        assert await self._ask() is False
        assert asked == []


class TestTheSweepIsWiredTheWayTheAppBuildsIt:
    """A hook nothing constructs is a hook that does not run. These build it
    the way the Beat task does rather than asserting the function exists.
    """

    def test_the_task_builds_the_real_lookup(self) -> None:
        from app.domains.guest.tasks import _build_activity_reporting_lookup

        lookup = _build_activity_reporting_lookup(MagicMock())
        assert callable(
            getattr(lookup, "venue_reports_guest_activity", None)
        ), "the Beat task's lookup does not satisfy VenueActivityReportingProtocol"

    async def test_the_sweep_run_passes_it_to_enforce_session_timeouts(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The wiring itself, end to end through the async bridge body: the
        sweep must hand ``enforce_session_timeouts`` a real lookup, not
        ``None``. Passing ``None`` here is exactly the shipped defect, and it
        would look completely ordinary in review."""
        from app.domains.guest import tasks as tasks_module

        seen: dict[str, object] = {}

        class _Session:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_exc):
                return False

            async def commit(self):
                return None

            async def rollback(self):
                return None

        async def _fake_enforce(repository, terminator=None, activity_reporting=None):
            seen["activity_reporting"] = activity_reporting
            return []

        monkeypatch.setattr(tasks_module, "SessionLocal", lambda: _Session())
        monkeypatch.setattr(tasks_module, "GuestRepository", lambda _s: MagicMock())
        monkeypatch.setattr(
            tasks_module, "_build_session_terminator", lambda _s, _r: None
        )
        monkeypatch.setattr(tasks_module, "enforce_session_timeouts", _fake_enforce)

        await tasks_module._run_session_timeout_sweep_async()

        lookup = seen["activity_reporting"]
        assert lookup is not None, "the sweep no longer asks the venue anything"
        assert callable(getattr(lookup, "venue_reports_guest_activity", None))


class TestMikrotikIsUntouched:
    """A RouterOS venue resolves no controller integration, so it takes the
    ``True`` branch and the sweep behaves exactly as it did. The suites that
    own that behaviour are the proof, and they are unmodified by this work:

    * ``tests/unit/test_guest.py`` -- ``TestSessionLifecycle``'s
      ``test_enforce_timeouts_expires_stale_sessions``,
      ``test_enforce_timeouts_ignores_fresh_sessions``,
      ``test_sweep_uses_idle_timeout_not_session_length``,
      ``test_sweep_leaves_guest_inside_idle_timeout_plus_grace``,
      ``test_short_idle_timeout_does_not_expire_between_interim_updates``,
      ``test_session_with_no_recorded_timeouts_is_not_exempt``,
      ``test_sweep_expires_session_past_its_time_limit_without_a_stop``,
      ``test_idle_cutoff_prefers_the_smaller_recorded_timeout``; and
      ``TestSessionTimeoutSweep``.
    * ``tests/unit/test_guest_session_presence.py`` -- the other exit for a
      RouterOS session the idle sweep cannot reach.
    * ``tests/unit/test_guest_last_ended_session.py`` -- the portal copy for
      ``inactivity_timeout``, which still means what it meant.

    Every one of those calls the sweep without an ``activity_reporting``
    lookup, which is the default and is the pre-change code path.
    """

    async def test_the_default_path_still_expires_an_idle_mikrotik_guest(
        self,
    ) -> None:
        fx = make_fixture()
        idle = await _session(fx, "+15553330100", idle_for=45)

        expired = await fx.guest_service.enforce_timeouts()

        assert [s.id for s in expired] == [idle.id]
        assert idle.disconnect_reason == SESSION_TIMEOUT_DISCONNECT_REASON

    async def test_a_venue_with_no_integration_row_reports_activity(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The RouterOS answer, through the real lookup rather than through a
        fake: no integration row, so nothing about the idle rule changes."""
        _install_integration(monkeypatch, None)
        lookup = client_hooks.build_controller_activity_reporting_lookup(MagicMock())

        assert (
            await lookup.venue_reports_guest_activity(
                organization_id=uuid.uuid4(), location_id=uuid.uuid4()
            )
            is True
        )
