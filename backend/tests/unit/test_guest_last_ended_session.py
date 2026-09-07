"""``GET /guest/session/last-ended`` -- what a returning guest is told
about the session that just stopped, and what they are not.

The feature exists because a guest whose session ends while the portal
tab is closed (which is every real guest -- sessions run for hours) lost
their internet and then met a sign-in page identical to a first-time
visit. Nothing connected the two events, so it read as "the WiFi is
broken again".

Two things are actually under test here, and the second matters more
than the first:

1. The decision table. Which endings produce the "you were disconnected"
   screen, and which deliberately produce nothing at all.
2. The disclosure boundary. This endpoint is unauthenticated and its only
   credential is a MAC address that, for an *ended* session, is backed by
   nothing -- the device is no longer authorised, so holding the MAC no
   longer implies being the guest. Anyone who can observe a MAC can ask.
   ``TestItTellsAStrangerNothingAboutTheGuest`` pins that down against
   the response object rather than trusting the schema's field list to
   stay short, because the tempting change here has always been "just
   reuse ``GuestLoginResponse``" -- which carries the guest's unmasked
   phone number and a ``disconnect_reason`` holding operators' private
   notes about guests.

Same plain-``assert``/native-``async def`` style as ``test_guest.py``,
whose fakes are reused rather than rebuilt so a change to the real
service signature breaks here too.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.domains.guest.constants import (
    DEFAULT_IDLE_TIMEOUT_MINUTES,
    LAST_ENDED_SESSION_WINDOW_MINUTES,
    GuestAuthMethod,
    GuestSessionEndedReason,
    GuestSessionStatus,
)
from app.domains.guest.service import _ended_session_reason
from app.domains.guest.validators import (
    has_session_reached_time_limit,
    is_session_timed_out,
)

from .test_guest import Fixture as GuestFixture
from .test_guest import make_fixture

pytestmark = pytest.mark.asyncio

_MAC = "aa:bb:cc:dd:ee:ff"


async def _login(fx: GuestFixture, *, mac: str = _MAC):
    return await fx.guest_service.login_via_otp(
        identifier="+15551234567",
        code="GOOD",
        auth_method=GuestAuthMethod.OTP_SMS,
        organization_id=None,
        location_id=fx.location_id,
        router_id=fx.router.id,
        device_mac=mac,
    )


async def _end(
    fx: GuestFixture,
    session,
    *,
    status: str,
    disconnect_reason: str | None,
    minutes_ago: float = 1.0,
):
    """Put a session into a real terminal state the way the production
    code paths do -- a direct repository write, which is exactly what
    ``enforce_session_timeouts`` and ``BlocklistEnforcer.enforce`` both
    do. Going through the service's own disconnect methods would refuse
    some of these transitions and would not let a test place ``ended_at``
    in the past, which is the whole point of the window tests."""
    return await fx.repository.update_session(
        session,
        {
            "status": status,
            "ended_at": datetime.now(UTC) - timedelta(minutes=minutes_ago),
            "disconnect_reason": disconnect_reason,
        },
    )


async def _nas_client(fx: GuestFixture):
    """A real, shared-secret-authenticated NAS identity, built the same
    way ``test_guest.py``'s RADIUS tests build theirs -- ``authorize``
    takes one and never re-authenticates it."""
    await fx.radius_service.register_nas(
        actor_user_id=uuid.uuid4(),
        router_id=fx.router.id,
        nas_identifier="nas-last-ended",
        shared_secret="supersecret123",
    )
    return await fx.radius_service.authenticate_nas(
        nas_identifier="nas-last-ended", shared_secret="supersecret123"
    )


class TestTheFoundersCase:
    async def test_a_session_that_timed_out_is_reported_as_timed_out(self) -> None:
        """The whole point: the guest's 240 minutes ran out while their
        browser was closed, they reopen it, and the portal now has
        something true to say instead of a blank form."""
        fx = make_fixture()
        login = await _login(fx)
        await _end(
            fx,
            login.session,
            status=GuestSessionStatus.EXPIRED.value,
            disconnect_reason="inactivity_timeout",
        )

        result = await fx.guest_service.get_last_ended_session_for_device(
            router_id=fx.router.id, device_mac=_MAC
        )

        assert result is not None
        assert result.reason is GuestSessionEndedReason.TIMED_OUT

    async def test_it_carries_the_venues_session_length(self) -> None:
        """``session_timeout_minutes`` is what lets the portal say "this
        is how long sessions last here" rather than only "it stopped".
        It is venue policy -- identical for every guest at the location
        -- which is why it is safe to return at all."""
        fx = make_fixture()
        login = await _login(fx)
        await _end(
            fx,
            login.session,
            status=GuestSessionStatus.EXPIRED.value,
            disconnect_reason="inactivity_timeout",
        )

        result = await fx.guest_service.get_last_ended_session_for_device(
            router_id=fx.router.id, device_mac=_MAC
        )

        assert result is not None
        assert result.session_timeout_minutes == login.session.session_timeout_minutes


class TestWhichEndingsAGuestIsToldAbout:
    @pytest.mark.parametrize(
        "disconnect_reason",
        [
            "radius_accounting_stop",
            "Lost-Service",  # a real Acct-Terminate-Cause seen in production
            "User-Request",
            "radius_accounting_on",
            "radius_accounting_off",
            "guest_initiated",
            None,
        ],
    )
    async def test_every_disconnected_ending_is_reported(
        self, disconnect_reason: str | None
    ) -> None:
        """``DISCONNECTED`` is defined by ``GuestSessionStatus`` as "a
        normal, non-punitive end of use ... reconnecting immediately is
        allowed" -- which is precisely the precondition for a screen
        whose main button is "Sign in again". So every one of its causes
        qualifies, and none of them needs the free-text reason read to
        decide."""
        fx = make_fixture()
        login = await _login(fx)
        await _end(
            fx,
            login.session,
            status=GuestSessionStatus.DISCONNECTED.value,
            disconnect_reason=disconnect_reason,
        )

        result = await fx.guest_service.get_last_ended_session_for_device(
            router_id=fx.router.id, device_mac=_MAC
        )

        assert result is not None
        assert result.reason is GuestSessionEndedReason.DISCONNECTED

    @pytest.mark.parametrize(
        "disconnect_reason",
        [
            "data_limit_exceeded",
            "fup_data_quota_exceeded_daily",
            "fup_data_quota_exceeded_weekly",
            "fup_data_quota_exceeded_monthly",
        ],
    )
    async def test_data_quota_exhaustion_is_not_reported_as_a_timeout(
        self, disconnect_reason: str
    ) -> None:
        """``EXPIRED`` is written for several different things, and only
        some of them are about time. A guest who has used up their DATA
        allowance has not run out of *time*, and telling them to sign in
        again sends them round a loop that ends the same way. They get
        the ordinary sign-in page, where the quota is enforced and
        explained properly.

        This is why the mapping matches ``inactivity_timeout`` exactly
        rather than keying off the status alone.

        The three ``fup_time_quota_exceeded_*`` reasons used to be in this
        list and now have their own test below. They left because they
        became tellable -- a daily time limit is now a real, enforced
        setting with a true sentence to say about it. These four stayed
        because a data limit still is not: the "Add a data limit" control
        remains unenforced and still says so on its face."""
        fx = make_fixture()
        login = await _login(fx)
        await _end(
            fx,
            login.session,
            status=GuestSessionStatus.EXPIRED.value,
            disconnect_reason=disconnect_reason,
        )

        assert (
            await fx.guest_service.get_last_ended_session_for_device(
                router_id=fx.router.id, device_mac=_MAC
            )
            is None
        )

    @pytest.mark.parametrize(
        "disconnect_reason",
        [
            "fup_time_quota_exceeded_daily",
            "fup_time_quota_exceeded_weekly",
            "fup_time_quota_exceeded_monthly",
        ],
    )
    async def test_a_spent_time_allowance_is_told_apart_from_a_timeout(
        self, disconnect_reason: str
    ) -> None:
        """A guest who has spent the venue's daily connected-time
        allowance and a guest whose session timed out are both EXPIRED,
        and they need opposite advice.

        The timed-out guest can sign straight back in. This one cannot --
        ``_enforce_fup_quota`` refuses the very next login until the
        period rolls over -- so showing them "sign in again to carry on"
        would walk them into a refusal with no explanation. They get their
        own reason so the portal can say something true instead.

        These three reasons used to return ``None`` (the guest was told
        nothing) and were parametrized into
        ``test_data_quota_exhaustion_is_not_reported_as_a_timeout``. They
        moved here because they became tellable: a daily time limit is now
        something the dashboard can set and this platform enforces
        end-to-end, so there is a true sentence to say. The data-quota
        reasons stayed behind, silent, because there still is not one.

        Asserted as "not TIMED_OUT" as well as "is TIME_LIMIT_REACHED",
        because collapsing the two back together is the regression this
        guards."""
        fx = make_fixture()
        login = await _login(fx)
        await _end(
            fx,
            login.session,
            status=GuestSessionStatus.EXPIRED.value,
            disconnect_reason=disconnect_reason,
        )

        result = await fx.guest_service.get_last_ended_session_for_device(
            router_id=fx.router.id, device_mac=_MAC
        )

        assert result is not None
        assert result.reason is GuestSessionEndedReason.TIME_LIMIT_REACHED
        assert result.reason is not GuestSessionEndedReason.TIMED_OUT

    async def test_an_unknown_future_expired_reason_is_not_reported(self) -> None:
        """The mapping is an allowlist and fails closed. Whoever adds the
        next ``EXPIRED`` reason has to decide what a guest should be told
        about it; until they do, the guest is told nothing, which is
        today's behaviour and merely unhelpful -- as opposed to being
        told something false."""
        fx = make_fixture()
        login = await _login(fx)
        await _end(
            fx,
            login.session,
            status=GuestSessionStatus.EXPIRED.value,
            disconnect_reason="some_reason_invented_next_year",
        )

        assert (
            await fx.guest_service.get_last_ended_session_for_device(
                router_id=fx.router.id, device_mac=_MAC
            )
            is None
        )


class TestABlockedGuestIsNeverToldTheirSessionExpired:
    """The single most important case in this file.

    ``guest_access.enforcement.BlocklistEnforcer`` ends a blocked guest's
    sessions as ``TERMINATED``. Showing that guest "your session expired
    -- sign in again" would be false, and would replace a clear refusal
    at the sign-in step with a detour through a retry that cannot
    succeed. It would also be a regression against backend #169, which
    removed the operator's private note from what a refused guest sees:
    the note lives on in ``disconnect_reason`` as
    ``"Blocked: {reason}"``.
    """

    async def test_a_terminated_session_produces_nothing(self) -> None:
        fx = make_fixture()
        login = await _login(fx)
        await _end(
            fx,
            login.session,
            status=GuestSessionStatus.TERMINATED.value,
            disconnect_reason="Blocked: ex-employee, do not readmit",
        )

        assert (
            await fx.guest_service.get_last_ended_session_for_device(
                router_id=fx.router.id, device_mac=_MAC
            )
            is None
        )

    async def test_the_operators_note_cannot_travel_even_as_a_bucket(self) -> None:
        """Belt and braces on the mapping itself: the note is not merely
        absent from the response, the row it sits on maps to no reportable
        reason at all, so there is no code path on which it could be
        read and re-emitted."""
        fx = make_fixture()
        login = await _login(fx)
        terminated = await _end(
            fx,
            login.session,
            status=GuestSessionStatus.TERMINATED.value,
            disconnect_reason="Blocked: chargeback, do not serve",
        )

        assert _ended_session_reason(terminated) is None

    async def test_a_blocked_guest_falls_through_to_the_ordinary_sign_in(self) -> None:
        """Stated as its own test because it is the *product* decision,
        not an implementation detail: ``None`` here means the portal
        routes them to ``/portal/welcome``, where a real sign-in attempt
        gets a real, correctly-worded refusal."""
        fx = make_fixture()
        login = await _login(fx)
        await _end(
            fx,
            login.session,
            status=GuestSessionStatus.TERMINATED.value,
            disconnect_reason="Blocked by a guest access rule",
        )

        assert (
            await fx.guest_service.get_last_ended_session_for_device(
                router_id=fx.router.id, device_mac=_MAC
            )
            is None
        )


class TestAPausedSessionIsNotAnEnding:
    async def test_paused_produces_nothing(self) -> None:
        """``PAUSED`` is the one non-terminal status -- an admin can
        resume it back to ``ACTIVE`` -- and the real pause path never
        writes ``ended_at`` at all. Nothing has ended, so there is
        nothing to report."""
        fx = make_fixture()
        login = await _login(fx)
        await _end(
            fx,
            login.session,
            status=GuestSessionStatus.PAUSED.value,
            disconnect_reason="paused pending review",
        )

        assert (
            await fx.guest_service.get_last_ended_session_for_device(
                router_id=fx.router.id, device_mac=_MAC
            )
            is None
        )


class TestAnActiveSessionIsNotThisEndpointsQuestion:
    async def test_a_live_session_produces_nothing_here(self) -> None:
        """A connected guest is answered by ``/session/active``, which
        the portal asks first. This endpoint must not also claim them,
        or a guest who is online would be told they were disconnected."""
        fx = make_fixture()
        await _login(fx)

        assert (
            await fx.guest_service.get_last_ended_session_for_device(
                router_id=fx.router.id, device_mac=_MAC
            )
            is None
        )


class TestTheFreshnessWindow:
    async def test_a_session_that_just_ended_is_reported(self) -> None:
        fx = make_fixture()
        login = await _login(fx)
        await _end(
            fx,
            login.session,
            status=GuestSessionStatus.EXPIRED.value,
            disconnect_reason="inactivity_timeout",
            minutes_ago=0.1,
        )

        assert (
            await fx.guest_service.get_last_ended_session_for_device(
                router_id=fx.router.id, device_mac=_MAC
            )
            is not None
        )

    async def test_a_session_inside_the_window_is_still_reported(self) -> None:
        """Deliberately near the far edge: the window has to be generous
        enough to survive a phone sitting in a pocket through a meal,
        because the portal is only ever reached when the device next asks
        for a page."""
        fx = make_fixture()
        login = await _login(fx)
        await _end(
            fx,
            login.session,
            status=GuestSessionStatus.EXPIRED.value,
            disconnect_reason="inactivity_timeout",
            minutes_ago=LAST_ENDED_SESSION_WINDOW_MINUTES - 1,
        )

        assert (
            await fx.guest_service.get_last_ended_session_for_device(
                router_id=fx.router.id, device_mac=_MAC
            )
            is not None
        )

    async def test_an_older_session_is_not_reported(self) -> None:
        """Past the window the guest is simply a returning guest.
        "You were disconnected" would describe an event from a previous
        visit and read as a fresh fault rather than an explanation."""
        fx = make_fixture()
        login = await _login(fx)
        await _end(
            fx,
            login.session,
            status=GuestSessionStatus.EXPIRED.value,
            disconnect_reason="inactivity_timeout",
            minutes_ago=LAST_ENDED_SESSION_WINDOW_MINUTES + 1,
        )

        assert (
            await fx.guest_service.get_last_ended_session_for_device(
                router_id=fx.router.id, device_mac=_MAC
            )
            is None
        )

    async def test_yesterdays_session_is_not_reported(self) -> None:
        fx = make_fixture()
        login = await _login(fx)
        await _end(
            fx,
            login.session,
            status=GuestSessionStatus.DISCONNECTED.value,
            disconnect_reason="radius_accounting_stop",
            minutes_ago=60 * 24,
        )

        assert (
            await fx.guest_service.get_last_ended_session_for_device(
                router_id=fx.router.id, device_mac=_MAC
            )
            is None
        )


class TestScoping:
    async def test_an_unknown_mac_produces_nothing(self) -> None:
        fx = make_fixture()
        login = await _login(fx)
        await _end(
            fx,
            login.session,
            status=GuestSessionStatus.EXPIRED.value,
            disconnect_reason="inactivity_timeout",
        )

        assert (
            await fx.guest_service.get_last_ended_session_for_device(
                router_id=fx.router.id, device_mac="11:22:33:44:55:66"
            )
            is None
        )

    async def test_another_routers_id_produces_nothing(self) -> None:
        """``router_id`` narrows rather than widens: it is ANDed with the
        device, so guessing a different router's id returns fewer rows,
        never another tenant's."""
        fx = make_fixture()
        login = await _login(fx)
        await _end(
            fx,
            login.session,
            status=GuestSessionStatus.EXPIRED.value,
            disconnect_reason="inactivity_timeout",
        )

        assert (
            await fx.guest_service.get_last_ended_session_for_device(
                router_id=uuid.uuid4(), device_mac=_MAC
            )
            is None
        )

    async def test_a_device_that_never_connected_produces_nothing(self) -> None:
        fx = make_fixture()

        assert (
            await fx.guest_service.get_last_ended_session_for_device(
                router_id=fx.router.id, device_mac=_MAC
            )
            is None
        )


class TestItTellsAStrangerNothingAboutTheGuest:
    """The endpoint is unauthenticated and a MAC with no live session
    behind it proves nothing about who is holding the device. So the
    response is checked here as a whole object, not field by field -- a
    later change that widens it (most plausibly by reaching for the
    existing ``GuestLoginResponse``) has to fail one of these.
    """

    async def _payload(self, fx: GuestFixture) -> dict:
        from app.domains.guest.schemas import GuestLastEndedSessionResponse

        result = await fx.guest_service.get_last_ended_session_for_device(
            router_id=fx.router.id, device_mac=_MAC
        )
        assert result is not None
        return GuestLastEndedSessionResponse(
            reason=result.reason,
            session_timeout_minutes=result.session_timeout_minutes,
            idle_timeout_minutes=result.idle_timeout_minutes,
        ).model_dump(mode="json")

    async def test_the_response_has_exactly_three_fields(self) -> None:
        """Was two. ``idle_timeout_minutes`` is the third, and it had to
        clear the same bar the other two did rather than being waved
        through: it is venue policy, identical for every guest at the
        location, so a stranger holding an observed MAC learns nothing
        about the guest from it. The count is asserted exactly -- not
        ``>= 3`` -- because the point of this test is that widening the
        response is a decision somebody has to come here and make."""
        fx = make_fixture()
        login = await _login(fx)
        await _end(
            fx,
            login.session,
            status=GuestSessionStatus.EXPIRED.value,
            disconnect_reason="inactivity_timeout",
        )

        assert set(await self._payload(fx)) == {
            "reason",
            "session_timeout_minutes",
            "idle_timeout_minutes",
        }

    async def test_it_never_carries_the_guests_identifier(self) -> None:
        """The identifier is the guest's real, unmasked phone number --
        ``GuestLoginResponse`` returns it deliberately, because there it
        is being shown back to the guest who just typed it. Keyed on a
        bare MAC it would hand anyone who observed that MAC the phone
        number of whoever used the device."""
        fx = make_fixture()
        login = await _login(fx)
        await _end(
            fx,
            login.session,
            status=GuestSessionStatus.EXPIRED.value,
            disconnect_reason="inactivity_timeout",
        )

        blob = json.dumps(await self._payload(fx))
        assert "+15551234567" not in blob
        assert str(login.guest.id) not in blob

    async def test_it_never_carries_the_disconnect_reason(self) -> None:
        """``disconnect_reason`` is free text from three mutually
        distrusting sources -- operators, the NAS, and the portal itself.
        It may inform the decision; it may never become the answer."""
        fx = make_fixture()
        login = await _login(fx)
        await _end(
            fx,
            login.session,
            status=GuestSessionStatus.DISCONNECTED.value,
            disconnect_reason="an operator typed this about the guest",
        )

        blob = json.dumps(await self._payload(fx))
        assert "an operator typed this" not in blob
        assert blob.count("disconnect_reason") == 0

    async def test_it_never_carries_a_timestamp(self) -> None:
        """No ``ended_at``. The disclosure is deliberately at the
        granularity of the window, not of the clock -- a caller learns
        "within the last hour", never "at 21:47"."""
        fx = make_fixture()
        login = await _login(fx)
        await _end(
            fx,
            login.session,
            status=GuestSessionStatus.EXPIRED.value,
            disconnect_reason="inactivity_timeout",
        )

        payload = await self._payload(fx)
        assert "ended_at" not in payload
        assert "started_at" not in payload

    async def test_the_reason_is_one_of_four_closed_values(self) -> None:
        """No caller-, operator- or NAS-authored string can travel
        through ``reason``, because the only values it can hold are the
        four written in this repository's own source.

        Was two. The vocabulary grew, and the guarantee this test exists
        to defend did not change with it: ``reason`` is still *derived*
        by comparing ``disconnect_reason`` against literals owned by this
        repository, and the column's own free-text contents still never
        reach a guest. Pinned as an exact set so that adding a member is
        a deliberate edit here, with that argument re-made, rather than
        something a mapping change can do on its own."""
        assert {r.value for r in GuestSessionEndedReason} == {
            "timed_out",
            "idle_timed_out",
            "time_limit_reached",
            "disconnected",
        }

    async def test_every_no_looks_identical_to_the_caller(self) -> None:
        """A blocked device, an unknown device and a device whose session
        ended last week all return exactly ``None``. If they differed,
        this endpoint would answer "is this MAC blocked at this venue?"
        for anyone who asked."""
        fx = make_fixture()
        blocked = await _login(fx, mac="aa:aa:aa:aa:aa:01")
        await _end(
            fx,
            blocked.session,
            status=GuestSessionStatus.TERMINATED.value,
            disconnect_reason="Blocked: ex-employee",
        )
        stale = await _login(fx, mac="aa:aa:aa:aa:aa:02")
        await _end(
            fx,
            stale.session,
            status=GuestSessionStatus.EXPIRED.value,
            disconnect_reason="inactivity_timeout",
            minutes_ago=60 * 24 * 7,
        )

        answers = [
            await fx.guest_service.get_last_ended_session_for_device(
                router_id=fx.router.id, device_mac=mac
            )
            for mac in ("aa:aa:aa:aa:aa:01", "aa:aa:aa:aa:aa:02", "aa:aa:aa:aa:aa:03")
        ]

        assert answers == [None, None, None]


# ============================================================================
# The enforcement half: does a venue's "30 min" actually end the session?
#
# The screen above is the visible half. It is only worth anything if the
# guest is genuinely off the network when it appears -- otherwise it
# announces an event that did not happen. These tests pin the hops this
# platform owns. The one hop they cannot cover is the device itself: that
# RouterOS honours the `Session-Timeout` in the Access-Accept is asserted
# by the vendor, not by this repository, and is named as unverified in the
# PR rather than quietly assumed here.
# ============================================================================


class TestThirtyMinutesMeansThirtyMinutes:
    """`session_timeout_minutes` is read by two mechanisms that disagree
    about what it means (see `has_session_reached_time_limit`). These pin
    the meaning the guest and the operator both expect: elapsed connected
    time, measured from `started_at`.
    """

    async def _aged_session(self, fx: GuestFixture, *, minutes: int, age: float):
        login = await _login(fx)
        return await fx.repository.update_session(
            login.session,
            {
                "session_timeout_minutes": minutes,
                "started_at": datetime.now(UTC) - timedelta(minutes=age),
                "last_activity_at": datetime.now(UTC),
            },
        )

    async def test_a_busy_guest_is_past_the_limit_at_thirty_minutes(self) -> None:
        """`last_activity_at` is deliberately *fresh* here -- that is the
        whole point. A guest actively browsing gets an Interim-Update
        every 300s, each of which refreshes it, so the idle sweep can
        never expire them. Measuring from `started_at` is what makes the
        venue's setting apply to the guest it was aimed at."""
        fx = make_fixture()
        session = await self._aged_session(fx, minutes=30, age=31)

        assert has_session_reached_time_limit(session, now=datetime.now(UTC)) is True
        assert is_session_timed_out(session, now=datetime.now(UTC)) is False

    async def test_a_guest_inside_the_limit_is_not(self) -> None:
        fx = make_fixture()
        session = await self._aged_session(fx, minutes=30, age=29)

        assert has_session_reached_time_limit(session, now=datetime.now(UTC)) is False

    async def test_an_unbounded_session_never_reaches_a_limit(self) -> None:
        fx = make_fixture()
        login = await _login(fx)
        session = await fx.repository.update_session(
            login.session, {"session_timeout_minutes": None}
        )

        assert has_session_reached_time_limit(session, now=datetime.now(UTC)) is False


class TestRadiusStopsAuthorizingASpentSession:
    async def test_authorize_refuses_a_session_past_its_limit(self) -> None:
        """The hop that makes the setting real. Before this, a guest the
        router had just dropped hit the portal, the portal re-POSTed to
        the hotspot, the NAS re-asked RADIUS, and this said yes -- so the
        30-minute limit could never be observed to work at all."""
        fx = make_fixture()
        login = await _login(fx)
        await fx.repository.update_session(
            login.session,
            {
                "session_timeout_minutes": 30,
                "started_at": datetime.now(UTC) - timedelta(minutes=31),
                "last_activity_at": datetime.now(UTC),
            },
        )
        nas = await _nas_client(fx)

        result = await fx.radius_service.authorize(
            nas_client=nas, username=login.guest.identifier
        )

        assert result.authorized is False
        assert result.session_timeout_seconds is None

    async def test_authorize_still_accepts_a_session_inside_its_limit(self) -> None:
        fx = make_fixture()
        login = await _login(fx)
        await fx.repository.update_session(
            login.session,
            {
                "session_timeout_minutes": 30,
                "started_at": datetime.now(UTC) - timedelta(minutes=10),
            },
        )
        nas = await _nas_client(fx)

        result = await fx.radius_service.authorize(
            nas_client=nas, username=login.guest.identifier
        )

        assert result.authorized is True

    async def test_the_reply_carries_remaining_time_not_the_full_allowance(
        self,
    ) -> None:
        """A NAS re-authorizes periodically, and the portal's own hotspot
        POST triggers one too. Sending the full allowance each time reset
        the guest's clock on every reauth, so the limit was unreachable by
        construction rather than merely late."""
        fx = make_fixture()
        login = await _login(fx)
        await fx.repository.update_session(
            login.session,
            {
                "session_timeout_minutes": 30,
                "started_at": datetime.now(UTC) - timedelta(minutes=20),
            },
        )
        nas = await _nas_client(fx)

        result = await fx.radius_service.authorize(
            nas_client=nas, username=login.guest.identifier
        )

        assert result.authorized is True
        # ~10 minutes left, not the full 1800s.
        assert result.session_timeout_seconds is not None
        assert 570 <= result.session_timeout_seconds <= 630

    async def test_an_unbounded_session_still_replies_with_no_timeout(self) -> None:
        """Absent is how RADIUS says "no limit". Sending a number here
        would impose one no venue asked for."""
        fx = make_fixture()
        login = await _login(fx)
        await fx.repository.update_session(
            login.session, {"session_timeout_minutes": None}
        )
        nas = await _nas_client(fx)

        result = await fx.radius_service.authorize(
            nas_client=nas, username=login.guest.identifier
        )

        assert result.authorized is True
        assert result.session_timeout_seconds is None


class TestTheGuestCanActuallySignBackIn:
    async def test_a_spent_session_is_not_reused_on_the_next_login(self) -> None:
        """Without this, the rest of the change would lock guests out
        permanently: reuse never refreshes `started_at`, so the new login
        would land on the same overrun row and be refused by Authorize
        again, for ever."""
        fx = make_fixture()
        first = await _login(fx)
        await fx.repository.update_session(
            first.session,
            {
                "session_timeout_minutes": 30,
                "started_at": datetime.now(UTC) - timedelta(minutes=31),
            },
        )

        second = await _login(fx)

        assert second.session.id != first.session.id

    async def test_the_new_session_authorizes(self) -> None:
        """End to end: signing in again after the limit really does put
        the guest back online, which is what the screen's "Sign in again"
        button promises."""
        fx = make_fixture()
        first = await _login(fx)
        await fx.repository.update_session(
            first.session,
            {
                "session_timeout_minutes": 30,
                "started_at": datetime.now(UTC) - timedelta(minutes=31),
            },
        )
        second = await _login(fx)
        nas = await _nas_client(fx)

        result = await fx.radius_service.authorize(
            nas_client=nas, username=second.guest.identifier
        )

        assert result.authorized is True


class TestTheRouterDropReachesTheScreen:
    async def test_a_radius_session_timeout_stop_reads_as_timed_out(self) -> None:
        """The founder's case as it actually arrives. RouterOS enforces
        the Session-Timeout and reports it via Accounting-Stop, so the row
        lands DISCONNECTED carrying the NAS's own RFC 2866 terminate
        cause -- NOT EXPIRED, which only the platform's idle sweep writes.
        Mapping it to the generic "you were disconnected" would lose the
        one thing that explains a venue's 30-minute limit."""
        fx = make_fixture()
        login = await _login(fx)
        await _end(
            fx,
            login.session,
            status=GuestSessionStatus.DISCONNECTED.value,
            disconnect_reason="Session-Timeout",
        )

        result = await fx.guest_service.get_last_ended_session_for_device(
            router_id=fx.router.id, device_mac=_MAC
        )

        assert result is not None
        assert result.reason is GuestSessionEndedReason.TIMED_OUT

    async def test_an_idle_timeout_stop_reads_as_its_own_reason(self) -> None:
        """This test used to assert DISCONNECTED, on the reasoning that
        "RouterOS's hotspot profile carries its own `idle-timeout`,
        independent of anything this platform sends", so cause 4 reported
        a number nobody had chosen and the generic copy described it well
        enough.

        That reasoning was sound and its premise is now false. This
        platform sends ``Idle-Timeout`` on every Access-Accept, from the
        venue's own SESSION policy, so cause 4 now reports the venue's own
        setting firing. It is a distinct, explicable event, and rolling it
        into "you were disconnected" would throw away the one fact that
        explains why a guest who was sitting still got signed out.

        It stays separate from TIMED_OUT for the reason that split exists
        at all: one guest used all their time, the other used none of it.
        """
        fx = make_fixture()
        login = await _login(fx)
        await _end(
            fx,
            login.session,
            status=GuestSessionStatus.DISCONNECTED.value,
            disconnect_reason="Idle-Timeout",
        )

        result = await fx.guest_service.get_last_ended_session_for_device(
            router_id=fx.router.id, device_mac=_MAC
        )

        assert result is not None
        assert result.reason is GuestSessionEndedReason.IDLE_TIMED_OUT
        assert result.reason is not GuestSessionEndedReason.TIMED_OUT
        assert result.reason is not GuestSessionEndedReason.DISCONNECTED

    async def test_an_idle_timeout_stop_reports_the_number_that_ended_it(
        self,
    ) -> None:
        """The reason alone is not enough to write honest copy. "You were
        signed out for being inactive" invites "after how long?", and the
        only defensible answer is the value THIS session carried -- not
        whatever is configured by the time the guest reads the screen."""
        fx = make_fixture()
        login = await _login(fx)
        await _end(
            fx,
            login.session,
            status=GuestSessionStatus.DISCONNECTED.value,
            disconnect_reason="Idle-Timeout",
        )

        result = await fx.guest_service.get_last_ended_session_for_device(
            router_id=fx.router.id, device_mac=_MAC
        )

        assert result is not None
        assert result.idle_timeout_minutes == DEFAULT_IDLE_TIMEOUT_MINUTES


class TestTheScreenWorksEvenIfTheRouterNeverTellsUs:
    """The case the whole feature has to survive on.

    If the NAS sends no Accounting-Stop -- a real possibility nobody has
    disproved on the device -- the row stays ACTIVE for ever, because the
    idle sweep cannot expire it either (a guest who was browsing has a
    fresh `last_activity_at`). Deriving the answer from the session's own
    elapsed life rather than from a disconnect event is what makes the
    screen reachable regardless.
    """

    async def test_an_overrun_active_session_is_not_reported_as_connected(self) -> None:
        """Otherwise the portal sends a guest with no internet to the
        "You're online" screen -- the most frustrating thing it can do."""
        fx = make_fixture()
        login = await _login(fx)
        await fx.repository.update_session(
            login.session,
            {
                "session_timeout_minutes": 30,
                "started_at": datetime.now(UTC) - timedelta(minutes=31),
                "last_activity_at": datetime.now(UTC),
            },
        )

        assert (
            await fx.guest_service.get_active_session_for_device(
                router_id=fx.router.id, device_mac=_MAC
            )
            is None
        )

    async def test_an_overrun_active_session_is_reported_as_timed_out(self) -> None:
        fx = make_fixture()
        login = await _login(fx)
        await fx.repository.update_session(
            login.session,
            {
                "session_timeout_minutes": 30,
                "started_at": datetime.now(UTC) - timedelta(minutes=31),
                "last_activity_at": datetime.now(UTC),
            },
        )

        result = await fx.guest_service.get_last_ended_session_for_device(
            router_id=fx.router.id, device_mac=_MAC
        )

        assert result is not None
        assert result.reason is GuestSessionEndedReason.TIMED_OUT
        assert result.session_timeout_minutes == 30

    async def test_a_long_abandoned_active_row_is_not_reported(self) -> None:
        """The window applies to this path too. A row left ACTIVE for a
        week is a bookkeeping artefact, not a greeting -- and without the
        bound this would be the one path able to report an arbitrarily old
        session."""
        fx = make_fixture()
        login = await _login(fx)
        await fx.repository.update_session(
            login.session,
            {
                "session_timeout_minutes": 30,
                "started_at": datetime.now(UTC) - timedelta(days=7),
                "last_activity_at": datetime.now(UTC) - timedelta(days=7),
            },
        )

        assert (
            await fx.guest_service.get_last_ended_session_for_device(
                router_id=fx.router.id, device_mac=_MAC
            )
            is None
        )

    async def test_a_session_inside_its_limit_is_still_reported_as_connected(
        self,
    ) -> None:
        """The guard must not cost a genuinely-connected guest their
        session."""
        fx = make_fixture()
        login = await _login(fx)
        await fx.repository.update_session(
            login.session,
            {
                "session_timeout_minutes": 240,
                "started_at": datetime.now(UTC) - timedelta(minutes=10),
            },
        )

        assert (
            await fx.guest_service.get_active_session_for_device(
                router_id=fx.router.id, device_mac=_MAC
            )
            is not None
        )
