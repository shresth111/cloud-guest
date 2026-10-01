"""The AAA trail: what the router and the hub said about a guest's login,
recorded in ``guest_session_events`` and told back as a timeline.

Pins five properties:

1. Every Authorize answer is recorded -- accept with what was granted,
   reject with *why* -- and a trail that cannot be written never changes the
   RADIUS answer.
2. Accounting start/interim/stop are recorded with the NAS's own fields, and
   interim updates coalesce instead of growing a row per packet.
3. A failed portal sign-in survives the request's rollback.
4. The timeline reads in plain words, stands in for accounting the router
   never sent, and is scoped like ``get_session``.
5. The hub may send the new accounting fields before or after the backend
   understands them.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.domains.guest.aaa import (
    AuthRejectReason,
    SessionEventType,
    build_timeline_entries,
    describe_disconnect_reason,
    describe_login_failure,
    describe_rate_limit,
    humanize_code,
)
from app.domains.guest.constants import GuestAuthMethod
from app.domains.guest.models import GuestLoginHistory, GuestSessionEvent
from app.domains.guest.repository import GuestRepository
from app.domains.guest.schemas import RadiusAccountingRequest
from tests.unit.test_guest import make_fixture

PHONE = "+15553334444"


class EventLog:
    """In-memory stand-in for the repository's AAA-trail methods, with the
    same coalescing rule as the real one."""

    def __init__(self) -> None:
        self.rows: list[GuestSessionEvent] = []
        self.fail = False

    async def record_session_event(self, *, coalesce_since=None, **fields):
        if self.fail:
            raise RuntimeError("database is on fire")
        if coalesce_since is not None:
            keys = GuestRepository._EVENT_IDENTITY
            for row in reversed(self.rows):
                if row.occurred_at >= coalesce_since and all(
                    getattr(row, k) == fields.get(k) for k in keys
                ):
                    row.occurred_at = fields["occurred_at"]
                    row.repeat_count += 1
                    for key in GuestRepository._EVENT_REFRESHED:
                        if fields.get(key) is not None:
                            setattr(row, key, fields[key])
                    return row
        row = GuestSessionEvent(
            id=uuid.uuid4(),
            first_seen_at=fields["occurred_at"],
            repeat_count=1,
            **fields,
        )
        self.rows.append(row)
        return row

    async def list_session_events(self, *, session_id, organization_id):
        return [
            r
            for r in self.rows
            if r.session_id == session_id and r.organization_id == organization_id
        ]

    async def list_unbound_guest_events(
        self, *, organization_id, router_id, guest_id, username, start, end
    ):
        return [
            r
            for r in self.rows
            if r.session_id is None
            and r.organization_id == organization_id
            and r.router_id == router_id
            and (r.guest_id == guest_id or r.username == username)
            and start <= r.occurred_at < end
        ]

    async def list_login_attempts_for_guest(
        self, *, organization_id, guest_id, identifier, start, end
    ):
        return []

    def of(self, kind: SessionEventType) -> list[GuestSessionEvent]:
        return [r for r in self.rows if r.event_type == kind.value]


def _fixture():
    fx = make_fixture()
    log = EventLog()
    for name in (
        "record_session_event",
        "list_session_events",
        "list_unbound_guest_events",
        "list_login_attempts_for_guest",
    ):
        setattr(fx.repository, name, getattr(log, name))
    return fx, log


async def _nas(fx):
    await fx.radius_service.register_nas(
        actor_user_id=uuid.uuid4(),
        router_id=fx.router.id,
        nas_identifier="nas-1",
        shared_secret="supersecret123",
    )
    return await fx.radius_service.authenticate_nas(
        nas_identifier="nas-1", shared_secret="supersecret123"
    )


async def _login(fx, mac: str | None = None):
    return await fx.guest_service.login_via_otp(
        identifier=PHONE,
        code="GOOD",
        auth_method=GuestAuthMethod.OTP_SMS,
        organization_id=None,
        location_id=fx.location_id,
        router_id=fx.router.id,
        device_mac=mac,
    )


# ============================================================================
# 1. Authorize
# ============================================================================


class TestAuthorizeIsRecorded:
    async def test_accept_records_what_was_granted(self) -> None:
        fx, log = _fixture()
        nas = await _nas(fx)
        login = await _login(fx)
        authz = await fx.radius_service.authorize(nas_client=nas, username=PHONE)
        assert authz.authorized is True
        (accept,) = log.of(SessionEventType.AUTH_ACCEPT)
        assert accept.session_id == login.session.id
        assert accept.organization_id == fx.organization_id
        assert (
            accept.granted["session_timeout_seconds"] == authz.session_timeout_seconds
        )
        assert accept.nas_identifier == "nas-1"
        assert accept.raw["Auth-Type"] == "Accept"

    async def test_reject_for_a_device_that_never_signed_in(self) -> None:
        fx, log = _fixture()
        nas = await _nas(fx)
        authz = await fx.radius_service.authorize(nas_client=nas, username="+1999")
        assert authz.authorized is False
        (reject,) = log.of(SessionEventType.AUTH_REJECT)
        assert reject.reason_code == AuthRejectReason.NOT_SIGNED_IN.value
        assert reject.session_id is None

    async def test_reject_after_the_session_ended_says_so(self) -> None:
        fx, log = _fixture()
        nas = await _nas(fx)
        login = await _login(fx)
        await fx.guest_service.disconnect_session(
            session_id=login.session.id, reason="test"
        )
        await fx.radius_service.authorize(nas_client=nas, username=PHONE)
        (reject,) = log.of(SessionEventType.AUTH_REJECT)
        assert reject.reason_code == AuthRejectReason.SESSION_ENDED.value
        assert reject.guest_id == login.guest.id

    async def test_reject_past_the_time_limit_is_bound_to_the_session(self) -> None:
        fx, log = _fixture()
        nas = await _nas(fx)
        login = await _login(fx)
        await fx.repository.update_session(
            login.session,
            {
                "session_timeout_minutes": 1,
                "started_at": datetime.now(UTC) - timedelta(minutes=5),
            },
        )
        authz = await fx.radius_service.authorize(nas_client=nas, username=PHONE)
        assert authz.authorized is False
        (reject,) = log.of(SessionEventType.AUTH_REJECT)
        assert reject.reason_code == AuthRejectReason.TIME_LIMIT_REACHED.value
        assert reject.session_id == login.session.id

    async def test_repeated_rejects_coalesce(self) -> None:
        fx, log = _fixture()
        nas = await _nas(fx)
        for _ in range(3):
            await fx.radius_service.authorize(nas_client=nas, username="+1999")
        (reject,) = log.of(SessionEventType.AUTH_REJECT)
        assert reject.repeat_count == 3

    async def test_a_trail_that_cannot_be_written_never_changes_the_answer(
        self,
    ) -> None:
        fx, log = _fixture()
        nas = await _nas(fx)
        await _login(fx)
        log.fail = True
        authz = await fx.radius_service.authorize(nas_client=nas, username=PHONE)
        assert authz.authorized is True
        assert log.rows == []


# ============================================================================
# 2. Accounting
# ============================================================================


class TestAccountingIsRecorded:
    async def test_start_interim_stop(self) -> None:
        fx, log = _fixture()
        nas = await _nas(fx)
        login = await _login(fx)
        await fx.radius_service.accounting_start(
            nas_client=nas,
            username=PHONE,
            acct_session_id="81a00001",
            framed_ip_address="10.5.50.23",
            nas_ip_address="10.20.0.31",
        )
        for total in (1_000, 5_000, 9_000):
            await fx.radius_service.accounting_interim_update(
                nas_client=nas,
                username=PHONE,
                bytes_uploaded_delta=0,
                bytes_downloaded_delta=0,
                bytes_uploaded_total=total,
                bytes_downloaded_total=total * 10,
                acct_session_id="81a00001",
                session_time_seconds=300,
            )
        await fx.radius_service.accounting_stop(
            nas_client=nas,
            username=PHONE,
            bytes_uploaded_total=9_500,
            bytes_downloaded_total=95_000,
            disconnect_reason="Lost-Carrier",
            acct_session_id="81a00001",
            session_time_seconds=900,
        )
        (start,) = log.of(SessionEventType.ACCT_START)
        assert start.framed_ip_address == "10.5.50.23"
        assert start.acct_session_id == "81a00001"
        # Three interim packets inside one clock hour are one row.
        (interim,) = log.of(SessionEventType.ACCT_INTERIM)
        assert interim.repeat_count == 3
        assert interim.bytes_downloaded_total == 90_000
        (stop,) = log.of(SessionEventType.ACCT_STOP)
        assert stop.reason_code == "Lost-Carrier"
        assert stop.session_time_seconds == 900
        assert {r.session_id for r in log.rows} == {login.session.id}

    async def test_framed_ip_heals_a_session_with_no_address(self) -> None:
        fx, log = _fixture()
        nas = await _nas(fx)
        login = await _login(fx)
        assert login.session.ip_address is None
        session = await fx.radius_service.accounting_start(
            nas_client=nas, username=PHONE, framed_ip_address="10.5.50.23"
        )
        assert session.ip_address == "10.5.50.23"

    async def test_garbage_framed_ip_is_ignored(self) -> None:
        fx, log = _fixture()
        nas = await _nas(fx)
        await _login(fx)
        session = await fx.radius_service.accounting_start(
            nas_client=nas, username=PHONE, framed_ip_address="not-an-ip"
        )
        assert session.ip_address is None
        assert log.of(SessionEventType.ACCT_START)[0].framed_ip_address is None

    async def test_accounting_on_records_a_reboot(self) -> None:
        fx, log = _fixture()
        nas = await _nas(fx)
        await _login(fx)
        await fx.radius_service.accounting_on(nas_client=nas)
        (reboot,) = log.of(SessionEventType.NAS_REBOOT)
        assert reboot.raw["sessions_closed"] == 1


class TestAccountingRequestSchema:
    def test_new_fields_are_optional(self) -> None:
        payload = RadiusAccountingRequest(status_type="start", username="x")
        assert payload.framed_ip_address is None
        assert payload.session_time is None

    def test_blank_session_time_from_rlm_rest_is_unknown(self) -> None:
        payload = RadiusAccountingRequest(
            status_type="interim-update",
            username="x",
            session_time="",
            framed_ip_address="",
        )
        assert payload.session_time is None

    def test_session_time_string_is_parsed(self) -> None:
        payload = RadiusAccountingRequest(
            status_type="stop", username="x", session_time="900"
        )
        assert payload.session_time == 900


# ============================================================================
# 3. Failed sign-ins survive the rollback
# ============================================================================


class _IndependentSession:
    committed: list[object] = []

    def __init__(self) -> None:
        self.pending: list[object] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def add(self, obj):
        self.pending.append(obj)

    async def commit(self):
        _IndependentSession.committed.extend(self.pending)

    async def refresh(self, obj):
        return None


class _RequestSession:
    """A request session that must NOT receive a failed attempt."""

    def add(self, obj):  # pragma: no cover - asserted not called
        raise AssertionError("failure row written to the request transaction")


async def test_failed_login_is_written_in_its_own_transaction() -> None:
    _IndependentSession.committed = []
    repo = GuestRepository(
        _RequestSession(),  # type: ignore[arg-type]
        independent_session_factory=_IndependentSession,
    )
    entry = await repo.create_login_history(
        guest_id=None,
        organization_id=uuid.uuid4(),
        location_id=uuid.uuid4(),
        identifier=PHONE,
        auth_method="otp_sms",
        success=False,
        failure_reason="OtpCodeMismatchError",
        attempted_at=datetime.now(UTC),
        ip_address="10.0.0.2",
    )
    assert _IndependentSession.committed == [entry]
    assert isinstance(entry, GuestLoginHistory)


# ============================================================================
# 4. Plain words and the timeline
# ============================================================================


class TestPlainWords:
    def test_known_codes(self) -> None:
        assert describe_login_failure("OtpCodeMismatchError") == "Wrong OTP entered."
        assert (
            describe_login_failure("VoucherExpiredError") == "The voucher has expired."
        )
        assert describe_disconnect_reason("Lost-Carrier") == "The device left the WiFi."
        assert describe_disconnect_reason("idle-timeout").startswith(
            "The device was idle"
        )

    def test_unknown_codes_are_humanized_not_shown_raw(self) -> None:
        assert humanize_code("SomeNewThingError") == "Some new thing."
        assert humanize_code("data_limit_reached") == "Data limit reached."

    def test_operator_free_text_is_kept(self) -> None:
        assert (
            describe_disconnect_reason("Disconnected by venue staff")
            == "Disconnected by venue staff"
        )

    def test_rate_limit_reads_from_the_guests_side(self) -> None:
        # Mikrotik-Rate-Limit is rx/tx from the router: rx = guest upload.
        assert describe_rate_limit("2M/10M") == "10M down / 2M up"


class TestTimeline:
    async def test_full_story_in_order(self) -> None:
        fx, log = _fixture()
        nas = await _nas(fx)
        await fx.radius_service.authorize(nas_client=nas, username=PHONE)  # reject
        login = await _login(fx)
        await fx.radius_service.authorize(nas_client=nas, username=PHONE)  # accept
        await fx.radius_service.accounting_start(nas_client=nas, username=PHONE)
        await fx.radius_service.accounting_stop(
            nas_client=nas, username=PHONE, disconnect_reason="User-Request"
        )
        timeline = await fx.guest_service.get_session_timeline(
            login.session.id, requesting_organization_id=fx.organization_id
        )
        kinds = [e["kind"] for e in timeline.entries]
        assert kinds == ["auth_reject", "auth_accept", "acct_start", "acct_stop"]
        phases = [e["phase"] for e in timeline.entries]
        assert phases == ["authentication", "authorization", "accounting", "accounting"]
        assert timeline.entries[-1]["detail"].startswith("The guest logged out.")
        assert timeline.authorization["router_checked"] is True
        assert timeline.accounting["router_reported"] is True
        # The identifier never rides in raw; it is a separate, masked field.
        assert all("User-Name" not in e["raw"] for e in timeline.entries)

    async def test_a_session_the_router_never_reported_still_has_a_story(
        self,
    ) -> None:
        fx, log = _fixture()
        login = await _login(fx)
        await fx.guest_service.disconnect_session(
            session_id=login.session.id, reason="inactivity_timeout"
        )
        timeline = await fx.guest_service.get_session_timeline(
            login.session.id, requesting_organization_id=fx.organization_id
        )
        kinds = [e["kind"] for e in timeline.entries]
        assert kinds == ["session_started", "session_ended"]
        assert timeline.entries[-1]["detail"] == "The device was idle for too long."
        assert timeline.notes  # says why the router part is missing

    async def test_another_organization_cannot_read_it(self) -> None:
        fx, log = _fixture()
        login = await _login(fx)
        with pytest.raises(Exception) as caught:
            await fx.guest_service.get_session_timeline(
                login.session.id, requesting_organization_id=uuid.uuid4()
            )
        assert getattr(caught.value, "status_code", 404) in (403, 404)


def test_builder_orders_same_instant_by_phase() -> None:
    now = datetime.now(UTC)
    session = type(
        "S",
        (),
        {
            "started_at": now,
            "ended_at": None,
            "ip_address": None,
            "disconnect_reason": None,
        },
    )()
    accept = GuestSessionEvent(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        event_type="auth_accept",
        occurred_at=now,
        first_seen_at=now,
        repeat_count=1,
        granted={"session_timeout_seconds": 3600, "data_limit_mb": 500},
    )
    entries = build_timeline_entries(
        session=session, login_attempts=[], events=[accept]
    )
    assert [e["phase"] for e in entries] == ["authorization", "accounting"]
    assert "time left 1h 0m" in entries[0]["detail"]
    assert "data cap 500 MB" in entries[0]["detail"]
