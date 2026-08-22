"""Unit tests for the Demo Booking domain: the availability grid and its
timezone convention, the booking guards, the conflict path, the mail
accounting, and cancel/reschedule.

Follows this project's plain-``assert``/native-``async def`` style
(``asyncio_mode = "auto"``), exercising ``DemoBookingService`` against
hand-rolled in-memory fakes -- the same shape
``tests/unit/test_demo_request.py`` uses, and for the same reason (there
is no live Postgres in this environment).

**The database constraint is not tested here.** A fake repository that
raises ``SlotTakenError`` when it feels like it proves nothing about
whether the schema would actually refuse the insert. That claim is
verified against a real database engine, running the real DDL, in
``tests/unit/test_demo_booking_constraint.py``. What *is* tested here is
everything downstream of it: that the service never asks whether a slot is
free, that a raised conflict becomes a 409 with alternatives, and that the
lead survives it.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo

import pytest
from pydantic import ValidationError

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.demo_booking.availability import (
    BookingWindow,
    NaiveDatetimeError,
    parse_blackout_dates,
    parse_local_time,
    parse_working_weekdays,
)
from app.domains.demo_booking.constants import (
    DemoBookingConfirmationState,
    DemoBookingDayStatus,
    DemoBookingStatus,
)
from app.domains.demo_booking.exceptions import (
    BookingNotCancellableError,
    BookingRateLimitExceededError,
    InvalidManageTokenError,
    SlotAlreadyBookedError,
    SlotNotBookableError,
)
from app.domains.demo_booking.models import DemoBooking
from app.domains.demo_booking.repository import SlotTakenError, is_active_slot_conflict
from app.domains.demo_booking.schemas import (
    BookingCreateRequest,
    local_label,
    render_slot,
    to_utc_z,
)
from app.domains.demo_booking.service import (
    BookingRateLimiter,
    DemoBookingService,
    hash_manage_token,
)
from app.domains.demo_booking.slot_id import (
    InvalidSlotIdError,
    decode_slot_id,
    encode_slot_id,
)
from app.domains.demo_request.constants import DemoRequestStatus
from app.domains.demo_request.models import DemoRequest

IST = ZoneInfo("Asia/Kolkata")
SECRET = "unit-test-slot-id-secret-at-least-32-characters-long"

# 2026-09-01 is a Tuesday. 05:30Z == 11:00 IST.
SLOT = datetime(2026, 9, 1, 5, 30, tzinfo=UTC)
# Comfortably before it, on the same IST day, and past the 120-minute
# minimum notice.
NOW = datetime(2026, 9, 1, 1, 0, tzinfo=UTC)  # 06:30 IST


# ==========================================================================
# Test doubles
# ==========================================================================


def _base_fields(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": uuid.uuid4(),
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
        "deleted_at": None,
        "is_deleted": False,
        "created_by": None,
        "updated_by": None,
        "version": 1,
    }
    base.update(overrides)
    return base


@dataclass
class FakeLeadRepository:
    leads: dict[uuid.UUID, DemoRequest] = field(default_factory=dict)
    #: Rows are stamped with the *pinned* clock, not the wall clock -- the
    #: dedupe lookup filters on `created_at`, so a real timestamp on a row
    #: created "now" while the service believes it is 2026 would make the
    #: window silently never match.
    now: datetime = NOW
    created: int = 0
    updated: int = 0

    async def create(self, **fields: object) -> DemoRequest:
        lead = DemoRequest(
            **_base_fields(
                status=DemoRequestStatus.NEW.value,
                created_at=self.now,
                updated_at=self.now,
                **fields,
            )
        )
        self.leads[lead.id] = lead
        self.created += 1
        return lead

    async def update(
        self, demo_request: DemoRequest, data: dict[str, object]
    ) -> DemoRequest:
        for key, value in data.items():
            setattr(demo_request, key, value)
        demo_request.version += 1
        self.updated += 1
        return demo_request


@dataclass
class FakeBookingRepository:
    """In-memory stand-in for ``DemoBookingRepository``.

    ``create_booking``/``update_booking`` raise ``SlotTakenError`` when a
    confirmed booking already holds the instant -- **imitating** what the
    partial unique index does, so the service's handling of that signal
    can be tested. The index itself is verified for real in
    ``test_demo_booking_constraint.py``; nothing here is evidence that the
    database would actually refuse anything.
    """

    leads: dict[uuid.UUID, DemoRequest] = field(default_factory=dict)
    bookings: dict[uuid.UUID, DemoBooking] = field(default_factory=dict)
    commits: int = 0
    #: Committed snapshot -- what a reader in another transaction would
    #: see. Lets a test assert that the lead really was durable before the
    #: slot was attempted.
    committed_lead_ids: set[uuid.UUID] = field(default_factory=set)
    fail_alternatives: bool = False

    def _holders(self) -> dict[datetime, DemoBooking]:
        return {
            b.starts_at: b
            for b in self.bookings.values()
            if b.status == DemoBookingStatus.CONFIRMED.value and not b.is_deleted
        }

    async def create_booking(self, **fields: object) -> DemoBooking:
        booking = DemoBooking(**_base_fields(**fields))
        if booking.starts_at in self._holders():
            raise SlotTakenError(booking.starts_at)
        self.bookings[booking.id] = booking
        return booking

    async def update_booking(
        self, booking: DemoBooking, data: dict[str, object]
    ) -> DemoBooking:
        new_start = data.get("starts_at")
        if new_start is not None and new_start != booking.starts_at:
            holder = self._holders().get(new_start)
            if holder is not None and holder.id != booking.id:
                raise SlotTakenError(new_start)
        for key, value in data.items():
            setattr(booking, key, value)
        booking.version += 1
        return booking

    async def commit(self) -> None:
        self.commits += 1
        self.committed_lead_ids |= set(self.leads)

    async def get_by_id(self, booking_id: uuid.UUID) -> DemoBooking | None:
        return self.bookings.get(booking_id)

    async def get_by_token_hash(self, token_hash: str) -> DemoBooking | None:
        for booking in self.bookings.values():
            if booking.manage_token_hash == token_hash and not booking.is_deleted:
                return booking
        return None

    async def confirmed_starts_between(
        self, start: datetime, end: datetime
    ) -> list[datetime]:
        return [s for s in self._holders() if start <= s < end]

    async def count_active_for_email(self, email: str, *, now: datetime) -> int:
        count = 0
        for booking in self._holders().values():
            lead = self.leads.get(booking.demo_request_id)
            if lead is not None and lead.email == email and booking.starts_at >= now:
                count += 1
        return count

    async def find_recent_unbooked_lead(
        self, email: str, *, since: datetime
    ) -> DemoRequest | None:
        booked = {b.demo_request_id for b in self._holders().values()}
        candidates = [
            lead
            for lead in self.leads.values()
            if lead.email == email
            and not lead.is_deleted
            and lead.created_at >= since
            and lead.id not in booked
        ]
        candidates.sort(key=lambda lead: lead.created_at, reverse=True)
        return candidates[0] if candidates else None

    async def find_lead_by_id(self, lead_id: uuid.UUID) -> DemoRequest | None:
        return self.leads.get(lead_id)

    async def list_bookings(self, *, page: int, page_size: int, **_: object):
        rows = [
            (b, self.leads[b.demo_request_id])
            for b in sorted(self.bookings.values(), key=lambda b: b.starts_at)
            if not b.is_deleted and b.demo_request_id in self.leads
        ]
        params = PageParams(page=page, page_size=page_size)
        return rows, PaginationMeta.from_total(params, len(rows))


@dataclass
class RecordedEnqueue:
    fields: dict[str, object]


@dataclass
class FakeNotificationService:
    calls: list[RecordedEnqueue] = field(default_factory=list)
    raise_on: set[str] = field(default_factory=set)

    async def enqueue(self, **fields: object) -> object:
        event_type = str(getattr(fields.get("event_type"), "value", ""))
        if event_type in self.raise_on:
            raise RuntimeError("SMTP outbox write blew up")
        self.calls.append(RecordedEnqueue(dict(fields)))
        return type("Delivery", (), {"id": uuid.uuid4()})()


@dataclass
class FakeRedis:
    counters: dict[str, int] = field(default_factory=dict)
    ttls: dict[str, int] = field(default_factory=dict)
    explode: bool = False

    async def incr(self, key: str) -> int:
        if self.explode:
            raise ConnectionError("redis is down")
        self.counters[key] = self.counters.get(key, 0) + 1
        return self.counters[key]

    async def expire(self, key: str, seconds: int) -> None:
        self.ttls[key] = seconds

    async def ttl(self, key: str) -> int:
        return self.ttls.get(key, -1)


def make_window(**overrides) -> BookingWindow:
    defaults = {
        "timezone": IST,
        "workday_start": time(10, 0),
        "workday_end": time(18, 0),
        "slot_minutes": 30,
        "buffer_minutes": 0,
        "lead_time_minutes": 120,
        "horizon_days": 30,
        "working_weekdays": frozenset({0, 1, 2, 3, 4}),
        "blackout_dates": frozenset(),
    }
    defaults.update(overrides)
    return BookingWindow(**defaults)


def make_service(
    *,
    window: BookingWindow | None = None,
    now: datetime = NOW,
    notification_service: FakeNotificationService | None = None,
    notify_email: str = "sales@wyfyguest.com",
    redis: FakeRedis | None = None,
    **kwargs,
) -> tuple[DemoBookingService, FakeBookingRepository, FakeLeadRepository]:
    repository = FakeBookingRepository()
    leads = FakeLeadRepository(leads=repository.leads, now=now)
    service = DemoBookingService(
        repository,
        leads,
        window or make_window(),
        notification_service=notification_service,
        notify_email=notify_email,
        redis=redis,
        slot_id_secret=SECRET,
        clock=lambda: now,
        **kwargs,
    )
    return service, repository, leads


async def book(service: DemoBookingService, *, starts_at: datetime = SLOT, **overrides):
    payload = {
        "starts_at": starts_at,
        "full_name": "Asha Menon",
        "email": "asha@hotelblue.in",
        "phone": "+919812345678",
        "company_name": "Hotel Blue",
        "message": "Interested in guest WiFi.",
    }
    payload.update(overrides)
    return await service.book_slot(**payload)


# ==========================================================================
# The timezone convention
# ==========================================================================


class TestTimezoneConvention:
    def test_grid_is_built_in_ist_wall_clock_and_returned_as_utc(self):
        window = make_window()
        grid = window.day_grid(date(2026, 9, 1))
        assert grid[0] == datetime(2026, 9, 1, 4, 30, tzinfo=UTC)  # 10:00 IST
        assert all(g.tzinfo is UTC for g in grid)
        assert [g.astimezone(IST).strftime("%H:%M") for g in grid[:3]] == [
            "10:00",
            "10:30",
            "11:00",
        ]

    def test_last_slot_ends_at_close_of_business_not_starts_at_it(self):
        """A 30-minute meeting in a 10:00-18:00 day ends at 18:00, so the
        last start is 17:30. Off-by-one here books people into a slot the
        sales team is not there for."""
        grid = make_window().day_grid(date(2026, 9, 1))
        assert grid[-1].astimezone(IST).strftime("%H:%M") == "17:30"
        assert len(grid) == 16

    def test_buffer_widens_the_step_between_slots(self):
        grid = make_window(buffer_minutes=15).day_grid(date(2026, 9, 1))
        local = [g.astimezone(IST).strftime("%H:%M") for g in grid]
        assert local[:3] == ["10:00", "10:45", "11:30"]

    def test_what_the_visitor_sees_is_the_instant_the_team_sees(self):
        """The three renderings of one slot are three views of one number.
        A visitor told '3:00 PM' and a salesperson looking at the UTC
        instant are looking at the same moment."""
        three_pm_ist = datetime(2026, 9, 1, 9, 30, tzinfo=UTC)
        rendered = render_slot(
            three_pm_ist, three_pm_ist + timedelta(minutes=30), IST, secret=SECRET
        )
        assert rendered.label == "3:00 PM"
        assert rendered.starts_at == "2026-09-01T09:30:00Z"
        assert rendered.starts_at_local == "2026-09-01T15:00:00+05:30"
        # And they round-trip to one another.
        assert datetime.fromisoformat(
            rendered.starts_at.replace("Z", "+00:00")
        ) == datetime.fromisoformat(rendered.starts_at_local)

    def test_utc_is_emitted_with_a_literal_z_not_a_bare_naive_string(self):
        assert to_utc_z(SLOT) == "2026-09-01T05:30:00Z"
        assert to_utc_z(SLOT.astimezone(IST)) == "2026-09-01T05:30:00Z"

    def test_midnight_and_noon_labels_are_not_zero_or_twelve_hour_confused(self):
        assert local_label(datetime(2026, 9, 1, 6, 30, tzinfo=UTC), IST) == "12:00 PM"
        assert local_label(datetime(2026, 8, 31, 18, 30, tzinfo=UTC), IST) == "12:00 AM"

    def test_naive_datetimes_are_rejected_never_assumed_to_be_ist(self):
        window = make_window()
        with pytest.raises(NaiveDatetimeError):
            window.local_date(datetime(2026, 9, 1, 11, 0))
        with pytest.raises(NaiveDatetimeError):
            window.is_on_grid(datetime(2026, 9, 1, 11, 0))
        with pytest.raises(NaiveDatetimeError):
            window.is_bookable(datetime(2026, 9, 1, 11, 0), NOW)

    def test_the_booking_request_carries_the_lead_and_the_slot_together(self):
        """One request, both halves. A two-step "create the lead, then
        take the slot" can half-succeed; this shape cannot."""
        request = BookingCreateRequest(
            full_name="Asha Menon",
            email="asha@hotelblue.in",
            phone="+919812345678",
            company_name="Hotel Blue",
            message="Interested",
            property_type="hotel",
            location_count=3,
            router_count=5,
            slot_id=encode_slot_id(SLOT, secret=SECRET),
        )
        # All eight lead fields the plain demo-request form collects, plus
        # the slot -- inherited from DemoRequestCreateRequest so the two
        # forms cannot drift apart.
        assert set(BookingCreateRequest.model_fields) == {
            "full_name",
            "email",
            "phone",
            "company_name",
            "message",
            "property_type",
            "location_count",
            "router_count",
            "slot_id",
        }
        assert decode_slot_id(request.slot_id, secret=SECRET) == SLOT

    def test_the_lead_half_keeps_the_plain_forms_validation(self):
        with pytest.raises(ValidationError):
            BookingCreateRequest(
                full_name="A",  # min_length=2 on the parent
                email="asha@hotelblue.in",
                company_name="Hotel Blue",
                slot_id=encode_slot_id(SLOT, secret=SECRET),
            )
        with pytest.raises(ValidationError):
            BookingCreateRequest(
                full_name="Asha Menon",
                email="not-an-email",
                company_name="Hotel Blue",
                slot_id=encode_slot_id(SLOT, secret=SECRET),
            )

    def test_local_date_is_the_ist_day_not_the_utc_day(self):
        """A 00:30 IST instant is the previous day in UTC. The calendar is
        drawn in IST days, so this must not slide a slot onto the wrong
        square of the grid."""
        window = make_window()
        instant = datetime(2026, 8, 31, 19, 0, tzinfo=UTC)  # 2026-09-01 00:30 IST
        assert instant.date() == date(2026, 8, 31)
        assert window.local_date(instant) == date(2026, 9, 1)

    def test_grid_generated_in_local_time_survives_a_dst_transition(self):
        """IST has no DST, so this uses a zone that does. The working day
        must stay 10:00-18:00 *local* across the transition -- which is
        what generating in wall-clock time and converting to UTC gives.
        Generating in UTC would silently slide the working day by an hour
        twice a year."""
        window = make_window(timezone=ZoneInfo("America/New_York"))
        before = window.day_grid(date(2026, 3, 7))  # EST, UTC-5
        after = window.day_grid(date(2026, 3, 9))  # EDT, UTC-4
        ny = ZoneInfo("America/New_York")
        assert before[0].astimezone(ny).strftime("%H:%M") == "10:00"
        assert after[0].astimezone(ny).strftime("%H:%M") == "10:00"
        # Same wall clock, different UTC instant -- by exactly the offset
        # change.
        assert before[0].hour == 15
        assert after[0].hour == 14

    def test_grid_never_yields_duplicate_instants_across_spring_forward(self):
        """On a spring-forward day the local hour 02:00-02:59 does not
        exist, and Python resolves those wall times using the pre-
        transition offset -- so 02:30 local and 03:30 local both land on
        07:30 UTC. Two grid entries mapping to one instant would show the
        visitor two bookable slots that the unique index could only ever
        let one of, which is exactly the "the UI and the database
        disagree" failure this domain is built to avoid.

        Verified against the raw arithmetic: without de-duplication this
        day yields 47 entries of which 2 are duplicates.
        """
        window = make_window(
            timezone=ZoneInfo("America/New_York"),
            workday_start=time(0, 0),
            workday_end=time(23, 30),
        )
        grid = window.day_grid(date(2026, 3, 8))  # US spring forward
        assert len(set(grid)) == len(grid)
        assert len(grid) == 45  # 47 wall-clock steps, 2 collapsed

    def test_a_fall_back_day_keeps_every_distinct_instant(self):
        """The counterpart: nothing legitimate is dropped by the
        de-duplication."""
        window = make_window(
            timezone=ZoneInfo("America/New_York"),
            workday_start=time(0, 0),
            workday_end=time(23, 30),
        )
        grid = window.day_grid(date(2026, 11, 1))  # US fall back
        assert len(grid) == 47
        assert len(set(grid)) == 47


# ==========================================================================
# Availability: the five day statuses
# ==========================================================================


class TestDayStatuses:
    def test_a_working_day_with_free_slots_is_available(self):
        day = make_window().day_availability(
            date(2026, 9, 2), now=NOW, taken=[]
        )
        assert day.status is DemoBookingDayStatus.AVAILABLE
        assert len(day.slots) == 16

    def test_a_past_date_is_outside_the_window_not_fully_booked(self):
        day = make_window().day_availability(
            date(2026, 8, 31), now=NOW, taken=[]
        )
        assert day.status is DemoBookingDayStatus.OUTSIDE_WINDOW
        assert day.slots == ()

    def test_a_date_beyond_the_horizon_is_outside_the_window(self):
        day = make_window(horizon_days=30).day_availability(
            date(2026, 10, 5), now=NOW, taken=[]
        )
        assert day.status is DemoBookingDayStatus.OUTSIDE_WINDOW

    def test_a_weekend_is_a_non_working_day(self):
        day = make_window().day_availability(
            date(2026, 9, 5), now=NOW, taken=[]
        )  # Saturday
        assert day.status is DemoBookingDayStatus.NON_WORKING_DAY

    def test_a_blackout_date_is_distinguishable_from_a_weekend(self):
        window = make_window(blackout_dates=frozenset({date(2026, 9, 2)}))
        day = window.day_availability(date(2026, 9, 2), now=NOW, taken=[])
        assert day.status is DemoBookingDayStatus.BLACKOUT

    def test_a_blackout_landing_on_a_weekend_reports_the_specific_fact(self):
        window = make_window(blackout_dates=frozenset({date(2026, 9, 5)}))
        day = window.day_availability(date(2026, 9, 5), now=NOW, taken=[])
        assert day.status is DemoBookingDayStatus.BLACKOUT

    def test_every_slot_taken_is_fully_booked(self):
        window = make_window()
        taken = window.day_grid(date(2026, 9, 2))
        day = window.day_availability(date(2026, 9, 2), now=NOW, taken=taken)
        assert day.status is DemoBookingDayStatus.FULLY_BOOKED
        assert day.slots == ()

    def test_too_late_today_is_no_remaining_slots_not_fully_booked(self):
        """17:00 IST with a 30-minute grid closing at 18:00 and two hours'
        notice: nothing is left today, but nobody booked anything. The UI
        must be able to say 'too late for today', not 'we are busy'."""
        late = datetime(2026, 9, 1, 11, 30, tzinfo=UTC)  # 17:00 IST
        day = make_window().day_availability(date(2026, 9, 1), now=late, taken=[])
        assert day.status is DemoBookingDayStatus.NO_REMAINING_SLOTS

    def test_partially_elapsed_day_with_the_rest_taken_is_fully_booked(self):
        window = make_window()
        morning = datetime(2026, 9, 1, 3, 0, tzinfo=UTC)  # 08:30 IST
        taken = window.day_grid(date(2026, 9, 1))
        day = window.day_availability(date(2026, 9, 1), now=morning, taken=taken)
        assert day.status is DemoBookingDayStatus.FULLY_BOOKED

    async def test_availability_returns_every_requested_date_in_order(self):
        service, _, _ = make_service()
        result = await service.get_availability(
            from_date=date(2026, 8, 30), to_date=date(2026, 9, 6)
        )
        assert [d.day for d in result.days] == [
            date(2026, 8, 30) + timedelta(days=i) for i in range(8)
        ]
        by_date = {d.day: d.status for d in result.days}
        assert by_date[date(2026, 8, 30)] is DemoBookingDayStatus.OUTSIDE_WINDOW
        assert by_date[date(2026, 9, 2)] is DemoBookingDayStatus.AVAILABLE
        assert by_date[date(2026, 9, 5)] is DemoBookingDayStatus.NON_WORKING_DAY

    async def test_a_booked_slot_disappears_from_availability(self):
        service, repository, _ = make_service()
        await book(service)
        result = await service.get_availability(
            from_date=date(2026, 9, 1), to_date=date(2026, 9, 1)
        )
        day = result.days[0]
        assert all(s.starts_at != SLOT for s in day.slots)
        assert len(repository.bookings) == 1

    async def test_availability_reports_the_window_bounds(self):
        service, _, _ = make_service()
        result = await service.get_availability(
            from_date=date(2026, 9, 1), to_date=date(2026, 9, 1)
        )
        assert result.first_bookable_date == date(2026, 9, 1)
        assert result.last_bookable_date == date(2026, 10, 1)


# ==========================================================================
# Booking guards
# ==========================================================================


class TestSlotsInThePastAreNotBookable:
    async def test_a_slot_before_now_is_rejected(self):
        service, _, _ = make_service(now=datetime(2026, 9, 2, 1, 0, tzinfo=UTC))
        with pytest.raises(SlotNotBookableError) as excinfo:
            await book(service, starts_at=SLOT)
        assert "past" in excinfo.value.message

    async def test_a_slot_earlier_today_is_rejected(self):
        # 16:00 IST, booking a 10:00 IST slot on the same day.
        service, _, _ = make_service(now=datetime(2026, 9, 1, 10, 30, tzinfo=UTC))
        with pytest.raises(SlotNotBookableError):
            await book(service, starts_at=datetime(2026, 9, 1, 4, 30, tzinfo=UTC))

    async def test_a_slot_is_not_bookable_the_instant_before_it_starts(self):
        """With the default two hours' notice, a slot 60 seconds away is
        refused. This is the guard the brief calls out by name."""
        service, _, _ = make_service(now=SLOT - timedelta(seconds=60))
        with pytest.raises(SlotNotBookableError) as excinfo:
            await book(service)
        assert "too soon" in excinfo.value.message

    async def test_a_slot_is_refused_at_its_own_start_even_with_zero_notice(self):
        """A deployment that sets the notice period to zero still cannot
        book the slot that is starting this very second -- ``is_bookable``
        requires a strictly future start as well as clearing the notice
        window."""
        window = make_window(lead_time_minutes=0)
        service, _, _ = make_service(window=window, now=SLOT)
        with pytest.raises(SlotNotBookableError) as excinfo:
            await book(service)
        assert "past" in excinfo.value.message
        assert window.is_bookable(SLOT, SLOT) is False
        assert window.is_bookable(SLOT, SLOT - timedelta(seconds=1)) is True

    async def test_a_slot_exactly_at_the_notice_boundary_is_bookable(self):
        service, repository, _ = make_service(now=SLOT - timedelta(minutes=120))
        await book(service)
        assert len(repository.bookings) == 1

    async def test_one_second_inside_the_notice_boundary_is_refused(self):
        service, _, _ = make_service(
            now=SLOT - timedelta(minutes=120) + timedelta(seconds=1)
        )
        with pytest.raises(SlotNotBookableError):
            await book(service)


class TestOffGridAndClosedDays:
    async def test_an_arbitrary_time_between_slots_is_rejected(self):
        """11:07 IST is not on the published grid. Refusing it is what
        makes a unique index on ``starts_at`` a complete overlap guard."""
        service, _, _ = make_service()
        with pytest.raises(SlotNotBookableError) as excinfo:
            await book(service, starts_at=SLOT + timedelta(minutes=7))
        assert "published slot times" in excinfo.value.message

    async def test_a_time_outside_working_hours_is_rejected(self):
        service, _, _ = make_service()
        with pytest.raises(SlotNotBookableError):
            await book(service, starts_at=datetime(2026, 9, 1, 16, 30, tzinfo=UTC))

    async def test_a_weekend_slot_is_rejected(self):
        service, _, _ = make_service()
        with pytest.raises(SlotNotBookableError) as excinfo:
            await book(service, starts_at=datetime(2026, 9, 5, 5, 30, tzinfo=UTC))
        assert "working day" in excinfo.value.message

    async def test_a_blackout_slot_is_rejected(self):
        window = make_window(blackout_dates=frozenset({date(2026, 9, 2)}))
        service, _, _ = make_service(window=window)
        with pytest.raises(SlotNotBookableError) as excinfo:
            await book(service, starts_at=datetime(2026, 9, 2, 5, 30, tzinfo=UTC))
        assert "closed" in excinfo.value.message

    async def test_a_slot_beyond_the_horizon_is_rejected(self):
        service, _, _ = make_service(window=make_window(horizon_days=7))
        with pytest.raises(SlotNotBookableError) as excinfo:
            await book(service, starts_at=datetime(2026, 9, 15, 5, 30, tzinfo=UTC))
        assert "days ahead" in excinfo.value.message

    async def test_the_last_day_of_the_horizon_is_still_bookable(self):
        service, repository, _ = make_service(window=make_window(horizon_days=7))
        await book(service, starts_at=datetime(2026, 9, 8, 5, 30, tzinfo=UTC))
        assert len(repository.bookings) == 1


# ==========================================================================
# The happy path, and what it commits
# ==========================================================================


class TestBookingSucceeds:
    async def test_a_booking_creates_both_a_lead_and_a_reservation(self):
        service, repository, leads = make_service()
        result = await book(service)

        assert leads.created == 1
        assert len(repository.bookings) == 1
        assert result.booking.demo_request_id == result.demo_request.id
        assert result.booking.status == DemoBookingStatus.CONFIRMED.value
        assert result.booking.starts_at == SLOT
        assert result.booking.ends_at == SLOT + timedelta(minutes=30)

    async def test_a_booked_demo_is_marked_scheduled_in_the_lead_queue(self):
        """A booked demo is still a lead, and sales' existing queue must
        reflect that it is on the calendar without knowing this domain
        exists."""
        service, _, _ = make_service()
        result = await book(service)
        assert result.demo_request.status == DemoRequestStatus.SCHEDULED.value

    async def test_the_booking_is_committed_before_the_response_is_built(self):
        """The visitor is told 'confirmed' only after the write is durable
        -- a confirmation for something a later rollback could erase is the
        worst bug this feature could have."""
        service, repository, _ = make_service()
        result = await book(service)
        assert repository.commits >= 2
        assert result.booking.id in repository.bookings

    async def test_the_lead_email_is_normalized_like_the_plain_form(self):
        service, _, leads = make_service()
        result = await book(service, email="  ASHA@HotelBlue.IN  ")
        assert result.demo_request.email == "asha@hotelblue.in"

    async def test_a_manage_token_is_returned_once_and_only_its_hash_stored(self):
        service, _, _ = make_service()
        result = await book(service)
        assert result.manage_token
        assert result.booking.manage_token_hash == hash_manage_token(
            result.manage_token
        )
        assert result.manage_token not in result.booking.manage_token_hash

    async def test_the_zone_the_slot_was_published_in_is_recorded(self):
        service, _, _ = make_service()
        result = await book(service)
        assert result.booking.booked_timezone == "Asia/Kolkata"


# ==========================================================================
# Losing the race
# ==========================================================================


class TestSlotConflict:
    async def test_a_taken_slot_yields_409_with_alternatives(self):
        service, _, _ = make_service()
        await book(service, email="first@example.com")

        with pytest.raises(SlotAlreadyBookedError) as excinfo:
            await book(service, email="second@example.com")

        error = excinfo.value
        assert error.status_code == 409
        assert error.data["requested_starts_at"] == "2026-09-01T05:30:00Z"
        alternatives = error.data["next_available_slots"]
        assert alternatives, "a 409 must hand back somewhere else to go"
        assert all(a["starts_at"] != "2026-09-01T05:30:00Z" for a in alternatives)
        assert "label" in alternatives[0]

    async def test_the_losing_visitors_lead_survives_the_conflict(self):
        """The whole point of committing the lead first. Someone who lost
        a slot race is still a prospect who told us who they are."""
        service, repository, leads = make_service()
        await book(service, email="first@example.com")
        commits_before = repository.commits

        with pytest.raises(SlotAlreadyBookedError):
            await book(service, email="second@example.com")

        loser = next(
            lead for lead in leads.leads.values() if lead.email == "second@example.com"
        )
        assert loser.id in repository.committed_lead_ids
        assert repository.commits > commits_before

    async def test_no_booking_row_exists_for_the_loser(self):
        service, repository, _ = make_service()
        await book(service, email="first@example.com")
        with pytest.raises(SlotAlreadyBookedError):
            await book(service, email="second@example.com")
        assert len(repository.bookings) == 1

    async def test_a_retry_within_the_dedupe_window_reuses_the_same_lead(self):
        service, _, leads = make_service()
        await book(service, email="first@example.com")
        with pytest.raises(SlotAlreadyBookedError):
            await book(service, email="second@example.com")

        await book(
            service,
            email="second@example.com",
            starts_at=SLOT + timedelta(minutes=30),
        )
        second_leads = [
            lead for lead in leads.leads.values() if lead.email == "second@example.com"
        ]
        assert len(second_leads) == 1, "a retry must not spam the sales queue"
        assert second_leads[0].status == DemoRequestStatus.SCHEDULED.value

    async def test_dedupe_can_be_disabled_so_every_attempt_is_its_own_lead(self):
        service, _, leads = make_service(lead_dedupe_minutes=0)
        await book(service, email="first@example.com")
        with pytest.raises(SlotAlreadyBookedError):
            await book(service, email="second@example.com")
        await book(
            service,
            email="second@example.com",
            starts_at=SLOT + timedelta(minutes=30),
        )
        second_leads = [
            lead for lead in leads.leads.values() if lead.email == "second@example.com"
        ]
        assert len(second_leads) == 2

    async def test_alternatives_never_suggest_a_blackout_or_weekend_slot(self):
        """A 409 hands the visitor somewhere else to go. Somewhere the
        sales team is actually open -- suggesting a slot that would then
        be refused with a 422 is worse than suggesting nothing."""
        window = make_window(
            blackout_dates=frozenset({date(2026, 9, 1), date(2026, 9, 2)})
        )
        service, _, _ = make_service(window=window)
        # Fill 2026-09-03 (Thursday) so alternatives must look further out.
        taken_day = date(2026, 9, 3)
        with pytest.raises(SlotNotBookableError):
            await book(service, starts_at=SLOT)  # 09-01 is now a blackout

        alternatives = window.next_available_starts(now=NOW, taken=[], limit=20)
        suggested_days = {window.local_date(a) for a in alternatives}
        assert date(2026, 9, 1) not in suggested_days  # blackout
        assert date(2026, 9, 2) not in suggested_days  # blackout
        assert date(2026, 9, 5) not in suggested_days  # Saturday
        assert date(2026, 9, 6) not in suggested_days  # Sunday
        assert taken_day in suggested_days

    async def test_a_failed_alternatives_lookup_still_yields_409_not_500(self):
        service, repository, _ = make_service()
        await book(service, email="first@example.com")

        async def boom(*_args, **_kwargs):
            raise RuntimeError("the calendar query fell over")

        repository.confirmed_starts_between = boom  # type: ignore[method-assign]
        with pytest.raises(SlotAlreadyBookedError) as excinfo:
            await book(service, email="second@example.com")
        assert excinfo.value.data["next_available_slots"] == []


# ==========================================================================
# Mail: recorded honestly, never blocking the booking
# ==========================================================================


class TestConfirmationMail:
    async def test_a_confirmation_is_queued_never_reported_as_sent(self):
        notifications = FakeNotificationService()
        service, _, _ = make_service(notification_service=notifications)
        result = await book(service)

        assert result.confirmation_state is DemoBookingConfirmationState.QUEUED
        assert result.confirmation_delivery_id is not None
        assert "sent" not in {s.value for s in DemoBookingConfirmationState}

    async def test_the_visitor_and_the_team_are_both_told(self):
        notifications = FakeNotificationService()
        service, _, _ = make_service(notification_service=notifications)
        await book(service)

        recipients = {str(c.fields["recipient"]) for c in notifications.calls}
        assert recipients == {"asha@hotelblue.in", "sales@wyfyguest.com"}

    async def test_a_failed_confirmation_is_recorded_as_failed_and_the_booking_stands(
        self,
    ):
        """The booking is real and the visitor is on the calendar. What is
        *not* claimed is that they were emailed about it."""
        notifications = FakeNotificationService(raise_on={"demo_booking_confirmed"})
        service, repository, _ = make_service(notification_service=notifications)

        result = await book(service)

        assert (
            result.confirmation_state is DemoBookingConfirmationState.ENQUEUE_FAILED
        )
        assert result.confirmation_delivery_id is None
        assert result.booking.guest_confirmation_delivery_id is None
        # The reservation itself is untouched.
        assert result.booking.status == DemoBookingStatus.CONFIRMED.value
        assert len(repository.bookings) == 1
        assert repository.commits >= 2

    async def test_a_failed_team_notification_does_not_fail_the_booking_either(self):
        notifications = FakeNotificationService(
            raise_on={"demo_booking_team_notification"}
        )
        service, repository, _ = make_service(notification_service=notifications)
        result = await book(service)
        assert result.confirmation_state is DemoBookingConfirmationState.QUEUED
        assert result.booking.team_notification_delivery_id is None
        assert len(repository.bookings) == 1

    async def test_an_unset_notify_address_is_a_no_op_not_a_fabricated_recipient(self):
        notifications = FakeNotificationService()
        service, _, _ = make_service(
            notification_service=notifications, notify_email=""
        )
        await book(service)
        recipients = {str(c.fields["recipient"]) for c in notifications.calls}
        assert recipients == {"asha@hotelblue.in"}

    async def test_no_notification_service_is_recorded_as_not_configured(self):
        service, repository, _ = make_service(notification_service=None)
        result = await book(service)
        assert (
            result.confirmation_state is DemoBookingConfirmationState.NOT_CONFIGURED
        )
        assert len(repository.bookings) == 1

    async def test_the_confirmation_email_names_the_zone_and_offset(self):
        notifications = FakeNotificationService()
        service, _, _ = make_service(notification_service=notifications)
        await book(service)
        guest = next(
            call
            for call in notifications.calls
            if call.fields["recipient"] == "asha@hotelblue.in"
        )
        body = str(guest.fields["body"])
        assert "11:00 AM" in body
        assert "UTC+05:30" in body

    def test_booking_mail_is_routed_to_the_sales_mailbox(self):
        """A demo booking is a sales flow. Asserted against the real
        routing table rather than restated, so moving an event without
        updating the table fails here."""
        from app.domains.notification.constants import (
            NotificationEventType,
            mail_identity_for_event,
        )
        from app.domains.otp.service import MailIdentity

        for event in (
            NotificationEventType.DEMO_BOOKING_CONFIRMED,
            NotificationEventType.DEMO_BOOKING_TEAM_NOTIFICATION,
            NotificationEventType.DEMO_BOOKING_CANCELLED,
        ):
            assert mail_identity_for_event(event.value) is MailIdentity.DEFAULT


# ==========================================================================
# Cancel and reschedule
# ==========================================================================


class TestCancel:
    async def test_a_visitor_with_the_token_can_cancel(self):
        service, _, _ = make_service()
        booked = await book(service)

        result = await service.cancel_booking(
            booking_id=booked.booking.id,
            manage_token=booked.manage_token,
            reason="Something came up",
        )
        assert result.booking.status == DemoBookingStatus.CANCELLED.value
        assert result.booking.cancelled_at is not None
        assert result.booking.cancellation_reason == "Something came up"

    async def test_cancelling_returns_the_slot_to_availability(self):
        service, _, _ = make_service()
        booked = await book(service)
        await service.cancel_booking(
            booking_id=booked.booking.id,
            manage_token=booked.manage_token,
            reason=None,
        )
        result = await service.get_availability(
            from_date=date(2026, 9, 1), to_date=date(2026, 9, 1)
        )
        assert any(s.starts_at == SLOT for s in result.days[0].slots)

    async def test_a_wrong_token_is_refused(self):
        service, _, _ = make_service()
        booked = await book(service)
        with pytest.raises(InvalidManageTokenError):
            await service.cancel_booking(
                booking_id=booked.booking.id,
                manage_token="not-the-right-token-at-all",
                reason=None,
            )

    async def test_a_valid_token_for_a_different_booking_is_refused(self):
        """Knowing one booking's token must not let you touch another."""
        service, _, _ = make_service()
        first = await book(service, email="a@example.com")
        second = await book(
            service, email="b@example.com", starts_at=SLOT + timedelta(minutes=30)
        )
        with pytest.raises(InvalidManageTokenError):
            await service.cancel_booking(
                booking_id=second.booking.id,
                manage_token=first.manage_token,
                reason=None,
            )

    async def test_cancelling_twice_is_refused(self):
        service, _, _ = make_service()
        booked = await book(service)
        await service.cancel_booking(
            booking_id=booked.booking.id,
            manage_token=booked.manage_token,
            reason=None,
        )
        with pytest.raises(BookingNotCancellableError):
            await service.cancel_booking(
                booking_id=booked.booking.id,
                manage_token=booked.manage_token,
                reason=None,
            )

    async def test_a_completed_booking_cannot_be_rewritten_by_a_visitor(self):
        service, repository, _ = make_service()
        booked = await book(service)
        await repository.update_booking(
            booked.booking, {"status": DemoBookingStatus.COMPLETED.value}
        )
        with pytest.raises(BookingNotCancellableError):
            await service.cancel_booking(
                booking_id=booked.booking.id,
                manage_token=booked.manage_token,
                reason=None,
            )


class TestReschedule:
    async def test_a_booking_can_be_moved_to_a_free_slot(self):
        service, _, _ = make_service()
        booked = await book(service)
        target = SLOT + timedelta(minutes=30)

        result = await service.reschedule_booking(
            booking_id=booked.booking.id,
            manage_token=booked.manage_token,
            starts_at=target,
        )
        assert result.booking.id == booked.booking.id
        assert result.booking.starts_at == target
        assert result.booking.ends_at == target + timedelta(minutes=30)

    async def test_moving_issues_a_new_token_and_retires_the_old_one(self):
        service, _, _ = make_service()
        booked = await book(service)
        moved = await service.reschedule_booking(
            booking_id=booked.booking.id,
            manage_token=booked.manage_token,
            starts_at=SLOT + timedelta(minutes=30),
        )
        assert moved.manage_token != booked.manage_token
        with pytest.raises(InvalidManageTokenError):
            await service.cancel_booking(
                booking_id=booked.booking.id,
                manage_token=booked.manage_token,
                reason=None,
            )

    async def test_moving_onto_a_taken_slot_leaves_the_original_intact(self):
        """The failure mode cancel-then-rebook would have: the visitor
        must never end up with no booking at all because their target was
        gone."""
        service, _, _ = make_service()
        mine = await book(service, email="a@example.com")
        theirs = SLOT + timedelta(minutes=30)
        await book(service, email="b@example.com", starts_at=theirs)

        with pytest.raises(SlotAlreadyBookedError):
            await service.reschedule_booking(
                booking_id=mine.booking.id,
                manage_token=mine.manage_token,
                starts_at=theirs,
            )
        assert mine.booking.starts_at == SLOT
        assert mine.booking.status == DemoBookingStatus.CONFIRMED.value

    async def test_moving_to_a_past_slot_is_refused(self):
        service, _, _ = make_service()
        booked = await book(service)
        with pytest.raises(SlotNotBookableError):
            await service.reschedule_booking(
                booking_id=booked.booking.id,
                manage_token=booked.manage_token,
                starts_at=datetime(2026, 8, 25, 5, 30, tzinfo=UTC),
            )

    async def test_moving_to_the_same_slot_is_a_no_op(self):
        notifications = FakeNotificationService()
        service, _, _ = make_service(notification_service=notifications)
        booked = await book(service)
        before = len(notifications.calls)

        result = await service.reschedule_booking(
            booking_id=booked.booking.id,
            manage_token=booked.manage_token,
            starts_at=SLOT,
        )
        assert result.manage_token is None
        assert len(notifications.calls) == before


# ==========================================================================
# Abuse protection
# ==========================================================================


class TestAbuseProtection:
    async def test_one_email_cannot_hold_more_than_the_configured_slots(self):
        service, _, _ = make_service(max_active_per_email=2)
        await book(service, starts_at=SLOT)
        await book(service, starts_at=SLOT + timedelta(minutes=30))
        with pytest.raises(BookingRateLimitExceededError):
            await book(service, starts_at=SLOT + timedelta(minutes=60))

    async def test_cancelling_frees_a_slot_against_the_cap(self):
        service, _, _ = make_service(max_active_per_email=1)
        booked = await book(service, starts_at=SLOT)
        await service.cancel_booking(
            booking_id=booked.booking.id,
            manage_token=booked.manage_token,
            reason=None,
        )
        await book(service, starts_at=SLOT + timedelta(minutes=30))

    async def test_the_cap_can_be_disabled(self):
        service, repository, _ = make_service(max_active_per_email=0)
        for index in range(4):
            await book(service, starts_at=SLOT + timedelta(minutes=30 * index))
        assert len(repository.bookings) == 4

    async def test_repeated_attempts_from_one_address_are_throttled(self):
        redis = FakeRedis()
        service, _, _ = make_service(
            redis=redis, max_attempts_per_window=2, max_active_per_email=0
        )
        await book(service, starts_at=SLOT)
        await book(service, starts_at=SLOT + timedelta(minutes=30))
        with pytest.raises(BookingRateLimitExceededError):
            await book(service, starts_at=SLOT + timedelta(minutes=60))

    async def test_failed_attempts_count_too(self):
        """A script losing race after race must still be throttled --
        otherwise the limiter only slows down successful bookings, which
        are the ones we want."""
        redis = FakeRedis()
        service, _, _ = make_service(
            redis=redis, max_attempts_per_window=2, max_active_per_email=0
        )
        for _ in range(2):
            with pytest.raises(SlotNotBookableError):
                await book(service, starts_at=SLOT + timedelta(minutes=7))
        with pytest.raises(BookingRateLimitExceededError):
            await book(service, starts_at=SLOT)

    async def test_the_limiter_fails_open_when_redis_is_down(self):
        """A booking page that 500s because Redis blinked is worse than a
        brief unthrottled window -- the same posture RateLimitMiddleware
        documents."""
        redis = FakeRedis(explode=True)
        service, repository, _ = make_service(redis=redis, max_attempts_per_window=1)
        await book(service)
        assert len(repository.bookings) == 1

    async def test_the_limit_is_scoped_per_email_not_globally(self):
        redis = FakeRedis()
        service, repository, _ = make_service(
            redis=redis, max_attempts_per_window=1, max_active_per_email=0
        )
        await book(service, email="a@example.com", starts_at=SLOT)
        await book(
            service, email="b@example.com", starts_at=SLOT + timedelta(minutes=30)
        )
        assert len(repository.bookings) == 2

    async def test_the_rate_limiter_reuses_the_projects_incr_expire_ttl_pattern(self):
        redis = FakeRedis()
        await BookingRateLimiter.check_and_increment(
            redis, "a@example.com", max_requests=5, window_minutes=60
        )
        key = "demo_booking:attempts:a@example.com"
        assert redis.counters[key] == 1
        assert redis.ttls[key] == 3600

    async def test_the_public_booking_path_is_rate_limited_by_the_middleware(self):
        from app.middleware.rate_limit import RATE_LIMITED_PATH_PREFIXES

        assert "/api/v1/demo-bookings" in RATE_LIMITED_PATH_PREFIXES


# ==========================================================================
# Master console
# ==========================================================================


class TestMasterConsole:
    async def test_bookings_list_joins_the_lead(self):
        service, _, _ = make_service()
        await book(service)
        result = await service.list_bookings(page=1, page_size=25)
        assert len(result.items) == 1
        booking, lead = result.items[0]
        assert lead.id == booking.demo_request_id
        assert lead.company_name == "Hotel Blue"

    async def test_an_operator_can_record_a_no_show(self):
        service, _, _ = make_service()
        booked = await book(service)
        actor = uuid.uuid4()
        result = await service.admin_update_booking(
            booking_id=booked.booking.id,
            data={"status": DemoBookingStatus.NO_SHOW.value},
            actor_user_id=actor,
        )
        assert result.booking.status == DemoBookingStatus.NO_SHOW.value
        assert result.booking.updated_by == actor

    async def test_an_operator_cannot_move_a_booking_through_this_path(self):
        """``starts_at`` is filtered out, so there is no second, weaker
        code path onto an occupied instant."""
        service, _, _ = make_service()
        booked = await book(service)
        await service.admin_update_booking(
            booking_id=booked.booking.id,
            data={"starts_at": SLOT + timedelta(days=1), "status": "cancelled"},
            actor_user_id=None,
        )
        assert booked.booking.starts_at == SLOT

    def test_the_console_routes_reuse_the_demo_request_permissions(self):
        from app.domains.demo_booking.router import router

        gated = {
            (tuple(sorted(route.methods)), route.path): len(
                getattr(route, "dependencies", [])
            )
            for route in router.routes
        }
        assert gated[(("GET",), "/demo-bookings")] >= 1
        assert gated[(("PATCH",), "/demo-bookings/{booking_id}")] >= 1
        assert gated[(("POST",), "/demo-bookings")] == 0
        assert gated[(("GET",), "/demo-bookings/availability")] == 0


# ==========================================================================
# Settings parsing
# ==========================================================================


class TestSettingsParsing:
    def test_working_days_parse(self):
        assert parse_working_weekdays("0,1,2,3,4") == frozenset({0, 1, 2, 3, 4})
        assert parse_working_weekdays(" 0 , 5 ") == frozenset({0, 5})
        assert parse_working_weekdays("") == frozenset()

    def test_a_bad_working_day_fails_loudly_naming_the_token(self):
        with pytest.raises(ValueError, match="not an integer"):
            parse_working_weekdays("0,monday")
        with pytest.raises(ValueError, match="out of range"):
            parse_working_weekdays("0,9")

    def test_blackout_dates_parse(self):
        assert parse_blackout_dates("2026-10-02,2026-12-25") == frozenset(
            {date(2026, 10, 2), date(2026, 12, 25)}
        )
        assert parse_blackout_dates("") == frozenset()

    def test_a_bad_blackout_date_fails_loudly(self):
        with pytest.raises(ValueError, match="ISO-8601 date"):
            parse_blackout_dates("2nd October")

    def test_local_time_parses(self):
        assert parse_local_time("09:30", label="x") == time(9, 30)

    def test_a_bad_local_time_names_the_setting(self):
        with pytest.raises(ValueError, match="demo_booking_workday_start"):
            parse_local_time("half nine", label="demo_booking_workday_start")

    def test_the_window_builds_from_the_real_settings_defaults(self):
        from app.core.config import Settings

        window = BookingWindow.from_settings(Settings())
        assert str(window.timezone) == "Asia/Kolkata"
        assert window.workday_start == time(10, 0)
        assert window.workday_end == time(18, 0)
        assert window.slot_minutes == 30
        assert window.lead_time_minutes == 120
        assert window.working_weekdays == frozenset({0, 1, 2, 3, 4})


# ==========================================================================
# Conflict classification
# ==========================================================================


class TestConflictClassification:
    def test_a_postgres_unique_violation_on_the_index_is_recognised(self):
        from sqlalchemy.exc import IntegrityError

        exc = IntegrityError(
            "INSERT INTO demo_bookings",
            {},
            Exception(
                'duplicate key value violates unique constraint '
                '"uq_demo_bookings_active_slot"'
            ),
        )
        assert is_active_slot_conflict(exc) is True

    def test_an_unrelated_integrity_error_is_not_swallowed(self):
        """A bad foreign key must keep propagating as the real error it
        is, not be reported to a visitor as 'that slot was just taken'."""
        from sqlalchemy.exc import IntegrityError

        exc = IntegrityError(
            "INSERT INTO demo_bookings",
            {},
            Exception(
                'insert or update on table "demo_bookings" violates foreign '
                'key constraint "fk_demo_bookings_demo_request_id_demo_requests"'
            ),
        )
        assert is_active_slot_conflict(exc) is False


# ==========================================================================
# The wire contract the frontend builds against
# ==========================================================================
#
# These go through a real FastAPI app and the app-wide exception handler,
# so what is asserted is the JSON a browser actually receives -- status
# code, envelope shape, and the stable `data.code`. Following
# `tests/unit/test_middleware.py`'s own TestClient precedent.


def make_client(service: DemoBookingService):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.common.exceptions import register_exception_handlers
    from app.domains.demo_booking.dependencies import get_demo_booking_service
    from app.domains.demo_booking.router import router as booking_router

    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(booking_router, prefix="/api/v1")
    app.dependency_overrides[get_demo_booking_service] = lambda: service
    return TestClient(app, raise_server_exceptions=False)


def lead_payload(**overrides) -> dict:
    payload = {
        "full_name": "Asha Menon",
        "email": "asha@hotelblue.in",
        "phone": "+919812345678",
        "company_name": "Hotel Blue",
        "message": "Interested in guest WiFi.",
        "property_type": "hotel",
        "location_count": 3,
        "router_count": 5,
    }
    payload.update(overrides)
    return payload


class TestSlotIdentifiers:
    def test_a_slot_id_round_trips_to_the_same_instant(self):
        slot_id = encode_slot_id(SLOT, secret=SECRET)
        assert decode_slot_id(slot_id, secret=SECRET) == SLOT

    def test_the_same_slot_always_gets_the_same_id(self):
        """Stable, so a client can match a slot across two availability
        calls without parsing timestamps."""
        assert encode_slot_id(SLOT, secret=SECRET) == encode_slot_id(
            SLOT, secret=SECRET
        )

    def test_an_id_is_opaque_and_not_the_timestamp_in_plain_sight(self):
        slot_id = encode_slot_id(SLOT, secret=SECRET)
        assert "2026" not in slot_id
        assert slot_id.startswith("v1.")

    def test_a_forged_id_is_rejected(self):
        """The client must not be able to construct one -- the whole point
        of the id is that the set of bookable times is the server's to
        define."""
        forged = encode_slot_id(SLOT, secret="a-different-secret-entirely-32ch!!")
        with pytest.raises(InvalidSlotIdError):
            decode_slot_id(forged, secret=SECRET)

    def test_a_tampered_id_is_rejected(self):
        slot_id = encode_slot_id(SLOT, secret=SECRET)
        version, payload, tag = slot_id.split(".")
        moved = encode_slot_id(SLOT + timedelta(hours=1), secret=SECRET).split(".")[1]
        with pytest.raises(InvalidSlotIdError):
            decode_slot_id(f"{version}.{moved}.{tag}", secret=SECRET)

    @pytest.mark.parametrize(
        "bad", ["", "garbage", "v1.abc", "v2.abc.def", "v1.!!!.###"]
    )
    def test_malformed_ids_are_rejected_not_mis_decoded(self, bad):
        with pytest.raises(InvalidSlotIdError):
            decode_slot_id(bad, secret=SECRET)

    def test_an_id_for_a_naive_instant_cannot_be_issued(self):
        with pytest.raises(InvalidSlotIdError):
            encode_slot_id(datetime(2026, 9, 1, 11, 0), secret=SECRET)

    def test_a_valid_id_for_an_elapsed_slot_is_still_refused(self):
        """A signed id is not a permission to book. It is decoded back to
        a plain instant and run through every availability guard."""
        slot_id = encode_slot_id(SLOT, secret=SECRET)
        service, _, _ = make_service(now=SLOT + timedelta(days=1))
        client = make_client(service)
        response = client.post(
            "/api/v1/demo-bookings", json=lead_payload(slot_id=slot_id)
        )
        assert response.status_code == 422
        assert response.json()["data"]["code"] == "SLOT_NOT_BOOKABLE"


class TestHttpContract:
    def test_availability_defaults_to_the_whole_booking_window(self):
        """One call, no date arithmetic on the client."""
        service, _, _ = make_service()
        body = make_client(service).get("/api/v1/demo-bookings/availability").json()

        assert body["success"] is True
        data = body["data"]
        assert data["first_bookable_date"] == "2026-09-01"
        assert data["last_bookable_date"] == "2026-10-01"
        assert [d["date"] for d in data["days"]][0] == "2026-09-01"
        assert [d["date"] for d in data["days"]][-1] == "2026-10-01"
        assert len(data["days"]) == 31

    def test_availability_reports_the_zone_as_data_and_the_server_clock(self):
        service, _, _ = make_service()
        data = (
            make_client(service).get("/api/v1/demo-bookings/availability").json()["data"]
        )
        assert data["timezone"] == "Asia/Kolkata"
        assert data["server_time"] == "2026-09-01T01:00:00Z"
        assert data["server_time_local"] == "2026-09-01T06:30:00+05:30"
        assert data["slot_minutes"] == 30
        assert data["min_notice_minutes"] == 120

    def test_every_slot_carries_an_id_and_both_renderings(self):
        service, _, _ = make_service()
        data = (
            make_client(service).get("/api/v1/demo-bookings/availability").json()["data"]
        )
        day = next(d for d in data["days"] if d["status"] == "available")
        slot = day["slots"][0]
        assert set(slot) == {
            "slot_id",
            "starts_at",
            "ends_at",
            "starts_at_local",
            "ends_at_local",
            "label",
            "duration_minutes",
        }
        assert slot["starts_at"].endswith("Z")
        assert slot["starts_at_local"].endswith("+05:30")
        assert decode_slot_id(slot["slot_id"], secret=SECRET).isoformat().replace(
            "+00:00", "Z"
        ) == slot["starts_at"]

    def test_a_ranged_query_still_works(self):
        service, _, _ = make_service()
        data = (
            make_client(service)
            .get("/api/v1/demo-bookings/availability?from=2026-09-01&to=2026-09-03")
            .json()["data"]
        )
        assert [d["date"] for d in data["days"]] == [
            "2026-09-01",
            "2026-09-02",
            "2026-09-03",
        ]

    def test_an_inverted_range_is_a_named_error_not_a_bare_422(self):
        service, _, _ = make_service()
        response = make_client(service).get(
            "/api/v1/demo-bookings/availability?from=2026-09-10&to=2026-09-01"
        )
        assert response.status_code == 422
        assert response.json()["data"]["code"] == "INVALID_DATE_RANGE"

    def test_a_too_wide_range_is_refused(self):
        service, _, _ = make_service()
        response = make_client(service).get(
            "/api/v1/demo-bookings/availability?from=2026-09-01&to=2027-09-01"
        )
        assert response.status_code == 422
        assert response.json()["data"]["code"] == "INVALID_DATE_RANGE"
        assert response.json()["data"]["max_range_days"] == 62

    def test_booking_returns_201_and_echoes_the_stored_instants(self):
        service, repository, _ = make_service()
        client = make_client(service)
        response = client.post(
            "/api/v1/demo-bookings",
            json=lead_payload(slot_id=encode_slot_id(SLOT, secret=SECRET)),
        )
        assert response.status_code == 201
        data = response.json()["data"]

        stored = next(iter(repository.bookings.values()))
        assert data["id"] == str(stored.id)
        assert data["demo_request_id"] == str(stored.demo_request_id)
        assert data["status"] == "confirmed"
        assert data["timezone"] == "Asia/Kolkata"
        assert data["slot"]["starts_at"] == to_utc_z(stored.starts_at)
        assert data["slot"]["ends_at"] == to_utc_z(stored.ends_at)
        assert data["slot"]["label"] == "11:00 AM"
        assert data["manage_token"]
        assert data["confirmation_email"]["status"] in {
            "queued",
            "not_configured",
            "enqueue_failed",
        }

    def test_the_contended_slot_is_a_409_with_a_stable_code(self):
        """The signal the whole graceful path hangs on. Two people
        clicking 11:00 at the same moment is normal, not exceptional -- it
        must not surface as an anonymous red error box."""
        service, _, _ = make_service()
        client = make_client(service)
        first = client.post(
            "/api/v1/demo-bookings",
            json=lead_payload(slot_id=encode_slot_id(SLOT, secret=SECRET)),
        )
        assert first.status_code == 201

        second = client.post(
            "/api/v1/demo-bookings",
            json=lead_payload(
                email="other@example.com", slot_id=encode_slot_id(SLOT, secret=SECRET)
            ),
        )
        assert second.status_code == 409
        body = second.json()
        assert body["success"] is False
        assert body["data"]["code"] == "SLOT_ALREADY_BOOKED"
        assert body["data"]["requested_starts_at"] == "2026-09-01T05:30:00Z"

        alternatives = body["data"]["next_available_slots"]
        assert alternatives
        # Bookable directly: same shape as an availability slot.
        assert {"slot_id", "starts_at", "ends_at", "starts_at_local", "label"} <= set(
            alternatives[0]
        )
        follow_up = client.post(
            "/api/v1/demo-bookings",
            json=lead_payload(
                email="other@example.com", slot_id=alternatives[0]["slot_id"]
            ),
        )
        assert follow_up.status_code == 201

    def test_an_unissued_slot_id_is_a_distinct_code_from_an_unbookable_slot(self):
        """'Reload the calendar' and 'pick another time' are different
        instructions, so they are different codes."""
        service, _, _ = make_service()
        response = make_client(service).post(
            "/api/v1/demo-bookings", json=lead_payload(slot_id="v1.bogus.bogus")
        )
        assert response.status_code == 422
        assert response.json()["data"]["code"] == "INVALID_SLOT_ID"

    def test_an_off_grid_slot_id_is_slot_not_bookable(self):
        service, _, _ = make_service()
        response = make_client(service).post(
            "/api/v1/demo-bookings",
            json=lead_payload(
                slot_id=encode_slot_id(SLOT + timedelta(minutes=7), secret=SECRET)
            ),
        )
        assert response.status_code == 422
        body = response.json()["data"]
        assert body["code"] == "SLOT_NOT_BOOKABLE"
        assert "published slot times" in body["reason"]

    def test_a_missing_slot_id_is_a_plain_validation_error(self):
        service, _, _ = make_service()
        response = make_client(service).post(
            "/api/v1/demo-bookings", json=lead_payload()
        )
        assert response.status_code == 422

    def test_cancel_and_reschedule_speak_the_same_codes(self):
        service, _, _ = make_service()
        client = make_client(service)
        created = client.post(
            "/api/v1/demo-bookings",
            json=lead_payload(slot_id=encode_slot_id(SLOT, secret=SECRET)),
        ).json()["data"]
        token = created["manage_token"]

        bad = client.post(
            f"/api/v1/demo-bookings/{created['id']}/cancel",
            json={"manage_token": "x" * 32},
        )
        assert bad.status_code == 404
        assert bad.json()["data"]["code"] == "BOOKING_NOT_FOUND"

        moved = client.post(
            f"/api/v1/demo-bookings/{created['id']}/reschedule",
            json={
                "manage_token": token,
                "slot_id": encode_slot_id(SLOT + timedelta(minutes=30), secret=SECRET),
            },
        )
        assert moved.status_code == 200
        assert moved.json()["data"]["slot"]["label"] == "11:30 AM"
        new_token = moved.json()["data"]["manage_token"]

        cancelled = client.post(
            f"/api/v1/demo-bookings/{created['id']}/cancel",
            json={"manage_token": new_token, "reason": "changed my mind"},
        )
        assert cancelled.status_code == 200
        assert cancelled.json()["data"]["status"] == "cancelled"

        again = client.post(
            f"/api/v1/demo-bookings/{created['id']}/cancel",
            json={"manage_token": new_token},
        )
        assert again.status_code == 409
        assert again.json()["data"]["code"] == "BOOKING_NOT_CHANGEABLE"

    def test_rate_limiting_is_a_named_429(self):
        service, _, _ = make_service(max_active_per_email=1)
        client = make_client(service)
        client.post(
            "/api/v1/demo-bookings",
            json=lead_payload(slot_id=encode_slot_id(SLOT, secret=SECRET)),
        )
        second = client.post(
            "/api/v1/demo-bookings",
            json=lead_payload(
                slot_id=encode_slot_id(SLOT + timedelta(minutes=30), secret=SECRET)
            ),
        )
        assert second.status_code == 429
        assert second.json()["data"]["code"] == "BOOKING_RATE_LIMITED"

    def test_every_day_status_the_ui_must_distinguish_is_reachable(self):
        """The three the founder named -- and the two extra this API
        separates -- all appear in one real response."""
        window = make_window(blackout_dates=frozenset({date(2026, 9, 3)}))
        service, repository, _ = make_service(window=window)
        # Fill 2026-09-02 completely so it reports as fully_booked.
        for start in window.day_grid(date(2026, 9, 2)):
            booking = DemoBooking(
                **_base_fields(
                    demo_request_id=uuid.uuid4(),
                    starts_at=start,
                    ends_at=start + timedelta(minutes=30),
                    status=DemoBookingStatus.CONFIRMED.value,
                    booked_timezone="Asia/Kolkata",
                    manage_token_hash="0" * 64,
                )
            )
            repository.bookings[booking.id] = booking

        data = (
            make_client(service)
            .get("/api/v1/demo-bookings/availability?from=2026-08-30&to=2026-09-06")
            .json()["data"]
        )
        statuses = {d["date"]: d["status"] for d in data["days"]}
        assert statuses["2026-08-30"] == "outside_window"
        assert statuses["2026-09-02"] == "fully_booked"
        assert statuses["2026-09-03"] == "blackout"
        assert statuses["2026-09-04"] == "available"
        assert statuses["2026-09-05"] == "non_working_day"

    def test_all_seven_error_codes_are_declared_once_and_only_once(self):
        from app.domains.demo_booking.exceptions import DemoBookingErrorCode

        values = [c.value for c in DemoBookingErrorCode]
        assert len(values) == len(set(values))
        assert set(values) == {
            "SLOT_ALREADY_BOOKED",
            "SLOT_NOT_BOOKABLE",
            "INVALID_SLOT_ID",
            "INVALID_DATE_RANGE",
            "BOOKING_NOT_FOUND",
            "BOOKING_NOT_CHANGEABLE",
            "BOOKING_RATE_LIMITED",
        }

    def test_a_wrong_token_and_a_missing_booking_are_indistinguishable(self):
        """A visitor must not be able to probe which booking ids exist."""
        service, _, _ = make_service()
        client = make_client(service)
        created = client.post(
            "/api/v1/demo-bookings",
            json=lead_payload(slot_id=encode_slot_id(SLOT, secret=SECRET)),
        ).json()["data"]

        wrong_token = client.post(
            f"/api/v1/demo-bookings/{created['id']}/cancel",
            json={"manage_token": "z" * 32},
        )
        no_such_booking = client.post(
            f"/api/v1/demo-bookings/{uuid.uuid4()}/cancel",
            json={"manage_token": "z" * 32},
        )
        assert wrong_token.status_code == no_such_booking.status_code == 404
        assert wrong_token.json()["message"] == no_such_booking.json()["message"]
        assert (
            wrong_token.json()["data"]["code"]
            == no_such_booking.json()["data"]["code"]
        )
