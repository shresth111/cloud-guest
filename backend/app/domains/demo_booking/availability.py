"""Pure, side-effect-free slot-grid computation for the Demo Booking
domain -- no I/O, no session, no clock of its own (``now`` is always
passed in), mirroring ``app.domains.notification.validators``/
``app.domains.otp.validators``'s identical "the service layer can call
this before writing a row" discipline.

=======================================================================
THE TIMEZONE CONVENTION. Read this before changing anything below.
=======================================================================

There are exactly two kinds of time in this domain and they are never
mixed:

**Instants** -- a specific moment on the world's timeline. Every instant
in this domain is a timezone-*aware* ``datetime``. Stored in Postgres as
``TIMESTAMPTZ`` (``DateTime(timezone=True)``), always normalized to UTC
before it is written, always emitted over the API as ISO-8601 UTC with a
literal ``Z`` (e.g. ``"2026-08-25T04:30:00Z"``). ``DemoBooking.starts_at``
is an instant. A naive ``datetime`` is never accepted anywhere in this
domain -- not from the API (``schemas`` rejects it with a 422), not from
this module (``_require_aware`` raises). "Assume it was IST" is precisely
the kind of silent, invisible guess that produces a meeting nobody shows
up to, so it is not done.

**Availability rules** -- working hours, working weekdays, blackout
dates, "which calendar day is this". These are *local* facts and they are
meaningless without a zone, so they are defined in exactly one, named
explicitly: ``Settings.demo_booking_timezone``, default ``Asia/Kolkata``.
The founder, the sales team and effectively every visitor are in IST; the
sales team's working day is 10:00-18:00 *in Kolkata*, not in UTC, and it
stays 10:00-18:00 in Kolkata no matter where the server runs.

The bridge between them is this module. It builds the grid in local
wall-clock time and converts each slot to UTC at the end
(``BookingWindow.day_grid``). That direction matters:

* Generating in local time and converting to UTC is correct across a DST
  transition -- a "10:00 AM local" slot stays 10:00 AM local, and its UTC
  instant shifts by the offset change.
* Generating in UTC and converting to local is not -- the working day
  would silently slide by an hour twice a year.

IST (UTC+05:30) has no DST, so today this distinction changes nothing in
production. It is written the correct way round anyway because the wrong
way round is invisible until the day it isn't, and because
``demo_booking_timezone`` is configurable: the first deployment that
points it at a DST zone must not be the thing that discovers this.
``day_grid`` additionally de-duplicates instants, which is the one
remaining DST artifact (a local wall time that repeats, or does not
exist, across a transition).

**What the visitor sees and what sales sees are the same instant.** The
API returns each slot three ways -- ``starts_at`` (UTC, the canonical
value, the only one anything should ever compare or store),
``starts_at_local`` (the same instant with an explicit ``+05:30`` offset)
and ``label`` (``"3:00 PM"``, for display only). They are three renderings
of one number, produced from one ``datetime``, so they cannot disagree.
The frontend must send ``starts_at`` back verbatim when booking.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterable, Iterator
from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo

from .constants import DemoBookingDayStatus


class NaiveDatetimeError(ValueError):
    """A timezone-naive ``datetime`` reached a function that requires an
    instant. See this module's docstring: guessing a zone is not done."""


def _require_aware(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise NaiveDatetimeError(
            f"{label} must be timezone-aware; a naive datetime has no "
            "single meaning and this domain never guesses one."
        )
    return value.astimezone(UTC)


@dataclasses.dataclass(frozen=True, slots=True)
class Slot:
    """One bookable meeting slot, as a pair of UTC instants."""

    starts_at: datetime
    ends_at: datetime


@dataclasses.dataclass(frozen=True, slots=True)
class DayAvailability:
    """One local calendar date's worth of the availability response.

    ``status`` is always meaningful; ``slots`` is non-empty **only** when
    ``status is DemoBookingDayStatus.AVAILABLE``. See
    ``constants.DemoBookingDayStatus`` for what each value means and why
    the distinctions exist.
    """

    day: date
    status: DemoBookingDayStatus
    slots: tuple[Slot, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class BookingWindow:
    """The availability rules, resolved from ``Settings`` once and then
    treated as an immutable value object.

    Every field except ``timezone`` is expressed in the ``timezone`` --
    see this module's docstring. Build one with
    :meth:`from_settings`, never field-by-field from scattered settings
    reads (the same discipline
    ``app.domains.otp.service.SmtpIdentity.from_settings_block`` enforces
    for the identical reason: a half-configured value object is a bug
    that ships).
    """

    timezone: ZoneInfo
    workday_start: time
    workday_end: time
    slot_minutes: int
    buffer_minutes: int
    lead_time_minutes: int
    horizon_days: int
    #: Python ``date.weekday()`` numbering -- Monday is 0, Sunday is 6.
    working_weekdays: frozenset[int]
    #: Local calendar dates on which nothing is bookable at all.
    blackout_dates: frozenset[date]

    # -- construction ------------------------------------------------------

    @classmethod
    def from_settings(cls, settings: object) -> BookingWindow:
        """Builds the window from the ``demo_booking_*`` block of
        ``app.core.config.Settings``. Takes ``object`` rather than
        ``Settings`` purely to keep this pure module import-free of the
        config module; every attribute read below is a real, documented
        field on ``Settings``."""
        return cls(
            timezone=ZoneInfo(str(settings.demo_booking_timezone)),  # type: ignore[attr-defined]
            workday_start=parse_local_time(
                str(settings.demo_booking_workday_start),  # type: ignore[attr-defined]
                label="demo_booking_workday_start",
            ),
            workday_end=parse_local_time(
                str(settings.demo_booking_workday_end),  # type: ignore[attr-defined]
                label="demo_booking_workday_end",
            ),
            slot_minutes=int(settings.demo_booking_slot_minutes),  # type: ignore[attr-defined]
            buffer_minutes=int(settings.demo_booking_buffer_minutes),  # type: ignore[attr-defined]
            lead_time_minutes=int(settings.demo_booking_lead_time_minutes),  # type: ignore[attr-defined]
            horizon_days=int(settings.demo_booking_horizon_days),  # type: ignore[attr-defined]
            working_weekdays=parse_working_weekdays(
                str(settings.demo_booking_working_days)  # type: ignore[attr-defined]
            ),
            blackout_dates=parse_blackout_dates(
                str(settings.demo_booking_blackout_dates)  # type: ignore[attr-defined]
            ),
        )

    # -- local calendar ----------------------------------------------------

    def local_date(self, instant: datetime) -> date:
        """Which local calendar date ``instant`` falls on. This -- not the
        server's own date, and not the UTC date -- is what "today" means
        everywhere in this domain."""
        return _require_aware(instant, label="instant").astimezone(self.timezone).date()

    def first_bookable_date(self, now: datetime) -> date:
        return self.local_date(now)

    def last_bookable_date(self, now: datetime) -> date:
        return self.local_date(now) + timedelta(days=self.horizon_days)

    def is_within_window(self, day: date, now: datetime) -> bool:
        return self.first_bookable_date(now) <= day <= self.last_bookable_date(now)

    def is_working_day(self, day: date) -> bool:
        return day.weekday() in self.working_weekdays and day not in self.blackout_dates

    # -- the grid ----------------------------------------------------------

    @property
    def step(self) -> timedelta:
        """Distance between consecutive slot *starts*: the meeting length
        plus the buffer the sales team gets between calls."""
        return timedelta(minutes=self.slot_minutes + self.buffer_minutes)

    def slot_end(self, starts_at: datetime) -> datetime:
        return _require_aware(starts_at, label="starts_at") + timedelta(
            minutes=self.slot_minutes
        )

    def day_grid(self, day: date) -> tuple[datetime, ...]:
        """Every slot start on local calendar date ``day``, as UTC
        instants, in ascending order -- *ignoring* who has booked what and
        ignoring the clock. This is the schedule, not the availability.

        Built in local wall-clock time and converted to UTC per slot; see
        this module's docstring for why that direction is the correct one.
        A meeting must fit entirely inside the working day, so the last
        slot is the last one whose *end* is at or before ``workday_end``.
        """
        cursor = datetime.combine(day, self.workday_start, tzinfo=self.timezone)
        closing = datetime.combine(day, self.workday_end, tzinfo=self.timezone)
        length = timedelta(minutes=self.slot_minutes)

        starts: list[datetime] = []
        seen: set[datetime] = set()
        while cursor + length <= closing:
            instant = cursor.astimezone(UTC)
            # A local wall time can repeat (or vanish) across a DST
            # transition. Two grid entries collapsing onto one instant
            # would make the slot double-bookable-looking in the UI while
            # the database constraint -- correctly -- allowed only one.
            # Drop the duplicate here so the two never disagree.
            if instant not in seen:
                seen.add(instant)
                starts.append(instant)
            cursor += self.step
        return tuple(starts)

    def is_on_grid(self, starts_at: datetime) -> bool:
        """Whether ``starts_at`` is exactly one of the scheduled slot
        starts. This is what makes the single-column unique index in
        ``models.DemoBooking`` a *complete* double-booking guard: an
        arbitrary 11:07 start could overlap an 11:00 booking without
        colliding on the indexed column, so arbitrary starts are simply
        never accepted."""
        instant = _require_aware(starts_at, label="starts_at")
        return instant in self.day_grid(self.local_date(instant))

    def is_bookable(self, starts_at: datetime, now: datetime) -> bool:
        """Whether ``starts_at`` is a slot a visitor may book *right now*,
        ignoring whether someone else already has it (that question has
        exactly one correct answer, and it comes from the database
        constraint -- see ``service.DemoBookingService.book_slot``).

        All four conditions must hold:

        1. it is on the grid (``is_on_grid``);
        2. its local date is a working, non-blackout day;
        3. its local date is inside the booking window;
        4. it clears the minimum-notice cutoff -- ``starts_at`` is both
           strictly in the future *and* at least
           ``lead_time_minutes`` away. Both halves are checked so that a
           deployment configuring ``lead_time_minutes = 0`` still cannot
           book the slot that is starting this very second; "a slot must
           not be bookable the instant before it starts" holds at every
           setting, not just the default.
        """
        instant = _require_aware(starts_at, label="starts_at")
        moment = _require_aware(now, label="now")
        day = self.local_date(instant)
        if not self.is_on_grid(instant):
            return False
        if not self.is_working_day(day):
            return False
        if not self.is_within_window(day, moment):
            return False
        return instant > moment and instant - moment >= timedelta(
            minutes=self.lead_time_minutes
        )

    # -- the answer the API returns ----------------------------------------

    def day_availability(
        self, day: date, *, now: datetime, taken: Iterable[datetime]
    ) -> DayAvailability:
        """Classify one local calendar date and list what is still free on
        it. ``taken`` is the set of ``starts_at`` instants already held by
        ``CONFIRMED`` bookings; the caller loads it, this function does no
        I/O.

        The precedence below is deliberate and total -- every date lands in
        exactly one bucket:

        1. outside the window -> ``OUTSIDE_WINDOW`` (a past date is
           reported as outside the window, never as "fully booked");
        2. an explicit blackout -> ``BLACKOUT``. Checked *before* the
           weekday rule so that a date which is both (a holiday landing on
           a Sunday) reports the specific fact rather than the generic
           one;
        3. not a working weekday -> ``NON_WORKING_DAY``;
        4. some slot is free -> ``AVAILABLE``;
        5. nothing on this date clears the notice cutoff ->
           ``NO_REMAINING_SLOTS``;
        6. otherwise every still-bookable slot is taken -> ``FULLY_BOOKED``.
        """
        if not self.is_within_window(day, now):
            return DayAvailability(day, DemoBookingDayStatus.OUTSIDE_WINDOW, ())
        if day in self.blackout_dates:
            return DayAvailability(day, DemoBookingDayStatus.BLACKOUT, ())
        if day.weekday() not in self.working_weekdays:
            return DayAvailability(day, DemoBookingDayStatus.NON_WORKING_DAY, ())

        taken_set = {_require_aware(t, label="taken") for t in taken}
        still_bookable = [
            start for start in self.day_grid(day) if self.is_bookable(start, now)
        ]
        free = [start for start in still_bookable if start not in taken_set]
        if free:
            slots = tuple(Slot(start, self.slot_end(start)) for start in free)
            return DayAvailability(day, DemoBookingDayStatus.AVAILABLE, slots)
        if not still_bookable:
            return DayAvailability(day, DemoBookingDayStatus.NO_REMAINING_SLOTS, ())
        return DayAvailability(day, DemoBookingDayStatus.FULLY_BOOKED, ())

    def next_available_starts(
        self, *, now: datetime, taken: Iterable[datetime], limit: int
    ) -> tuple[datetime, ...]:
        """The next ``limit`` free slot starts from ``now`` forward -- what
        a "that slot was just taken, here are the next ones" 409 carries,
        so a visitor who lost a race is one click from recovering instead
        of being told to go back and look again."""
        taken_set = {_require_aware(t, label="taken") for t in taken}
        found: list[datetime] = []
        for day in iterate_dates(
            self.first_bookable_date(now), self.last_bookable_date(now)
        ):
            if not self.is_working_day(day):
                continue
            for start in self.day_grid(day):
                if start in taken_set or not self.is_bookable(start, now):
                    continue
                found.append(start)
                if len(found) >= limit:
                    return tuple(found)
        return tuple(found)


# ==========================================================================
# Settings parsing -- comma-separated strings, not JSON lists
# ==========================================================================
# pydantic-settings parses a `list[str]` field from the environment as
# JSON, which makes `CLOUDGUEST_DEMO_BOOKING_BLACKOUT_DATES=2026-10-02`
# a startup crash rather than the obvious thing. These stay plain `str`
# fields on Settings and are parsed here, once, into real `date`/`int`
# values -- so a typo fails loudly at parse time with the offending token
# named, instead of being silently dropped.


def parse_local_time(raw: str, *, label: str) -> time:
    """``"10:00"``/``"09:30"`` -> ``time``. Raises ``ValueError`` naming
    the setting, because a mis-typed working hour that silently defaulted
    would quietly publish the wrong calendar."""
    try:
        hour_text, minute_text = raw.strip().split(":", 1)
        return time(hour=int(hour_text), minute=int(minute_text))
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"{label}: {raw!r} is not a HH:MM local time -- e.g. '10:00'."
        ) from exc


def parse_working_weekdays(raw: str) -> frozenset[int]:
    """``"0,1,2,3,4"`` -> ``{0,1,2,3,4}``, Python ``date.weekday()``
    numbering (Monday 0 ... Sunday 6). An empty string means *no* working
    days, which is a legal (if useless) configuration and is reported
    honestly as every date being ``NON_WORKING_DAY`` rather than being
    quietly replaced with a default."""
    days: set[int] = set()
    for token in _tokens(raw):
        try:
            value = int(token)
        except ValueError as exc:
            raise ValueError(
                f"demo_booking_working_days: {token!r} is not an integer "
                "0-6 (Monday is 0)."
            ) from exc
        if not 0 <= value <= 6:
            raise ValueError(
                f"demo_booking_working_days: {value} is out of range -- "
                "0 (Monday) to 6 (Sunday)."
            )
        days.add(value)
    return frozenset(days)


def parse_blackout_dates(raw: str) -> frozenset[date]:
    """``"2026-10-02,2026-12-25"`` -> a set of local calendar dates."""
    days: set[date] = set()
    for token in _tokens(raw):
        try:
            days.add(date.fromisoformat(token))
        except ValueError as exc:
            raise ValueError(
                f"demo_booking_blackout_dates: {token!r} is not an "
                "ISO-8601 date (YYYY-MM-DD)."
            ) from exc
    return frozenset(days)


def _tokens(raw: str) -> Iterator[str]:
    for token in raw.split(","):
        stripped = token.strip()
        if stripped:
            yield stripped


def iterate_dates(start: date, end: date) -> Iterator[date]:
    """Inclusive on both ends."""
    cursor = start
    while cursor <= end:
        yield cursor
        cursor += timedelta(days=1)


__all__ = [
    "BookingWindow",
    "DayAvailability",
    "NaiveDatetimeError",
    "Slot",
    "iterate_dates",
    "parse_blackout_dates",
    "parse_local_time",
    "parse_working_weekdays",
]
