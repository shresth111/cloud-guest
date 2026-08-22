"""SQLAlchemy ORM model for the Demo Booking domain.

:class:`DemoBooking` -- one visitor-reserved demo slot on the sales team's
calendar, booked through the public, unauthenticated calendar on
wyfyguest.com.

## Why this is a second table and not columns on ``demo_requests``

**A booked demo is still a lead.** The 15 rows already in ``demo_requests``
came from the free-text "Book a Demo" form, sales works that queue every
day, and ``DemoRequestService._notify_team`` already emails
``sales@wyfyguest.com`` on every new one. None of that may regress. So a
booking does not *replace* a demo request -- it is layered on top of one:

* ``DemoBookingService.book_slot`` writes a ``DemoRequest`` row exactly
  like the existing form does (same columns, same notification event, same
  Master-console queue), and *then* a ``DemoBooking`` row pointing at it.
  A booked demo therefore shows up in the existing sales queue whether or
  not anyone ever opens a calendar view.
* The 15 existing rows are untouched -- no backfill, no data migration, no
  ``NOT NULL`` column added to their table. A demo request with no booking
  is simply one that came from the plain form, which is still live and
  still the fallback when a prospect does not want to pick a time.
* Sales' own follow-up state (``DemoRequest.status``,
  ``internal_notes``) stays on the lead where it already is, rather than
  being split across two tables.

The alternative -- ``starts_at``/``ends_at`` nullable on ``demo_requests``
-- would have made the double-booking constraint a partial index over a
mostly-NULL column on the table that already carries every unbooked lead,
and would have coupled "sales closed this lead" to "this meeting is on the
calendar". Two facts, two rows.

## Double-booking is prevented by the database, not by a query

``uq_demo_bookings_active_slot`` is a **partial unique index** on
``starts_at``, scoped to rows that are actually holding the slot
(``status = 'confirmed' AND is_deleted = false``). It is the entire
mechanism. Two visitors clicking 11:00 in the same millisecond both pass
any "is this slot free?" ``SELECT`` -- that check is a race by
construction and this domain does not perform one. Both ``INSERT``s reach
Postgres, exactly one commits, and the loser gets an ``IntegrityError``
that ``service.DemoBookingService.book_slot`` turns into a clean
``SlotAlreadyBookedError`` carrying the next free slots.

Two properties make a *single-column* index sufficient, rather than an
``EXCLUDE ... USING gist (tstzrange(...) WITH &&)`` exclusion constraint:

1. every booking is exactly ``Settings.demo_booking_slot_minutes`` long,
   so equal starts and overlapping ranges are the same question; and
2. a start is only ever accepted if it is exactly on the published grid
   (``availability.BookingWindow.is_on_grid``), so there is no way to
   insert an 11:07 booking that would overlap 11:00 without colliding on
   the indexed column.

The honest limitation: if ``demo_booking_slot_minutes`` or
``demo_booking_workday_start`` is changed while future bookings already
exist, previously-booked rows keep their old ``ends_at`` and a *new* grid
slot could overlap one of them without colliding on ``starts_at``. That is
a deliberate, documented trade -- an exclusion constraint would need the
``btree_gist`` extension and cannot be exercised outside Postgres, and
changing the working schedule out from under booked meetings needs a human
looking at the calendar regardless. See ``docs`` note in the migration.

The partial predicate (rather than a plain unique index) is what makes
cancellation real: a cancelled booking stops holding its slot the moment
its status changes, so the slot returns to the availability response for
the next visitor. A plain unique index would have made every cancellation
a permanent tombstone on that time.

## Timezones

``starts_at``/``ends_at`` are ``TIMESTAMPTZ`` and always hold UTC
instants. Every availability *rule* (working hours, weekends, blackouts)
is defined in ``Settings.demo_booking_timezone`` (IST). See
``availability.py``'s module docstring -- the convention is stated there
once, in full, and nothing else in this domain restates it.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import DemoBookingStatus

#: The index that makes double-booking impossible. Defined as a module
#: constant so the name appears in exactly one place in application code
#: and can be asserted on by name in tests -- the migration hard-codes the
#: same string, by this repo's own "migrations are self-contained
#: snapshots" convention.
ACTIVE_SLOT_INDEX_NAME = "uq_demo_bookings_active_slot"

#: The predicate, per dialect. Postgres is production. SQLite is what the
#: test suite can create a real table on (CI has no Postgres service --
#: see ``.github/workflows/ci.yml``), and it supports partial indexes, so
#: the concurrency test exercises a genuine database constraint rather
#: than a simulation of one. The two differ only in boolean spelling.
_ACTIVE_SLOT_WHERE_POSTGRESQL = "status = 'confirmed' AND is_deleted = false"
_ACTIVE_SLOT_WHERE_SQLITE = "status = 'confirmed' AND is_deleted = 0"


class DemoBooking(BaseModel):
    """A visitor-reserved slot on the sales team's demo calendar."""

    __tablename__ = "demo_bookings"

    #: The lead this booking is for. ``RESTRICT``, not ``CASCADE``:
    #: deleting a lead out from under a confirmed meeting would silently
    #: erase something a salesperson has in their calendar. Never
    #: nullable -- a booking without a lead is exactly the "slots exist
    #: but leads are lost" state this design exists to prevent.
    demo_request_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("demo_requests.id", ondelete="RESTRICT"),
        nullable=False,
    )
    starts_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    #: Stored, not derived from ``starts_at`` plus the current
    #: ``demo_booking_slot_minutes`` setting: a booking's length is a fact
    #: about the meeting that was agreed, and changing the setting must
    #: not retroactively move the end of a meeting already in someone's
    #: calendar.
    ends_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=DemoBookingStatus.CONFIRMED.value
    )
    #: The IANA zone the slot was *published* in when it was booked (e.g.
    #: ``"Asia/Kolkata"``). ``starts_at`` alone is unambiguous, so this is
    #: not needed to know when the meeting is -- it is here so that a
    #: later change to ``Settings.demo_booking_timezone`` leaves a record
    #: of which zone each existing booking's "3:00 PM" was.
    booked_timezone: Mapped[str] = mapped_column(String(64), nullable=False)
    #: SHA-256 hex of the opaque manage token handed to the visitor. The
    #: token itself is never stored, exactly as
    #: ``app.domains.router_provisioning`` treats its own one-time tokens
    #: -- a leaked database dump must not let anyone cancel arbitrary
    #: meetings.
    manage_token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    cancellation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    cancelled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: The ``notification_deliveries`` rows this booking's two emails were
    #: written to, or ``NULL`` if no outbox row was ever created. This is
    #: the honest record of what happened to the mail: the delivery row
    #: itself carries ``sent``/``retrying``/``failed`` and is the only
    #: thing that ever claims a message was sent. See
    #: ``constants.DemoBookingConfirmationState`` for why the booking
    #: response never says "sent".
    guest_confirmation_delivery_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("notification_deliveries.id", ondelete="SET NULL"),
        nullable=True,
    )
    team_notification_delivery_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("notification_deliveries.id", ondelete="SET NULL"),
        nullable=True,
    )

    __table_args__ = (
        # ------------------------------------------------------------------
        # THE constraint. See this module's docstring. Nothing in the
        # application layer prevents double-booking; this does.
        # ------------------------------------------------------------------
        Index(
            ACTIVE_SLOT_INDEX_NAME,
            "starts_at",
            unique=True,
            postgresql_where=text(_ACTIVE_SLOT_WHERE_POSTGRESQL),
            sqlite_where=text(_ACTIVE_SLOT_WHERE_SQLITE),
        ),
        # Availability lists a date range; the Master console lists a
        # calendar. Both scan by start instant.
        Index("ix_demo_bookings_starts_at", "starts_at"),
        Index("ix_demo_bookings_status", "status"),
        Index("ix_demo_bookings_demo_request_id", "demo_request_id"),
        # Cancel/reschedule looks a booking up by its token hash before it
        # knows anything else about it.
        Index("ix_demo_bookings_manage_token_hash", "manage_token_hash"),
    )

    def __repr__(self) -> str:
        return (
            f"<DemoBooking(id={self.id}, starts_at={self.starts_at!r}, "
            f"status={self.status})>"
        )


__all__ = ["ACTIVE_SLOT_INDEX_NAME", "DemoBooking"]
