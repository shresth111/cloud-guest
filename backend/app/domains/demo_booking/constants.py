"""Enumerations and module constants for the Demo Booking domain.

Every enum here is stored (where stored at all) as a plain ``String``
column, never a native PostgreSQL enum type -- the same reason
``app.domains.demo_request.constants`` documents for its own: adding a new
status never requires an ``ALTER TYPE`` migration, only a code change.
"""

from __future__ import annotations

from enum import StrEnum


class DemoBookingStatus(StrEnum):
    """Lifecycle of one ``DemoBooking`` row.

    ``CONFIRMED`` is the only status that *holds* a slot -- the partial
    unique index in ``models.DemoBooking.__table_args__`` is scoped to it
    (see that model's own docstring), so cancelling a booking genuinely
    frees the slot for the next visitor rather than leaving a tombstone
    that blocks it forever.

    ``COMPLETED``/``NO_SHOW`` are terminal, sales-set outcomes recorded
    after the meeting time has passed. Neither holds the slot either: the
    slot is in the past by then, and past slots are never bookable
    regardless (see ``availability.BookingWindow.is_bookable``).
    """

    CONFIRMED = "confirmed"
    CANCELLED = "cancelled"
    COMPLETED = "completed"
    NO_SHOW = "no_show"


#: Statuses a *visitor-facing* cancel/reschedule may act on. A booking that
#: sales has already marked ``COMPLETED``/``NO_SHOW`` is a record of
#: something that already happened -- rewriting it from the marketing site
#: would silently destroy sales' own outcome data.
MUTABLE_BY_VISITOR_STATUSES: frozenset[str] = frozenset({DemoBookingStatus.CONFIRMED})


class DemoBookingDayStatus(StrEnum):
    """Why a given local calendar date looks the way it does in the
    availability response.

    The marketing-site calendar has to say three genuinely different
    things -- "pick a time", "this day is full", "you cannot book this day
    at all" -- and it can only do that if the API distinguishes them
    instead of returning an empty ``slots`` list for every case. All five
    values below are reachable; an *error* is never one of them (errors use
    the app-wide ``ApiResponse`` envelope with ``success=false``, so
    "failed to load" is never confusable with "nothing free").

    ``AVAILABLE``
        At least one slot on this date is bookable right now. ``slots`` is
        non-empty.

    ``FULLY_BOOKED``
        This date has slots that would otherwise be bookable, and every
        one of them is already held by a ``CONFIRMED`` booking. ``slots``
        is empty. UI: "fully booked -- try another day".

    ``NO_REMAINING_SLOTS``
        This date is a working day inside the booking window, but no slot
        on it still satisfies the minimum-notice cutoff (see
        ``Settings.demo_booking_lead_time_minutes``). In practice this is
        *today*, late in the day. Distinct from ``FULLY_BOOKED`` because
        the honest message is "too late for today", not "we are busy".

    ``NON_WORKING_DAY``
        Not one of ``Settings.demo_booking_working_days`` -- a weekend, by
        default. UI: "we're closed".

    ``BLACKOUT``
        An explicit closure on ``Settings.demo_booking_blackout_dates``
        (a public holiday, an offsite). Deliberately distinct from
        ``NON_WORKING_DAY``: a recurring weekly closure and a one-off
        holiday are different facts, and sales will ask which one a date
        was.

    ``OUTSIDE_WINDOW``
        Before today or beyond ``Settings.demo_booking_horizon_days``.
        This is the value that answers the founder's "a day with no
        remaining slots must be distinguishable from a day outside the
        booking window".
    """

    AVAILABLE = "available"
    FULLY_BOOKED = "fully_booked"
    NO_REMAINING_SLOTS = "no_remaining_slots"
    NON_WORKING_DAY = "non_working_day"
    BLACKOUT = "blackout"
    OUTSIDE_WINDOW = "outside_window"


#: How the booking flow's own outgoing mail is accounted for on the
#: booking row -- see ``models.DemoBooking.guest_confirmation_delivery_id``
#: and ``schemas.ConfirmationEmailState``.
class DemoBookingConfirmationState(StrEnum):
    """What actually happened to the visitor's confirmation email, as far
    as the booking response can honestly claim at the moment it is built.

    Note the value that is deliberately absent: **there is no ``SENT``.**
    ``NotificationService.enqueue`` writes a ``PENDING`` outbox row; the
    real SMTP call happens later in
    ``app.domains.notification.tasks.run_notification_dispatch_sweep``.
    At the instant the visitor's HTTP response is built, nothing has been
    sent yet, so claiming "sent" would be exactly the class of
    reports-success-while-doing-nothing bug this codebase has been burned
    by repeatedly. The booking response says ``QUEUED``; whether it was
    ever really delivered is answered by the ``NotificationDelivery`` row
    this booking points at, which records ``SENT``/``RETRYING``/``FAILED``
    truthfully.
    """

    QUEUED = "queued"
    #: No notification service was wired at all (unit tests, a bare
    #: checkout). A genuine no-op, recorded as such.
    NOT_CONFIGURED = "not_configured"
    #: The outbox write itself raised. The booking still stands -- losing a
    #: confirmed meeting over a mail hiccup is worse than a manual
    #: follow-up (the same trade
    #: ``DemoRequestService._notify_team`` already makes).
    ENQUEUE_FAILED = "enqueue_failed"


#: Length of the opaque, URL-safe manage token handed to a visitor so they
#: can cancel/reschedule their own booking without an account. 32 bytes of
#: ``secrets.token_urlsafe`` entropy (~43 characters), mirroring the
#: entropy class of this codebase's other unauthenticated one-off tokens.
MANAGE_TOKEN_BYTES = 32

#: Redis key for the per-email booking-attempt counter -- the
#: identifier-scoped half of this domain's abuse protection. Mirrors
#: ``app.domains.otp.constants.OTP_REQUEST_RATE_LIMIT_KEY_TEMPLATE``'s
#: identical shape, because it is the identical INCR+EXPIRE+TTL pattern
#: applied to a different identifier.
BOOKING_RATE_LIMIT_KEY_TEMPLATE = "demo_booking:attempts:{identifier}"


__all__ = [
    "BOOKING_RATE_LIMIT_KEY_TEMPLATE",
    "MANAGE_TOKEN_BYTES",
    "MUTABLE_BY_VISITOR_STATUSES",
    "DemoBookingConfirmationState",
    "DemoBookingDayStatus",
    "DemoBookingStatus",
]
