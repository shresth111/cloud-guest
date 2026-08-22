"""Demo Booking domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like
every other domain's exception hierarchy -- mirrors
``app.domains.demo_request.exceptions``'s identical style. The base
class's ``data`` becomes the envelope's ``data`` field verbatim.

## Every error carries a stable machine-readable ``code``

``data.code`` is part of the API contract and will not change once
shipped; the human-readable ``message`` may be reworded at any time and
must never be parsed. This exists because the frontend has to tell
*contention* apart from every other 4xx: "someone else took 11:00 a
half-second before you" is a normal, expected outcome that deserves a
calm "here are the next times" -- not a red error box. Without a code the
booking flow's most likely real-world failure degrades into its ugliest
presentation. See :data:`DemoBookingErrorCode`.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from enum import StrEnum

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "BookingNotCancellableError",
    "BookingRateLimitExceededError",
    "DemoBookingError",
    "DemoBookingErrorCode",
    "DemoBookingNotFoundError",
    "InvalidAvailabilityRangeError",
    "InvalidManageTokenError",
    "InvalidSlotIdentifierError",
    "SlotAlreadyBookedError",
    "SlotNotBookableError",
]


class DemoBookingErrorCode(StrEnum):
    """Stable error codes for this domain. Frozen contract -- add values,
    never rename or repurpose one."""

    #: 409. The slot was taken between the visitor seeing it and booking
    #: it. The response carries ``next_available_slots``. This is the one
    #: the frontend must special-case: it is contention, not a fault.
    SLOT_ALREADY_BOOKED = "SLOT_ALREADY_BOOKED"
    #: 422. The named slot is not bookable at all -- past, too soon, off
    #: the schedule, on a closed day, or beyond the horizon. ``reason``
    #: carries a short human explanation.
    SLOT_NOT_BOOKABLE = "SLOT_NOT_BOOKABLE"
    #: 422. ``slot_id`` was malformed, of an unknown version, or did not
    #: verify. Distinct from SLOT_NOT_BOOKABLE: the client sent something
    #: this server never issued, so the right UI response is "reload the
    #: calendar", not "pick another time".
    INVALID_SLOT_ID = "INVALID_SLOT_ID"
    #: 422. The availability query's date range was inverted or too wide.
    INVALID_DATE_RANGE = "INVALID_DATE_RANGE"
    #: 404. No booking matches this id, or the manage token does not
    #: match it. Deliberately one code for both -- see
    #: :class:`InvalidManageTokenError`.
    BOOKING_NOT_FOUND = "BOOKING_NOT_FOUND"
    #: 409. The booking exists but is not in a state a visitor may change.
    BOOKING_NOT_CHANGEABLE = "BOOKING_NOT_CHANGEABLE"
    #: 429. Too many booking attempts from this email address, or this
    #: address already holds its maximum number of future slots.
    BOOKING_RATE_LIMITED = "BOOKING_RATE_LIMITED"


class DemoBookingError(CloudGuestError):
    """Base exception for Demo Booking domain errors. Always stamps
    ``data.code``."""

    def __init__(
        self,
        message: str,
        *,
        code: DemoBookingErrorCode,
        status_code: int,
        data: dict[str, object] | None = None,
    ) -> None:
        payload: dict[str, object] = {"code": code.value}
        payload.update(data or {})
        self.code = code
        super().__init__(message, status_code=status_code, data=payload)


class DemoBookingNotFoundError(DemoBookingError):
    def __init__(self, booking_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Booking not found: {booking_id}",
            code=DemoBookingErrorCode.BOOKING_NOT_FOUND,
            status_code=status.HTTP_404_NOT_FOUND,
        )


class SlotAlreadyBookedError(DemoBookingError):
    """Raised when the database's own ``uq_demo_bookings_active_slot``
    partial unique index rejected the write -- i.e. someone else's booking
    for this exact instant committed first.

    This is **not** raised from an application-level "is this slot free?"
    check, because no such check exists in this domain (see
    ``models.DemoBooking``'s module docstring). It is raised strictly from
    a caught ``IntegrityError``, which means it can only ever be raised
    when the slot really is taken, and it is always raised when it really
    is.

    Carries ``next_available_slots`` so the frontend can re-render
    immediately rather than telling the visitor to go back and look again.
    """

    def __init__(self, starts_at: datetime, alternatives: Sequence[dict]) -> None:
        super().__init__(
            "That slot was just taken. Here are the next available times.",
            code=DemoBookingErrorCode.SLOT_ALREADY_BOOKED,
            status_code=status.HTTP_409_CONFLICT,
            data={
                "requested_starts_at": starts_at.isoformat().replace("+00:00", "Z"),
                "next_available_slots": list(alternatives),
            },
        )


class SlotNotBookableError(DemoBookingError):
    """The requested instant is not a slot anyone could book -- it is off
    the published grid, in the past, inside the minimum-notice cutoff,
    beyond the booking horizon, or on a non-working/blackout day. Distinct
    from :class:`SlotAlreadyBookedError`, which means the slot was real and
    someone else got it."""

    def __init__(self, starts_at: datetime, reason: str) -> None:
        super().__init__(
            f"That time cannot be booked: {reason}",
            code=DemoBookingErrorCode.SLOT_NOT_BOOKABLE,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            data={
                "requested_starts_at": starts_at.isoformat().replace("+00:00", "Z"),
                "reason": reason,
            },
        )


class InvalidSlotIdentifierError(DemoBookingError):
    """``slot_id`` was not something this server issued. The client's
    calendar is stale or the value was tampered with -- either way the
    correct UI response is to reload availability, which is why this does
    not share a code with :class:`SlotNotBookableError`."""

    def __init__(self, reason: str) -> None:
        super().__init__(
            "That slot is no longer valid -- please reload the calendar.",
            code=DemoBookingErrorCode.INVALID_SLOT_ID,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            data={"reason": reason},
        )


class InvalidAvailabilityRangeError(DemoBookingError):
    def __init__(self, reason: str, *, max_days: int) -> None:
        super().__init__(
            reason,
            code=DemoBookingErrorCode.INVALID_DATE_RANGE,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            data={"max_range_days": max_days},
        )


class InvalidManageTokenError(DemoBookingError):
    """A cancel/reschedule call presented a token that does not match this
    booking.

    Deliberately indistinguishable from "no such booking" -- same status,
    same code, same message. A visitor with a bad token must not be able to
    use this endpoint to confirm that a given booking id exists.
    """

    def __init__(self) -> None:
        super().__init__(
            "Booking not found, or the link has expired.",
            code=DemoBookingErrorCode.BOOKING_NOT_FOUND,
            status_code=status.HTTP_404_NOT_FOUND,
        )


class BookingNotCancellableError(DemoBookingError):
    """The booking exists but is not in a state a visitor may change --
    already cancelled, or already recorded by sales as completed/no-show.
    See ``constants.MUTABLE_BY_VISITOR_STATUSES``."""

    def __init__(self, current_status: str) -> None:
        super().__init__(
            f"This booking can no longer be changed (status: {current_status}).",
            code=DemoBookingErrorCode.BOOKING_NOT_CHANGEABLE,
            status_code=status.HTTP_409_CONFLICT,
            data={"status": current_status},
        )


class BookingRateLimitExceededError(DemoBookingError):
    """Too many booking attempts from one email address inside the
    configured window, or that address already holds its maximum number of
    future slots -- the identifier-scoped half of this domain's abuse
    protection (the per-IP half is
    ``app.middleware.rate_limit.RateLimitMiddleware``). Mirrors
    ``app.domains.otp.exceptions.OtpRequestRateLimitExceededError``'s
    shape, including carrying the retry hint."""

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__(
            "Too many booking attempts -- please try again later.",
            code=DemoBookingErrorCode.BOOKING_RATE_LIMITED,
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            data={"retry_after_seconds": retry_after_seconds},
        )
