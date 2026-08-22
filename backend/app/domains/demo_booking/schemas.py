"""Pydantic request/response schemas for the Demo Booking API.

Same pydantic v2 conventions as every other domain
(``ConfigDict(from_attributes=True)``, explicit ``Field`` descriptions,
``field_validator``-checked enums) and wrapped in the project's standard
``ApiResponse``/``build_response`` envelope by ``router.py``.

## Two decisions worth reading before changing anything here

**``BookingCreateRequest`` subclasses ``DemoRequestCreateRequest``.** The
booking form collects a lead *and* a time; the lead half must stay exactly
the lead the plain "Book a Demo" form already collects, with the same
validation, the same bounds and the same vertical taxonomy. Subclassing
makes that structural rather than aspirational -- a field added to the
marketing form appears on the booking form automatically, and the two can
never drift into collecting different things about the same prospect.

**Every instant is emitted three times, from one value.** ``starts_at``
(UTC, ``...Z``) is canonical and is the only thing a client should ever
store, compare, or send back. ``starts_at_local`` (same instant, explicit
``+05:30`` offset) and ``label`` (``"3:00 PM"``) exist so the frontend
never has to do timezone arithmetic to render a calendar, and so a
misconfigured browser clock cannot make the page disagree with the
server. All three are rendered by ``render_slot`` from a single
``datetime``, so they cannot disagree with each other. See
``availability.py``'s module docstring for the full convention.
"""

from __future__ import annotations

# `date` is imported under an alias because DayAvailabilityResponse has a
# field literally named `date` -- the clearest name for the frontend -- and
# pydantic cannot resolve an annotation a same-named field shadows.
import uuid
from datetime import UTC, datetime
from datetime import date as CalendarDate
from zoneinfo import ZoneInfo

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.domains.demo_request.schemas import DemoRequestCreateRequest

from .constants import (
    DemoBookingConfirmationState,
    DemoBookingDayStatus,
    DemoBookingStatus,
)
from .slot_id import encode_slot_id

__all__ = [
    "AvailabilityResponse",
    "BookingAdminUpdateRequest",
    "BookingCancelRequest",
    "BookingCreateRequest",
    "BookingListResponse",
    "BookingRescheduleRequest",
    "BookingResponse",
    "ConfirmationEmailState",
    "DayAvailabilityResponse",
    "SlotResponse",
    "local_label",
    "render_slot",
    "to_utc_z",
]

_ALLOWED_BOOKING_STATUSES = {s.value for s in DemoBookingStatus}


# ==========================================================================
# Rendering helpers -- one instant in, three consistent renderings out
# ==========================================================================


def to_utc_z(instant: datetime) -> str:
    """ISO-8601 UTC with a literal ``Z``: ``2026-08-25T04:30:00Z``.

    ``Z`` rather than ``+00:00`` because ``Date.parse``/``new Date()`` in
    every browser accepts it, and because it is visually impossible to
    mistake for a local time -- which ``2026-08-25T04:30:00`` (no offset
    at all) very much is.
    """
    return instant.astimezone(UTC).isoformat().replace("+00:00", "Z")


def local_label(instant: datetime, timezone: ZoneInfo) -> str:
    """``"3:00 PM"`` -- 12-hour, no leading zero, for display only.

    Never parse this back. It is the one rendering in the response that
    deliberately throws information away.
    """
    local = instant.astimezone(timezone)
    meridiem = "AM" if local.hour < 12 else "PM"
    return f"{local.hour % 12 or 12}:{local.minute:02d} {meridiem}"


def render_slot(
    starts_at: datetime,
    ends_at: datetime,
    timezone: ZoneInfo,
    *,
    secret: str,
) -> SlotResponse:
    """One instant in, one fully-rendered slot out -- id, canonical UTC,
    local-with-offset and display label all derived from the same
    ``datetime``, so no two of them can disagree."""
    return SlotResponse(
        slot_id=encode_slot_id(starts_at, secret=secret),
        starts_at=to_utc_z(starts_at),
        ends_at=to_utc_z(ends_at),
        starts_at_local=starts_at.astimezone(timezone).isoformat(),
        ends_at_local=ends_at.astimezone(timezone).isoformat(),
        label=local_label(starts_at, timezone),
        duration_minutes=int((ends_at - starts_at).total_seconds() // 60),
    )


# ==========================================================================
# Availability
# ==========================================================================


class SlotResponse(BaseModel):
    slot_id: str = Field(
        ...,
        description=(
            "Opaque, server-issued identifier for this slot. Send it back "
            "verbatim to book or reschedule -- NEVER construct, parse or "
            "modify one. Stable: the same slot always has the same id, so "
            "it is safe to compare across availability calls. Holding an "
            "id reserves nothing."
        ),
    )
    starts_at: str = Field(
        ...,
        description=(
            "Canonical UTC instant, ISO-8601 with a literal 'Z'. Send this "
            "value back verbatim when booking; never reconstruct it from "
            "the local fields."
        ),
    )
    ends_at: str = Field(..., description="Canonical UTC instant of the slot end.")
    starts_at_local: str = Field(
        ...,
        description=(
            "The same instant in the booking timezone, with an explicit "
            "offset (e.g. '2026-08-25T10:00:00+05:30'). Display only."
        ),
    )
    ends_at_local: str
    label: str = Field(
        ..., description="Human display time in the booking timezone, e.g. '3:00 PM'."
    )
    duration_minutes: int


class DayAvailabilityResponse(BaseModel):
    date: CalendarDate = Field(
        ...,
        description=(
            "Local calendar date in the booking timezone -- NOT the UTC "
            "date. A 00:30 IST slot would belong to the previous UTC day; "
            "the calendar is drawn in the visitor's own local days."
        ),
    )
    status: DemoBookingDayStatus = Field(
        ...,
        description=(
            "Why this day looks the way it does. 'available' is the only "
            "value for which 'slots' is non-empty. See "
            "DemoBookingDayStatus for the meaning of each value -- "
            "'fully_booked', 'no_remaining_slots', 'non_working_day', "
            "'blackout' and 'outside_window' are five genuinely different "
            "messages to show a visitor, and an API error is none of them."
        ),
    )
    slots: list[SlotResponse]


class AvailabilityResponse(BaseModel):
    timezone: str = Field(
        ...,
        description=(
            "IANA zone the availability rules and every '*_local' field "
            "are expressed in, e.g. 'Asia/Kolkata'."
        ),
    )
    slot_minutes: int
    buffer_minutes: int = Field(
        ..., description="Gap the sales team gets between consecutive meetings."
    )
    min_notice_minutes: int = Field(
        ...,
        description=(
            "How far ahead a slot must start before it can be booked. A "
            "slot inside this window is absent from 'slots' and will be "
            "rejected with 422 if booked directly."
        ),
    )
    server_time: str = Field(
        ...,
        description=(
            "The server's own 'now', canonical UTC with a literal 'Z'. "
            "Every past/too-soon decision in this response was made "
            "against this instant -- so a client with a skewed clock can "
            "render relative times against the server's clock instead of "
            "its own, rather than hiding real slots or offering elapsed "
            "ones."
        ),
    )
    server_time_local: str = Field(
        ..., description="The same instant in the booking timezone."
    )
    first_bookable_date: CalendarDate
    last_bookable_date: CalendarDate
    days: list[DayAvailabilityResponse] = Field(
        ...,
        description=(
            "One entry per requested calendar date, in ascending order. "
            "Every requested date is present -- days outside the booking "
            "window are returned with status 'outside_window' rather than "
            "omitted, so the UI can render a full month grid without "
            "inferring anything."
        ),
    )


# ==========================================================================
# Booking
# ==========================================================================


class BookingCreateRequest(DemoRequestCreateRequest):
    """The public booking submission: everything the plain "Book a Demo"
    form collects (inherited, unchanged) plus the chosen slot.

    **The lead and the slot arrive together, in one request.** There is no
    two-step "create the lead, then take the slot" -- that shape can
    half-succeed and lose one of the two, and losing a lead is the outcome
    this whole design refuses. One request, and a booking is always a
    lead."""

    slot_id: str = Field(
        ...,
        min_length=8,
        max_length=256,
        description=(
            "The chosen slot's opaque id, copied verbatim from the "
            "availability response. The server decodes it to an instant "
            "and re-checks every availability rule against it -- an id "
            "issued before a slot elapsed is refused like any other stale "
            "time (422 SLOT_NOT_BOOKABLE); an id this server never issued "
            "is refused as 422 INVALID_SLOT_ID."
        ),
    )


class BookingCancelRequest(BaseModel):
    manage_token: str = Field(
        ...,
        min_length=16,
        max_length=128,
        description="The opaque token returned when the booking was created.",
    )
    reason: str | None = Field(default=None, max_length=1_000)


class BookingRescheduleRequest(BaseModel):
    manage_token: str = Field(..., min_length=16, max_length=128)
    slot_id: str = Field(
        ...,
        min_length=8,
        max_length=256,
        description="The new slot, same rules as BookingCreateRequest.slot_id.",
    )


class BookingAdminUpdateRequest(BaseModel):
    """Master-console-only. Lets sales record the real outcome of a
    meeting (completed / no-show) or cancel one a prospect called in
    about. Cannot move a booking's time -- rescheduling goes through the
    same constraint-guarded path a visitor uses, and giving the console a
    second, weaker way to set ``starts_at`` would be exactly the kind of
    "one more code path" that lets a double-booking in."""

    status: str | None = Field(default=None)
    cancellation_reason: str | None = Field(default=None, max_length=1_000)

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str | None) -> str | None:
        if value is not None and value not in _ALLOWED_BOOKING_STATUSES:
            raise ValueError(
                f"status must be one of {sorted(_ALLOWED_BOOKING_STATUSES)}"
            )
        return value


class ConfirmationEmailState(BaseModel):
    """What honestly happened to the visitor's confirmation email.

    There is no ``"sent"`` value. At the moment this response is built the
    message is a ``PENDING`` row in the notification outbox and no SMTP
    conversation has happened; the dispatch sweep records the real
    outcome on ``delivery_id`` later. Claiming "sent" here would be a
    success report for work that has not been done.
    """

    status: DemoBookingConfirmationState
    delivery_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "The notification_deliveries row that carries the real "
            "sent/retrying/failed outcome. NULL when nothing was enqueued."
        ),
    )


class BookingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    demo_request_id: uuid.UUID = Field(
        ...,
        description=(
            "The lead this booking created. A booked demo is still a lead: "
            "this row is in the same demo_requests queue sales already "
            "works, and it survives even if the booking is later cancelled."
        ),
    )
    status: DemoBookingStatus
    slot: SlotResponse = Field(
        ...,
        description=(
            "The instants that are ACTUALLY IN THE DATABASE for this "
            "booking, re-rendered from the stored row -- not an echo of "
            "what the client asked for. Render the confirmation screen "
            "from these values; if they ever differ from what was "
            "selected, that difference is real and must be shown, not "
            "hidden."
        ),
    )
    timezone: str = Field(
        ..., description="IANA zone the '*_local' fields are expressed in."
    )
    full_name: str
    email: str
    company_name: str
    confirmation_email: ConfirmationEmailState
    manage_token: str | None = Field(
        default=None,
        description=(
            "Returned ONLY in the response that creates or moves a "
            "booking -- it is not stored in retrievable form (only a "
            "SHA-256 hash is persisted) and cannot be recovered later. "
            "Required to cancel or reschedule."
        ),
    )
    created_at: datetime


class BookingListResponse(BaseModel):
    items: list[BookingResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool
