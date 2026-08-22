"""FastAPI routes for the Demo Booking domain -- the calendar behind
"Book a Demo" on wyfyguest.com.

## The contract, in one place

Public (no auth)::

    GET  /api/v1/demo-bookings/availability[?from=&to=]  -> 200
    POST /api/v1/demo-bookings                           -> 201
    POST /api/v1/demo-bookings/{id}/cancel               -> 200
    POST /api/v1/demo-bookings/{id}/reschedule           -> 200

Master console (RBAC)::

    GET   /api/v1/demo-bookings      -> 200  (demo_requests.read)
    PATCH /api/v1/demo-bookings/{id} -> 200  (demo_requests.manage)

Everything is wrapped in the project-wide
``{success, message, data, request_id}`` envelope. **Every error this
domain raises carries a stable ``data.code``** (see
``exceptions.DemoBookingErrorCode``) -- ``message`` is human-facing prose
and must never be parsed. The one the client most needs is
``409 SLOT_ALREADY_BOOKED``: two visitors clicking 11:00 in the same
moment is normal traffic, not a fault, and it arrives with
``next_available_slots`` already populated so the calendar can re-render
into "that time went, here are the next ones" instead of an error box.

Three rules the client depends on:

* **The client never constructs a time.** Availability issues an opaque,
  signed ``slot_id`` per slot; booking and rescheduling name a slot by
  that id. See ``slot_id.py``.
* **The client never does timezone arithmetic.** Every slot carries
  ``starts_at`` (UTC, ``...Z``), ``starts_at_local`` (explicit ``+05:30``
  offset) and ``label`` (``"3:00 PM"``), all rendered from one
  ``datetime``; the IANA zone comes back as data, and so does the
  server's own ``server_time`` so a skewed device clock cannot hide real
  slots or offer elapsed ones.
* **The confirmation is read back from the database.** ``BookingResponse
  .slot`` is re-rendered from the stored row, never echoed from the
  request, so a mismatch surfaces rather than hiding.

Availability defaults to the *entire* booking window when ``from``/``to``
are omitted -- one call, no date arithmetic. Ranged queries still work,
capped at ``MAX_AVAILABILITY_RANGE_DAYS``.

## The public half is unauthenticated, exactly like the form it replaces

``GET /demo-bookings/availability``, ``POST /demo-bookings``,
``POST /demo-bookings/{id}/cancel`` and
``POST /demo-bookings/{id}/reschedule`` carry no ``RequirePermission``/
``CurrentUser`` dependency, for the same reason
``app.domains.demo_request.router``'s module docstring already gives for
``POST /demo-requests``: a prospective customer has, by definition, no
platform identity or JWT to present, so there is no RBAC permission a
visitor could ever be granted. All four are allowlisted (with that reason)
in ``tests/unit/test_route_permission_coverage.py``.

Abuse protection is layered, and none of it is new machinery:

1. ``app.middleware.rate_limit.RateLimitMiddleware`` -- per client IP, via
   the ``"/api/v1/demo-bookings"`` prefix added to
   ``RATE_LIMITED_PATH_PREFIXES``. Same throttle every other genuinely
   public endpoint already gets.
2. ``service.BookingRateLimiter`` -- per email address, the same Redis
   INCR+EXPIRE+TTL pattern ``OtpRateLimiter``/``AuthSecurity`` use. Stops
   one address being driven from many IPs.
3. ``Settings.demo_booking_max_active_per_email`` -- a hard cap on how
   many *future* slots one address may hold at once, checked against the
   database. This is the one that actually bounds "someone scripting 500
   bookings would fill the calendar": counters can be flushed, held rows
   cannot.
4. Pydantic validation plus the availability window itself -- there are
   only so many slots in a working week to fill.

Cancel/reschedule are authorized by a per-booking opaque manage token
(only its SHA-256 is stored), not by RBAC -- the same "gated by a
one-time token in the request body, not by a permission" category as
``POST /routers/provisioning/check-in``.

## The console half is RBAC-gated, and reuses the demo-request keys

``GET /demo-bookings`` and ``PATCH /demo-bookings/{id}`` are gated on
``demo_requests.read``/``demo_requests.manage`` rather than a new
``demo_bookings`` permission module. A booking is *when* a demo request is
happening; anyone who may read the lead queue may read the calendar of
that same queue, and there is no coherent role that should see one and not
the other. Reusing the keys also means no RBAC seed change and no
permission migration -- see ``app.domains.rbac.seed``'s
``MODULE_ACTIONS[PermissionModule.DEMO_REQUESTS]``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.auth.models import AuthUser
from app.domains.demo_request.models import DemoRequest
from app.domains.rbac.dependencies import CurrentUser, RequirePermission

from .availability import BookingWindow
from .constants import DemoBookingConfirmationState
from .dependencies import get_demo_booking_service
from .exceptions import InvalidAvailabilityRangeError, InvalidSlotIdentifierError
from .models import DemoBooking
from .schemas import (
    AvailabilityResponse,
    BookingAdminUpdateRequest,
    BookingCancelRequest,
    BookingCreateRequest,
    BookingListResponse,
    BookingRescheduleRequest,
    BookingResponse,
    ConfirmationEmailState,
    DayAvailabilityResponse,
    render_slot,
    to_utc_z,
)
from .service import BookingResult, DemoBookingService
from .slot_id import InvalidSlotIdError, decode_slot_id

router = APIRouter(prefix="/demo-bookings", tags=["Demo Bookings"])

#: Hard ceiling on how many calendar days one availability call may span.
#: Two months covers "render this month and let me page forward" without
#: letting an unauthenticated caller ask for ten years of grid in one
#: request.
MAX_AVAILABILITY_RANGE_DAYS = 62


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _booking_response(
    booking: DemoBooking,
    lead: DemoRequest,
    window: BookingWindow,
    *,
    secret: str,
    manage_token: str | None = None,
    confirmation: ConfirmationEmailState,
) -> BookingResponse:
    return BookingResponse(
        id=booking.id,
        demo_request_id=booking.demo_request_id,
        status=booking.status,
        # Rendered from the row that is in the database, never from the
        # request that created it -- see BookingResponse.slot.
        slot=render_slot(
            booking.starts_at, booking.ends_at, window.timezone, secret=secret
        ),
        timezone=str(window.timezone),
        full_name=lead.full_name,
        email=lead.email,
        company_name=lead.company_name,
        confirmation_email=confirmation,
        manage_token=manage_token,
        created_at=booking.created_at,
    )


def _from_result(
    result: BookingResult, window: BookingWindow, *, secret: str
) -> BookingResponse:
    return _booking_response(
        result.booking,
        result.demo_request,
        window,
        secret=secret,
        manage_token=result.manage_token,
        confirmation=ConfirmationEmailState(
            status=result.confirmation_state,
            delivery_id=result.confirmation_delivery_id,
        ),
    )


# ============================================================================
# Public: no auth
# ============================================================================


@router.get(
    "/availability",
    response_model=ApiResponse[AvailabilityResponse],
    status_code=status.HTTP_200_OK,
)
async def get_availability(
    request: Request,
    from_date: date | None = Query(
        default=None,
        alias="from",
        description=(
            "First local calendar date to describe (inclusive), in the "
            "booking timezone. YYYY-MM-DD. OPTIONAL -- omit both 'from' "
            "and 'to' and the response covers the entire booking window "
            "(today through the horizon) in one call, which is the "
            "intended default. Supply them only to page beyond that."
        ),
    ),
    to_date: date | None = Query(
        default=None,
        alias="to",
        description=(
            "Last local calendar date to describe (inclusive). Defaults to "
            "the last bookable date when omitted."
        ),
    ),
    service: DemoBookingService = Depends(get_demo_booking_service),
):
    """Per-day time slots over a date range.

    Defaults to the whole booking window, so the common case is one
    request and no date arithmetic on the client. Every requested date is
    present in ``days`` -- dates nobody can book come back with a status
    saying why, never as an absence.
    """
    now = service.now()
    window = service.window
    if from_date is None:
        from_date = window.first_bookable_date(now)
    if to_date is None:
        to_date = min(
            window.last_bookable_date(now),
            from_date + timedelta(days=MAX_AVAILABILITY_RANGE_DAYS - 1),
        )
    if to_date < from_date:
        raise InvalidAvailabilityRangeError(
            "'to' must not be earlier than 'from'.",
            max_days=MAX_AVAILABILITY_RANGE_DAYS,
        )
    if (to_date - from_date).days + 1 > MAX_AVAILABILITY_RANGE_DAYS:
        raise InvalidAvailabilityRangeError(
            f"Range too wide -- at most {MAX_AVAILABILITY_RANGE_DAYS} days "
            "per request.",
            max_days=MAX_AVAILABILITY_RANGE_DAYS,
        )

    result = await service.get_availability(from_date=from_date, to_date=to_date)
    window = result.window
    secret = service.slot_id_secret
    payload = AvailabilityResponse(
        timezone=str(window.timezone),
        slot_minutes=window.slot_minutes,
        buffer_minutes=window.buffer_minutes,
        min_notice_minutes=window.lead_time_minutes,
        server_time=to_utc_z(result.server_time),
        server_time_local=result.server_time.astimezone(window.timezone).isoformat(),
        first_bookable_date=result.first_bookable_date,
        last_bookable_date=result.last_bookable_date,
        days=[
            DayAvailabilityResponse(
                date=day.day,
                status=day.status,
                slots=[
                    render_slot(
                        slot.starts_at, slot.ends_at, window.timezone, secret=secret
                    )
                    for slot in day.slots
                ],
            )
            for day in result.days
        ],
    )
    return build_response(
        success=True,
        message="Availability retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "",
    response_model=ApiResponse[BookingResponse],
    status_code=status.HTTP_201_CREATED,
)
async def book_slot(
    request: Request,
    payload: BookingCreateRequest,
    service: DemoBookingService = Depends(get_demo_booking_service),
):
    result = await service.book_slot(
        starts_at=_slot_instant(payload.slot_id, service),
        full_name=payload.full_name,
        email=payload.email,
        phone=payload.phone,
        company_name=payload.company_name,
        message=payload.message,
        property_type=payload.property_type,
        location_count=payload.location_count,
        router_count=payload.router_count,
    )
    return build_response(
        success=True,
        message="Your demo is confirmed. Check your inbox for the details.",
        data=_from_result(
            result, service.window, secret=service.slot_id_secret
        ).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/{booking_id}/cancel",
    response_model=ApiResponse[BookingResponse],
    status_code=status.HTTP_200_OK,
)
async def cancel_booking(
    request: Request,
    booking_id: uuid.UUID,
    payload: BookingCancelRequest,
    service: DemoBookingService = Depends(get_demo_booking_service),
):
    result = await service.cancel_booking(
        booking_id=booking_id,
        manage_token=payload.manage_token,
        reason=payload.reason,
    )
    return build_response(
        success=True,
        message="Your demo has been cancelled.",
        data=_from_result(
            result, service.window, secret=service.slot_id_secret
        ).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/{booking_id}/reschedule",
    response_model=ApiResponse[BookingResponse],
    status_code=status.HTTP_200_OK,
)
async def reschedule_booking(
    request: Request,
    booking_id: uuid.UUID,
    payload: BookingRescheduleRequest,
    service: DemoBookingService = Depends(get_demo_booking_service),
):
    result = await service.reschedule_booking(
        booking_id=booking_id,
        manage_token=payload.manage_token,
        starts_at=_slot_instant(payload.slot_id, service),
    )
    return build_response(
        success=True,
        message="Your demo has been moved.",
        data=_from_result(
            result, service.window, secret=service.slot_id_secret
        ).model_dump(mode="json"),
        request_id=_request_id(request),
    )


# ============================================================================
# Master console: RBAC-gated (reuses the demo_requests.* keys -- see the
# module docstring)
# ============================================================================


@router.get(
    "",
    response_model=ApiResponse[BookingListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("demo_requests.read"))],
)
async def list_bookings(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    booking_status: str | None = Query(default=None, alias="status"),
    from_instant: datetime | None = Query(
        default=None,
        alias="from",
        description="Lower bound on starts_at, inclusive. ISO-8601 with an offset.",
    ),
    to_instant: datetime | None = Query(
        default=None,
        alias="to",
        description="Upper bound on starts_at, exclusive. ISO-8601 with an offset.",
    ),
    search: str | None = Query(default=None),
    service: DemoBookingService = Depends(get_demo_booking_service),
):
    result = await service.list_bookings(
        page=page,
        page_size=page_size,
        status=booking_status,
        from_instant=_as_utc(from_instant, "from"),
        to_instant=_as_utc(to_instant, "to"),
        search=search,
    )
    window = service.window
    payload = BookingListResponse(
        items=[
            _booking_response(
                booking,
                lead,
                window,
                secret=service.slot_id_secret,
                confirmation=ConfirmationEmailState(
                    status=_delivery_state(booking),
                    delivery_id=booking.guest_confirmation_delivery_id,
                ),
            )
            for booking, lead in result.items
        ],
        page=result.meta.page,
        page_size=result.meta.page_size,
        total_items=result.meta.total_items,
        total_pages=result.meta.total_pages,
        has_next=result.meta.has_next,
        has_previous=result.meta.has_previous,
    )
    return build_response(
        success=True,
        message="Demo bookings retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.patch(
    "/{booking_id}",
    response_model=ApiResponse[BookingResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("demo_requests.manage"))],
)
async def update_booking(
    request: Request,
    booking_id: uuid.UUID,
    payload: BookingAdminUpdateRequest,
    user: AuthUser = Depends(CurrentUser),
    service: DemoBookingService = Depends(get_demo_booking_service),
):
    result = await service.admin_update_booking(
        booking_id=booking_id,
        data=payload.model_dump(exclude_unset=True),
        actor_user_id=uuid.UUID(user.id),
    )
    return build_response(
        success=True,
        message="Booking updated",
        data=_from_result(
            result, service.window, secret=service.slot_id_secret
        ).model_dump(mode="json"),
        request_id=_request_id(request),
    )


def _slot_instant(slot_id: str, service: DemoBookingService) -> datetime:
    """Decode a client-supplied ``slot_id`` back to the instant the server
    issued it for.

    A verified id is *not* a permission to book. It is turned straight
    back into a plain instant, which then goes through exactly the same
    ``BookingWindow`` guards and the same database constraint as anything
    else -- so a stale id for a slot that has since elapsed, or that now
    falls on a blackout date, is refused like any other stale time. What
    the signature buys is a clean, separate error for "this is not a slot
    we ever published" versus "this slot is no longer bookable", which are
    different things to tell a visitor.
    """
    try:
        return decode_slot_id(slot_id, secret=service.slot_id_secret)
    except InvalidSlotIdError as exc:
        raise InvalidSlotIdentifierError(str(exc)) from exc


def _as_utc(value: datetime | None, name: str) -> datetime | None:
    """Reject a naive bound rather than guessing a zone for it -- the same
    rule the booking body follows (see ``availability.py``'s module
    docstring). Query parameters cannot use ``AwareDatetime`` directly
    without losing the ISO-8601 parsing FastAPI already does, so the check
    is here."""
    if value is None:
        return None
    if value.tzinfo is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"'{name}' must include a timezone offset (e.g. "
                "2026-08-25T00:00:00+05:30 or ...Z)."
            ),
        )
    return value.astimezone(UTC)


def _delivery_state(booking: DemoBooking) -> str:
    """What the console list can honestly say about a booking's
    confirmation email *without* joining the outbox: only whether a
    delivery row was ever created for it.

    ``queued`` here therefore means "an outbox row exists", not "it went
    out" -- ``delivery_id`` is returned alongside precisely so the console
    can fetch that row, which is the only thing that ever claims
    sent/retrying/failed. Nothing in this response is allowed to imply a
    message was delivered.
    """
    if booking.guest_confirmation_delivery_id is None:
        return DemoBookingConfirmationState.NOT_CONFIGURED.value
    return DemoBookingConfirmationState.QUEUED.value


__all__ = ["MAX_AVAILABILITY_RANGE_DAYS", "router"]
