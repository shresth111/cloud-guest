"""Demo Booking business logic.

## The one thing this module exists to get right

**Double-booking is a race, not a check.** Two visitors clicking 11:00 in
the same millisecond both pass any ``SELECT ... WHERE starts_at = :t``, and
both then ``INSERT``. So this service never performs that ``SELECT``. It
attempts the insert and lets ``uq_demo_bookings_active_slot`` -- a partial
unique index in Postgres -- be the arbiter, then turns the resulting
``IntegrityError`` into a clean 409 carrying the next free times. See
``models.DemoBooking``'s module docstring for the constraint itself and
``repository.DemoBookingRepository.create_booking`` for the ``SAVEPOINT``
that keeps the loser's lead alive.

The corollary, and the reason this codebase cares: **the response a
visitor gets is built only after the write has committed.** A booking
confirmed to someone who is not actually on the calendar is the worst bug
this feature could have -- someone would show up to a meeting nobody knows
about. So ``book_slot`` commits, and only then constructs what it returns.
It never reports a reservation it did not make.

## Write ordering, and why the lead is committed first

``book_slot`` writes two rows: a ``DemoRequest`` (the lead) and a
``DemoBooking`` (the reservation). They are committed in that order, in
two transactions, deliberately:

1. the lead is committed **before** the slot is even attempted. A booking
   attempt that loses the race still leaves a real, worked lead in the
   queue sales already reads. Losing a prospect's name and email because
   someone else got 11:00 first would be strictly worse than the manual
   follow-up. This is the same reasoning -- and the same technique --
   ``app.domains.auth.repository.AuthRepository.record_login_attempt``
   already uses to survive a caller's later rollback.
2. the booking is inserted inside a ``SAVEPOINT``, so a constraint
   rejection rolls back only itself.

The cost of that ordering is a duplicate lead when a visitor loses a race
and immediately picks another time. ``find_recent_unbooked_lead`` absorbs
that case by reusing the lead it just wrote. A duplicate lead is a
tidiness problem; a lost lead is a business problem. The design trades the
former away to eliminate the latter, not the other way round.

## Mail

A demo booking is a sales flow, so all of its mail goes out from
``sales@wyfyguest.com`` -- ``MailIdentity.DEFAULT``, declared explicitly in
``app.domains.notification.constants.MAIL_IDENTITY_BY_EVENT_TYPE`` next to
``DEMO_REQUEST_RECEIVED`` rather than left to the default, so the sales
half of the two-mailbox split stays visible as a presence and not an
absence. It goes through the existing ``app.domains.notification`` outbox
-- no parallel send path -- which is also what makes "a confirmation that
failed to send is recorded as failed, never as sent" true rather than
aspirational: ``enqueue`` writes a ``PENDING`` row, the dispatch sweep
moves it to ``SENT`` or ``RETRYING``/``FAILED`` from a real provider
result, and the booking response says only ``queued``.

Failure to enqueue never fails the booking, for the same reason
``DemoRequestService._notify_team`` never fails a submission -- but unlike
a silent best-effort, it is *recorded*: the booking's
``guest_confirmation_delivery_id`` stays ``NULL`` and the response says
``enqueue_failed``.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Protocol

from redis.asyncio import Redis

from app.core.email_layout import (
    callout,
    esc,
    heading,
    info_box,
    paragraph,
    render_email,
)
from app.database.utils.pagination import PaginationMeta
from app.domains.demo_request.constants import DemoRequestStatus
from app.domains.demo_request.models import DemoRequest

from .availability import BookingWindow, DayAvailability, iterate_dates
from .constants import (
    BOOKING_RATE_LIMIT_KEY_TEMPLATE,
    MANAGE_TOKEN_BYTES,
    MUTABLE_BY_VISITOR_STATUSES,
    DemoBookingConfirmationState,
    DemoBookingStatus,
)
from .exceptions import (
    BookingNotCancellableError,
    BookingRateLimitExceededError,
    DemoBookingNotFoundError,
    InvalidManageTokenError,
    SlotAlreadyBookedError,
    SlotNotBookableError,
)
from .models import DemoBooking
from .repository import (
    DemoBookingRepositoryProtocol,
    LeadRepositoryProtocol,
    SlotTakenError,
)
from .slot_id import encode_slot_id

logger = logging.getLogger(__name__)

#: Brand accent for booking mail -- the same indigo the demo-request
#: notification already uses, so the two look like one product.
_ACCENT = "#6366f1"


class NotificationEnqueuer(Protocol):
    """The narrow subset of ``app.domains.notification.service
    .NotificationService`` this module needs -- identical narrow-protocol
    posture to ``app.domains.demo_request.service.NotificationEnqueuer``,
    for the identical reason (depend on the one method actually used)."""

    async def enqueue(self, **fields: object) -> object: ...


def hash_manage_token(token: str) -> str:
    """SHA-256 hex of a manage token. The token itself is never persisted
    -- a database dump must not hand anyone the ability to cancel other
    people's meetings. Plain SHA-256 (not a password KDF) is right here:
    the token is 32 bytes of ``secrets`` entropy, so there is no
    dictionary to attack and nothing for a slow hash to buy."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class BookingRateLimiter:
    """Per-email booking-attempt limiter.

    A static-method facade over Redis using the exact INCR+EXPIRE+TTL
    pattern ``app.domains.otp.service.OtpRateLimiter`` and
    ``app.domains.auth.security.AuthSecurity.check_rate_limit`` already
    establish -- reused, not reinvented, and deliberately *not* a new
    in-memory limiter (an in-process dict does not survive a worker
    restart and does not exist at all on the other three workers).

    This is the identifier-scoped half of this domain's abuse protection.
    The other half is ``app.middleware.rate_limit.RateLimitMiddleware``,
    which throttles ``/api/v1/demo-bookings`` per client IP. Applying both
    is the same defense-in-depth that middleware's own docstring describes:
    the per-IP bucket stops one host hammering the endpoint while rotating
    email addresses, and this bucket stops one address being used from many
    hosts. Neither alone stops "someone scripting 500 bookings"; together
    with ``Settings.demo_booking_max_active_per_email`` (a hard cap on how
    many future slots one address may *hold*, enforced against the database
    rather than a counter) they bound it in three independent ways.

    Fails **open** on a Redis error, matching ``RateLimitMiddleware``: a
    limiter that 500s when Redis blinks would take the public booking page
    down, which is a worse outcome than a brief unthrottled window.
    """

    @staticmethod
    async def check_and_increment(
        redis: Redis,
        identifier: str,
        *,
        max_requests: int,
        window_minutes: int,
    ) -> None:
        key = BOOKING_RATE_LIMIT_KEY_TEMPLATE.format(identifier=identifier)
        try:
            current = await redis.incr(key)
            if current == 1:
                await redis.expire(key, window_minutes * 60)
            if current > max_requests:
                ttl = await redis.ttl(key)
                raise BookingRateLimitExceededError(
                    ttl if ttl and ttl > 0 else window_minutes * 60
                )
        except BookingRateLimitExceededError:
            raise
        except Exception as exc:  # noqa: BLE001 -- fail open, see docstring
            logger.warning(
                "demo_booking_rate_limit_backend_unavailable_failing_open",
                extra={"error": str(exc)},
            )


@dataclass
class AvailabilityResult:
    window: BookingWindow
    #: The instant every past/too-soon decision in this result was made
    #: against. Returned to the client so a device with a skewed clock
    #: renders against the server's "now" rather than its own -- a browser
    #: an hour fast would otherwise grey out slots that are genuinely
    #: still open, and one an hour slow would offer slots that have gone.
    server_time: datetime
    first_bookable_date: date
    last_bookable_date: date
    days: list[DayAvailability]


@dataclass
class BookingResult:
    """Everything ``router.py`` needs to render a booking response.

    ``manage_token`` is the plaintext token, present only on the call that
    created or moved the booking -- it exists nowhere else, in memory or on
    disk, after this object is discarded.
    """

    booking: DemoBooking
    demo_request: DemoRequest
    manage_token: str | None
    confirmation_state: DemoBookingConfirmationState
    confirmation_delivery_id: uuid.UUID | None


@dataclass
class BookingListResult:
    items: list[tuple[DemoBooking, DemoRequest]]
    meta: PaginationMeta


class DemoBookingService:
    def __init__(
        self,
        repository: DemoBookingRepositoryProtocol,
        lead_repository: LeadRepositoryProtocol,
        window: BookingWindow,
        *,
        notification_service: NotificationEnqueuer | None = None,
        notify_email: str = "",
        redis: Redis | None = None,
        max_attempts_per_window: int = 10,
        attempt_window_minutes: int = 60,
        max_active_per_email: int = 2,
        lead_dedupe_minutes: int = 60,
        alternatives_limit: int = 5,
        slot_id_secret: str = "demo-booking-slot-id-secret-placeholder",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.repository = repository
        self.lead_repository = lead_repository
        self.window = window
        # notification_service/notify_email/redis all default to inert so
        # unit tests can build this service directly -- the same posture
        # DemoRequestService already takes, and for the same reason.
        # `notify_email` empty is a genuine no-op, never a fabricated
        # recipient: see Settings.demo_request_notify_email's docstring.
        self.notification_service = notification_service
        self.notify_email = notify_email
        self.redis = redis
        self.max_attempts_per_window = max_attempts_per_window
        self.attempt_window_minutes = attempt_window_minutes
        self.max_active_per_email = max_active_per_email
        self.lead_dedupe_minutes = lead_dedupe_minutes
        self.alternatives_limit = alternatives_limit
        # Keys the HMAC on every published slot id (see `slot_id.py`).
        # Wired from `Settings.jwt_secret_key` by `dependencies.py`; the
        # default exists only so a unit test can build this service
        # directly, exactly as the notification/redis dependencies above.
        self.slot_id_secret = slot_id_secret
        # Injected so tests can pin "now" without patching a module-level
        # clock -- every time-dependent guard in this domain reads it.
        self._clock = clock or (lambda: datetime.now(UTC))

    def now(self) -> datetime:
        return self._clock()

    # ======================================================================
    # Availability
    # ======================================================================

    async def get_availability(
        self, *, from_date: date, to_date: date
    ) -> AvailabilityResult:
        """Classify every local calendar date in ``[from_date, to_date]``.

        Every requested date comes back, including ones nobody can book --
        a month grid should render fully, and "this day is outside the
        booking window" is information the UI needs rather than an absence
        it has to infer. Range validation (order, maximum span) belongs to
        the router's query schema; by here the range is already sane.
        """
        now = self.now()
        # One query for the whole range, not one per day: the taken set is
        # loaded across the full span and then partitioned locally.
        span_start = datetime.combine(
            from_date, datetime.min.time(), tzinfo=self.window.timezone
        ).astimezone(UTC)
        span_end = datetime.combine(
            to_date + timedelta(days=1),
            datetime.min.time(),
            tzinfo=self.window.timezone,
        ).astimezone(UTC)
        taken = await self.repository.confirmed_starts_between(span_start, span_end)
        taken_set = {t.astimezone(UTC) for t in taken}

        days = [
            self.window.day_availability(day, now=now, taken=taken_set)
            for day in iterate_dates(from_date, to_date)
        ]
        return AvailabilityResult(
            window=self.window,
            server_time=now,
            first_bookable_date=self.window.first_bookable_date(now),
            last_bookable_date=self.window.last_bookable_date(now),
            days=days,
        )

    # ======================================================================
    # Booking
    # ======================================================================

    async def book_slot(
        self,
        *,
        starts_at: datetime,
        full_name: str,
        email: str,
        phone: str | None,
        company_name: str,
        message: str | None,
        property_type: str | None = None,
        location_count: int | None = None,
        router_count: int | None = None,
    ) -> BookingResult:
        """Reserve one slot. See this module's docstring for the ordering
        and why it is what it is."""
        now = self.now()
        normalized_email = str(email).strip().lower()
        requested = starts_at.astimezone(UTC)

        await self._enforce_attempt_limit(normalized_email)
        self._require_bookable(requested, now)
        await self._enforce_active_cap(normalized_email, now)

        # --- 1. the lead, committed before the slot is even attempted ----
        lead = await self._record_lead(
            now=now,
            full_name=full_name,
            email=normalized_email,
            phone=phone,
            company_name=company_name,
            message=message,
            property_type=property_type,
            location_count=location_count,
            router_count=router_count,
        )
        await self.repository.commit()

        # --- 2. the slot, arbitrated by the database ---------------------
        token = secrets.token_urlsafe(MANAGE_TOKEN_BYTES)
        try:
            booking = await self.repository.create_booking(
                demo_request_id=lead.id,
                starts_at=requested,
                ends_at=self.window.slot_end(requested),
                status=DemoBookingStatus.CONFIRMED.value,
                booked_timezone=str(self.window.timezone),
                manage_token_hash=hash_manage_token(token),
            )
        except SlotTakenError as exc:
            logger.info(
                "demo_booking_slot_conflict",
                extra={
                    "starts_at": requested.isoformat(),
                    "demo_request_id": str(lead.id),
                },
            )
            raise SlotAlreadyBookedError(
                requested, await self._alternatives(now)
            ) from exc

        # The lead is now a scheduled one. Kept on the lead row (not
        # duplicated onto the booking) so the Master console's existing
        # demo-request queue reflects reality without knowing this domain
        # exists.
        await self.lead_repository.update(
            lead, {"status": DemoRequestStatus.SCHEDULED.value}
        )

        state, delivery_id, team_delivery_id = await self._send_booking_mail(
            booking, lead, rescheduled=False
        )
        await self.repository.update_booking(
            booking,
            {
                "guest_confirmation_delivery_id": delivery_id,
                "team_notification_delivery_id": team_delivery_id,
            },
        )

        # Commit BEFORE building the response. Everything the visitor is
        # about to be told is now durable; nothing is claimed that a later
        # rollback could erase.
        await self.repository.commit()
        logger.info(
            "demo_booking_confirmed",
            extra={
                "booking_id": str(booking.id),
                "demo_request_id": str(lead.id),
                "starts_at": requested.isoformat(),
                "confirmation_state": state.value,
            },
        )
        return BookingResult(
            booking=booking,
            demo_request=lead,
            manage_token=token,
            confirmation_state=state,
            confirmation_delivery_id=delivery_id,
        )

    async def cancel_booking(
        self, *, booking_id: uuid.UUID, manage_token: str, reason: str | None
    ) -> BookingResult:
        """Visitor-initiated cancellation. Frees the slot for real -- the
        double-booking index only covers ``CONFIRMED`` rows, so the instant
        this status flips the time reappears in availability."""
        booking, lead = await self._load_for_visitor(booking_id, manage_token)
        await self.repository.update_booking(
            booking,
            {
                "status": DemoBookingStatus.CANCELLED.value,
                "cancellation_reason": (reason.strip() if reason else None),
                "cancelled_at": self.now(),
            },
        )
        state, delivery_id = await self._enqueue_team(
            _cancellation_email(booking, lead, self.window),
            subject=f"Demo cancelled: {lead.company_name}",
            preheader=f"{lead.full_name} cancelled their demo.",
            event="cancelled",
        )
        await self.repository.update_booking(
            booking, {"team_notification_delivery_id": delivery_id}
        )
        await self.repository.commit()
        logger.info("demo_booking_cancelled", extra={"booking_id": str(booking.id)})
        return BookingResult(
            booking=booking,
            demo_request=lead,
            manage_token=None,
            confirmation_state=state,
            confirmation_delivery_id=None,
        )

    async def reschedule_booking(
        self, *, booking_id: uuid.UUID, manage_token: str, starts_at: datetime
    ) -> BookingResult:
        """Move a booking to a different slot.

        Implemented as an ``UPDATE`` of ``starts_at`` on the existing row,
        not as cancel-then-rebook. Two reasons, both about not lying:
        cancel-then-rebook can leave the visitor with *no* booking at all
        if the new slot turns out to be taken (they released a slot they
        had), and it would send them a cancellation for a meeting that is
        still on. As an update, the same
        ``uq_demo_bookings_active_slot`` index arbitrates the move -- if
        the target is taken, the update is rejected and the original
        booking is untouched.

        A new manage token is issued on every successful move, so the link
        in the newest confirmation email is the only one that works.
        """
        now = self.now()
        requested = starts_at.astimezone(UTC)
        booking, lead = await self._load_for_visitor(booking_id, manage_token)
        self._require_bookable(requested, now)

        if requested == booking.starts_at.astimezone(UTC):
            # A no-op move must not burn the visitor's token or re-send
            # mail; returning the booking unchanged is the honest answer.
            return BookingResult(
                booking=booking,
                demo_request=lead,
                manage_token=None,
                confirmation_state=DemoBookingConfirmationState.NOT_CONFIGURED,
                confirmation_delivery_id=None,
            )

        token = secrets.token_urlsafe(MANAGE_TOKEN_BYTES)
        try:
            await self.repository.update_booking(
                booking,
                {
                    "starts_at": requested,
                    "ends_at": self.window.slot_end(requested),
                    "booked_timezone": str(self.window.timezone),
                    "manage_token_hash": hash_manage_token(token),
                },
            )
        except SlotTakenError as exc:
            raise SlotAlreadyBookedError(
                requested, await self._alternatives(now)
            ) from exc

        state, delivery_id, team_delivery_id = await self._send_booking_mail(
            booking, lead, rescheduled=True
        )
        await self.repository.update_booking(
            booking,
            {
                "guest_confirmation_delivery_id": delivery_id,
                "team_notification_delivery_id": team_delivery_id,
            },
        )
        await self.repository.commit()
        logger.info(
            "demo_booking_rescheduled",
            extra={"booking_id": str(booking.id), "starts_at": requested.isoformat()},
        )
        return BookingResult(
            booking=booking,
            demo_request=lead,
            manage_token=token,
            confirmation_state=state,
            confirmation_delivery_id=delivery_id,
        )

    # ======================================================================
    # Master console
    # ======================================================================

    async def list_bookings(
        self,
        *,
        page: int = 1,
        page_size: int = 25,
        status: str | None = None,
        from_instant: datetime | None = None,
        to_instant: datetime | None = None,
        search: str | None = None,
    ) -> BookingListResult:
        items, meta = await self.repository.list_bookings(
            page=page,
            page_size=page_size,
            status=status,
            from_instant=from_instant,
            to_instant=to_instant,
            search=search,
        )
        return BookingListResult(items=items, meta=meta)

    async def admin_update_booking(
        self,
        *,
        booking_id: uuid.UUID,
        data: dict[str, object],
        actor_user_id: uuid.UUID | None,
    ) -> BookingResult:
        """Record a real outcome, or cancel on a prospect's behalf. Cannot
        move a booking's time -- see
        ``schemas.BookingAdminUpdateRequest``."""
        booking = await self.repository.get_by_id(booking_id)
        if booking is None or booking.is_deleted:
            raise DemoBookingNotFoundError(booking_id)
        lead = await self._lead_for(booking)

        allowed = {"status", "cancellation_reason"}
        update: dict[str, object] = {
            key: value for key, value in data.items() if key in allowed
        }
        update["updated_by"] = actor_user_id
        if update.get("status") == DemoBookingStatus.CANCELLED.value:
            update["cancelled_at"] = self.now()
        await self.repository.update_booking(booking, update)
        await self.repository.commit()
        logger.info(
            "demo_booking_admin_updated",
            extra={"booking_id": str(booking.id), "status": booking.status},
        )
        return BookingResult(
            booking=booking,
            demo_request=lead,
            manage_token=None,
            confirmation_state=DemoBookingConfirmationState.NOT_CONFIGURED,
            confirmation_delivery_id=None,
        )

    # ======================================================================
    # Guards
    # ======================================================================

    def _require_bookable(self, starts_at: datetime, now: datetime) -> None:
        """Raise ``SlotNotBookableError`` unless ``starts_at`` is a slot
        anyone could book right now.

        Every rejection names its own reason rather than returning a
        generic "invalid time": a frontend that gets ``"in the past"``
        versus ``"not on the published schedule"`` can tell a visitor
        something useful, and an operator reading logs can tell a clock
        problem from a config problem.

        Note what this does **not** check: whether the slot is already
        taken. That question is answered by the database, once, at insert
        time. Answering it here would be a ``SELECT`` before an
        ``INSERT`` -- the exact race this whole design exists to avoid --
        and would additionally create a window in which this method says
        "free" and the insert then says "taken", i.e. two sources of truth
        that can disagree.
        """
        day = self.window.local_date(starts_at)
        if not self.window.is_on_grid(starts_at):
            raise SlotNotBookableError(
                starts_at, "it is not one of the published slot times"
            )
        if day in self.window.blackout_dates:
            raise SlotNotBookableError(starts_at, "we are closed on that date")
        if day.weekday() not in self.window.working_weekdays:
            raise SlotNotBookableError(starts_at, "that is not a working day")
        if day < self.window.first_bookable_date(now):
            raise SlotNotBookableError(starts_at, "it is in the past")
        if day > self.window.last_bookable_date(now):
            raise SlotNotBookableError(
                starts_at,
                f"bookings open only {self.window.horizon_days} days ahead",
            )
        if starts_at <= now:
            raise SlotNotBookableError(starts_at, "it is in the past")
        if starts_at - now < timedelta(minutes=self.window.lead_time_minutes):
            raise SlotNotBookableError(
                starts_at,
                f"it starts too soon -- we need at least "
                f"{self.window.lead_time_minutes} minutes' notice",
            )

    async def _enforce_attempt_limit(self, email: str) -> None:
        if self.redis is None:
            return
        await BookingRateLimiter.check_and_increment(
            self.redis,
            email,
            max_requests=self.max_attempts_per_window,
            window_minutes=self.attempt_window_minutes,
        )

    async def _enforce_active_cap(self, email: str, now: datetime) -> None:
        """A hard ceiling on how many future slots one address may hold at
        once. Unlike the Redis counter this is enforced against the
        database, so it cannot be washed away by a Redis flush or a
        restart, and it is the guard that actually bounds "someone
        scripting 500 bookings would fill the calendar"."""
        if self.max_active_per_email <= 0:
            return
        held = await self.repository.count_active_for_email(email, now=now)
        if held >= self.max_active_per_email:
            raise BookingRateLimitExceededError(0)

    # ======================================================================
    # Internals
    # ======================================================================

    async def _record_lead(
        self,
        *,
        now: datetime,
        full_name: str,
        email: str,
        phone: str | None,
        company_name: str,
        message: str | None,
        property_type: str | None,
        location_count: int | None,
        router_count: int | None,
    ) -> DemoRequest:
        """Write (or refresh) the lead this booking is for.

        Reuses a very recent lead from the same address that has no
        confirmed booking -- which is exactly the visitor who just lost a
        slot race and is picking again -- so a retry updates one queue
        entry instead of adding a second. Outside that window every
        submission is its own lead, because a prospect coming back next
        week genuinely is one.
        """
        fields: dict[str, object] = {
            "full_name": full_name.strip(),
            "email": email,
            "phone": phone.strip() if phone else None,
            "company_name": company_name.strip(),
            "message": message.strip() if message else None,
            "property_type": property_type,
            "location_count": location_count,
            "router_count": router_count,
        }
        # 0 disables reuse outright rather than degenerating into a
        # zero-width window -- a zero-width window still matches a lead
        # created in the same instant, which is the opposite of "off".
        if self.lead_dedupe_minutes > 0:
            existing = await self.repository.find_recent_unbooked_lead(
                email, since=now - timedelta(minutes=self.lead_dedupe_minutes)
            )
            if existing is not None:
                return await self.lead_repository.update(existing, dict(fields))
        return await self.lead_repository.create(**fields)

    async def _lead_for(self, booking: DemoBooking) -> DemoRequest:
        lead = await self.repository.find_lead_by_id(booking.demo_request_id)
        if lead is None:
            # A booking with no lead should be impossible -- the FK is
            # NOT NULL with ON DELETE RESTRICT. If it ever happens, say so
            # loudly rather than rendering a half-empty response.
            raise DemoBookingNotFoundError(booking.id)
        return lead

    async def _load_for_visitor(
        self, booking_id: uuid.UUID, manage_token: str
    ) -> tuple[DemoBooking, DemoRequest]:
        """Look a booking up by *token*, then confirm the id matches.

        The lookup is by ``manage_token_hash`` rather than by id, so a
        caller who knows a booking id but not its token learns nothing --
        every failure mode returns the same 404-shaped
        ``InvalidManageTokenError``, whether the booking does not exist,
        the token is wrong, or the pair does not match.
        """
        booking = await self.repository.get_by_token_hash(
            hash_manage_token(manage_token)
        )
        if booking is None or booking.id != booking_id:
            raise InvalidManageTokenError()
        if booking.status not in MUTABLE_BY_VISITOR_STATUSES:
            raise BookingNotCancellableError(booking.status)
        return booking, await self._lead_for(booking)

    async def _alternatives(self, now: datetime) -> list[dict]:
        """The next few genuinely-free slots, for a 409 body. Best effort:
        if this lookup itself fails, the 409 still goes out (with an empty
        list) rather than becoming a 500 -- the visitor needs to be told
        they lost the slot far more than they need suggestions."""
        try:
            horizon_end = datetime.combine(
                self.window.last_bookable_date(now) + timedelta(days=1),
                datetime.min.time(),
                tzinfo=self.window.timezone,
            ).astimezone(UTC)
            taken = await self.repository.confirmed_starts_between(now, horizon_end)
            starts = self.window.next_available_starts(
                now=now, taken=taken, limit=self.alternatives_limit
            )
        except Exception as exc:  # noqa: BLE001 -- see docstring
            logger.warning(
                "demo_booking_alternatives_lookup_failed", extra={"error": str(exc)}
            )
            return []
        return [
            {
                # Same shape as an availability slot, id included, so the
                # frontend can render a 409's alternatives with the very
                # same component -- and book one directly.
                "slot_id": encode_slot_id(start, secret=self.slot_id_secret),
                "starts_at": start.isoformat().replace("+00:00", "Z"),
                "ends_at": self.window.slot_end(start)
                .isoformat()
                .replace("+00:00", "Z"),
                "starts_at_local": start.astimezone(self.window.timezone).isoformat(),
                "label": _label(start, self.window),
            }
            for start in starts
        ]

    # -- mail --------------------------------------------------------------

    async def _send_booking_mail(
        self, booking: DemoBooking, lead: DemoRequest, *, rescheduled: bool
    ) -> tuple[DemoBookingConfirmationState, uuid.UUID | None, uuid.UUID | None]:
        """Enqueue the visitor's confirmation and the team's heads-up.

        Returns the *visitor* confirmation's honest state plus both
        delivery ids. Neither send can fail the booking -- but a failure is
        recorded (``enqueue_failed`` + a NULL delivery id), never papered
        over as success.
        """
        state, guest_id = await self._enqueue_guest(booking, lead, rescheduled)
        _, team_id = await self._enqueue_team(
            _team_booking_email(booking, lead, self.window, rescheduled=rescheduled),
            subject=(
                f"Demo {'moved' if rescheduled else 'booked'}: {lead.company_name}"
            ),
            preheader=(
                f"{lead.full_name} from {lead.company_name} "
                f"{'moved' if rescheduled else 'booked'} a demo."
            ),
            event="booked",
        )
        return state, guest_id, team_id

    async def _enqueue_guest(
        self, booking: DemoBooking, lead: DemoRequest, rescheduled: bool
    ) -> tuple[DemoBookingConfirmationState, uuid.UUID | None]:
        if self.notification_service is None:
            return DemoBookingConfirmationState.NOT_CONFIGURED, None
        try:
            from app.domains.notification.constants import (
                NotificationChannelType,
                NotificationEventType,
            )

            delivery = await self.notification_service.enqueue(
                event_type=NotificationEventType.DEMO_BOOKING_CONFIRMED,
                channel=NotificationChannelType.EMAIL,
                recipient=lead.email,
                subject=(
                    "Your Wyfy Guest demo has been moved"
                    if rescheduled
                    else "Your Wyfy Guest demo is confirmed"
                ),
                body=render_email(
                    preheader=(
                        f"Your demo is now {_label(booking.starts_at, self.window)} "
                        f"on {_date_label(booking.starts_at, self.window)}."
                    ),
                    content_html=_guest_booking_email(
                        booking, lead, self.window, rescheduled=rescheduled
                    ),
                    accent=_ACCENT,
                ),
                organization_id=None,
            )
            return (
                DemoBookingConfirmationState.QUEUED,
                getattr(delivery, "id", None),
            )
        except Exception as exc:  # noqa: BLE001 -- never fails the booking
            logger.warning(
                "demo_booking_confirmation_enqueue_failed",
                extra={"booking_id": str(booking.id), "error": str(exc)},
            )
            return DemoBookingConfirmationState.ENQUEUE_FAILED, None

    async def _enqueue_team(
        self,
        content_html: str,
        *,
        subject: str,
        preheader: str,
        event: str,
    ) -> tuple[DemoBookingConfirmationState, uuid.UUID | None]:
        """The internal-team heads-up. An unset
        ``Settings.demo_request_notify_email`` is a genuine no-op, not a
        fabricated recipient -- see that setting's own docstring; this
        domain reuses the same address rather than adding a second one to
        keep in sync."""
        if self.notification_service is None or not self.notify_email:
            return DemoBookingConfirmationState.NOT_CONFIGURED, None
        try:
            from app.domains.notification.constants import (
                NotificationChannelType,
                NotificationEventType,
            )

            event_type = (
                NotificationEventType.DEMO_BOOKING_CANCELLED
                if event == "cancelled"
                else NotificationEventType.DEMO_BOOKING_TEAM_NOTIFICATION
            )
            delivery = await self.notification_service.enqueue(
                event_type=event_type,
                channel=NotificationChannelType.EMAIL,
                recipient=self.notify_email,
                subject=subject,
                body=render_email(
                    preheader=preheader, content_html=content_html, accent=_ACCENT
                ),
                organization_id=None,
            )
            return (
                DemoBookingConfirmationState.QUEUED,
                getattr(delivery, "id", None),
            )
        except Exception as exc:  # noqa: BLE001 -- never fails the booking
            logger.warning(
                "demo_booking_team_notify_failed", extra={"error": str(exc)}
            )
            return DemoBookingConfirmationState.ENQUEUE_FAILED, None


# ==========================================================================
# Email bodies
# ==========================================================================


def _label(instant: datetime, window: BookingWindow) -> str:
    local = instant.astimezone(window.timezone)
    meridiem = "AM" if local.hour < 12 else "PM"
    return f"{local.hour % 12 or 12}:{local.minute:02d} {meridiem}"


def _date_label(instant: datetime, window: BookingWindow) -> str:
    local = instant.astimezone(window.timezone)
    return local.strftime("%A, %d %B %Y")


def _when(booking: DemoBooking, window: BookingWindow) -> str:
    """The one string every booking email uses for "when". Always carries
    the zone abbreviation *and* the offset -- "3:00 PM" alone in an email
    read on a phone in another country is an appointment waiting to be
    missed."""
    local = booking.starts_at.astimezone(window.timezone)
    offset = local.strftime("%z")
    pretty_offset = f"{offset[:3]}:{offset[3:]}" if offset else ""
    return (
        f"{_date_label(booking.starts_at, window)}, "
        f"{_label(booking.starts_at, window)} - "
        f"{_label(booking.ends_at, window)} "
        f"({local.tzname()}, UTC{pretty_offset})"
    )


def _guest_booking_email(
    booking: DemoBooking,
    lead: DemoRequest,
    window: BookingWindow,
    *,
    rescheduled: bool,
) -> str:
    return (
        heading("Your demo is moved" if rescheduled else "Your demo is confirmed")
        + paragraph(
            f"Hi {esc(lead.full_name)}, thanks for booking time with the "
            "Wyfy Guest team."
        )
        + info_box(
            [
                ("When", esc(_when(booking, window))),
                ("Company", esc(lead.company_name)),
                ("Reference", esc(str(booking.id))),
            ]
        )
        + callout(
            "Need a different time? Reply to this email and we will sort it out."
        )
    )


def _team_booking_email(
    booking: DemoBooking,
    lead: DemoRequest,
    window: BookingWindow,
    *,
    rescheduled: bool,
) -> str:
    return (
        heading("Demo rescheduled" if rescheduled else "New demo booked")
        + paragraph(
            f"<strong>{esc(lead.full_name)}</strong> ({esc(lead.email)}) from "
            f"<strong>{esc(lead.company_name)}</strong> "
            f"{'moved their demo' if rescheduled else 'booked a demo'}."
        )
        + info_box(
            [
                ("When", esc(_when(booking, window))),
                ("Phone", esc(lead.phone or "—")),
                ("Property type", esc(lead.property_type or "—")),
                (
                    "Locations",
                    esc(
                        str(lead.location_count)
                        if lead.location_count is not None
                        else "—"
                    ),
                ),
                ("Message", esc(lead.message or "—")),
            ]
        )
        + paragraph("It is on the Master console under Demo Requests.", muted=True)
    )


def _cancellation_email(
    booking: DemoBooking, lead: DemoRequest, window: BookingWindow
) -> str:
    return (
        heading("Demo cancelled")
        + paragraph(
            f"<strong>{esc(lead.full_name)}</strong> ({esc(lead.email)}) from "
            f"<strong>{esc(lead.company_name)}</strong> cancelled their demo. "
            "The slot is free again."
        )
        + info_box(
            [
                ("Was", esc(_when(booking, window))),
                ("Reason", esc(booking.cancellation_reason or "—")),
            ]
        )
    )


__all__ = [
    "AvailabilityResult",
    "BookingListResult",
    "BookingRateLimiter",
    "BookingResult",
    "DemoBookingService",
    "NotificationEnqueuer",
    "hash_manage_token",
]
