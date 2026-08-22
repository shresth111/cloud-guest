"""Data access layer for the Demo Booking domain.

Mirrors ``app.domains.demo_request.repository``'s shape: ``Protocol``s
describing what the service layer needs, plus a concrete,
``GenericRepository``-backed implementation.

Two things here are deliberately *not* like the neighbouring domains.

**The insert is not routed through ``GenericRepository.create``.** That
helper calls ``session.rollback()`` and re-raises every ``IntegrityError``
as a generic ``DuplicateRecordError`` -- which would (a) lose the
information about *which* constraint fired, and (b) roll back the whole
request-scoped transaction, taking the lead row with it. Booking needs the
opposite of both: a precisely-identified conflict on
``uq_demo_bookings_active_slot``, contained inside a ``SAVEPOINT`` so the
lead that was already committed and the session itself both survive.

**There is no ``is this slot free?`` query.** Deliberately, and it is not
an oversight -- see ``models.DemoBooking``'s module docstring. The only
free/taken question this module answers is the *bulk* one that renders the
calendar (``confirmed_starts_between``), which is a display concern; it is
never consulted to decide whether an insert may proceed.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Protocol

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PageParams, PaginationMeta, paginate
from app.domains.demo_request.models import DemoRequest

from .constants import DemoBookingStatus
from .models import ACTIVE_SLOT_INDEX_NAME, DemoBooking


class SlotTakenError(Exception):
    """The database refused an insert/update because
    ``uq_demo_bookings_active_slot`` already holds that instant.

    A repository-level signal, not the API-level exception: the service
    layer catches this and re-raises
    ``exceptions.SlotAlreadyBookedError``, which needs the *alternatives*
    that this layer has no business computing.
    """

    def __init__(self, starts_at: datetime) -> None:
        self.starts_at = starts_at
        super().__init__(f"Slot already held: {starts_at.isoformat()}")


def is_active_slot_conflict(exc: IntegrityError) -> bool:
    """Whether ``exc`` is specifically the double-booking constraint
    firing, as opposed to any other integrity failure (a bad FK, say)
    which must keep propagating as the real error it is.

    PostgreSQL names the offending index in its message
    (``duplicate key value violates unique constraint
    "uq_demo_bookings_active_slot"``), so the primary check is on that
    name. SQLite -- which the test suite uses to create a real table with
    this same partial unique index, because CI has no Postgres service --
    reports ``UNIQUE constraint failed: demo_bookings.starts_at`` and
    names the *column* instead. Both spellings are matched.

    Nothing else on this table can produce a unique violation mentioning
    ``starts_at``: the only other unique constraint is the primary key on
    a freshly generated UUID4.
    """
    message = str(getattr(exc, "orig", exc)).lower()
    if ACTIVE_SLOT_INDEX_NAME in message:
        return True
    return "unique" in message and "starts_at" in message


class LeadRepositoryProtocol(Protocol):
    """The narrow slice of ``app.domains.demo_request.repository
    .DemoRequestRepository`` this domain needs -- composition, not
    duplication, the same narrow-protocol posture
    ``app.domains.demo_request.service.NotificationEnqueuer`` already uses
    for its own cross-domain dependency."""

    async def create(self, **fields: object) -> DemoRequest: ...

    async def update(
        self, demo_request: DemoRequest, data: dict[str, object]
    ) -> DemoRequest: ...


class DemoBookingRepositoryProtocol(Protocol):
    async def create_booking(self, **fields: object) -> DemoBooking: ...

    async def get_by_id(self, booking_id: uuid.UUID) -> DemoBooking | None: ...

    async def get_by_token_hash(self, token_hash: str) -> DemoBooking | None: ...

    async def update_booking(
        self, booking: DemoBooking, data: dict[str, object]
    ) -> DemoBooking: ...

    async def confirmed_starts_between(
        self, start: datetime, end: datetime
    ) -> list[datetime]: ...

    async def count_active_for_email(self, email: str, *, now: datetime) -> int: ...

    async def find_recent_unbooked_lead(
        self, email: str, *, since: datetime
    ) -> DemoRequest | None: ...

    async def find_lead_by_id(self, lead_id: uuid.UUID) -> DemoRequest | None: ...

    async def list_bookings(
        self,
        *,
        page: int,
        page_size: int,
        status: str | None = None,
        from_instant: datetime | None = None,
        to_instant: datetime | None = None,
        search: str | None = None,
    ) -> tuple[list[tuple[DemoBooking, DemoRequest]], PaginationMeta]: ...

    async def commit(self) -> None: ...


class DemoBookingRepository:
    """Concrete, SQLAlchemy-backed implementation."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.bookings = GenericRepository(DemoBooking, session)

    # -- writes ------------------------------------------------------------

    async def create_booking(self, **fields: object) -> DemoBooking:
        """Insert one booking. Raises :class:`SlotTakenError` -- and
        nothing else -- when the double-booking index rejects it.

        The insert runs inside a ``SAVEPOINT`` (``begin_nested``) so that a
        rejected insert rolls back *only itself*. Without it, the
        ``IntegrityError`` would poison the whole request transaction and
        the already-written lead row would go with it, which is exactly the
        "slots exist but leads are lost" outcome this feature must not
        produce.
        """
        booking = DemoBooking(**fields)
        try:
            async with self.session.begin_nested():
                self.session.add(booking)
                await self.session.flush()
        except IntegrityError as exc:
            if is_active_slot_conflict(exc):
                raise SlotTakenError(booking.starts_at) from exc
            raise
        return booking

    async def update_booking(
        self, booking: DemoBooking, data: dict[str, object]
    ) -> DemoBooking:
        """Mutate one booking. Also ``SAVEPOINT``-wrapped and also raises
        :class:`SlotTakenError`, because a *reschedule* moves ``starts_at``
        and is therefore governed by the identical index -- there is no
        second, weaker code path by which a booking can land on an
        occupied instant."""
        for key, value in data.items():
            setattr(booking, key, value)
        booking.version += 1
        try:
            async with self.session.begin_nested():
                await self.session.flush()
        except IntegrityError as exc:
            if is_active_slot_conflict(exc):
                raise SlotTakenError(booking.starts_at) from exc
            raise
        return booking

    async def commit(self) -> None:
        await self.session.commit()

    # -- reads -------------------------------------------------------------

    async def get_by_id(self, booking_id: uuid.UUID) -> DemoBooking | None:
        return await self.bookings.get_by_id(booking_id)

    async def get_by_token_hash(self, token_hash: str) -> DemoBooking | None:
        statement = select(DemoBooking).where(
            DemoBooking.manage_token_hash == token_hash,
            DemoBooking.is_deleted.is_(False),
        )
        result = await self.session.execute(statement)
        return result.scalars().first()

    async def confirmed_starts_between(
        self, start: datetime, end: datetime
    ) -> list[datetime]:
        """Every instant currently *held* in ``[start, end)``.

        Scoped to ``CONFIRMED``/not-deleted, i.e. exactly the rows the
        partial unique index covers -- so what the calendar shows as taken
        and what the database will actually refuse are the same set by
        construction, not by two predicates that have to be kept in sync
        by hand.
        """
        statement = select(DemoBooking.starts_at).where(
            DemoBooking.status == DemoBookingStatus.CONFIRMED.value,
            DemoBooking.is_deleted.is_(False),
            DemoBooking.starts_at >= start,
            DemoBooking.starts_at < end,
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    async def count_active_for_email(self, email: str, *, now: datetime) -> int:
        """How many *future* confirmed bookings this email already holds --
        the per-identifier cap that stops one scripted address from
        reserving the whole calendar (see
        ``Settings.demo_booking_max_active_per_email``)."""
        statement = (
            select(func.count())
            .select_from(DemoBooking)
            .join(DemoRequest, DemoRequest.id == DemoBooking.demo_request_id)
            .where(
                DemoBooking.status == DemoBookingStatus.CONFIRMED.value,
                DemoBooking.is_deleted.is_(False),
                DemoBooking.starts_at >= now,
                DemoRequest.email == email,
            )
        )
        result = await self.session.execute(statement)
        return int(result.scalar_one())

    async def find_recent_unbooked_lead(
        self, email: str, *, since: datetime
    ) -> DemoRequest | None:
        """The most recent lead from ``email`` that has no confirmed
        booking attached and was created at or after ``since``.

        This is what stops a visitor who lost a slot race -- and then
        immediately picked another time -- from landing in the sales queue
        twice. It is a plain ``SELECT``, and unlike the double-booking
        question it is genuinely safe as one: the worst case under
        concurrency is a duplicate *lead*, which is a tidiness problem, not
        a correctness one. (Losing a lead would be the correctness
        problem, and that is why the lead is committed before the booking
        is even attempted -- see ``service.DemoBookingService.book_slot``.)
        """
        booked = (
            select(DemoBooking.demo_request_id)
            .where(
                DemoBooking.status == DemoBookingStatus.CONFIRMED.value,
                DemoBooking.is_deleted.is_(False),
            )
            .scalar_subquery()
        )
        statement = (
            select(DemoRequest)
            .where(
                DemoRequest.email == email,
                DemoRequest.is_deleted.is_(False),
                DemoRequest.created_at >= since,
                DemoRequest.id.not_in(booked),
            )
            .order_by(DemoRequest.created_at.desc())
            .limit(1)
        )
        result = await self.session.execute(statement)
        return result.scalars().first()

    async def find_lead_by_id(self, lead_id: uuid.UUID) -> DemoRequest | None:
        """The lead a booking belongs to. Read through this domain's own
        session rather than reaching into ``DemoRequestRepository`` for a
        plain by-id read -- one query, no extra composition."""
        statement = select(DemoRequest).where(
            DemoRequest.id == lead_id, DemoRequest.is_deleted.is_(False)
        )
        result = await self.session.execute(statement)
        return result.scalars().first()

    async def list_bookings(
        self,
        *,
        page: int,
        page_size: int,
        status: str | None = None,
        from_instant: datetime | None = None,
        to_instant: datetime | None = None,
        search: str | None = None,
    ) -> tuple[list[tuple[DemoBooking, DemoRequest]], PaginationMeta]:
        """The Master console's calendar view: bookings joined to the lead
        they belong to, so an operator sees who is coming without a second
        round trip."""
        filters: list = [DemoBooking.is_deleted.is_(False)]
        if status is not None:
            filters.append(DemoBooking.status == status)
        if from_instant is not None:
            filters.append(DemoBooking.starts_at >= from_instant)
        if to_instant is not None:
            filters.append(DemoBooking.starts_at < to_instant)
        if search is not None:
            like = f"%{search}%"
            filters.append(
                or_(
                    DemoRequest.full_name.ilike(like),
                    DemoRequest.email.ilike(like),
                    DemoRequest.company_name.ilike(like),
                )
            )

        joined = DemoRequest.id == DemoBooking.demo_request_id
        count_statement = (
            select(func.count())
            .select_from(DemoBooking)
            .join(DemoRequest, joined)
            .where(*filters)
        )
        total_result = await self.session.execute(count_statement)
        total_items = int(total_result.scalar_one())

        statement = (
            select(DemoBooking, DemoRequest)
            .join(DemoRequest, joined)
            .where(*filters)
            .order_by(DemoBooking.starts_at.asc())
        )
        params = PageParams(page=page, page_size=page_size)
        result = await self.session.execute(paginate(statement, params))
        rows: Sequence = result.all()
        return [(row[0], row[1]) for row in rows], PaginationMeta.from_total(
            params, total_items
        )


__all__ = [
    "DemoBookingRepository",
    "DemoBookingRepositoryProtocol",
    "LeadRepositoryProtocol",
    "SlotTakenError",
    "is_active_slot_conflict",
]
