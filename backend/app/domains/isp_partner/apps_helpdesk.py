"""J16 HelpDesk: the ISP's own ticket queue for its customers and
subscribers (distinct from ``monitor_support``, where the ISP files tickets
*to Wyfy*).

Rules:

* a ticket always names a customer of this ISP (``IspScope``), optionally a
  subscriber of that customer;
* the SLA is the ticket type's ``sla_minutes``, snapshotted at open, so
  editing a type never moves existing deadlines; ``due_at = opened_at + sla``;
* TAT = ``resolved_at - opened_at`` (minutes). ``sla_state`` is ``breached``
  when resolved after ``due_at``, or still open past it; ``no_sla`` without
  a target. Time on hold is NOT excluded (kept simple, stated in the UI);
* resolving or closing needs an RFO reason when the type says so (types
  default to requiring one); a ticket without a type does not;
* "close after raising" records a first-contact fix: opened, resolved and
  closed at the same instant (TAT 0) so it still counts in the reports;
* every change writes an ``isp_ticket_events`` row.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, time, timedelta
from typing import Any

from sqlalchemy import and_, func, or_, select

from .apps_common import (
    DONE_TICKET_STATUSES,
    OPEN_TICKET_STATUSES,
    IspAppsConflictError,
    IspAppsInvalidError,
    IspAppsNotFoundError,
    RfoReason,
    TicketStatus,
    assert_assignee,
    fmt_number,
    next_number,
    org_names,
    resolve_subscriber,
    subscriber_label,
    user_names,
    visible_customer_filter,
)
from .apps_models import IspTicket, IspTicketEvent, IspTicketType
from .plans_models import IspSubscriber
from .scoping import IspScope

#: allowed status moves (anything -> same status is a no-op)
TRANSITIONS: dict[str, frozenset[str]] = {
    TicketStatus.OPEN: frozenset(
        {
            TicketStatus.IN_PROGRESS,
            TicketStatus.ON_HOLD,
            TicketStatus.RESOLVED,
            TicketStatus.CLOSED,
        }
    ),
    TicketStatus.IN_PROGRESS: frozenset(
        {
            TicketStatus.OPEN,
            TicketStatus.ON_HOLD,
            TicketStatus.RESOLVED,
            TicketStatus.CLOSED,
        }
    ),
    TicketStatus.ON_HOLD: frozenset(
        {
            TicketStatus.OPEN,
            TicketStatus.IN_PROGRESS,
            TicketStatus.RESOLVED,
            TicketStatus.CLOSED,
        }
    ),
    TicketStatus.RESOLVED: frozenset({TicketStatus.CLOSED, TicketStatus.OPEN}),
    TicketStatus.CLOSED: frozenset({TicketStatus.OPEN}),
}

DEFAULT_TYPES: tuple[tuple[str, int | None], ...] = (
    ("No connection", 240),
    ("Slow speed", 480),
    ("Frequent disconnection", 480),
    ("Billing query", 1440),
    ("New connection / shifting", 2880),
)


def _now() -> datetime:
    return datetime.now(UTC)


def tat_minutes(t: Any) -> int | None:
    if t.resolved_at is None:
        return None
    return max(0, int((t.resolved_at - t.opened_at).total_seconds() // 60))


def sla_state(t: Any, now: datetime | None = None) -> str:
    if t.due_at is None:
        return "no_sla"
    if t.resolved_at is not None:
        return "breached" if t.resolved_at > t.due_at else "within"
    return "breached" if (now or _now()) > t.due_at else "within"


def check_transition(current: str, target: str) -> None:
    if current == target:
        return
    if target not in TRANSITIONS.get(current, frozenset()):
        raise IspAppsInvalidError(f"A {current} ticket cannot move to {target}")


def needs_rfo(ticket_type: Any | None) -> bool:
    return bool(ticket_type is not None and ticket_type.requires_rfo)


def apply_status(t: Any, target: str, *, now: datetime) -> None:
    """Move ``t`` to ``target`` and stamp the lifecycle times."""
    check_transition(t.status, target)
    if target == t.status:
        return
    if target in (TicketStatus.RESOLVED, TicketStatus.CLOSED) and t.resolved_at is None:
        t.resolved_at = now
    if target == TicketStatus.CLOSED:
        t.closed_at = now
    if target in OPEN_TICKET_STATUSES:
        # reopened: the old resolution no longer stands
        t.resolved_at = None
        t.closed_at = None
    if target != TicketStatus.OPEN and t.first_response_at is None:
        t.first_response_at = now
    t.status = target


def date_bounds(
    since: date | None, until: date | None
) -> tuple[datetime | None, datetime | None]:
    lo = datetime.combine(since, time.min, tzinfo=UTC) if since else None
    hi = (
        datetime.combine(until, time.min, tzinfo=UTC) + timedelta(days=1)
        if until
        else None
    )
    return lo, hi


class HelpdeskService:
    def __init__(self, session: Any) -> None:
        self.session = session

    # -- types ---------------------------------------------------------------
    async def list_types(
        self, isp: Any, *, include_inactive: bool = True
    ) -> list[dict]:
        q = select(IspTicketType).where(
            IspTicketType.isp_organization_id == isp.isp_org_id,
            IspTicketType.is_deleted.is_(False),
        )
        if not include_inactive:
            q = q.where(IspTicketType.active.is_(True))
        rows = (
            (
                await self.session.execute(
                    q.order_by(IspTicketType.sort_order, IspTicketType.name)
                )
            )
            .scalars()
            .all()
        )
        return [self.type_view(r) for r in rows]

    @staticmethod
    def type_view(r: Any) -> dict:
        return {
            "id": r.id,
            "name": r.name,
            "sla_minutes": r.sla_minutes,
            "requires_rfo": r.requires_rfo,
            "active": r.active,
            "sort_order": r.sort_order,
        }

    async def _type(self, isp: Any, type_id: uuid.UUID) -> IspTicketType:
        r = await self.session.get(IspTicketType, type_id)
        if r is None or r.is_deleted or r.isp_organization_id != isp.isp_org_id:
            raise IspAppsNotFoundError("Ticket type not found")
        return r

    async def _name_taken(
        self, isp: Any, name: str, exclude: uuid.UUID | None = None
    ) -> bool:
        q = select(IspTicketType.id).where(
            IspTicketType.isp_organization_id == isp.isp_org_id,
            IspTicketType.is_deleted.is_(False),
            func.lower(IspTicketType.name) == name.lower(),
        )
        if exclude:
            q = q.where(IspTicketType.id != exclude)
        return (await self.session.execute(q)).first() is not None

    async def create_type(self, isp: Any, data: dict) -> dict:
        if await self._name_taken(isp, data["name"]):
            raise IspAppsConflictError("A ticket type with this name exists")
        r = IspTicketType(isp_organization_id=isp.isp_org_id, **data)
        self.session.add(r)
        await self.session.flush()
        return self.type_view(r)

    async def update_type(self, isp: Any, type_id: uuid.UUID, data: dict) -> dict:
        r = await self._type(isp, type_id)
        if "name" in data and await self._name_taken(isp, data["name"], exclude=r.id):
            raise IspAppsConflictError("A ticket type with this name exists")
        for k, v in data.items():
            setattr(r, k, v)
        await self.session.flush()
        return self.type_view(r)

    async def seed_default_types(self, isp: Any) -> list[dict]:
        """Quick action: add the standard set; existing names are kept."""
        for i, (name, sla) in enumerate(DEFAULT_TYPES):
            if not await self._name_taken(isp, name):
                self.session.add(
                    IspTicketType(
                        isp_organization_id=isp.isp_org_id,
                        name=name,
                        sla_minutes=sla,
                        requires_rfo=name != "Billing query",
                        sort_order=i,
                    )
                )
        await self.session.flush()
        return await self.list_types(isp)

    # -- tickets -------------------------------------------------------------
    async def _ticket(self, isp: Any, ticket_id: uuid.UUID) -> IspTicket:
        t = await self.session.get(IspTicket, ticket_id)
        if t is None or t.is_deleted or t.isp_organization_id != isp.isp_org_id:
            raise IspAppsNotFoundError("Ticket not found")
        try:
            await IspScope.assert_customer(isp, t.customer_organization_id)
        except Exception:  # noqa: BLE001 -- confinement: same 404
            raise IspAppsNotFoundError("Ticket not found") from None
        return t

    def _event(
        self,
        t: Any,
        kind: str,
        actor: uuid.UUID,
        *,
        body: str | None = None,
        **detail: Any,
    ) -> None:
        self.session.add(
            IspTicketEvent(
                ticket_id=t.id,
                kind=kind,
                body=body,
                detail={
                    k: (str(v) if isinstance(v, uuid.UUID) else v)
                    for k, v in detail.items()
                },
                actor_user_id=actor,
                at=_now(),
            )
        )

    async def create_ticket(self, isp: Any, data: dict) -> dict:
        customer_id = data["isp_customer_id"]
        await IspScope.assert_customer(isp, customer_id)
        if data.get("subscriber_id"):
            await resolve_subscriber(
                isp, self.session, data["subscriber_id"], customer_id=customer_id
            )
        ttype = await self._type(isp, data["type_id"]) if data.get("type_id") else None
        if ttype is not None and not ttype.active:
            raise IspAppsInvalidError("That ticket type is switched off")
        if data.get("assignee_user_id"):
            await assert_assignee(
                isp, data["assignee_user_id"], customer_id=customer_id
            )
        close_now = bool(data.get("close_after_raising"))
        if close_now and needs_rfo(ttype) and not data.get("rfo_reason"):
            raise IspAppsInvalidError("Pick a reason for outage to close this ticket")
        now = _now()
        sla = ttype.sla_minutes if ttype is not None else None
        t = IspTicket(
            isp_organization_id=isp.isp_org_id,
            customer_organization_id=customer_id,
            subscriber_id=data.get("subscriber_id"),
            number=await next_number(self.session, isp.isp_org_id, "ticket"),
            type_id=ttype.id if ttype else None,
            subject=data["subject"],
            description=data.get("description"),
            source=data.get("source") or "phone",
            priority=data.get("priority") or "normal",
            status=TicketStatus.OPEN.value,
            assignee_user_id=data.get("assignee_user_id"),
            rfo_reason=data.get("rfo_reason"),
            resolution_note=data.get("resolution_note"),
            sla_minutes=sla,
            opened_at=now,
            due_at=now + timedelta(minutes=sla) if sla else None,
            raised_by_user_id=isp.user_id,
        )
        self.session.add(t)
        await self.session.flush()
        self._event(t, "status", isp.user_id, to_status="open")
        if close_now:
            apply_status(t, TicketStatus.CLOSED, now=now)
            self._event(
                t,
                "status",
                isp.user_id,
                from_status="open",
                to_status="closed",
                first_contact=True,
            )
        await self.session.flush()
        return await self.detail(isp, t.id)

    async def update_ticket(self, isp: Any, ticket_id: uuid.UUID, data: dict) -> dict:
        t = await self._ticket(isp, ticket_id)
        now = _now()
        if "type_id" in data:
            new_type = (
                await self._type(isp, data["type_id"]) if data["type_id"] else None
            )
            t.type_id = new_type.id if new_type else None
            self._event(t, "update", isp.user_id, field="type_id", value=t.type_id)
        if "priority" in data and data["priority"] != t.priority:
            self._event(
                t, "update", isp.user_id, field="priority", value=data["priority"]
            )
            t.priority = data["priority"]
        if (
            "assignee_user_id" in data
            and data["assignee_user_id"] != t.assignee_user_id
        ):
            if data["assignee_user_id"] is not None:
                await assert_assignee(
                    isp,
                    data["assignee_user_id"],
                    customer_id=t.customer_organization_id,
                )
            t.assignee_user_id = data["assignee_user_id"]
            if t.first_response_at is None and t.assignee_user_id is not None:
                t.first_response_at = now
            self._event(t, "assign", isp.user_id, assignee_user_id=t.assignee_user_id)
        if "rfo_reason" in data:
            t.rfo_reason = data["rfo_reason"]
        if "resolution_note" in data:
            t.resolution_note = data["resolution_note"]
        target = data.get("status")
        if target and target != t.status:
            if target in DONE_TICKET_STATUSES:
                ttype = (
                    await self.session.get(IspTicketType, t.type_id)
                    if t.type_id
                    else None
                )
                if needs_rfo(ttype) and not t.rfo_reason:
                    raise IspAppsInvalidError(
                        "Pick a reason for outage before resolving"
                    )
            before = t.status
            apply_status(t, target, now=now)
            self._event(t, "status", isp.user_id, from_status=before, to_status=target)
        await self.session.flush()
        return await self.detail(isp, t.id)

    async def add_comment(self, isp: Any, ticket_id: uuid.UUID, body: str) -> dict:
        t = await self._ticket(isp, ticket_id)
        if t.first_response_at is None:
            t.first_response_at = _now()
        self._event(t, "comment", isp.user_id, body=body)
        await self.session.flush()
        return await self.detail(isp, t.id)

    async def list_tickets(
        self,
        isp: Any,
        *,
        isp_customer_id: uuid.UUID | None = None,
        subscriber_id: uuid.UUID | None = None,
        status: str | None = None,
        assignee_user_id: uuid.UUID | None = None,
        type_id: uuid.UUID | None = None,
        rfo_reason: str | None = None,
        sla: str | None = None,
        since: date | None = None,
        until: date | None = None,
        search: str | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[dict], int]:
        customers = await visible_customer_filter(isp, isp_customer_id)
        if not customers:
            return [], 0
        conds: list[Any] = [
            IspTicket.isp_organization_id == isp.isp_org_id,
            IspTicket.is_deleted.is_(False),
            IspTicket.customer_organization_id.in_(customers),
        ]
        if subscriber_id is not None:
            conds.append(IspTicket.subscriber_id == subscriber_id)
        if status == "open":
            # "open" in a filter means "not done yet"; exact statuses also work
            conds.append(IspTicket.status.in_([s.value for s in OPEN_TICKET_STATUSES]))
        elif status:
            conds.append(IspTicket.status == status)
        if assignee_user_id is not None:
            conds.append(IspTicket.assignee_user_id == assignee_user_id)
        if type_id is not None:
            conds.append(IspTicket.type_id == type_id)
        if rfo_reason:
            conds.append(IspTicket.rfo_reason == rfo_reason)
        lo, hi = date_bounds(since, until)
        if lo:
            conds.append(IspTicket.opened_at >= lo)
        if hi:
            conds.append(IspTicket.opened_at < hi)
        now = _now()
        if sla == "breached":
            conds.append(
                and_(
                    IspTicket.due_at.is_not(None),
                    or_(
                        IspTicket.resolved_at > IspTicket.due_at,
                        and_(IspTicket.resolved_at.is_(None), IspTicket.due_at < now),
                    ),
                )
            )
        elif sla == "within":
            conds.append(
                and_(
                    IspTicket.due_at.is_not(None),
                    or_(
                        IspTicket.resolved_at <= IspTicket.due_at,
                        and_(IspTicket.resolved_at.is_(None), IspTicket.due_at >= now),
                    ),
                )
            )
        elif sla == "no_sla":
            conds.append(IspTicket.due_at.is_(None))
        if search:
            like = f"%{search.strip()}%"
            digits = search.strip().upper().removeprefix("T-").lstrip("0")
            sub_q = select(IspSubscriber.id).where(
                IspSubscriber.isp_organization_id == isp.isp_org_id,
                or_(
                    IspSubscriber.identifier.ilike(like),
                    IspSubscriber.phone.ilike(like),
                    IspSubscriber.first_name.ilike(like),
                    IspSubscriber.last_name.ilike(like),
                ),
            )
            ors = [IspTicket.subject.ilike(like), IspTicket.subscriber_id.in_(sub_q)]
            if digits.isdigit():
                ors.append(IspTicket.number == int(digits))
            conds.append(or_(*ors))
        total = int(
            (
                await self.session.execute(
                    select(func.count()).select_from(IspTicket).where(*conds)
                )
            ).scalar_one()
        )
        rows = (
            (
                await self.session.execute(
                    select(IspTicket)
                    .where(*conds)
                    .order_by(IspTicket.opened_at.desc())
                    .offset((page - 1) * page_size)
                    .limit(page_size)
                )
            )
            .scalars()
            .all()
        )
        return await self.views(rows), total

    async def views(self, rows: list[Any]) -> list[dict]:
        types = {}
        type_ids = {r.type_id for r in rows if r.type_id}
        if type_ids:
            for tt in (
                await self.session.execute(
                    select(IspTicketType).where(IspTicketType.id.in_(type_ids))
                )
            ).scalars():
                types[tt.id] = tt.name
        subs = {}
        sub_ids = {r.subscriber_id for r in rows if r.subscriber_id}
        if sub_ids:
            for s in (
                await self.session.execute(
                    select(IspSubscriber).where(IspSubscriber.id.in_(sub_ids))
                )
            ).scalars():
                subs[s.id] = subscriber_label(s)
        users = await user_names(self.session, {r.assignee_user_id for r in rows})
        orgs = await org_names(self.session, {r.customer_organization_id for r in rows})
        now = _now()
        return [
            {
                "id": r.id,
                "number": fmt_number("T", r.number),
                "isp_customer_id": r.customer_organization_id,
                "customer_name": orgs.get(r.customer_organization_id),
                "subscriber_id": r.subscriber_id,
                "subscriber_label": subs.get(r.subscriber_id),
                "type_id": r.type_id,
                "type_name": types.get(r.type_id),
                "subject": r.subject,
                "description": r.description,
                "source": r.source,
                "priority": r.priority,
                "status": r.status,
                "assignee_user_id": r.assignee_user_id,
                "assignee_name": users.get(r.assignee_user_id),
                "rfo_reason": r.rfo_reason,
                "resolution_note": r.resolution_note,
                "opened_at": r.opened_at,
                "first_response_at": r.first_response_at,
                "resolved_at": r.resolved_at,
                "closed_at": r.closed_at,
                "due_at": r.due_at,
                "sla_minutes": r.sla_minutes,
                "tat_minutes": tat_minutes(r),
                "sla_state": sla_state(r, now),
            }
            for r in rows
        ]

    async def detail(self, isp: Any, ticket_id: uuid.UUID) -> dict:
        t = await self._ticket(isp, ticket_id)
        view = (await self.views([t]))[0]
        events = (
            (
                await self.session.execute(
                    select(IspTicketEvent)
                    .where(IspTicketEvent.ticket_id == t.id)
                    .order_by(IspTicketEvent.at)
                )
            )
            .scalars()
            .all()
        )
        actors = await user_names(self.session, {e.actor_user_id for e in events})
        view["events"] = [
            {
                "kind": e.kind,
                "body": e.body,
                "detail": e.detail,
                "actor_name": actors.get(e.actor_user_id),
                "at": e.at,
            }
            for e in events
        ]
        return view

    async def stats(
        self,
        isp: Any,
        *,
        isp_customer_id: uuid.UUID | None,
        since: date | None,
        until: date | None,
    ) -> dict:
        """RFO / TAT roll-up over tickets OPENED in the range."""
        empty = {
            "by_rfo": {r.value: 0 for r in RfoReason},
            "by_type": [],
            "overall": {
                "count": 0,
                "resolved": 0,
                "avg_tat_minutes": None,
                "breached": 0,
            },
        }
        customers = await visible_customer_filter(isp, isp_customer_id)
        if not customers:
            return empty
        conds: list[Any] = [
            IspTicket.isp_organization_id == isp.isp_org_id,
            IspTicket.is_deleted.is_(False),
            IspTicket.customer_organization_id.in_(customers),
        ]
        lo, hi = date_bounds(since, until)
        if lo:
            conds.append(IspTicket.opened_at >= lo)
        if hi:
            conds.append(IspTicket.opened_at < hi)
        rows = (
            (await self.session.execute(select(IspTicket).where(*conds)))
            .scalars()
            .all()
        )
        return summarise(rows, await self._type_names(isp), now=_now())

    async def _type_names(self, isp: Any) -> dict[uuid.UUID, str]:
        rows = await self.session.execute(
            select(IspTicketType.id, IspTicketType.name).where(
                IspTicketType.isp_organization_id == isp.isp_org_id
            )
        )
        return dict(rows.all())


def summarise(
    rows: list[Any], type_names: dict[uuid.UUID, str], *, now: datetime
) -> dict:
    by_rfo = {r.value: 0 for r in RfoReason}
    groups: dict[uuid.UUID | None, list[Any]] = {}
    for r in rows:
        if r.rfo_reason in by_rfo:
            by_rfo[r.rfo_reason] += 1
        groups.setdefault(r.type_id, []).append(r)

    def agg(items: list[Any]) -> dict:
        tats = [m for m in (tat_minutes(i) for i in items) if m is not None]
        return {
            "count": len(items),
            "resolved": len(tats),
            "avg_tat_minutes": round(sum(tats) / len(tats), 1) if tats else None,
            "breached": sum(1 for i in items if sla_state(i, now) == "breached"),
        }

    by_type = [
        {
            "type_id": tid,
            "type_name": type_names.get(tid) if tid else "Untyped",
            **agg(items),
        }
        for tid, items in groups.items()
    ]
    by_type.sort(key=lambda x: -x["count"])
    return {"by_rfo": by_rfo, "by_type": by_type, "overall": agg(list(rows))}
