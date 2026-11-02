"""COLLECTIONS-1 service: the overdue list, promises, notes/timeline, cash in
the field and the end-of-day cash handover.

Money only moves through the existing billing code:
``IspBillingService.record_payment`` (the function behind ``POST
/isp/billing/payments``) records the cash, and ``_apply_credit`` (the existing
"advance auto-applies" path) spreads any remainder over the party's other
open bills, oldest first. Nothing here writes ``isp_invoices`` or
``isp_payments`` directly.

Scope: every read goes through ``isp.child_ids()`` (confinement, narrowed by
ZONE-1's ``scope_zone_id``) and ORM selects of ``IspInvoice`` also carry the
zone loader criteria. Every id from a request is resolved through
``IspScope`` (customer) or ``subscriber_in_scope`` and answers 404 outside
the caller's ISP or customers.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import UTC, date, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import and_, func, or_, select

from . import collections_logic as L
from .apps_common import org_names, subscriber_label, user_names
from .billing_models import (
    IspInvoice,
    IspInvoiceReminder,
    IspPayment,
    IspPaymentAllocation,
)
from .billing_service import IspBillingService, balance_of
from .collections_config import (
    ISP_COLLECTIONS_APPROVE,
    IspHandoverEmptyError,
    IspHandoverNotFoundError,
    IspHandoverSelfApprovalError,
    IspHandoverStateError,
    IspPromiseNotFoundError,
)
from .collections_models import (
    IspCashHandover,
    IspCashHandoverItem,
    IspCollectionEvent,
    IspCollectionPromise,
)
from .exceptions import IspBadRequestError
from .plans_models import IspSubscriber
from .scoping import IspScope

OPEN_STATUSES = ("issued", "partially_paid")
PARTY_KINDS = ("subscriber", "customer")
Party = tuple[uuid.UUID, uuid.UUID | None]


def _iso(v: Any) -> Any:
    return v.isoformat() if v is not None and hasattr(v, "isoformat") else v


def has_key(isp: Any, key: str) -> bool:
    from .rbac_roles import ROLES_BY_SLUG

    role = ROLES_BY_SLUG.get(getattr(isp, "role_slug", ""))
    return role is not None and key in role.permission_keys


def party_of(row: Any) -> Party:
    return (row.customer_organization_id, row.subscriber_id)


def _party_filter(model: Any, party: Party) -> Any:
    cust, sub = party
    if sub is not None:
        return model.subscriber_id == sub
    return and_(model.customer_organization_id == cust, model.subscriber_id.is_(None))


class IspCollectionsService:
    def __init__(self, *, session: Any, audit: Any = None, clock: Any = None) -> None:
        self.session = session
        self.audit = audit
        self._clock = clock or (lambda: datetime.now(UTC))
        self.billing = IspBillingService(session=session, audit=audit, clock=clock)

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def now(self) -> datetime:
        return self._clock()

    def tz(self, isp: Any) -> ZoneInfo:
        return ZoneInfo(isp.organization.timezone or "Asia/Kolkata")

    def today(self, isp: Any) -> date:
        return self.now().astimezone(self.tz(isp)).date()

    async def _audit(
        self, isp: Any, action: str, entity_id: Any, customer_id=None, **meta
    ) -> None:  # noqa: ANN001, E501
        if self.audit is None:
            return
        await self.audit.create_audit_log_entry(
            actor_user_id=isp.user_id,
            action=action,
            entity_type="isp_collections",
            entity_id=entity_id,
            description=action.replace("_", " "),
            event_metadata={
                "console": "isp",
                "isp_organization_id": str(isp.isp_org_id),
                **{
                    k: (str(v) if isinstance(v, uuid.UUID) else v)
                    for k, v in meta.items()
                },
            },
            organization_id=customer_id or isp.isp_org_id,
            location_id=None,
        )

    async def resolve_party(
        self,
        isp: Any,
        *,
        subscriber_id: uuid.UUID | None,
        isp_customer_id: uuid.UUID | None,
    ) -> tuple[Party, Any]:
        """Exactly one of the two; 404 outside the caller's scope."""
        if (subscriber_id is None) == (isp_customer_id is None):
            raise IspBadRequestError(
                "Give exactly one of subscriber_id or isp_customer_id",
                field="subscriber_id",
                reason="ISP_TARGET_REQUIRED",
            )
        if subscriber_id is not None:
            s = await self.billing.subscriber_in_scope(isp, subscriber_id)
            return (s.customer_organization_id, s.id), s
        org = await IspScope.assert_customer(isp, isp_customer_id)
        return (org.id, None), org

    async def _open_invoices(
        self, isp: Any, customer_ids: list[uuid.UUID], party: Party | None = None
    ) -> list[IspInvoice]:
        if not customer_ids:
            return []
        q = select(IspInvoice).where(
            IspInvoice.isp_organization_id == isp.isp_org_id,
            IspInvoice.customer_organization_id.in_(customer_ids),
            IspInvoice.doc_type == "invoice",
            IspInvoice.bill_to_kind.in_(PARTY_KINDS),
            IspInvoice.status.in_(OPEN_STATUSES),
            IspInvoice.is_deleted.is_(False),
        )
        if party is not None:
            q = q.where(_party_filter(IspInvoice, party))
        rows = (await self.session.execute(q)).scalars().all()
        return [r for r in rows if balance_of(r) > 0]

    async def _paid_between(
        self, isp: Any, parties: set[Party], since: datetime
    ) -> list[tuple[Party, datetime, int]]:
        """(party, received_at, amount) of confirmed payments since ``since``."""
        if not parties:
            return []
        customers = {c for c, _ in parties}
        rows = (
            await self.session.execute(
                select(
                    IspPayment.customer_organization_id,
                    IspPayment.subscriber_id,
                    IspPayment.received_at,
                    IspPayment.amount_paise,
                ).where(
                    IspPayment.isp_organization_id == isp.isp_org_id,
                    IspPayment.customer_organization_id.in_(customers),
                    IspPayment.status == "confirmed",
                    IspPayment.received_at >= since,
                    IspPayment.is_deleted.is_(False),
                )
            )
        ).all()
        return [((c, s), at, amt) for c, s, at, amt in rows if (c, s) in parties]

    async def _promises(
        self, isp: Any, customer_ids: list[uuid.UUID], *, statuses: tuple | None = None
    ) -> list[IspCollectionPromise]:
        if not customer_ids:
            return []
        q = select(IspCollectionPromise).where(
            IspCollectionPromise.isp_organization_id == isp.isp_org_id,
            IspCollectionPromise.customer_organization_id.in_(customer_ids),
            IspCollectionPromise.is_deleted.is_(False),
        )
        # P3-SWEEP: in a zone-scoped request a promise follows its
        # subscriber's own zone (customer-level promises: the customer's
        # zone), like ZONE-1 does for invoices. Only narrows; no zone scope
        # (incl. the daily Celery pass) = unchanged.
        from .zones_scope import party_zone_clause

        zone = party_zone_clause(
            self.session,
            IspCollectionPromise.subscriber_id,
            IspCollectionPromise.customer_organization_id,
        )
        if zone is not None:
            q = q.where(zone)
        if statuses:
            q = q.where(IspCollectionPromise.status.in_(statuses))
        return list((await self.session.execute(q)).scalars().all())

    async def effective_statuses(
        self, isp: Any, promises: list[IspCollectionPromise]
    ) -> dict[uuid.UUID, str]:
        """Effective status of every promise (only ``open`` ones move)."""
        out = {p.id: p.status for p in promises}
        open_ = [p for p in promises if p.status == L.PROMISE_OPEN]
        if not open_:
            return out
        tz = self.tz(isp)
        today = self.today(isp)
        since = min(p.created_at for p in open_)
        pays = await self._paid_between(isp, {party_of(p) for p in open_}, since)
        by_party: dict[Party, list[tuple[datetime, int]]] = defaultdict(list)
        for party, at, amt in pays:
            by_party[party].append((at, amt))
        for p in open_:
            _, deadline = L.day_bounds_utc(p.promised_on, tz)
            paid = sum(
                amt
                for at, amt in by_party.get(party_of(p), [])
                if p.created_at <= at < deadline
            )
            out[p.id] = L.promise_status(
                stored=p.status,
                promised_on=p.promised_on,
                target_paise=p.target_paise,
                paid_by_deadline_paise=paid,
                today=today,
            )
        return out

    # ------------------------------------------------------------------
    # the overdue list
    # ------------------------------------------------------------------
    async def _party_facts(
        self, isp: Any, parties: set[Party], customer_ids: list[uuid.UUID]
    ) -> dict[Party, dict]:
        """last payment, late payments in 180 d, broken promises in 90 d."""
        out: dict[Party, dict] = {
            p: {"last_payment_at": None, "late": 0, "broken": 0} for p in parties
        }
        if not parties:
            return out
        customers = list({c for c, _ in parties})
        last = (
            await self.session.execute(
                select(
                    IspPayment.customer_organization_id,
                    IspPayment.subscriber_id,
                    func.max(IspPayment.received_at),
                )
                .where(
                    IspPayment.isp_organization_id == isp.isp_org_id,
                    IspPayment.customer_organization_id.in_(customers),
                    IspPayment.status == "confirmed",
                    IspPayment.is_deleted.is_(False),
                )
                .group_by(IspPayment.customer_organization_id, IspPayment.subscriber_id)
            )
        ).all()
        for c, s, at in last:
            if (c, s) in out:
                out[(c, s)]["last_payment_at"] = at
        today = self.today(isp)
        paid_at = (
            await self.session.execute(
                select(
                    IspInvoice.customer_organization_id,
                    IspInvoice.subscriber_id,
                    IspInvoice.due_date,
                    func.max(IspPayment.received_at),
                )
                .join(
                    IspPaymentAllocation,
                    and_(
                        IspPaymentAllocation.invoice_id == IspInvoice.id,
                        IspPaymentAllocation.is_deleted.is_(False),
                    ),
                )
                .join(IspPayment, IspPayment.id == IspPaymentAllocation.payment_id)
                .where(
                    IspInvoice.isp_organization_id == isp.isp_org_id,
                    IspInvoice.customer_organization_id.in_(customers),
                    IspInvoice.doc_type == "invoice",
                    IspInvoice.status == "paid",
                    IspInvoice.due_date >= today - timedelta(days=180),
                    IspPayment.status == "confirmed",
                )
                .group_by(
                    IspInvoice.id,
                    IspInvoice.customer_organization_id,
                    IspInvoice.subscriber_id,
                    IspInvoice.due_date,
                )
            )
        ).all()
        tz = self.tz(isp)
        for c, s, due, at in paid_at:
            if (
                (c, s) in out
                and at is not None
                and (at.astimezone(tz).date() - due).days > L.LATE_PAYMENT_DAYS
            ):
                out[(c, s)]["late"] += 1
        promises = await self._promises(isp, customer_ids)
        status = await self.effective_statuses(isp, promises)
        cutoff = self.now() - timedelta(days=90)
        for p in promises:
            key = party_of(p)
            if key not in out:
                continue
            st = status[p.id]
            if st == L.PROMISE_BROKEN and (
                p.status == L.PROMISE_OPEN or (p.resolved_at or p.created_at) >= cutoff
            ):
                out[key]["broken"] += 1
            if st == L.PROMISE_OPEN:
                out[key]["open_promise"] = p
        return out

    async def overdue(
        self,
        isp: Any,
        *,
        party_kind: str | None = None,
        isp_customer_id: uuid.UUID | None = None,
        band: str | None = None,
        promise: str | None = None,
        min_days: int = 0,
        search: str | None = None,
        sort: str = "priority",
        page: int = 1,
        page_size: int = 50,
    ) -> dict:
        if isp_customer_id is not None:
            await IspScope.assert_customer(isp, isp_customer_id)
            customer_ids = [isp_customer_id]
        else:
            customer_ids = await isp.child_ids()
        items = await self._overdue_items(isp, customer_ids)
        if party_kind:
            items = [i for i in items if i["party_kind"] == party_kind]
        if band:
            items = [i for i in items if i["risk"]["band"] == band]
        if min_days:
            items = [i for i in items if i["days_overdue"] >= min_days]
        if promise == "open":
            items = [
                i for i in items if i["promise"] and i["promise"]["status"] == "open"
            ]
        elif promise == "broken":
            items = [i for i in items if i["broken_promises_90d"] > 0]
        elif promise == "none":
            items = [i for i in items if not i["promise"]]
        if search:
            needle = search.strip().lower()
            items = [
                i
                for i in items
                if any(
                    needle in (v or "").lower()
                    for v in (
                        i["name"],
                        i["identifier"],
                        i["phone"],
                        i["customer_name"],
                        *i["invoice_numbers"],
                    )
                )
            ]
        items.sort(key=lambda i: L.sort_key(i, sort))
        summary = {
            "parties": len(items),
            "overdue_paise": sum(i["overdue_paise"] for i in items),
            "by_band": {
                b: {
                    "parties": sum(1 for i in items if i["risk"]["band"] == b),
                    "overdue_paise": sum(
                        i["overdue_paise"] for i in items if i["risk"]["band"] == b
                    ),
                }
                for b in ("high", "medium", "low")
            },
            "open_promises": sum(
                1 for i in items if i["promise"] and i["promise"]["status"] == "open"
            ),
        }
        start = (page - 1) * page_size
        return {
            "items": items[start : start + page_size],
            "total": len(items),
            "page": page,
            "page_size": page_size,
            "summary": summary,
            "as_of": self.today(isp).isoformat(),
            "rules": L.__doc__.split("**Predicted")[0].strip(),
        }

    async def _overdue_items(
        self, isp: Any, customer_ids: list[uuid.UUID]
    ) -> list[dict]:
        today = self.today(isp)
        invoices = await self._open_invoices(isp, customer_ids)
        groups: dict[Party, list[IspInvoice]] = defaultdict(list)
        for inv in invoices:
            groups[party_of(inv)].append(inv)
        overdue_parties = {
            p for p, invs in groups.items() if any(i.due_date < today for i in invs)
        }
        facts = await self._party_facts(isp, overdue_parties, customer_ids)
        subs = await self._subscribers({s for _, s in overdue_parties if s})
        orgs = await org_names(self.session, {c for c, _ in overdue_parties})
        notes = await self._last_notes(isp, overdue_parties, customer_ids)
        items = []
        for party in overdue_parties:
            invs = sorted(groups[party], key=lambda i: (i.due_date, i.number))
            late = [i for i in invs if i.due_date < today]
            f = facts[party]
            days_since = (
                (today - f["last_payment_at"].astimezone(self.tz(isp)).date()).days
                if f["last_payment_at"]
                else None
            )
            open_p = f.get("open_promise")
            risk = L.score(
                L.PartyFacts(
                    days_overdue=(today - late[0].due_date).days,
                    overdue_invoices=len(late),
                    broken_promises_90d=f["broken"],
                    late_payments_180d=f["late"],
                    days_since_last_payment=days_since,
                    open_promise_on=open_p.promised_on if open_p else None,
                ),
                today=today,
            )
            cust, sub_id = party
            s = subs.get(sub_id) if sub_id else None
            items.append(
                {
                    "party_kind": "subscriber" if sub_id else "customer",
                    "party_key": f"{cust}:{sub_id or ''}",
                    "subscriber_id": str(sub_id) if sub_id else None,
                    "isp_customer_id": str(cust),
                    "customer_name": orgs.get(cust),
                    "name": subscriber_label(s)
                    if s
                    else (late[0].bill_to_name or orgs.get(cust)),
                    "identifier": s.identifier if s else None,
                    "circuit_id": s.circuit_id if s else None,
                    "phone": s.phone if s else None,
                    "zone_id": str(s.zone_id)
                    if s and s.zone_id
                    else (str(late[0].zone_id) if late[0].zone_id else None),
                    "subscriber_status": s.status if s else None,
                    "overdue_paise": sum(balance_of(i) for i in late),
                    "balance_paise": sum(balance_of(i) for i in invs),
                    "invoices_overdue": len(late),
                    "invoice_numbers": [i.number for i in late],
                    "oldest_invoice_id": str(late[0].id),
                    "oldest_due_date": late[0].due_date.isoformat(),
                    "days_overdue": (today - late[0].due_date).days,
                    "risk": risk.view(),
                    "promise": self._promise_brief(open_p, L.PROMISE_OPEN)
                    if open_p
                    else None,
                    "broken_promises_90d": f["broken"],
                    "last_payment_at": _iso(f["last_payment_at"]),
                    "last_note": notes.get(party),
                }
            )
        return items

    async def _subscribers(self, ids: set) -> dict:
        if not ids:
            return {}
        rows = (
            await self.session.execute(
                select(IspSubscriber).where(IspSubscriber.id.in_(ids))
            )
        ).scalars()
        return {s.id: s for s in rows}

    async def _last_notes(
        self, isp: Any, parties: set[Party], customer_ids: list[uuid.UUID]
    ) -> dict[Party, dict]:
        if not parties:
            return {}
        rows = (
            await self.session.execute(
                select(IspCollectionEvent)
                .where(
                    IspCollectionEvent.isp_organization_id == isp.isp_org_id,
                    IspCollectionEvent.customer_organization_id.in_(
                        {c for c, _ in parties}
                    ),
                    IspCollectionEvent.kind == "note",
                    IspCollectionEvent.is_deleted.is_(False),
                )
                .order_by(IspCollectionEvent.occurred_at.desc())
            )
        ).scalars()
        out: dict[Party, dict] = {}
        for e in rows:
            key = party_of(e)
            if key in parties and key not in out:
                out[key] = {
                    "at": _iso(e.occurred_at),
                    "outcome": e.outcome,
                    "body": (e.body or "")[:160],
                }
        return out

    @staticmethod
    def _promise_brief(p: IspCollectionPromise, status: str) -> dict:
        return {
            "id": str(p.id),
            "promised_on": p.promised_on.isoformat(),
            "amount_paise": p.amount_paise,
            "target_paise": p.target_paise,
            "status": status,
        }

    # ------------------------------------------------------------------
    # forecast
    # ------------------------------------------------------------------
    async def forecast(self, isp: Any) -> dict:
        today = self.today(isp)
        tz = self.tz(isp)
        start, end = L.week_bounds(today)
        customer_ids = await isp.child_ids()
        collected = 0
        if customer_ids:
            lo, _ = L.day_bounds_utc(start, tz)
            collected = int(
                (
                    await self.session.execute(
                        select(
                            func.coalesce(func.sum(IspPayment.amount_paise), 0)
                        ).where(
                            IspPayment.isp_organization_id == isp.isp_org_id,
                            IspPayment.customer_organization_id.in_(customer_ids),
                            IspPayment.status == "confirmed",
                            IspPayment.received_at >= lo,
                            IspPayment.is_deleted.is_(False),
                            IspPayment.mode != "prepaid_coupon",
                        )
                    )
                ).scalar_one()
            )
        items = await self._overdue_items(isp, customer_ids)
        invoices = await self._open_invoices(isp, customer_ids)
        promises = await self._promises(isp, customer_ids)
        status = await self.effective_statuses(isp, promises)
        balances: dict[Party, int] = defaultdict(int)
        for inv in invoices:
            balances[party_of(inv)] += balance_of(inv)
        promise_parties: set[Party] = set()
        promises_due = []
        for p in promises:
            if status[p.id] == L.PROMISE_OPEN:
                promise_parties.add(party_of(p))
                if today <= p.promised_on <= end:
                    promises_due.append(
                        min(p.target_paise, balances.get(party_of(p), 0))
                    )
        due_this_week = [
            balance_of(i)
            for i in invoices
            if today <= i.due_date <= end and party_of(i) not in promise_parties
        ]
        by_band: dict[str, list[int]] = defaultdict(list)
        for it in items:
            key = (
                uuid.UUID(it["isp_customer_id"]),
                uuid.UUID(it["subscriber_id"]) if it["subscriber_id"] else None,
            )
            if key in promise_parties:
                continue
            by_band[it["risk"]["band"]].append(it["overdue_paise"])
        kept = sum(
            1
            for p in promises
            if status[p.id] == L.PROMISE_KEPT
            and p.created_at >= self.now() - timedelta(days=180)
        )
        broken = sum(
            1
            for p in promises
            if status[p.id] == L.PROMISE_BROKEN
            and p.created_at >= self.now() - timedelta(days=180)
        )
        on_time, total_due = await self._on_time(isp, customer_ids, today)
        return L.forecast(
            today=today,
            collected_so_far_paise=collected,
            promises_due=[x for x in promises_due if x > 0],
            keep=L.keep_rate(kept, broken),
            invoices_due=due_this_week,
            on_time=L.on_time_rate(on_time, total_due),
            overdue_by_band=dict(by_band),
        )

    async def _on_time(
        self, isp: Any, customer_ids: list[uuid.UUID], today: date
    ) -> tuple[int, int]:
        """(paid in full within the slack, total) for invoices due in the last
        90 days (before today)."""
        if not customer_ids:
            return 0, 0
        rows = (
            (
                await self.session.execute(
                    select(IspInvoice).where(
                        IspInvoice.isp_organization_id == isp.isp_org_id,
                        IspInvoice.customer_organization_id.in_(customer_ids),
                        IspInvoice.doc_type == "invoice",
                        IspInvoice.bill_to_kind.in_(PARTY_KINDS),
                        IspInvoice.status != "cancelled",
                        IspInvoice.due_date >= today - timedelta(days=90),
                        IspInvoice.due_date
                        < today - timedelta(days=L.ON_TIME_SLACK_DAYS),
                        IspInvoice.is_deleted.is_(False),
                    )
                )
            )
            .scalars()
            .all()
        )
        if not rows:
            return 0, 0
        paid_at = dict(
            (
                await self.session.execute(
                    select(
                        IspPaymentAllocation.invoice_id,
                        func.max(IspPayment.received_at),
                    )
                    .join(IspPayment, IspPayment.id == IspPaymentAllocation.payment_id)
                    .where(
                        IspPaymentAllocation.invoice_id.in_([r.id for r in rows]),
                        IspPaymentAllocation.is_deleted.is_(False),
                        IspPayment.status == "confirmed",
                    )
                    .group_by(IspPaymentAllocation.invoice_id)
                )
            ).all()
        )
        tz = self.tz(isp)
        on_time = 0
        for r in rows:
            at = paid_at.get(r.id)
            if (
                balance_of(r) == 0
                and at is not None
                and (at.astimezone(tz).date() - r.due_date).days <= L.ON_TIME_SLACK_DAYS
            ):
                on_time += 1
        return on_time, len(rows)

    # ------------------------------------------------------------------
    # notes, promises, timeline
    # ------------------------------------------------------------------
    def _event(
        self, isp: Any, party: Party, kind: str, **kw: Any
    ) -> IspCollectionEvent:
        e = IspCollectionEvent(
            isp_organization_id=isp.isp_org_id,
            customer_organization_id=party[0],
            subscriber_id=party[1],
            kind=kind,
            occurred_at=self.now(),
            created_by=isp.user_id,
            detail=kw.pop("detail", {}) or {},
            **kw,
        )
        self.session.add(e)
        return e

    async def add_note(
        self, isp: Any, party: Party, *, body: str, outcome: str | None
    ) -> dict:
        e = self._event(isp, party, "note", body=body, outcome=outcome)
        await self.session.flush()
        return (await self._event_views([e]))[0]

    async def _overdue_for_party(self, isp: Any, party: Party) -> int:
        today = self.today(isp)
        return sum(
            balance_of(i)
            for i in await self._open_invoices(isp, [party[0]], party)
            if i.due_date < today
        )

    async def create_promise(
        self,
        isp: Any,
        party: Party,
        *,
        promised_on: date,
        amount_paise: int | None,
        note: str | None,
    ) -> dict:
        today = self.today(isp)
        if promised_on < today or promised_on > today + timedelta(days=60):
            raise IspBadRequestError(
                "The promise date must be between today and 60 days ahead",
                field="promised_on",
            )
        overdue = await self._overdue_for_party(isp, party)
        balance = sum(
            balance_of(i) for i in await self._open_invoices(isp, [party[0]], party)
        )
        target = amount_paise if amount_paise else (overdue or balance)
        if target <= 0:
            raise IspBadRequestError(
                "Nothing is due from this subscriber or customer", field="amount_paise"
            )
        for old in await self._party_promises(isp, party, statuses=(L.PROMISE_OPEN,)):
            old.status = L.PROMISE_SUPERSEDED
            old.resolved_at = self.now()
            old.resolved_reason = "Replaced by a new promise"
        p = IspCollectionPromise(
            isp_organization_id=isp.isp_org_id,
            customer_organization_id=party[0],
            subscriber_id=party[1],
            promised_on=promised_on,
            amount_paise=amount_paise,
            target_paise=target,
            overdue_at_creation_paise=overdue,
            note=note,
            status=L.PROMISE_OPEN,
            created_by=isp.user_id,
        )
        self.session.add(p)
        await self.session.flush()
        self._event(
            isp,
            party,
            "promise_made",
            body=note,
            promise_id=p.id,
            detail={"promised_on": promised_on.isoformat(), "target_paise": target},
        )
        await self.session.flush()
        await self._audit(
            isp,
            "isp_collection_promise_made",
            p.id,
            party[0],
            subscriber_id=party[1],
            promised_on=promised_on.isoformat(),
            target_paise=target,
        )
        return (await self.promise_views(isp, [p]))[0]

    async def _party_promises(
        self, isp: Any, party: Party, *, statuses: tuple | None = None
    ) -> list:
        q = select(IspCollectionPromise).where(
            IspCollectionPromise.isp_organization_id == isp.isp_org_id,
            _party_filter(IspCollectionPromise, party),
            IspCollectionPromise.is_deleted.is_(False),
        )
        if statuses:
            q = q.where(IspCollectionPromise.status.in_(statuses))
        return list((await self.session.execute(q)).scalars().all())

    async def promise(self, isp: Any, promise_id: uuid.UUID) -> IspCollectionPromise:
        p = await self.session.get(IspCollectionPromise, promise_id)
        if p is None or p.is_deleted or p.isp_organization_id != isp.isp_org_id:
            raise IspPromiseNotFoundError()
        try:
            if p.subscriber_id is not None:
                await self.billing.subscriber_in_scope(isp, p.subscriber_id)
            else:
                await IspScope.assert_customer(isp, p.customer_organization_id)
        except Exception:  # noqa: BLE001 -- any scope miss is the same 404
            raise IspPromiseNotFoundError() from None
        return p

    async def cancel_promise(
        self, isp: Any, promise_id: uuid.UUID, *, reason: str
    ) -> dict:
        p = await self.promise(isp, promise_id)
        status = (await self.effective_statuses(isp, [p]))[p.id]
        if status != L.PROMISE_OPEN:
            raise IspHandoverStateError(f"This promise is already {status}")
        p.status = L.PROMISE_CANCELLED
        p.resolved_at = self.now()
        p.resolved_reason = reason
        self._event(isp, party_of(p), "promise_cancelled", body=reason, promise_id=p.id)
        await self.session.flush()
        await self._audit(
            isp,
            "isp_collection_promise_cancelled",
            p.id,
            p.customer_organization_id,
            reason=reason,
        )
        return (await self.promise_views(isp, [p]))[0]

    async def resolve_promises(
        self, isp: Any, party: Party | None = None
    ) -> dict[str, int]:
        """Persist kept/broken for open promises (all visible, or one party).
        Writes one timeline line per change. Returns counts. Broken ones are
        returned to the caller for the follow-up step."""
        if party is not None:
            open_ = await self._party_promises(isp, party, statuses=(L.PROMISE_OPEN,))
        else:
            open_ = await self._promises(
                isp, await isp.child_ids(), statuses=(L.PROMISE_OPEN,)
            )
        status = await self.effective_statuses(isp, open_)
        out = {"kept": 0, "broken": 0}
        self._just_broken: list[IspCollectionPromise] = []
        for p in open_:
            st = status[p.id]
            if st == L.PROMISE_OPEN:
                continue
            p.status = st
            p.resolved_at = self.now()
            out[st] += 1
            self.session.add(
                IspCollectionEvent(
                    isp_organization_id=p.isp_organization_id,
                    customer_organization_id=p.customer_organization_id,
                    subscriber_id=p.subscriber_id,
                    kind=f"promise_{st}",
                    promise_id=p.id,
                    occurred_at=self.now(),
                    created_by=getattr(isp, "user_id", None),
                    detail={
                        "promised_on": p.promised_on.isoformat(),
                        "target_paise": p.target_paise,
                    },
                )
            )
            if st == L.PROMISE_BROKEN:
                self._just_broken.append(p)
        await self.session.flush()
        return out

    async def list_promises(
        self,
        isp: Any,
        *,
        status: str | None,
        due: str | None,
        page: int,
        page_size: int,
    ) -> dict:
        rows = await self._promises(isp, await isp.child_ids())
        st = await self.effective_statuses(isp, rows)
        today = self.today(isp)
        _, end = L.week_bounds(today)
        if status:
            rows = [p for p in rows if st[p.id] == status]
        if due == "today":
            rows = [p for p in rows if p.promised_on == today]
        elif due == "week":
            rows = [p for p in rows if today <= p.promised_on <= end]
        elif due == "missed":
            rows = [p for p in rows if st[p.id] == L.PROMISE_BROKEN]
        rows.sort(key=lambda p: (p.promised_on, p.created_at), reverse=due == "missed")
        start = (page - 1) * page_size
        return {
            "items": await self.promise_views(isp, rows[start : start + page_size], st),
            "total": len(rows),
            "page": page,
            "page_size": page_size,
        }

    async def promise_views(
        self, isp: Any, rows: list, statuses: dict | None = None
    ) -> list[dict]:
        statuses = statuses or await self.effective_statuses(isp, rows)
        subs = await self._subscribers(
            {p.subscriber_id for p in rows if p.subscriber_id}
        )
        orgs = await org_names(self.session, {p.customer_organization_id for p in rows})
        users = await user_names(self.session, {p.created_by for p in rows})
        out = []
        for p in rows:
            s = subs.get(p.subscriber_id)
            out.append(
                {
                    "id": str(p.id),
                    "subscriber_id": str(p.subscriber_id) if p.subscriber_id else None,
                    "isp_customer_id": str(p.customer_organization_id),
                    "customer_name": orgs.get(p.customer_organization_id),
                    "name": subscriber_label(s)
                    if s
                    else orgs.get(p.customer_organization_id),
                    "phone": s.phone if s else None,
                    "promised_on": p.promised_on.isoformat(),
                    "amount_paise": p.amount_paise,
                    "target_paise": p.target_paise,
                    "overdue_at_creation_paise": p.overdue_at_creation_paise,
                    "note": p.note,
                    "status": statuses.get(p.id, p.status),
                    "stored_status": p.status,
                    "resolved_at": _iso(p.resolved_at),
                    "resolved_reason": p.resolved_reason,
                    "followup_task_id": str(p.followup_task_id)
                    if p.followup_task_id
                    else None,
                    "created_at": _iso(p.created_at),
                    "created_by": {
                        "id": str(p.created_by),
                        "name": users.get(p.created_by),
                    }
                    if p.created_by
                    else None,
                }
            )
        return out

    async def _event_views(self, rows: list) -> list[dict]:
        users = await user_names(self.session, {e.created_by for e in rows})
        return [
            {
                "id": str(e.id),
                "source": "collections",
                "kind": e.kind,
                "outcome": e.outcome,
                "body": e.body,
                "promise_id": str(e.promise_id) if e.promise_id else None,
                "payment_id": str(e.payment_id) if e.payment_id else None,
                "detail": e.detail or {},
                "at": _iso(e.occurred_at),
                "actor": {"id": str(e.created_by), "name": users.get(e.created_by)}
                if e.created_by
                else None,
            }
            for e in rows
        ]

    async def timeline(self, isp: Any, party: Party, *, limit: int = 200) -> dict:
        events = (
            (
                await self.session.execute(
                    select(IspCollectionEvent)
                    .where(
                        IspCollectionEvent.isp_organization_id == isp.isp_org_id,
                        _party_filter(IspCollectionEvent, party),
                        IspCollectionEvent.is_deleted.is_(False),
                    )
                    .order_by(IspCollectionEvent.occurred_at.desc())
                    .limit(limit)
                )
            )
            .scalars()
            .all()
        )
        out = await self._event_views(list(events))
        invoices = (
            (
                await self.session.execute(
                    select(IspInvoice)
                    .where(
                        IspInvoice.isp_organization_id == isp.isp_org_id,
                        IspInvoice.customer_organization_id == party[0],
                        _party_filter(IspInvoice, party),
                        IspInvoice.bill_to_kind.in_(PARTY_KINDS),
                        IspInvoice.is_deleted.is_(False),
                    )
                    .order_by(IspInvoice.issue_date.desc())
                    .limit(limit)
                )
            )
            .scalars()
            .all()
        )
        for i in invoices:
            out.append(
                {
                    "id": str(i.id),
                    "source": "billing",
                    "kind": "invoice" if i.doc_type == "invoice" else "credit_note",
                    "body": f"{i.number} {i.description or ''}".strip(),
                    "detail": {
                        "invoice_id": str(i.id),
                        "number": i.number,
                        "total_paise": i.total_paise,
                        "balance_paise": balance_of(i),
                        "due_date": i.due_date.isoformat(),
                        "status": i.status,
                    },
                    "at": datetime.combine(
                        i.issue_date, datetime.min.time(), tzinfo=self.tz(isp)
                    ).isoformat(),
                    "actor": None,
                }
            )
        pays = (
            (
                await self.session.execute(
                    select(IspPayment)
                    .where(
                        IspPayment.isp_organization_id == isp.isp_org_id,
                        IspPayment.customer_organization_id == party[0],
                        _party_filter(IspPayment, party),
                        IspPayment.is_deleted.is_(False),
                    )
                    .order_by(IspPayment.received_at.desc())
                    .limit(limit)
                )
            )
            .scalars()
            .all()
        )
        payers = await user_names(self.session, {p.recorded_by for p in pays})
        for p in pays:
            out.append(
                {
                    "id": str(p.id),
                    "source": "billing",
                    "kind": "payment",
                    "body": f"{p.receipt_number} · {p.mode}",
                    "detail": {
                        "payment_id": str(p.id),
                        "receipt_number": p.receipt_number,
                        "amount_paise": p.amount_paise,
                        "mode": p.mode,
                        "status": p.status,
                    },
                    "at": _iso(p.received_at),
                    "actor": {
                        "id": str(p.recorded_by),
                        "name": payers.get(p.recorded_by),
                    }
                    if p.recorded_by
                    else None,
                }
            )
        if invoices:
            reminders = (
                await self.session.execute(
                    select(IspInvoiceReminder, IspInvoice.number)
                    .join(IspInvoice, IspInvoice.id == IspInvoiceReminder.invoice_id)
                    .where(IspInvoiceReminder.invoice_id.in_([i.id for i in invoices]))
                )
            ).all()
            for r, number in reminders:
                out.append(
                    {
                        "id": str(r.id),
                        "source": "billing",
                        "kind": "reminder",
                        "body": f"Reminder for {number} by {r.channel} ({r.status})",
                        "detail": {"channel": r.channel, "status": r.status},
                        "at": _iso(r.sent_at),
                        "actor": None,
                    }
                )
        out.sort(key=lambda e: e["at"] or "", reverse=True)
        promises = await self._party_promises(isp, party)
        open_ = [p for p in promises if p.status == L.PROMISE_OPEN]
        overdue = await self._overdue_for_party(isp, party)
        # P3-SWEEP (Subscriber 360 card): everything still owed, due or not.
        open_paise = sum(
            balance_of(i) for i in await self._open_invoices(isp, [party[0]], party)
        )
        return {
            "items": out[:limit],
            "open_paise": open_paise,
            "promises": await self.promise_views(
                isp, sorted(promises, key=lambda p: p.created_at, reverse=True)[:20]
            ),
            "open_promise": (await self.promise_views(isp, open_))[0]
            if open_
            else None,
            "overdue_paise": overdue,
        }

    # ------------------------------------------------------------------
    # cash in the field
    # ------------------------------------------------------------------
    async def collect_cash(
        self,
        isp: Any,
        party: Party,
        *,
        amount_paise: int,
        invoice_id: uuid.UUID | None,
        note: str | None,
        idempotency_key: str | None,
    ) -> dict:
        """Record cash through the existing payment path, then spread any
        remainder over the party's other open bills, oldest first."""
        cust, sub = party
        if idempotency_key:
            repeat = (
                await self.session.execute(
                    select(IspPayment).where(
                        IspPayment.isp_organization_id == isp.isp_org_id,
                        IspPayment.idempotency_key == idempotency_key,
                    )
                )
            ).scalar_one_or_none()
            if repeat is not None:
                if party_of(repeat) != party or repeat.mode != "cash":
                    raise IspBadRequestError(
                        "This Idempotency-Key was used for another payment",
                        field="idempotency_key",
                        reason="ISP_IDEMPOTENCY_KEY_REUSED",
                    )
                return await self._cash_view(isp, repeat, repeat=True)
        open_invoices = sorted(
            await self._open_invoices(isp, [cust], party),
            key=lambda i: (i.due_date, i.issue_date, i.number),
        )
        if invoice_id is None and open_invoices:
            invoice_id = open_invoices[0].id
        pay = await self.billing.record_payment(
            isp,
            amount_paise=amount_paise,
            mode="cash",
            isp_customer_id=None if sub else cust,
            subscriber_id=sub,
            invoice_id=invoice_id,
            reference=None,
            idempotency_key=idempotency_key,
        )
        for inv in open_invoices:
            if pay.unallocated_paise <= 0:
                break
            if inv.id == invoice_id or balance_of(inv) <= 0:
                continue
            await self.billing._apply_credit(isp, inv)
        self._event(
            isp,
            party,
            "cash_collected",
            body=note,
            payment_id=pay.id,
            detail={"amount_paise": amount_paise, "receipt_number": pay.receipt_number},
        )
        await self.session.flush()
        changed = await self.resolve_promises(isp, party)
        await self._audit(
            isp,
            "isp_collection_cash_recorded",
            pay.id,
            cust,
            subscriber_id=sub,
            receipt=pay.receipt_number,
            amount_paise=amount_paise,
        )
        view = await self._cash_view(isp, pay)
        view["promise_kept"] = changed["kept"] > 0
        return view

    async def _cash_view(
        self, isp: Any, pay: IspPayment, *, repeat: bool = False
    ) -> dict:
        row = (await self.billing.payment_rows(isp, [pay]))[0]
        allocs = (
            await self.session.execute(
                select(IspInvoice.number, IspPaymentAllocation.amount_paise)
                .join(IspInvoice, IspInvoice.id == IspPaymentAllocation.invoice_id)
                .where(
                    IspPaymentAllocation.payment_id == pay.id,
                    IspPaymentAllocation.is_deleted.is_(False),
                )
            )
        ).all()
        return {
            "payment": row,
            "allocations": [
                {"invoice_number": n, "amount_paise": a} for n, a in allocs
            ],
            "slip_path": f"/isp/collections/payments/{pay.id}/slip.pdf",
            "repeat": repeat,
        }

    async def slip_payment(self, isp: Any, payment_id: uuid.UUID) -> IspPayment:
        """The payment, if the caller recorded it or may approve handovers."""
        from .exceptions import IspPaymentNotFoundError

        pay = await self.billing._payment(isp, payment_id)
        if pay.recorded_by != isp.user_id and not has_key(isp, ISP_COLLECTIONS_APPROVE):
            raise IspPaymentNotFoundError()
        return pay

    async def _unhanded_cash(
        self, isp: Any, user_id: uuid.UUID, day: date
    ) -> list[IspPayment]:
        customer_ids = await isp.child_ids()
        if not customer_ids:
            return []
        lo, hi = L.day_bounds_utc(day, self.tz(isp))
        live = select(IspCashHandoverItem.payment_id).where(
            IspCashHandoverItem.is_deleted.is_(False)
        )
        return list(
            (
                await self.session.execute(
                    select(IspPayment)
                    .where(
                        IspPayment.isp_organization_id == isp.isp_org_id,
                        IspPayment.customer_organization_id.in_(customer_ids),
                        IspPayment.recorded_by == user_id,
                        IspPayment.mode == "cash",
                        IspPayment.status == "confirmed",
                        IspPayment.received_at >= lo,
                        IspPayment.received_at < hi,
                        IspPayment.is_deleted.is_(False),
                        IspPayment.id.not_in(live),
                    )
                    .order_by(IspPayment.received_at)
                )
            )
            .scalars()
            .all()
        )

    async def my_cash(self, isp: Any, day: date) -> dict:
        customer_ids = await isp.child_ids()
        lo, hi = L.day_bounds_utc(day, self.tz(isp))
        rows: list[IspPayment] = []
        if customer_ids:
            rows = list(
                (
                    await self.session.execute(
                        select(IspPayment)
                        .where(
                            IspPayment.isp_organization_id == isp.isp_org_id,
                            IspPayment.customer_organization_id.in_(customer_ids),
                            IspPayment.recorded_by == isp.user_id,
                            IspPayment.mode == "cash",
                            IspPayment.received_at >= lo,
                            IspPayment.received_at < hi,
                            IspPayment.is_deleted.is_(False),
                        )
                        .order_by(IspPayment.received_at)
                    )
                )
                .scalars()
                .all()
            )
        handed = dict(
            (
                await self.session.execute(
                    select(IspCashHandoverItem.payment_id, IspCashHandover.status)
                    .join(
                        IspCashHandover,
                        IspCashHandover.id == IspCashHandoverItem.handover_id,
                    )
                    .where(
                        IspCashHandoverItem.payment_id.in_(
                            [p.id for p in rows] or [uuid.UUID(int=0)]
                        ),
                        IspCashHandoverItem.is_deleted.is_(False),
                    )
                )
            ).all()
        )
        views = await self.billing.payment_rows(isp, rows)
        for v, p in zip(views, rows, strict=True):
            v["handover_status"] = handed.get(p.id)
        live = [p for p in rows if p.status == "confirmed"]
        return {
            "date": day.isoformat(),
            "items": views,
            "total_paise": sum(p.amount_paise for p in live),
            "pending_handover_paise": sum(
                p.amount_paise for p in live if p.id not in handed
            ),
            "pending_handover_count": sum(1 for p in live if p.id not in handed),
        }

    # ------------------------------------------------------------------
    # handovers
    # ------------------------------------------------------------------
    async def submit_handover(
        self, isp: Any, *, business_date: date, declared_paise: int, note: str | None
    ) -> dict:
        today = self.today(isp)
        if business_date > today or business_date < today - timedelta(days=31):
            raise IspBadRequestError(
                "Hand over cash for today or one of the last 31 days",
                field="business_date",
            )
        pays = await self._unhanded_cash(isp, isp.user_id, business_date)
        if not pays:
            raise IspHandoverEmptyError()
        expected = sum(p.amount_paise for p in pays)
        h = IspCashHandover(
            isp_organization_id=isp.isp_org_id,
            collector_user_id=isp.user_id,
            business_date=business_date,
            expected_paise=expected,
            declared_paise=declared_paise,
            status="submitted",
            note=note,
            submitted_at=self.now(),
            created_by=isp.user_id,
        )
        self.session.add(h)
        await self.session.flush()
        for p in pays:
            self.session.add(
                IspCashHandoverItem(
                    handover_id=h.id, payment_id=p.id, amount_paise=p.amount_paise
                )
            )
        await self.session.flush()
        await self._audit(
            isp,
            "isp_cash_handover_submitted",
            h.id,
            None,
            business_date=business_date.isoformat(),
            expected_paise=expected,
            declared_paise=declared_paise,
            payments=len(pays),
        )
        return await self.handover_detail(isp, h.id)

    async def _items(self, handover_ids: list[uuid.UUID]) -> dict[uuid.UUID, list]:
        if not handover_ids:
            return {}
        rows = (
            await self.session.execute(
                select(IspCashHandoverItem, IspPayment)
                .join(IspPayment, IspPayment.id == IspCashHandoverItem.payment_id)
                .where(
                    IspCashHandoverItem.handover_id.in_(handover_ids),
                    IspCashHandoverItem.is_deleted.is_(False),
                )
            )
        ).all()
        out: dict[uuid.UUID, list] = defaultdict(list)
        for item, pay in rows:
            out[item.handover_id].append((item, pay))
        return out

    async def _decided_items(self, h: IspCashHandover) -> list:
        """A rejected handover's items are soft-deleted; read them anyway for
        its own detail page."""
        rows = (
            await self.session.execute(
                select(IspCashHandoverItem, IspPayment)
                .join(IspPayment, IspPayment.id == IspCashHandoverItem.payment_id)
                .where(IspCashHandoverItem.handover_id == h.id)
            )
        ).all()
        return list(rows)

    async def handover(
        self, isp: Any, handover_id: uuid.UUID, *, full: bool = False
    ) -> tuple:
        """(handover, items). Visible to its collector; to anyone holding
        approve when at least one payment (``full``: every payment) is in a
        customer they can see. Otherwise 404."""
        h = await self.session.get(IspCashHandover, handover_id)
        if h is None or h.is_deleted or h.isp_organization_id != isp.isp_org_id:
            raise IspHandoverNotFoundError()
        items = await self._decided_items(h)
        visible = set(await isp.child_ids())
        seen = [pay.customer_organization_id in visible for _, pay in items]
        own = h.collector_user_id == isp.user_id
        if full:
            if not has_key(isp, ISP_COLLECTIONS_APPROVE) or not all(seen):
                raise IspHandoverNotFoundError()
        elif not own and not (has_key(isp, ISP_COLLECTIONS_APPROVE) and any(seen)):
            raise IspHandoverNotFoundError()
        if not own and isp.confined_customer_ids is not None:
            items = [r for r, ok_ in zip(items, seen, strict=True) if ok_]
        return h, items

    async def handover_detail(self, isp: Any, handover_id: uuid.UUID) -> dict:
        h, items = await self.handover(isp, handover_id)
        view = (await self.handover_views([h]))[0]
        pay_rows = await self.billing.payment_rows(isp, [p for _, p in items])
        view["items"] = pay_rows
        view["expected_now_paise"] = sum(
            p.amount_paise for _, p in items if p.status == "confirmed"
        )
        view["voided_since_submit"] = [
            str(p.id) for _, p in items if p.status != "confirmed"
        ]
        return view

    async def handover_views(self, rows: list) -> list[dict]:
        users = await user_names(
            self.session,
            {h.collector_user_id for h in rows}
            | {h.decided_by for h in rows if h.decided_by},
        )
        out = []
        for h in rows:
            out.append(
                {
                    "id": str(h.id),
                    "collector": {
                        "id": str(h.collector_user_id),
                        "name": users.get(h.collector_user_id),
                    },
                    "business_date": h.business_date.isoformat(),
                    "expected_paise": h.expected_paise,
                    "declared_paise": h.declared_paise,
                    "declared_difference_paise": h.declared_paise - h.expected_paise,
                    "received_paise": h.received_paise,
                    "variance_paise": (h.received_paise - h.expected_paise)
                    if h.received_paise is not None
                    else None,
                    "status": h.status,
                    "note": h.note,
                    "submitted_at": _iso(h.submitted_at),
                    "decided_by": {
                        "id": str(h.decided_by),
                        "name": users.get(h.decided_by),
                    }
                    if h.decided_by
                    else None,
                    "decided_at": _iso(h.decided_at),
                    "decision_note": h.decision_note,
                }
            )
        return out

    async def list_handovers(
        self,
        isp: Any,
        *,
        status: str | None,
        isp_user_id: uuid.UUID | None,
        date_from: date | None,
        date_to: date | None,
        page: int,
        page_size: int,
    ) -> dict:
        q = select(IspCashHandover).where(
            IspCashHandover.isp_organization_id == isp.isp_org_id,
            IspCashHandover.is_deleted.is_(False),
        )
        approver = has_key(isp, ISP_COLLECTIONS_APPROVE)
        if not approver:
            q = q.where(IspCashHandover.collector_user_id == isp.user_id)
        elif isp.confined_customer_ids is not None:
            visible = await isp.child_ids()
            q = q.where(
                or_(
                    IspCashHandover.collector_user_id == isp.user_id,
                    IspCashHandover.id.in_(
                        select(IspCashHandoverItem.handover_id)
                        .join(
                            IspPayment, IspPayment.id == IspCashHandoverItem.payment_id
                        )
                        .where(
                            IspPayment.customer_organization_id.in_(
                                visible or [uuid.UUID(int=0)]
                            )
                        )
                    ),
                )
            )
        if status:
            q = q.where(IspCashHandover.status == status)
        if isp_user_id:
            q = q.where(IspCashHandover.collector_user_id == isp_user_id)
        if date_from:
            q = q.where(IspCashHandover.business_date >= date_from)
        if date_to:
            q = q.where(IspCashHandover.business_date <= date_to)
        total = (
            await self.session.execute(select(func.count()).select_from(q.subquery()))
        ).scalar_one()
        rows = (
            (
                await self.session.execute(
                    q.order_by(
                        IspCashHandover.business_date.desc(),
                        IspCashHandover.submitted_at.desc(),
                    )
                    .offset((page - 1) * page_size)
                    .limit(page_size)
                )
            )
            .scalars()
            .all()
        )
        pending = (
            (
                await self.session.execute(
                    select(
                        func.count(),
                        func.coalesce(func.sum(IspCashHandover.expected_paise), 0),
                    ).select_from(
                        q.where(IspCashHandover.status == "submitted").subquery()
                    )
                )
            ).one()
            if not status
            else (None, None)
        )
        return {
            "items": await self.handover_views(list(rows)),
            "total": total,
            "page": page,
            "page_size": page_size,
            "can_approve": approver,
            "pending": {"count": int(pending[0]), "expected_paise": int(pending[1])}
            if pending[0] is not None
            else None,
        }

    async def decide_handover(
        self,
        isp: Any,
        handover_id: uuid.UUID,
        *,
        approve: bool,
        received_paise: int | None,
        note: str | None,
    ) -> dict:
        h, items = await self.handover(isp, handover_id, full=True)
        if h.status != "submitted":
            raise IspHandoverStateError()
        if h.collector_user_id == isp.user_id:
            raise IspHandoverSelfApprovalError()
        h.decided_by = isp.user_id
        h.decided_at = self.now()
        h.decision_note = note
        if approve:
            if received_paise is None:
                raise IspBadRequestError(
                    "Enter the cash you counted", field="received_paise"
                )
            h.status = "approved"
            h.received_paise = received_paise
        else:
            if not (note or "").strip():
                raise IspBadRequestError("Give a reason", field="note")
            h.status = "rejected"
            for item, _ in items:
                if not item.is_deleted:
                    item.mark_deleted()
        h.updated_by = isp.user_id
        await self.session.flush()
        await self._audit(
            isp,
            "isp_cash_handover_approved" if approve else "isp_cash_handover_rejected",
            h.id,
            None,
            collector_user_id=h.collector_user_id,
            expected_paise=h.expected_paise,
            received_paise=received_paise,
            note=note,
        )
        return await self.handover_detail(isp, h.id)


__all__ = ["IspCollectionsService", "has_key"]
