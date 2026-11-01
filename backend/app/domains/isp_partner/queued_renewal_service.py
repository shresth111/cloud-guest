"""QUEUED-RENEWAL: pay now, the next plan starts when the current one ends.

* **Create** runs the existing JAZE-1 renew (``IspSubscriber360Service.renew``
  -> ``IspPlansService.recharge``): same invoice code, same override price,
  cycles, paid-now payment, idempotency, the same "renewed" timeline event and
  the same validity extension from ``valid_until``. The only difference is
  that the subscriber keeps the package and speed it has today; this row
  remembers the new ones and ``starts_at`` (the old ``valid_until``).
* **Activation** (``run_queued_renewals``, the 120 s ISP pass in
  ``tasks.py``) switches the package and speed once ``starts_at`` has passed.
  Idempotent: only ``pending`` rows, locked with SKIP LOCKED, each in a
  SAVEPOINT; an already active row is never touched again.
* **Cancel** (pending only) goes through JAZE-1 revert, which issues the
  credit note through the existing billing path and puts the validity back.
  A paid bill first has its receipt voided through the existing
  ``void_payment`` (needs ``isp_billing.manage``); a receipt that also paid
  other bills is refused rather than unpicked.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from app.core.logging import get_logger

from .exceptions import IspBadRequestError
from .plans_models import IspPackage, IspSubscriber
from .queued_renewal_config import (
    IspQueuedRenewalNotFoundError,
    IspQueuedRenewalStateError,
    get_queued_renewal_settings,
)
from .queued_renewal_models import IspQueuedRenewal
from .subscriber360_models import IspSubscriberEvent

logger = get_logger(__name__)


def _iso(v: Any) -> Any:
    return v.isoformat() if v is not None and hasattr(v, "isoformat") else v


class IspQueuedRenewalService:
    def __init__(self, *, s360: Any, audit: Any = None, clock: Any = None) -> None:
        self.s360 = s360
        self.plans = s360.plans
        self.session = s360.session
        self.audit = audit
        self._clock = clock or (lambda: datetime.now(UTC))

    def now(self) -> datetime:
        return self._clock()

    async def _audit(
        self, isp: Any, action: str, entity_id: Any, customer_id: Any, **meta: Any
    ) -> None:  # noqa: E501
        if self.audit is None:
            return
        await self.audit.create_audit_log_entry(
            actor_user_id=isp.user_id,
            action=action,
            entity_type="isp_queued_renewal",
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

    async def _names(self, rows: list) -> dict:
        ids = {r.package_id for r in rows} | {
            r.previous_package_id for r in rows if r.previous_package_id
        }
        if not ids:
            return {}
        res = await self.session.execute(
            select(IspPackage.id, IspPackage.name).where(IspPackage.id.in_(ids))
        )
        return dict(res.all())

    async def views(self, rows: list) -> list[dict]:
        from .billing_models import IspInvoice

        names = await self._names(rows)
        invs = {}
        ids = [r.invoice_id for r in rows if r.invoice_id]
        if ids:
            invs = {
                i.id: i
                for i in (
                    await self.session.execute(
                        select(IspInvoice).where(IspInvoice.id.in_(ids))
                    )
                ).scalars()
            }
        out = []
        for r in rows:
            inv = invs.get(r.invoice_id)
            out.append(
                {
                    "id": str(r.id),
                    "subscriber_id": str(r.subscriber_id),
                    "isp_customer_id": str(r.customer_organization_id),
                    "package": {
                        "id": str(r.package_id),
                        "name": names.get(r.package_id),
                    },
                    "previous_package": {
                        "id": str(r.previous_package_id),
                        "name": names.get(r.previous_package_id),
                    }
                    if r.previous_package_id
                    else None,
                    "cycles": r.cycles,
                    "starts_at": _iso(r.starts_at),
                    "ends_at": _iso(r.ends_at),
                    "status": r.status,
                    "invoice": {
                        "id": str(inv.id),
                        "number": inv.number,
                        "total_paise": inv.total_paise,
                        "paid_paise": inv.paid_paise,
                        "status": inv.status,
                    }
                    if inv is not None
                    else None,
                    "activated_at": _iso(r.activated_at),
                    "cancelled_at": _iso(r.cancelled_at),
                    "cancel_reason": r.cancel_reason,
                    "outcome": r.outcome or {},
                    "created_at": _iso(r.created_at),
                }
            )
        return out

    async def _rows(self, isp: Any, subscriber_id: uuid.UUID) -> list:
        return list(
            (
                await self.session.execute(
                    select(IspQueuedRenewal)
                    .where(
                        IspQueuedRenewal.isp_organization_id == isp.isp_org_id,
                        IspQueuedRenewal.subscriber_id == subscriber_id,
                        IspQueuedRenewal.is_deleted.is_(False),
                    )
                    .order_by(IspQueuedRenewal.created_at.desc())
                )
            )
            .scalars()
            .all()
        )

    async def list_for(self, isp: Any, subscriber_id: uuid.UUID) -> dict:
        s = await self.plans.subscriber(isp, subscriber_id)  # 404 out of scope
        rows = await self._rows(isp, s.id)
        return {
            "subscriber_id": str(s.id),
            "valid_until": _iso(s.valid_until),
            "can_queue": bool(s.valid_until and s.valid_until > self.now())
            and not any(r.status == "pending" for r in rows),
            "items": await self.views(rows),
        }

    async def list_pending(self, isp: Any, page: int, page_size: int) -> dict:
        children = await isp.child_ids()
        rows: list = []
        if children:
            rows = list(
                (
                    await self.session.execute(
                        select(IspQueuedRenewal)
                        .where(
                            IspQueuedRenewal.isp_organization_id == isp.isp_org_id,
                            IspQueuedRenewal.customer_organization_id.in_(children),
                            IspQueuedRenewal.status == "pending",
                            IspQueuedRenewal.is_deleted.is_(False),
                        )
                        .order_by(IspQueuedRenewal.starts_at)
                    )
                )
                .scalars()
                .all()
            )
        # zone scope: only subscribers the caller can read in this request
        if rows:
            seen = set(
                (
                    await self.session.execute(
                        select(IspSubscriber.id).where(
                            IspSubscriber.id.in_([r.subscriber_id for r in rows])
                        )
                    )
                ).scalars()
            )
            rows = [r for r in rows if r.subscriber_id in seen]
        start = (page - 1) * page_size
        return {
            "items": await self.views(rows[start : start + page_size]),
            "total": len(rows),
            "page": page,
            "page_size": page_size,
        }

    async def create(self, isp: Any, subscriber_id: uuid.UUID, data: dict) -> dict:
        s = await self.plans.subscriber(isp, subscriber_id)
        key = data["idempotency_key"]
        prior = (
            await self.session.execute(
                select(IspQueuedRenewal).where(
                    IspQueuedRenewal.isp_organization_id == isp.isp_org_id,
                    IspQueuedRenewal.idempotency_key == key,
                )
            )
        ).scalar_one_or_none()
        if prior is not None:
            if prior.subscriber_id != s.id:
                raise IspBadRequestError(
                    "This idempotency key was used for another subscriber",
                    field="idempotency_key",
                )
            return {"queued": (await self.views([prior]))[0], "repeat": True}
        await self.session.execute(
            select(IspSubscriber.id).where(IspSubscriber.id == s.id).with_for_update()
        )
        await self.session.refresh(s)
        now = self.now()
        if s.valid_until is None or s.valid_until <= now:
            raise IspQueuedRenewalStateError(
                "The current plan has already ended: renew instead, it starts now"
            )
        if any(r.status == "pending" for r in await self._rows(isp, s.id)):
            raise IspQueuedRenewalStateError(
                "A next plan is already queued; cancel it first"
            )
        package = await self.plans.package(isp, data["package_id"])
        prev_package, prev_speed = s.package_id, s.speed_group_id
        starts = s.valid_until
        result = await self.s360.renew(
            isp,
            s.id,
            {
                "package_id": package.id,
                "cycles": data.get("cycles") or 1,
                "paid_now": bool(data.get("paid_now")),
                "payment": data.get("payment"),
                "po_number": data.get("po_number"),
                "idempotency_key": key,
            },
        )
        # the only change against a plain renew: today's plan keeps running
        s.package_id, s.speed_group_id = prev_package, prev_speed
        await self.session.flush()
        event = (
            await self.session.execute(
                select(IspSubscriberEvent)
                .where(
                    IspSubscriberEvent.subscriber_id == s.id,
                    IspSubscriberEvent.kind == "renewed",
                    IspSubscriberEvent.detail["idempotency_key"].astext == key,
                )
                .order_by(IspSubscriberEvent.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        inv = result.get("invoice") or {}
        q = IspQueuedRenewal(
            isp_organization_id=isp.isp_org_id,
            customer_organization_id=s.customer_organization_id,
            subscriber_id=s.id,
            package_id=package.id,
            speed_group_id=package.speed_group_id,
            previous_package_id=prev_package,
            cycles=int(data.get("cycles") or 1),
            invoice_id=uuid.UUID(inv["id"]) if inv.get("id") else None,
            renewal_event_id=event.id if event else None,
            starts_at=starts,
            ends_at=s.valid_until,
            status="pending",
            idempotency_key=key,
            created_by=isp.user_id,
        )
        self.session.add(q)
        await self.session.flush()
        await self.s360.event(
            isp,
            s,
            "queued_renewal",
            f"{package.name} queued from {starts.date().isoformat()}",
            queued_renewal_id=q.id,
            package_id=package.id,
            starts_at=starts,
            ends_at=q.ends_at,
            invoice_number=inv.get("number"),
        )
        await self._audit(
            isp,
            "isp_queued_renewal_created",
            q.id,
            s.customer_organization_id,
            subscriber_id=s.id,
            package_id=package.id,
            invoice=inv.get("number"),
        )
        return {
            "queued": (await self.views([q]))[0],
            "invoice": result.get("invoice"),
            "payment": result.get("payment"),
            "repeat": False,
        }

    async def cancel(
        self,
        isp: Any,
        subscriber_id: uuid.UUID,
        queue_id: uuid.UUID,
        *,
        reason: str,
        may_void_payments: bool,
    ) -> dict:
        from .billing_models import IspPayment, IspPaymentAllocation
        from .exceptions import IspRoleRequiredError

        s = await self.plans.subscriber(isp, subscriber_id)
        q = await self.session.get(IspQueuedRenewal, queue_id)
        if (
            q is None
            or q.is_deleted
            or q.isp_organization_id != isp.isp_org_id
            or q.subscriber_id != s.id
        ):
            raise IspQueuedRenewalNotFoundError()
        await self.session.execute(
            select(IspSubscriber.id).where(IspSubscriber.id == s.id).with_for_update()
        )
        if q.status != "pending":
            raise IspQueuedRenewalStateError(f"It is already {q.status}")
        last = await self.s360._last_renewal(s)
        if last is None or last.id != q.renewal_event_id:
            raise IspQueuedRenewalStateError(
                "A later renewal exists: revert that one first"
            )
        billing = self.plans._billing()
        voided: list[str] = []
        if q.invoice_id is not None:
            inv = await billing._invoice(isp, q.invoice_id)
            if inv.paid_paise > 0:
                if not may_void_payments:
                    raise IspRoleRequiredError(
                        "This bill is paid: cancelling voids its receipt, which "
                        "needs isp_billing.manage"
                    )
                pays = (
                    (
                        await self.session.execute(
                            select(IspPayment)
                            .join(
                                IspPaymentAllocation,
                                IspPaymentAllocation.payment_id == IspPayment.id,
                            )
                            .where(
                                IspPaymentAllocation.invoice_id == inv.id,
                                IspPaymentAllocation.is_deleted.is_(False),
                                IspPayment.status == "confirmed",
                            )
                        )
                    )
                    .scalars()
                    .unique()
                    .all()
                )
                for p in pays:
                    other = (
                        await self.session.execute(
                            select(IspPaymentAllocation.id).where(
                                IspPaymentAllocation.payment_id == p.id,
                                IspPaymentAllocation.invoice_id != inv.id,
                                IspPaymentAllocation.is_deleted.is_(False),
                            )
                        )
                    ).first()
                    if other is not None:
                        raise IspQueuedRenewalStateError(
                            f"Receipt {p.receipt_number} also paid other bills; "
                            "reverse it from Billing first"
                        )
                for p in pays:
                    await billing.void_payment(
                        isp, p.id, reason=f"Queued renewal cancelled: {reason}"
                    )
                    voided.append(p.receipt_number)
        r = await self.s360.revert(
            isp, s.id, reason=f"Queued renewal cancelled: {reason}"
        )
        q.status = "cancelled"
        q.cancelled_at = self.now()
        q.cancel_reason = reason
        q.outcome = {
            "credit_note_number": r.get("credit_note_number"),
            "voided_receipts": voided,
        }
        q.updated_by = isp.user_id
        await self.session.flush()
        await self._audit(
            isp,
            "isp_queued_renewal_cancelled",
            q.id,
            s.customer_organization_id,
            subscriber_id=s.id,
            credit_note=r.get("credit_note_number"),
            voided_receipts=voided,
        )
        return {
            "queued": (await self.views([q]))[0],
            "valid_until": r.get("valid_until"),
            "credit_note_number": r.get("credit_note_number"),
            "voided_receipts": voided,
        }


async def run_queued_renewals(session: Any, *, now: datetime | None = None) -> dict:
    """Switch the plan of every pending queued renewal whose start time has
    passed. Safe to run any number of times."""
    out = {"activated": 0, "cancelled": 0, "errors": 0}
    if not get_queued_renewal_settings().queued_renewal_enabled:
        return out
    now = now or datetime.now(UTC)
    rows = (
        (
            await session.execute(
                select(IspQueuedRenewal)
                .where(
                    IspQueuedRenewal.status == "pending",
                    IspQueuedRenewal.starts_at <= now,
                    IspQueuedRenewal.is_deleted.is_(False),
                )
                .order_by(IspQueuedRenewal.starts_at)
                .limit(500)
                .with_for_update(skip_locked=True)
            )
        )
        .scalars()
        .all()
    )
    for q in rows:
        try:
            async with session.begin_nested():
                s = await session.get(IspSubscriber, q.subscriber_id)
                ev = (
                    await session.get(IspSubscriberEvent, q.renewal_event_id)
                    if q.renewal_event_id
                    else None
                )
                if (
                    s is None
                    or s.is_deleted
                    or (ev and (ev.detail or {}).get("reverted"))
                ):
                    q.status, q.cancelled_at = "cancelled", now
                    q.cancel_reason = (
                        "Reverted from the subscriber page"
                        if s is not None and not s.is_deleted
                        else "Subscriber removed"
                    )
                    out["cancelled"] += 1
                    continue
                s.package_id, s.speed_group_id = q.package_id, q.speed_group_id
                if s.status == "expired" and s.valid_until and s.valid_until > now:
                    s.status = "active"
                q.status, q.activated_at = "active", now
                session.add(
                    IspSubscriberEvent(
                        isp_organization_id=q.isp_organization_id,
                        subscriber_id=s.id,
                        kind="queued_started",
                        summary="Queued plan started",
                        detail={
                            "queued_renewal_id": str(q.id),
                            "package_id": str(q.package_id),
                        },
                    )
                )
                await session.flush()
                out["activated"] += 1
        except Exception:  # noqa: BLE001 -- one row never blocks the rest
            out["errors"] += 1
            logger.exception("isp_queued_renewal_failed", extra={"queue": str(q.id)})
    return out


__all__ = ["IspQueuedRenewalService", "run_queued_renewals"]
