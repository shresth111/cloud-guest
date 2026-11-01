"""FRANCHISE-2 (ADDENDUM_06; founder YES 2026-11-01, LANE_NOTES [COORD]).

Flags (all default OFF):
* ``ISP_FRANCHISE_ENABLED``: the ``/isp/franchise/*`` routes.
* ``ISP_ZONE_AUTODEBIT_ENABLED``: renewal auto-debit / reversal.
* ``ISP_ZONE_ENFORCE_CREDIT``: an auto-debit that would take the zone below
  its credit limit blocks the renewal (409). Off = never blocks.

**Auto-debit.** A ``before_flush`` listener watches new subscriber invoices
(and credit notes / cancellations of them) that carry a ``zone_id`` whose
zone has a share plan. It is the one place every renewal path passes
through (JAZE-1 renew, recharge, coupon/billing runs), so no renewal code is
edited. For each:
* invoice -> ``debit``: percent (invoice total x (1 - the zone's JAZE-4
  ``revenue_share_bp``)) or the plan's wholesale amount, as a JAZE-4 ledger
  ``reduce`` entry (reference = invoice number);
* credit note against it -> ``reversal`` of the same share of the debit as
  the note is of the invoice (an ``add`` entry); a cancellation reverses
  up to the share of the bill's UNPAID part (founder 2026-11-01), never the
  share of what was paid.
``isp_zone_autodebits`` is unique per (document, kind): a retried request
never debits twice. The zone row is locked like JAZE-4 ``_lock_zone``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime
from functools import lru_cache
from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import event, func, select
from sqlalchemy.orm import Session


class IspFranchiseSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="ISP_", case_sensitive=False, extra="ignore"
    )

    franchise_enabled: bool = Field(default=False)
    zone_autodebit_enabled: bool = Field(default=False)
    zone_enforce_credit: bool = Field(default=False)


@lru_cache(maxsize=1)
def get_franchise_settings() -> IspFranchiseSettings:
    return IspFranchiseSettings()


# --------------------------------------------------------------------------
# pure maths
# --------------------------------------------------------------------------


def isp_share(
    mode: str, *, total_paise: int, zone_share_bp: int, wholesale_paise: int
) -> int:
    """What the zone owes the ISP for one renewal invoice."""
    if mode == "wholesale":
        return max(0, int(wholesale_paise))
    bp = min(10000, max(0, int(zone_share_bp)))
    return max(0, (int(total_paise) * (10000 - bp)) // 10000)


def reversal_amount(
    debit_paise: int,
    *,
    note_paise: int,
    invoice_total_paise: int,
    already_reversed: int,
) -> int:
    """The share of a debit that a credit note gives back, capped at what
    is still unreversed."""
    if invoice_total_paise <= 0 or debit_paise <= 0:
        return 0
    want = (int(debit_paise) * int(note_paise)) // int(invoice_total_paise)
    return max(0, min(want, int(debit_paise) - int(already_reversed)))


def cancel_reversal_target(
    debit_paise: int, *, invoice_total_paise: int, paid_paise: int
) -> int:
    """How much of a debit a CANCELLED bill gives back in total: the share of
    its unpaid part (founder 2026-11-01). Share 30 %, a Rs 1,000 bill with
    Rs 400 paid: debit 300, target 300 x 600 / 1000 = 180; 120 stays."""
    if invoice_total_paise <= 0 or debit_paise <= 0:
        return 0
    unpaid = max(0, int(invoice_total_paise) - max(0, int(paid_paise)))
    return min(
        int(debit_paise), (int(debit_paise) * unpaid) // int(invoice_total_paise)
    )


def standing(balance: int, min_balance: int) -> str:
    """JAZE-4's own rule: PAID at or above the minimum, else UNPAID."""
    return "paid" if balance >= min_balance else "unpaid"


def due_period(
    today: date, day_of_month: int, starts_on: date, last_period: str | None
) -> str | None:
    """The "YYYY-MM" to charge today, or None."""
    if today < starts_on or today.day < day_of_month:
        return None
    period = today.strftime("%Y-%m")
    return None if last_period == period else period


# --------------------------------------------------------------------------
# the auto-debit hook (sync: runs inside Session.flush)
# --------------------------------------------------------------------------


def _balance(session: Session, zone_id: uuid.UUID) -> int:
    from .finance_models import IspZoneLedgerEntry as E

    return int(
        session.execute(
            select(func.coalesce(func.sum(E.amount_paise), 0)).where(
                E.zone_id == zone_id, E.is_deleted.is_(False)
            )
        ).scalar_one()
    )


def _lock(session: Session, zone_id: uuid.UUID) -> None:
    from .billing_models import IspZone

    session.execute(select(IspZone.id).where(IspZone.id == zone_id).with_for_update())


def _plan(session: Session, zone_id: uuid.UUID) -> Any:
    from .franchise_models import IspZoneSharePlan

    return session.execute(
        select(IspZoneSharePlan).where(
            IspZoneSharePlan.zone_id == zone_id, IspZoneSharePlan.is_deleted.is_(False)
        )
    ).scalar_one_or_none()


def _profile(session: Session, zone_id: uuid.UUID) -> Any:
    from .finance_models import IspZoneProfile

    return session.execute(
        select(IspZoneProfile).where(
            IspZoneProfile.zone_id == zone_id, IspZoneProfile.is_deleted.is_(False)
        )
    ).scalar_one_or_none()


def _existing(session: Session, document_id: uuid.UUID, kind: str) -> Any:
    from .franchise_models import IspZoneAutoDebit

    return session.execute(
        select(IspZoneAutoDebit).where(
            IspZoneAutoDebit.document_id == document_id, IspZoneAutoDebit.kind == kind
        )
    ).scalar_one_or_none()


def _post(
    session: Session,
    *,
    isp_org_id: uuid.UUID,
    zone_id: uuid.UUID,
    amount: int,
    kind: str,
    reference: str,
    note: str,
    detail: dict[str, Any],
    actor: uuid.UUID | None,
) -> Any:
    from .finance_models import IspZoneLedgerEntry

    balance = _balance(session, zone_id)
    e = IspZoneLedgerEntry(
        id=uuid.uuid4(),
        isp_organization_id=isp_org_id,
        zone_id=zone_id,
        entry_kind=kind,
        amount_paise=amount,
        balance_after_paise=balance + amount,
        mode="adjustment",
        reference=reference[:100],
        note=note[:255],
        detail=detail,
        occurred_at=datetime.now(UTC),
        created_by=actor,
    )
    session.add(e)
    return e


def _debit_invoice(session: Session, inv: Any) -> None:
    from .finance_service import IspZoneCreditExceededError
    from .franchise_models import IspZoneAutoDebit

    plan = _plan(session, inv.zone_id)
    if plan is None or not plan.auto_debit:
        return
    if inv.id is None:
        inv.id = uuid.uuid4()
    if _existing(session, inv.id, "debit") is not None:
        return
    prof = _profile(session, inv.zone_id)
    amount = isp_share(
        plan.mode,
        total_paise=inv.total_paise or 0,
        zone_share_bp=prof.revenue_share_bp if prof else 0,
        wholesale_paise=plan.wholesale_paise,
    )
    if amount <= 0:
        return
    _lock(session, inv.zone_id)
    if get_franchise_settings().zone_enforce_credit:
        credit = prof.credit_limit_paise if prof else 0
        balance = _balance(session, inv.zone_id)
        if balance - amount < -credit:
            raise IspZoneCreditExceededError(available_paise=balance + credit)
    e = _post(
        session,
        isp_org_id=inv.isp_organization_id,
        zone_id=inv.zone_id,
        amount=-amount,
        kind="reduce",
        reference=inv.number or "",
        note=f"Auto-debit: ISP share of renewal {inv.number or ''}".strip(),
        detail={"auto": "renewal_debit", "invoice_id": str(inv.id), "mode": plan.mode},
        actor=inv.created_by,
    )
    session.add(
        IspZoneAutoDebit(
            isp_organization_id=inv.isp_organization_id,
            zone_id=inv.zone_id,
            document_id=inv.id,
            invoice_id=inv.id,
            kind="debit",
            amount_paise=amount,
            ledger_entry_id=e.id,
            mode=plan.mode,
        )
    )


def _reversed_so_far(session: Session, invoice_id: uuid.UUID) -> int:
    """Stored reversals plus any added earlier in this same flush (a revert
    writes a credit note AND may cancel the invoice in one transaction)."""
    from .franchise_models import IspZoneAutoDebit as A

    stored = int(
        session.execute(
            select(func.coalesce(func.sum(A.amount_paise), 0)).where(
                A.invoice_id == invoice_id, A.kind == "reversal"
            )
        ).scalar_one()
    )
    pending = sum(
        o.amount_paise
        for o in session.new
        if isinstance(o, A) and o.invoice_id == invoice_id and o.kind == "reversal"
    )
    return stored + pending


def _reverse(
    session: Session, *, document: Any, invoice: Any, debit: Any, amount: int, why: str
) -> None:
    from .franchise_models import IspZoneAutoDebit

    if amount <= 0:
        return
    if document.id is None:
        document.id = uuid.uuid4()
    if _existing(session, document.id, "reversal") is not None:
        return
    _lock(session, debit.zone_id)
    e = _post(
        session,
        isp_org_id=invoice.isp_organization_id,
        zone_id=debit.zone_id,
        amount=amount,
        kind="add",
        reference=(document.number or invoice.number or "")[:100],
        note=f"Auto-debit reversed: {why} {invoice.number or ''}".strip(),
        detail={
            "auto": "renewal_reversal",
            "invoice_id": str(invoice.id),
            "document_id": str(document.id),
        },
        actor=getattr(document, "updated_by", None)
        or getattr(document, "created_by", None),
    )
    session.add(
        IspZoneAutoDebit(
            isp_organization_id=invoice.isp_organization_id,
            zone_id=debit.zone_id,
            document_id=document.id,
            invoice_id=invoice.id,
            kind="reversal",
            amount_paise=amount,
            ledger_entry_id=e.id,
            mode=debit.mode,
        )
    )


@event.listens_for(Session, "before_flush")
def _zone_autodebit(session: Session, _ctx: Any, _instances: Any) -> None:
    if not get_franchise_settings().zone_autodebit_enabled:
        return
    from sqlalchemy import inspect

    from .billing_models import IspInvoice

    new = [o for o in session.new if isinstance(o, IspInvoice)]
    dirty = [o for o in session.dirty if isinstance(o, IspInvoice)]
    if not new and not dirty:
        return
    with session.no_autoflush:
        for inv in new:
            if inv.bill_to_kind != "subscriber":
                continue
            if inv.doc_type == "invoice" and inv.zone_id and inv.status != "cancelled":
                _debit_invoice(session, inv)
            elif inv.doc_type == "credit_note" and inv.credit_note_for_invoice_id:
                orig = session.get(IspInvoice, inv.credit_note_for_invoice_id)
                debit = _existing(session, inv.credit_note_for_invoice_id, "debit")
                if orig is None or debit is None:
                    continue
                _reverse(
                    session,
                    document=inv,
                    invoice=orig,
                    debit=debit,
                    amount=reversal_amount(
                        debit.amount_paise,
                        note_paise=inv.total_paise or 0,
                        invoice_total_paise=orig.total_paise or 0,
                        already_reversed=_reversed_so_far(session, orig.id),
                    ),
                    why="credit note",
                )
        for inv in dirty:
            if inv.doc_type != "invoice" or inv.bill_to_kind != "subscriber":
                continue
            hist = inspect(inv).attrs.status.history
            if "cancelled" not in (hist.added or ()) or inv.status != "cancelled":
                continue
            debit = _existing(session, inv.id, "debit")
            if debit is None:
                continue
            # Founder 2026-11-01 (LANE_NOTES [COORD]): a cancelled bill gives
            # back the zone's share of its UNPAID part only; the share of what
            # was actually paid stays debited. Credit notes already reversed
            # their own proportion, so only the gap up to that target is left.
            left = cancel_reversal_target(
                debit.amount_paise,
                invoice_total_paise=inv.total_paise or 0,
                paid_paise=inv.paid_paise or 0,
            ) - _reversed_so_far(session, inv.id)
            _reverse(
                session,
                document=inv,
                invoice=inv,
                debit=debit,
                amount=left,
                why="cancelled",
            )


# --------------------------------------------------------------------------
# daily: recurring charges + min-balance alerts (async; JAZE-4 daily sweep)
# --------------------------------------------------------------------------


async def run_franchise_daily(session: Any, isp: Any, today: date) -> dict[str, int]:
    """Called from JAZE-4 ``run_finance_daily`` (one line there). Due monthly
    zone charges become ledger ``reduce`` entries (once per charge per
    month); zones whose balance dropped below their minimum get one J14
    Telegram alert per dip."""
    from .finance_models import IspZoneLedgerEntry
    from .franchise_models import IspZoneCharge

    out = {"charges": 0, "alerts": 0}
    if not get_franchise_settings().franchise_enabled:
        return out
    charges = (
        (
            await session.execute(
                select(IspZoneCharge).where(
                    IspZoneCharge.isp_organization_id == isp.isp_org_id,
                    IspZoneCharge.active.is_(True),
                    IspZoneCharge.is_deleted.is_(False),
                )
            )
        )
        .scalars()
        .all()
    )
    for ch in charges:
        period = due_period(today, ch.day_of_month, ch.starts_on, ch.last_period)
        if period is None:
            continue
        await session.run_sync(lambda s, c=ch: _lock(s, c.zone_id))
        bal = await session.run_sync(lambda s, c=ch: _balance(s, c.zone_id))
        session.add(
            IspZoneLedgerEntry(
                isp_organization_id=isp.isp_org_id,
                zone_id=ch.zone_id,
                entry_kind="reduce",
                amount_paise=-int(ch.amount_paise),
                balance_after_paise=bal - int(ch.amount_paise),
                mode="adjustment",
                reference=f"{ch.name} {period}"[:100],
                note=f"Recurring zone charge: {ch.name}"[:255],
                detail={
                    "auto": "zone_charge",
                    "charge_id": str(ch.id),
                    "period": period,
                },
                occurred_at=datetime.now(UTC),
            )
        )
        ch.last_period = period
        out["charges"] += 1
        await session.flush()
    out["alerts"] = await _min_balance_alerts(session, isp)
    return out


async def _min_balance_alerts(session: Any, isp: Any) -> int:
    from .automation import _token, automation_settings, telegram_send
    from .billing_models import IspZone
    from .finance_config import get_finance_settings
    from .franchise_models import IspZoneSharePlan

    plans = (
        await session.execute(
            select(IspZoneSharePlan, IspZone.name)
            .join(IspZone, IspZone.id == IspZoneSharePlan.zone_id)
            .where(
                IspZoneSharePlan.isp_organization_id == isp.isp_org_id,
                IspZoneSharePlan.is_deleted.is_(False),
            )
        )
    ).all()
    if not plans:
        return 0
    st = await automation_settings(session, isp.isp_org_id)
    can_send = bool(
        get_finance_settings().telegram_alerts_enabled
        and st
        and st.telegram_enabled
        and st.telegram_chat_id
        and _token(st)
    )
    sent = 0
    now = datetime.now(UTC)
    for plan, name in plans:
        prof = await session.run_sync(lambda s, p=plan: _profile(s, p.zone_id))
        bal = await session.run_sync(lambda s, p=plan: _balance(s, p.zone_id))
        floor = prof.min_balance_paise if prof else 0
        if bal >= floor:
            plan.below_min_since = None
            plan.alerted_at = None
            continue
        if plan.below_min_since is None:
            plan.below_min_since = now
        if plan.alerted_at is None and can_send:
            err = await telegram_send(
                _token(st),
                st.telegram_chat_id,
                f"Zone wallet low: {name} is at Rs {bal / 100:.2f}, below its "
                f"minimum of Rs {floor / 100:.2f}. Top it up in Finance tools > Zones.",
            )
            if err is None:
                plan.alerted_at = now
                sent += 1
    await session.flush()
    return sent


__all__ = [
    "due_period",
    "get_franchise_settings",
    "isp_share",
    "reversal_amount",
    "run_franchise_daily",
    "standing",
]
