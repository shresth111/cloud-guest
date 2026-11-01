"""FRANCHISE-2 routes. ``ISP_FRANCHISE_ENABLED`` (default OFF): every route
answers 404 ``ISP_FRANCHISE_DISABLED`` while off. Top-up / reduce / credit
limit stay JAZE-4's ``/isp/finance/zones/{zone_id}/entries``; this adds the
share plan, the wallet overview with PAID/UNPAID, the revenue drill-down,
recurring charges and settlements. Zones never get logins (D6).
"""

from __future__ import annotations

import io
import uuid
from datetime import UTC, date, datetime, time, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session

from . import franchise_service as fs
from .constants import ISP_ZONES_MANAGE, ISP_ZONES_READ
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import IspBadRequestError, IspZoneNotFoundError, _err
from .http import ok

IST = ZoneInfo("Asia/Kolkata")

IspFranchiseDisabledError = _err(
    "IspFranchiseDisabledError", "ISP_FRANCHISE_DISABLED", 404, "Not Found"
)


async def RequireFranchiseEnabled() -> None:
    if not fs.get_franchise_settings().franchise_enabled:
        raise IspFranchiseDisabledError()


franchise_router = APIRouter(prefix="/franchise", tags=["ISP Partner: franchise zones"])
_ON = [Depends(RequireFranchiseEnabled)]


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class SharePlanRequest(_Body):
    mode: str = Field(pattern="^(percent|wholesale)$")
    wholesale_paise: int = Field(default=0, ge=0, le=10_000_000_00)
    auto_debit: bool = True


class ChargeRequest(_Body):
    name: str = Field(min_length=1, max_length=120)
    amount_paise: int = Field(gt=0, le=10_000_000_00)
    day_of_month: int = Field(ge=1, le=28)
    starts_on: date
    active: bool = True


class ChargePatch(_Body):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    amount_paise: int | None = Field(default=None, gt=0, le=10_000_000_00)
    day_of_month: int | None = Field(default=None, ge=1, le=28)
    active: bool | None = None


class SettlementRequest(_Body):
    date_from: date
    date_to: date


def _iso(v: Any) -> str | None:
    return v.isoformat() if v else None


async def _zone(db: AsyncSession, isp: IspContext, zone_id: uuid.UUID) -> Any:
    from .billing_models import IspZone

    z = await db.get(IspZone, zone_id)
    if z is None or z.is_deleted or z.isp_organization_id != isp.isp_org_id:
        raise IspZoneNotFoundError()
    return z


async def _plan(db: AsyncSession, zone_id: uuid.UUID) -> Any:
    return await db.run_sync(lambda s: fs._plan(s, zone_id))


def _plan_view(p: Any) -> dict | None:
    if p is None:
        return None
    return {
        "mode": p.mode,
        "wholesale_paise": p.wholesale_paise,
        "auto_debit": p.auto_debit,
        "below_min_since": _iso(p.below_min_since),
        "alerted_at": _iso(p.alerted_at),
    }


def _day_bounds(d0: date, d1: date) -> tuple[datetime, datetime]:
    if d1 < d0 or (d1 - d0).days > 400:
        raise IspBadRequestError("Range must be 1 to 401 days, start before end")
    return (
        datetime.combine(d0, time.min, tzinfo=IST).astimezone(UTC),
        datetime.combine(d1 + timedelta(days=1), time.min, tzinfo=IST).astimezone(UTC),
    )


# --------------------------------------------------------------------------
# wallet overview + share plan
# --------------------------------------------------------------------------


@franchise_router.get("/zones", dependencies=_ON + isp_guards(ISP_ZONES_READ))
async def wallets(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    from .finance_service import IspFinanceService
    from .franchise_models import IspZoneAutoDebit as A

    fin = IspFinanceService(session=db)
    items = []
    for z in await fin.list_zone_ledgers(isp):
        zid = uuid.UUID(z["zone_id"])
        plan = await _plan(db, zid)
        debited = (
            await db.execute(
                select(A.kind, func.coalesce(func.sum(A.amount_paise), 0))
                .where(A.zone_id == zid)
                .group_by(A.kind)
            )
        ).all()
        sums = dict(debited)
        items.append(
            {
                **z,
                "standing": fs.standing(z["balance_paise"], z["min_balance_paise"]),
                "below_minimum": z["balance_paise"] < z["min_balance_paise"],
                "share_plan": _plan_view(plan),
                "auto_debited_paise": int(sums.get("debit", 0)),
                "auto_reversed_paise": int(sums.get("reversal", 0)),
            }
        )
    st = fs.get_franchise_settings()
    return ok(
        request,
        {
            "items": items,
            "auto_debit_enabled": st.zone_autodebit_enabled,
            "enforce_credit": st.zone_enforce_credit,
            "rules": (
                "Each renewal invoice of a subscriber in a zone with a share plan "
                "debits the ISP's share from the zone wallet once; a credit note or "
                "cancellation reverses it. A low balance never blocks a renewal "
                "unless enforcing the credit limit is switched on."
            ),
        },
        "Zone wallets",
    )


@franchise_router.put(
    "/zones/{zone_id}/share", dependencies=_ON + isp_guards(ISP_ZONES_MANAGE)
)
async def put_share(
    request: Request,
    zone_id: uuid.UUID,
    body: SharePlanRequest,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    from .franchise_models import IspZoneSharePlan

    z = await _zone(db, isp, zone_id)
    if body.mode == "wholesale" and body.wholesale_paise <= 0:
        raise IspBadRequestError(
            "A wholesale plan needs a rate", field="wholesale_paise"
        )
    p = await _plan(db, z.id)
    if p is None:
        p = IspZoneSharePlan(
            isp_organization_id=isp.isp_org_id,
            zone_id=z.id,
            created_by=isp.user_id,
            mode=body.mode,
        )
        db.add(p)
    p.mode, p.wholesale_paise, p.auto_debit = (
        body.mode,
        body.wholesale_paise,
        body.auto_debit,
    )
    p.updated_by = isp.user_id
    await db.flush()
    view = _plan_view(p)
    await db.commit()
    return ok(request, view, "Share plan saved")


# --------------------------------------------------------------------------
# revenue drill-down
# --------------------------------------------------------------------------


@franchise_router.get(
    "/zones/{zone_id}/revenue", dependencies=_ON + isp_guards(ISP_ZONES_READ)
)
async def zone_revenue(
    request: Request,
    zone_id: uuid.UUID,
    date_from: date = Query(),
    date_to: date = Query(),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    from .billing_models import IspInvoice
    from .franchise_models import IspZoneAutoDebit as A
    from .plans_models import IspSubscriber

    z = await _zone(db, isp, zone_id)
    _day_bounds(date_from, date_to)
    children = await isp.child_ids()
    plan = await _plan(db, z.id)
    prof = await db.run_sync(lambda s: fs._profile(s, z.id))
    bp = prof.revenue_share_bp if prof else 0
    rows = (
        await db.execute(
            select(IspInvoice, IspSubscriber.identifier, IspSubscriber.circuit_id)
            .outerjoin(IspSubscriber, IspSubscriber.id == IspInvoice.subscriber_id)
            .where(
                IspInvoice.isp_organization_id == isp.isp_org_id,
                IspInvoice.zone_id == z.id,
                IspInvoice.doc_type == "invoice",
                IspInvoice.is_deleted.is_(False),
                IspInvoice.customer_organization_id.in_(children or [uuid.UUID(int=0)]),
                IspInvoice.issue_date >= date_from,
                IspInvoice.issue_date <= date_to,
            )
            .order_by(IspInvoice.issue_date, IspInvoice.number)
        )
    ).all()
    ids = [i.id for i, *_ in rows]
    auto: dict[tuple, int] = {}
    if ids:
        for inv_id, kind, amt in (
            await db.execute(
                select(A.invoice_id, A.kind, func.sum(A.amount_paise))
                .where(A.invoice_id.in_(ids))
                .group_by(A.invoice_id, A.kind)
            )
        ).all():
            auto[(inv_id, kind)] = int(amt)
    items = []
    tot = {
        "invoiced": 0,
        "collected": 0,
        "zone_share": 0,
        "isp_share": 0,
        "auto_net": 0,
    }
    for inv, ident, circuit in rows:
        if inv.status == "cancelled":
            continue
        share = fs.isp_share(
            plan.mode if plan else "percent",
            total_paise=inv.total_paise,
            zone_share_bp=bp,
            wholesale_paise=plan.wholesale_paise if plan else 0,
        )
        deb, rev = auto.get((inv.id, "debit"), 0), auto.get((inv.id, "reversal"), 0)
        items.append(
            {
                "invoice_id": str(inv.id),
                "number": inv.number,
                "issue_date": inv.issue_date.isoformat(),
                "subscriber": ident,
                "circuit_id": circuit,
                "invoice_kind": inv.invoice_kind,
                "total_paise": inv.total_paise,
                "paid_paise": inv.paid_paise,
                "credit_noted_paise": inv.credit_noted_paise,
                "isp_share_paise": share,
                "zone_share_paise": inv.total_paise - share,
                "auto_debit_paise": deb,
                "auto_reversed_paise": rev,
            }
        )
        tot["invoiced"] += inv.total_paise
        tot["collected"] += inv.paid_paise
        tot["isp_share"] += share
        tot["zone_share"] += inv.total_paise - share
        tot["auto_net"] += deb - rev
    return ok(
        request,
        {
            "zone_id": str(z.id),
            "name": z.name,
            "mode": plan.mode if plan else None,
            "revenue_share_bp": bp,
            "totals": {f"{k}_paise": v for k, v in tot.items()},
            "items": items,
        },
        "Zone revenue",
    )


# --------------------------------------------------------------------------
# recurring charges
# --------------------------------------------------------------------------


def _charge_view(c: Any) -> dict:
    return {
        "id": str(c.id),
        "zone_id": str(c.zone_id),
        "name": c.name,
        "amount_paise": c.amount_paise,
        "day_of_month": c.day_of_month,
        "starts_on": c.starts_on.isoformat(),
        "active": c.active,
        "last_period": c.last_period,
    }


@franchise_router.get(
    "/zones/{zone_id}/charges", dependencies=_ON + isp_guards(ISP_ZONES_READ)
)
async def list_charges(
    request: Request,
    zone_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    from .franchise_models import IspZoneCharge

    z = await _zone(db, isp, zone_id)
    rows = (
        await db.execute(
            select(IspZoneCharge)
            .where(IspZoneCharge.zone_id == z.id, IspZoneCharge.is_deleted.is_(False))
            .order_by(IspZoneCharge.created_at)
        )
    ).scalars()
    return ok(request, [_charge_view(c) for c in rows], "Zone charges")


@franchise_router.post(
    "/zones/{zone_id}/charges",
    status_code=201,
    dependencies=_ON + isp_guards(ISP_ZONES_MANAGE),
)
async def add_charge(
    request: Request,
    zone_id: uuid.UUID,
    body: ChargeRequest,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    from .franchise_models import IspZoneCharge

    z = await _zone(db, isp, zone_id)
    c = IspZoneCharge(
        isp_organization_id=isp.isp_org_id,
        zone_id=z.id,
        created_by=isp.user_id,
        **body.model_dump(),
    )
    db.add(c)
    await db.flush()
    view = _charge_view(c)
    await db.commit()
    return ok(request, view, "Charge added")


@franchise_router.patch(
    "/charges/{charge_id}", dependencies=_ON + isp_guards(ISP_ZONES_MANAGE)
)
async def patch_charge(
    request: Request,
    charge_id: uuid.UUID,
    body: ChargePatch,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    from .franchise_models import IspZoneCharge

    c = await db.get(IspZoneCharge, charge_id)
    if c is None or c.is_deleted or c.isp_organization_id != isp.isp_org_id:
        raise IspZoneNotFoundError("Charge not found")
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(c, k, v)
    c.updated_by = isp.user_id
    await db.flush()
    view = _charge_view(c)
    await db.commit()
    return ok(request, view, "Charge saved")


@franchise_router.post("/charges/run", dependencies=_ON + isp_guards(ISP_ZONES_MANAGE))
async def run_charges(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    """Charge what is due today now (the daily sweep does the same)."""
    out = await fs.run_franchise_daily(db, isp, datetime.now(IST).date())
    await db.commit()
    return ok(request, out, "Due charges run")


# --------------------------------------------------------------------------
# settlements
# --------------------------------------------------------------------------


def _settlement_view(s: Any, zone_name: str | None = None, invoice: Any = None) -> dict:
    from .zone_invoices import invoice_brief

    return {
        # FINISH: the GST tax invoice issued for this settlement (or None:
        # nothing billed, billing not set up, or a settlement from before
        # 0188 not invoiced yet -- POST .../invoice issues it).
        "invoice": invoice_brief(invoice),
        "invoice_id": str(s.invoice_id) if getattr(s, "invoice_id", None) else None,
        "id": str(s.id),
        "zone_id": str(s.zone_id),
        "zone_name": zone_name,
        "number": s.number,
        "period_from": s.period_from.isoformat(),
        "period_to": s.period_to.isoformat(),
        "opening_paise": s.opening_paise,
        "debits_paise": s.debits_paise,
        "credits_paise": s.credits_paise,
        "closing_paise": s.closing_paise,
        "billed_paise": s.billed_paise,
        "taxable_paise": s.taxable_paise,
        "cgst_paise": s.cgst_paise,
        "sgst_paise": s.sgst_paise,
        "igst_paise": s.igst_paise,
        "lines": s.lines,
        "issued_at": _iso(s.created_at),
    }


@franchise_router.post(
    "/zones/{zone_id}/settlements",
    status_code=201,
    dependencies=_ON + isp_guards(ISP_ZONES_MANAGE),
)
async def create_settlement(
    request: Request,
    zone_id: uuid.UUID,
    body: SettlementRequest,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    """A numbered settlement from the zone ledger for the period. What is
    billed is the ISP's share of renewals plus zone charges (the ledger's
    automatic debits net of reversals); GST is split from it when the ISP
    bills GST, by the zone's state against the ISP's."""
    from .billing_models import IspBillingSettings
    from .finance_models import IspZoneLedgerEntry as E
    from .franchise_models import IspZoneSettlement
    from .gst import fiscal_year

    z = await _zone(db, isp, zone_id)
    start, end = _day_bounds(body.date_from, body.date_to)
    await db.run_sync(lambda s: fs._lock(s, z.id))
    opening = int(
        (
            await db.execute(
                select(func.coalesce(func.sum(E.amount_paise), 0)).where(
                    E.zone_id == z.id, E.is_deleted.is_(False), E.occurred_at < start
                )
            )
        ).scalar_one()
    )
    entries = list(
        (
            await db.execute(
                select(E)
                .where(
                    E.zone_id == z.id,
                    E.is_deleted.is_(False),
                    E.occurred_at >= start,
                    E.occurred_at < end,
                )
                .order_by(E.occurred_at, E.created_at)
            )
        ).scalars()
    )
    debits = -sum(e.amount_paise for e in entries if e.amount_paise < 0)
    credits = sum(e.amount_paise for e in entries if e.amount_paise > 0)
    auto = {"renewal_debit", "zone_charge"}
    billed = -sum(
        e.amount_paise
        for e in entries
        if (e.detail or {}).get("auto") in auto and e.amount_paise < 0
    ) - sum(
        e.amount_paise
        for e in entries
        if (e.detail or {}).get("auto") == "renewal_reversal"
    )
    billed = max(0, billed)
    settings = (
        await db.execute(
            select(IspBillingSettings).where(
                IspBillingSettings.isp_organization_id == isp.isp_org_id
            )
        )
    ).scalar_one_or_none()
    taxable, cgst, sgst, igst = billed, 0, 0, 0
    if settings is not None and settings.gst_enabled and billed:
        # The billed amount is taken as tax-inclusive (it came out of the
        # subscriber totals), so tax is split out of it.
        rate = int(settings.gst_rate_bp)
        taxable = (billed * 10000) // (10000 + rate)
        tax = billed - taxable
        if (z.state_code or settings.state_code) == settings.state_code:
            cgst = tax // 2
            sgst = tax - cgst
        else:
            igst = tax
    fy = fiscal_year(body.date_to)
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:k))"),
        {"k": f"isp_zone_settlement:{isp.isp_org_id}:{fy}"},
    )
    seq = 1 + int(
        (
            await db.execute(
                select(func.coalesce(func.max(IspZoneSettlement.seq), 0)).where(
                    IspZoneSettlement.isp_organization_id == isp.isp_org_id,
                    IspZoneSettlement.fy == fy,
                )
            )
        ).scalar_one()
    )
    s = IspZoneSettlement(
        isp_organization_id=isp.isp_org_id,
        zone_id=z.id,
        number=f"ZS/{fy}/{seq:04d}",
        seq=seq,
        fy=fy,
        period_from=body.date_from,
        period_to=body.date_to,
        opening_paise=opening,
        debits_paise=debits,
        credits_paise=credits,
        closing_paise=opening - debits + credits,
        billed_paise=billed,
        taxable_paise=taxable,
        cgst_paise=cgst,
        sgst_paise=sgst,
        igst_paise=igst,
        lines=[
            {
                "at": e.occurred_at.isoformat(),
                "kind": e.entry_kind,
                "amount_paise": e.amount_paise,
                "reference": e.reference,
                "note": e.note,
                "auto": (e.detail or {}).get("auto"),
            }
            for e in entries
        ],
        snapshot={
            "zone_name": z.name,
            "zone_state_code": z.state_code,
            "seller": getattr(settings, "legal_name", None),
            "seller_state_code": getattr(settings, "state_code", None),
            "gst_rate_bp": getattr(settings, "gst_rate_bp", None) if settings else None,
        },
        created_by=isp.user_id,
    )
    db.add(s)
    await db.flush()
    inv = await _settlement_invoice(db, isp, s, required=False)
    if inv is not None:  # the settlement shows the invoice's own tax split
        s.taxable_paise, s.cgst_paise = inv.taxable_paise, inv.cgst_paise
        s.sgst_paise, s.igst_paise = inv.sgst_paise, inv.igst_paise
        await db.flush()
    view = _settlement_view(s, z.name, inv)
    await db.commit()
    return ok(request, view, "Settlement issued")


async def _settlement_invoice(
    db: AsyncSession, isp: IspContext, s: Any, *, required: bool
) -> Any:
    """FINISH: the settlement's tax invoice through the regular engine. With
    ``required=False`` (on create) a missing billing setup leaves the
    settlement un-invoiced, exactly as before 0188."""
    from .billing_service import IspBillingService
    from .exceptions import IspBillingNotConfiguredError
    from .zone_invoices import invoice_for_settlement

    billing = IspBillingService(session=db)
    if not required and await billing.settings(isp, required=False) is None:
        return None
    try:
        return await invoice_for_settlement(billing, isp, s)
    except IspBillingNotConfiguredError:
        if required:
            raise
        return None


@franchise_router.post(
    "/settlements/{settlement_id}/invoice",
    dependencies=_ON + isp_guards(ISP_ZONES_MANAGE),
)
async def invoice_settlement(
    request: Request,
    settlement_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    """FINISH: issue (once) the GST tax invoice for a settlement -- the path
    for ZS settlements issued before 0188. Idempotent."""
    from .franchise_models import IspZoneSettlement

    s = await db.get(IspZoneSettlement, settlement_id)
    if s is None or s.is_deleted or s.isp_organization_id != isp.isp_org_id:
        raise IspZoneNotFoundError("Settlement not found")
    z = await _zone(db, isp, s.zone_id)
    await db.run_sync(lambda ss: fs._lock(ss, z.id))
    inv = await _settlement_invoice(db, isp, s, required=True)
    view = _settlement_view(s, z.name, inv)
    await db.commit()
    return ok(request, view, "Settlement invoiced" if inv else "Nothing billed")


@franchise_router.get(
    "/zones/{zone_id}/settlements", dependencies=_ON + isp_guards(ISP_ZONES_READ)
)
async def list_settlements(
    request: Request,
    zone_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    from .franchise_models import IspZoneSettlement

    z = await _zone(db, isp, zone_id)
    rows = (
        await db.execute(
            select(IspZoneSettlement)
            .where(
                IspZoneSettlement.zone_id == z.id,
                IspZoneSettlement.is_deleted.is_(False),
            )
            .order_by(IspZoneSettlement.created_at.desc())
        )
    ).scalars()
    rows = list(rows)
    from .billing_models import IspInvoice

    inv_ids = [s.invoice_id for s in rows if s.invoice_id]
    invs = (
        {
            i.id: i
            for i in (
                await db.execute(select(IspInvoice).where(IspInvoice.id.in_(inv_ids)))
            ).scalars()
        }
        if inv_ids
        else {}
    )
    return ok(
        request,
        [_settlement_view(s, z.name, invs.get(s.invoice_id)) for s in rows],
        "Settlements",
    )


@franchise_router.get(
    "/settlements/{settlement_id}/pdf", dependencies=_ON + isp_guards(ISP_ZONES_READ)
)
async def settlement_pdf(
    settlement_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> Response:
    from xml.sax.saxutils import escape

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    from .franchise_models import IspZoneSettlement

    s = await db.get(IspZoneSettlement, settlement_id)
    if s is None or s.is_deleted or s.isp_organization_id != isp.isp_org_id:
        raise IspZoneNotFoundError("Settlement not found")
    rs = lambda p: f"Rs {p / 100:,.2f}"  # noqa: E731
    st = getSampleStyleSheet()
    small = st["BodyText"].clone("small", fontSize=8, leading=10)
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=1.5 * cm, rightMargin=1.5 * cm)
    snap = s.snapshot or {}
    story: list[Any] = [
        Paragraph(f"Settlement {escape(s.number)}", st["Title"]),
        Paragraph(
            escape(
                f"{snap.get('seller') or ''} to zone {snap.get('zone_name') or ''} · "
                f"{s.period_from.isoformat()} to {s.period_to.isoformat()}"
            ),
            st["BodyText"],
        ),
        Spacer(1, 6),
    ]
    summary = [
        ["Opening balance", rs(s.opening_paise)],
        ["Debits", rs(s.debits_paise)],
        ["Credits (top-ups, reversals)", rs(s.credits_paise)],
        ["Closing balance", rs(s.closing_paise)],
        ["ISP share billed (renewals + charges)", rs(s.billed_paise)],
        ["Taxable value", rs(s.taxable_paise)],
        [
            "CGST / SGST / IGST",
            f"{rs(s.cgst_paise)} / {rs(s.sgst_paise)} / {rs(s.igst_paise)}",
        ],
    ]
    t = Table(summary, colWidths=[9 * cm, 6 * cm])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.grey)]))
    story += [t, Spacer(1, 8), Paragraph("Ledger entries", st["Heading3"])]
    data = [["Date", "Entry", "Amount", "Reference / note"]] + [
        [
            Paragraph(escape(line["at"][:10]), small),
            Paragraph(escape(line.get("auto") or line["kind"]), small),
            Paragraph(escape(rs(line["amount_paise"])), small),
            Paragraph(
                escape(f"{line.get('reference') or ''} {line.get('note') or ''}"), small
            ),
        ]
        for line in s.lines
    ]
    lt = Table(data, colWidths=[2.5 * cm, 3.5 * cm, 3 * cm, 9 * cm], repeatRows=1)
    lt.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
            ]
        )
    )
    story.append(lt)
    doc.build(story)
    return Response(
        content=buf.getvalue(),
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{s.number.replace("/", "-")}.pdf"'
            ),
            "Cache-Control": "no-store",
        },
    )


__all__ = ["franchise_router"]
