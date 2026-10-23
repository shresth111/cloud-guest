"""ISP billing HTTP surface.

* ``/isp/billing/*`` -- ADDENDUM_01 §B.3 (``isp_billing.*`` keys): settings,
  customer plan, ledger, payments, receipts, suspend-for-dues, CSV exports,
  and the 1b invoice routes, now thin aliases of the unified invoices.
* ``/isp/invoices*`` -- ADDENDUM_03 Part A (``isp_invoices.*`` keys): list,
  detail, PDF, manual, credit notes, bulk, reminders, export, settings,
  reports.
* ``/isp/zones*`` -- ``isp_zones.*``.

Every id resolves through the customer (``IspScope``): another ISP's invoice,
payment or zone is a 404, and confined staff see their customers only.
Static paths are declared before ``/{invoice_id}`` so they are not parsed as
ids.
"""

from __future__ import annotations

import csv
import html
import io
import uuid
import zipfile
from datetime import UTC, date, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Header, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.organization.models import Organization
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .billing_pdf import render_invoice_pdf, render_receipt_pdf
from .billing_service import IspBillingService, balance_of
from .constants import (
    DEFAULT_PAGE_SIZE,
    ISP_BILLING_CREATE,
    ISP_BILLING_EXECUTE,
    ISP_BILLING_EXPORT,
    ISP_BILLING_MANAGE,
    ISP_BILLING_READ,
    ISP_BILLING_UPDATE,
    ISP_INVOICES_CREATE,
    ISP_INVOICES_EXECUTE,
    ISP_INVOICES_EXPORT,
    ISP_INVOICES_MANAGE,
    ISP_INVOICES_READ,
    ISP_ZONES_MANAGE,
    ISP_ZONES_READ,
    MAX_PAGE_SIZE,
)
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import IspBulkTooLargeError, IspNoDuesError
from .http import ok
from .providers import get_service_control
from .service_control import IspServiceControl
from .views import page as make_page

billing_router = APIRouter(tags=["ISP Partner: billing"])

_Page = Query(default=1, ge=1)
_PageSize = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE)


def get_billing_service(
    db: AsyncSession = Depends(get_db_session),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> IspBillingService:
    return IspBillingService(session=db, audit=audit)


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class BillingSettingsRequest(_Body):
    legal_name: str | None = Field(default=None, max_length=255)
    gstin: str | None = Field(default=None, max_length=15)
    state_code: str | None = Field(default=None, pattern=r"^[0-9]{2}$")
    address: str | None = None
    invoice_prefix: str | None = Field(default=None, max_length=12)
    credit_note_prefix: str | None = Field(default=None, max_length=12)
    receipt_prefix: str | None = Field(default=None, min_length=1, max_length=12)
    gst_enabled: bool | None = None
    gst_rate_bp: int | None = Field(default=None, ge=0, le=2800)
    sac_code: str | None = Field(default=None, max_length=8)
    upi_vpa: str | None = Field(default=None, max_length=100)
    payee_name: str | None = Field(default=None, max_length=100)
    default_due_days: int | None = Field(default=None, ge=0, le=90)
    grace_days: int | None = Field(default=None, ge=0, le=90)
    auto_suspend_enabled: bool | None = None
    auto_suspend_after_days: int | None = Field(default=None, ge=1, le=365)
    coupon_invoice_on_activation: bool | None = None
    reminder_days_before_expiry: int | None = Field(default=None, ge=0, le=30)
    invoice_footer: str | None = None


class CustomerPlanRequest(_Body):
    plan_name: str | None = Field(default=None, min_length=1, max_length=100)
    amount_paise: int | None = Field(default=None, ge=0)
    price_includes_gst: bool | None = None
    billing_cycle: str | None = Field(
        default=None, pattern="^(monthly|quarterly|half_yearly|yearly)$"
    )
    anchor_day: int | None = Field(default=None, ge=1, le=28)
    next_invoice_date: date | None = None
    gst_applicable: bool | None = None
    place_of_supply_state_code: str | None = Field(default=None, pattern=r"^[0-9]{2}$")
    buyer_gstin: str | None = Field(default=None, max_length=15)
    active: bool | None = None
    notes: str | None = None


class SimpleInvoiceRequest(_Body):
    """The 1b body (ADDENDUM_01 §B.3)."""

    isp_customer_id: uuid.UUID
    period_start: date | None = None
    period_end: date | None = None
    description: str = Field(min_length=1, max_length=255)
    amount_paise: int = Field(gt=0)
    due_date: date | None = None


class InvoiceLineIn(_Body):
    description: str = Field(min_length=1, max_length=255)
    sac_code: str | None = Field(default=None, max_length=8)
    amount_paise: int = Field(gt=0)
    quantity: int = Field(default=1, ge=1, le=1000)
    price_includes_gst: bool = False


class BillTo(_Body):
    kind: str = Field(pattern="^(customer|subscriber)$")
    isp_customer_id: uuid.UUID | None = None
    subscriber_id: uuid.UUID | None = None

    @model_validator(mode="after")
    def _one_party(self) -> BillTo:
        need = "subscriber_id" if self.kind == "subscriber" else "isp_customer_id"
        if getattr(self, need) is None:
            raise ValueError(f"{need} is required for kind={self.kind}")
        return self


class ManualInvoiceRequest(_Body):
    """ADDENDUM_03 §12: bill a customer or (Part B) a subscriber."""

    bill_to: BillTo
    invoice_date: date | None = None
    due_date: date | None = None
    lines: list[InvoiceLineIn] = Field(min_length=1, max_length=50)
    po_number: str | None = Field(default=None, max_length=40)
    buyer_gstin: str | None = Field(default=None, max_length=15)


class ReasonRequest(_Body):
    reason: str = Field(min_length=1, max_length=255)


class CreditNoteRequest(_Body):
    amount_paise: int | None = Field(default=None, gt=0)
    reason: str = Field(min_length=1, max_length=255)


class PaymentRequest(_Body):
    """Exactly one of ``isp_customer_id`` / ``subscriber_id`` (Part B)."""

    isp_customer_id: uuid.UUID | None = None
    subscriber_id: uuid.UUID | None = None
    invoice_id: uuid.UUID | None = None
    amount_paise: int = Field(gt=0)
    mode: str = Field(max_length=16)
    reference: str | None = Field(default=None, max_length=100)
    received_at: datetime | None = None


class BulkPayment(_Body):
    mode: str = Field(max_length=16)
    reference_prefix: str | None = Field(default=None, max_length=80)
    received_at: datetime | None = None


class BulkRequest(_Body):
    action: str = Field(pattern="^(mark_paid|download_pdfs|send_reminder)$")
    invoice_ids: list[uuid.UUID] = Field(min_length=1)
    payment: BulkPayment | None = None
    channel: str | None = Field(default="email", pattern="^(email|sms)$")


class RemindRequest(_Body):
    channel: str = Field(default="email", pattern="^(email|sms)$")


class ZoneRequest(_Body):
    name: str = Field(min_length=1, max_length=100)
    city: str | None = Field(default=None, max_length=100)
    state_code: str | None = Field(default=None, pattern=r"^[0-9]{2}$")
    notes: str | None = None


class ZoneUpdateRequest(_Body):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    city: str | None = Field(default=None, max_length=100)
    state_code: str | None = Field(default=None, pattern=r"^[0-9]{2}$")
    notes: str | None = None


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


async def _rows(isp: IspContext, svc: IspBillingService, invoices: list) -> list[dict]:
    orgs = await isp.repository.organizations_by_id(
        list({i.customer_organization_id for i in invoices})
    )
    zones = {
        z["id"]: {"id": z["id"], "name": z["name"]} for z in await svc.list_zones(isp)
    }
    overdue = (
        {i.id for i in await svc.overdue_invoices(isp, list(orgs))} if orgs else set()
    )
    subs, packages = await svc.row_extras(invoices)
    out = []
    for i in invoices:
        org = orgs.get(i.customer_organization_id)
        out.append(
            svc.invoice_row(
                i,
                org.name if org else None,
                zones.get(str(i.zone_id)) if i.zone_id else None,
                contact_phone=org.contact_phone if org else None,
                overdue=i.id in overdue,
                subscriber=subs.get(i.id),
                package=packages.get(i.id),
            )
        )
    return out


async def _sync_coupon_activations(isp: IspContext, svc: IspBillingService) -> None:
    """Coupon activations become invoices through the same throttled
    subscriber sync (ADDENDUM_03 §7); run it before listing so they show."""
    from .plans_service import IspPlansService

    await IspPlansService(session=svc.session, audit=svc.audit).sync_subscribers(isp)


async def _pdf_for(
    isp: IspContext, svc: IspBillingService, invoice_id: uuid.UUID
) -> tuple[bytes, str]:
    view = await svc.invoice_detail(isp, invoice_id)
    settings = svc.settings_view(await svc.settings(isp)) or {}
    against = None
    if view.get("credit_note_for_invoice_id"):
        from .billing_models import IspInvoice

        orig = await svc.session.get(
            IspInvoice, uuid.UUID(view["credit_note_for_invoice_id"])
        )
        against = orig.number if orig else None
    content = render_invoice_pdf(
        view, seller=settings, isp_name=isp.organization.name, against=against
    )
    return content, view["number"].replace("/", "-") + ".pdf"


def _file(content: bytes, media: str, filename: str) -> Response:
    return Response(
        content=content,
        media_type=media,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


def _csv(header: list[str], rows: list[list[Any]]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    for r in rows:
        w.writerow(
            [
                ("'" + str(v)) if isinstance(v, str) and v[:1] in "=+-@\t\r" else v
                for v in r
            ]
        )
    return buf.getvalue().encode()


async def _is_cut(db: AsyncSession, customer_id: uuid.UUID) -> bool:
    return await IspServiceControl(session=db).is_cut(customer_id)


# ---------------------------------------------------------------------------
# /isp/billing (ADDENDUM_01 §B.3)
# ---------------------------------------------------------------------------


@billing_router.get("/billing/settings", dependencies=isp_guards(ISP_BILLING_READ))
async def get_billing_settings(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
) -> dict:
    return ok(
        request,
        svc.settings_view(await svc.settings(isp, required=False)),
        "Billing settings",
    )


@billing_router.put("/billing/settings", dependencies=isp_guards(ISP_BILLING_MANAGE))
async def put_billing_settings(
    request: Request,
    payload: BillingSettingsRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
) -> dict:
    return ok(
        request,
        await svc.put_settings(isp, payload.model_dump(exclude_unset=True)),
        "Billing settings saved",
    )


@billing_router.get(
    "/billing/customers/{isp_customer_id}/plan",
    dependencies=isp_guards(ISP_BILLING_READ),
)
async def get_customer_plan(
    request: Request,
    isp_customer_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
) -> dict:
    return ok(
        request,
        svc.plan_view(await svc.plan(isp, isp_customer_id), isp_customer_id),
        "Customer plan",
    )


@billing_router.put(
    "/billing/customers/{isp_customer_id}/plan",
    dependencies=isp_guards(ISP_BILLING_UPDATE),
)
async def put_customer_plan(
    request: Request,
    isp_customer_id: uuid.UUID,
    payload: CustomerPlanRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
) -> dict:
    return ok(
        request,
        await svc.put_plan(
            isp, isp_customer_id, payload.model_dump(exclude_unset=True)
        ),
        "Customer plan saved",
    )


@billing_router.get(
    "/billing/customers/{isp_customer_id}/ledger",
    dependencies=isp_guards(ISP_BILLING_READ),
)
async def get_ledger(
    request: Request,
    isp_customer_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    cut = await _is_cut(db, isp_customer_id)
    return ok(request, await svc.ledger(isp, isp_customer_id, cut=cut), "Ledger")


@billing_router.get("/billing/invoices", dependencies=isp_guards(ISP_BILLING_READ))
async def billing_list_invoices(
    request: Request,
    isp_customer_id: uuid.UUID | None = Query(default=None),
    status: str | None = Query(
        default=None, pattern="^(issued|partially_paid|paid|cancelled)$"
    ),
    overdue: bool | None = Query(default=None),
    since: date | None = Query(default=None),
    until: date | None = Query(default=None),
    page: int = _Page,
    page_size: int = _PageSize,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
) -> dict:
    rows, total = await svc.list_invoices(
        isp,
        isp_customer_id=isp_customer_id,
        status=status,
        overdue=overdue,
        doc_type="invoice",
        bill_to_kind="customer",
        since=since,
        until=until,
        page=page,
        page_size=page_size,
    )
    return ok(
        request,
        make_page(await _rows(isp, svc, rows), total, page, page_size),
        "Invoices",
    )


@billing_router.post(
    "/billing/invoices", status_code=201, dependencies=isp_guards(ISP_BILLING_CREATE)
)
async def billing_create_invoice(
    request: Request,
    payload: SimpleInvoiceRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
) -> dict:
    inv = await svc.issue_invoice(
        isp,
        payload.isp_customer_id,
        lines=[
            {
                "description": payload.description,
                "amount_paise": payload.amount_paise,
                "period_from": payload.period_start,
                "period_to": payload.period_end,
            }
        ],
        invoice_kind="manual",
        due_date=payload.due_date,
        period_start=payload.period_start,
        period_end=payload.period_end,
        description=payload.description,
    )
    return ok(request, (await _rows(isp, svc, [inv]))[0], "Invoice issued")


@billing_router.post(
    "/billing/invoices/generate-due", dependencies=isp_guards(ISP_BILLING_CREATE)
)
async def billing_generate_due(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
) -> dict:
    created = await svc.generate_due(isp)
    return ok(
        request, {"created": await _rows(isp, svc, created)}, "Due invoices generated"
    )


@billing_router.get(
    "/billing/invoices/{invoice_id}", dependencies=isp_guards(ISP_BILLING_READ)
)
async def billing_get_invoice(
    request: Request,
    invoice_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
) -> dict:
    return ok(request, await svc.invoice_detail(isp, invoice_id), "Invoice")


@billing_router.get(
    "/billing/invoices/{invoice_id}/pdf", dependencies=isp_guards(ISP_BILLING_READ)
)
async def billing_invoice_pdf(
    invoice_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
) -> Response:
    content, name = await _pdf_for(isp, svc, invoice_id)
    return _file(content, "application/pdf", name)


@billing_router.post(
    "/billing/invoices/{invoice_id}/void", dependencies=isp_guards(ISP_BILLING_MANAGE)
)
async def billing_void_invoice(
    request: Request,
    invoice_id: uuid.UUID,
    payload: ReasonRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
) -> dict:
    """1b "void" = a full credit note for the remaining balance (Part A:
    numbers are never reused or deleted)."""
    note = await svc.void_invoice(isp, invoice_id, reason=payload.reason)
    return ok(
        request,
        {
            "credit_note": (await _rows(isp, svc, [note]))[0],
            "invoice": await svc.invoice_detail(isp, invoice_id),
        },
        "Invoice voided",
    )


@billing_router.post(
    "/billing/payments", status_code=201, dependencies=isp_guards(ISP_BILLING_EXECUTE)
)
async def billing_record_payment(
    request: Request,
    payload: PaymentRequest,
    idempotency_key: str | None = Header(
        default=None, alias="Idempotency-Key", max_length=100
    ),
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    pay = await svc.record_payment(
        isp, idempotency_key=idempotency_key, **payload.model_dump()
    )
    data = (await svc.payment_rows(isp, [pay]))[0]
    # "Resume service now?" prompt (B.3): never auto-resume in 1b.
    data["can_resume"] = False
    if payload.isp_customer_id is not None and await _is_cut(
        db, payload.isp_customer_id
    ):
        data["can_resume"] = not await svc.overdue_invoices(
            isp, [payload.isp_customer_id]
        )
    return ok(request, data, "Payment recorded")


@billing_router.get("/billing/payments", dependencies=isp_guards(ISP_BILLING_READ))
async def billing_list_payments(
    request: Request,
    isp_customer_id: uuid.UUID | None = Query(default=None),
    page: int = _Page,
    page_size: int = _PageSize,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
) -> dict:
    rows, total = await svc.list_payments(
        isp, isp_customer_id=isp_customer_id, page=page, page_size=page_size
    )
    return ok(
        request,
        make_page(await svc.payment_rows(isp, rows), total, page, page_size),
        "Payments",
    )


@billing_router.get(
    "/billing/payments/{payment_id}/receipt.pdf",
    dependencies=isp_guards(ISP_BILLING_READ),
)
async def billing_receipt_pdf(
    payment_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
) -> Response:
    from app.domains.auth.models import User

    pay = await svc._payment(isp, payment_id)
    user = await svc.session.get(User, pay.recorded_by) if pay.recorded_by else None
    names = await isp.repository.names(Organization, [pay.customer_organization_id])
    content = render_receipt_pdf(
        svc.payment_row(pay),
        isp_name=isp.organization.name,
        seller=svc.settings_view(await svc.settings(isp)) or {},
        recorded_by=f"{user.first_name} {user.last_name}".strip() if user else None,
        customer_name=names.get(pay.customer_organization_id, ""),
    )
    return _file(
        content, "application/pdf", pay.receipt_number.replace("/", "-") + ".pdf"
    )


@billing_router.post(
    "/billing/payments/{payment_id}/void", dependencies=isp_guards(ISP_BILLING_MANAGE)
)
async def billing_void_payment(
    request: Request,
    payment_id: uuid.UUID,
    payload: ReasonRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
) -> dict:
    pay = await svc.void_payment(isp, payment_id, reason=payload.reason)
    return ok(request, (await svc.payment_rows(isp, [pay]))[0], "Payment voided")


@billing_router.post(
    "/billing/customers/{isp_customer_id}/suspend-for-dues",
    dependencies=isp_guards(ISP_BILLING_EXECUTE),
)
async def billing_suspend_for_dues(
    request: Request,
    isp_customer_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
    control: IspServiceControl = Depends(get_service_control),
) -> dict:
    customer = await svc._customer(isp, isp_customer_id)
    overdue = await svc.overdue_invoices(isp, [customer.id])
    if not overdue:
        raise IspNoDuesError()
    data = await control.suspend(
        isp.isp_org_id,
        customer,
        actor=isp.user_id,
        reason="non_payment",
        support_line=isp.profile.support_phone,
        isp_name=isp.organization.name,
        extra_audit={"invoice_ids": [str(i.id) for i in overdue]},
    )
    return ok(request, data, "Service suspended for dues")


@billing_router.get("/billing/export.csv", dependencies=isp_guards(ISP_BILLING_EXPORT))
async def billing_export(
    kind: str = Query(pattern="^(invoices|payments|dues)$"),
    since: date | None = Query(default=None),
    until: date | None = Query(default=None),
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
) -> Response:
    stamp = datetime.now(UTC).strftime("%Y%m%d")
    if kind == "payments":
        rows, _ = await svc.list_payments(
            isp, isp_customer_id=None, page=1, page_size=100_000
        )
        names = await isp.repository.names(
            Organization, [p.customer_organization_id for p in rows]
        )
        body = _csv(
            [
                "receipt",
                "customer",
                "received_at",
                "mode",
                "reference",
                "amount",
                "status",
            ],
            [
                [
                    p.receipt_number,
                    names.get(p.customer_organization_id),
                    p.received_at.isoformat(),
                    p.mode,
                    p.reference or "",
                    f"{p.amount_paise / 100:.2f}",
                    p.status,
                ]
                for p in rows
                if (not since or p.received_at.date() >= since)
                and (not until or p.received_at.date() <= until)
            ],
        )
    else:
        invoices, _ = await svc.list_invoices(
            isp,
            doc_type="invoice",
            overdue=kind == "dues",
            since=since,
            until=until,
            page=1,
            page_size=100_000,
        )
        body = _csv(
            [
                "number",
                "customer",
                "issue_date",
                "due_date",
                "total",
                "paid",
                "credit_noted",
                "balance",
                "status",
            ],
            [
                [
                    i.number,
                    i.bill_to_name,
                    i.issue_date.isoformat(),
                    i.due_date.isoformat(),
                    f"{i.total_paise / 100:.2f}",
                    f"{i.paid_paise / 100:.2f}",
                    f"{i.credit_noted_paise / 100:.2f}",
                    f"{balance_of(i) / 100:.2f}",
                    i.status,
                ]
                for i in invoices
            ],
        )
    return _file(
        body,
        "text/csv; charset=utf-8",
        f"isp-{kind}-{isp.organization.slug}-{stamp}.csv",
    )


# ---------------------------------------------------------------------------
# /isp/invoices (ADDENDUM_03 Part A)
# ---------------------------------------------------------------------------


@billing_router.get("/invoices", dependencies=isp_guards(ISP_INVOICES_READ))
async def list_invoices(
    request: Request,
    isp_customer_id: uuid.UUID | None = Query(default=None),
    status: str | None = Query(
        default=None, pattern="^(issued|partially_paid|paid|cancelled)$"
    ),
    doc_type: str | None = Query(default=None, pattern="^(invoice|credit_note)$"),
    bill_to_kind: str | None = Query(default=None, pattern="^(customer|subscriber)$"),
    zone_id: uuid.UUID | None = Query(default=None),
    subscriber_id: uuid.UUID | None = Query(default=None),
    package_id: uuid.UUID | None = Query(default=None),
    username: str | None = Query(default=None, max_length=100),
    overdue: bool | None = Query(default=None),
    since: date | None = Query(default=None),
    until: date | None = Query(default=None),
    search: str | None = Query(default=None, max_length=100),
    page: int = _Page,
    page_size: int = _PageSize,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
) -> dict:
    await _sync_coupon_activations(isp, svc)
    filters = {
        "isp_customer_id": isp_customer_id,
        "status": status,
        "overdue": overdue,
        "zone_id": zone_id,
        "doc_type": doc_type,
        "since": since,
        "until": until,
        "search": search,
        "bill_to_kind": bill_to_kind,
        "subscriber_id": subscriber_id,
        "package_id": package_id,
        "username": username,
    }
    rows, total = await svc.list_invoices(
        isp, page=page, page_size=page_size, **filters
    )
    data = make_page(await _rows(isp, svc, rows), total, page, page_size)
    # Totals for the whole filtered set (CONTRACT_CHANGES FE #30).
    data["totals"] = await svc.invoice_totals(isp, **filters)
    return ok(request, data, "Invoices")


@billing_router.post(
    "/invoices", status_code=201, dependencies=isp_guards(ISP_INVOICES_CREATE)
)
async def create_manual_invoice(
    request: Request,
    payload: ManualInvoiceRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
) -> dict:
    bill_to = payload.bill_to
    common = {
        "lines": [line.model_dump() for line in payload.lines],
        "invoice_kind": "manual",
        "issue_date": payload.invoice_date,
        "due_date": payload.due_date,
        "po_number": payload.po_number,
        "buyer_gstin": payload.buyer_gstin,
    }
    if bill_to.kind == "subscriber":
        sub = await svc.subscriber_in_scope(isp, bill_to.subscriber_id)
        inv = await svc.issue_subscriber_invoice(isp, sub, **common)
    else:
        inv = await svc.issue_invoice(isp, bill_to.isp_customer_id, **common)
    return ok(request, await svc.invoice_detail(isp, inv.id), "Invoice issued")


@billing_router.get("/invoices/settings", dependencies=isp_guards(ISP_INVOICES_READ))
async def get_invoice_settings(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
) -> dict:
    return ok(
        request,
        svc.settings_view(await svc.settings(isp, required=False)),
        "Invoice settings",
    )


@billing_router.put("/invoices/settings", dependencies=isp_guards(ISP_INVOICES_MANAGE))
async def put_invoice_settings(
    request: Request,
    payload: BillingSettingsRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
) -> dict:
    return ok(
        request,
        await svc.put_settings(isp, payload.model_dump(exclude_unset=True)),
        "Invoice settings saved",
    )


@billing_router.get("/invoices/export", dependencies=isp_guards(ISP_INVOICES_EXPORT))
async def export_invoices(
    format: str = Query(default="csv", pattern="^(csv|xlsx)$"),
    status: str | None = Query(default=None),
    zone_id: uuid.UUID | None = Query(default=None),
    bill_to_kind: str | None = Query(default=None, pattern="^(customer|subscriber)$"),
    since: date | None = Query(default=None),
    until: date | None = Query(default=None),
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
) -> Response:
    from app.domains.analytics.constants import ExportFormat
    from app.domains.analytics.export import render_report
    from app.domains.analytics.report_types import ReportPayload, ReportSection

    rows, _ = await svc.list_invoices(
        isp,
        status=status,
        zone_id=zone_id,
        since=since,
        until=until,
        bill_to_kind=bill_to_kind,
        page=1,
        page_size=100_000,
    )
    zones = {z["id"]: z["name"] for z in await svc.list_zones(isp)}
    subs, packages = await svc.row_extras(rows)
    table = [
        {
            "Created": i.created_at.isoformat() if i.created_at else "",
            "Invoice No.": i.number,
            "Invoice Id": i.display_id,
            "Username": (subs.get(i.id) or {}).get("username")
            or i.bill_to_username
            or "",
            "Circuit Id": i.circuit_id_snapshot or "",
            "First Name": (subs.get(i.id) or {}).get("first_name") or i.bill_to_name,
            "Last Name": (subs.get(i.id) or {}).get("last_name") or "",
            "Zone": zones.get(str(i.zone_id), "") if i.zone_id else "",
            "Package": (packages.get(i.id) or {}).get("name") or i.description or "",
            "Invoice Kind": i.invoice_kind,
            "PO No.": i.po_number or "",
            "Buyer GSTIN": i.bill_to_gstin or "",
            "Taxable": i.taxable_paise / 100,
            "CGST": i.cgst_paise / 100,
            "SGST": i.sgst_paise / 100,
            "IGST": i.igst_paise / 100,
            "Total": i.total_paise / 100,
            "Paid": i.paid_paise / 100,
            "Balance": balance_of(i) / 100 if i.doc_type == "invoice" else 0,
            "Status": i.status,
        }
        for i in rows
    ]
    payload = ReportPayload(
        report_type="isp_invoices",
        title=f"{isp.organization.name} invoices",
        generated_at=datetime.now(UTC).isoformat(),
        organization_id=None,
        location_id=None,
        period_start=since.isoformat() if since else None,
        period_end=until.isoformat() if until else None,
        sections=[
            ReportSection(key="invoices", title="Invoices", data={"invoices": table})
        ],
    )
    rendered = render_report(
        payload, ExportFormat.CSV if format == "csv" else ExportFormat.EXCEL
    )
    stamp = datetime.now(UTC).strftime("%Y%m%d")
    return _file(
        rendered.content,
        rendered.content_type,
        f"invoices-{isp.organization.slug}-{stamp}.{format}",
    )


@billing_router.get(
    "/invoices/reports/collections", dependencies=isp_guards(ISP_INVOICES_READ)
)
async def report_collections(
    request: Request,
    group_by: str = Query(default="month", pattern="^(zone|month|package)$"),
    since: date | None = Query(default=None),
    until: date | None = Query(default=None),
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
) -> dict:
    today = svc.today(isp)
    data = await svc.collections(
        isp,
        group_by="month" if group_by == "package" else group_by,
        since=since or today - timedelta(days=90),
        until=until or today,
    )
    return ok(request, data, "Collections")


@billing_router.get(
    "/invoices/reports/outstanding", dependencies=isp_guards(ISP_INVOICES_READ)
)
async def report_outstanding(
    request: Request,
    as_of: date | None = Query(default=None),
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
) -> dict:
    return ok(
        request,
        await svc.outstanding(isp, as_of=as_of or svc.today(isp)),
        "Outstanding",
    )


@billing_router.post("/invoices/bulk", dependencies=isp_guards(ISP_INVOICES_EXECUTE))
async def bulk_invoices(
    request: Request,
    payload: BulkRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
) -> Any:
    if len(payload.invoice_ids) > 500:
        raise IspBulkTooLargeError()
    from .exceptions import IspInvoiceNotFoundError

    if payload.action == "download_pdfs":
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for iid in payload.invoice_ids:
                try:
                    content, name = await _pdf_for(isp, svc, iid)
                except IspInvoiceNotFoundError:
                    continue
                zf.writestr(name, content)
        return _file(
            buf.getvalue(),
            "application/zip",
            f"invoices-{datetime.now(UTC):%Y%m%d}.zip",
        )
    if payload.action == "send_reminder":
        queued = skipped = 0
        for iid in payload.invoice_ids:
            try:
                sent = await _remind(isp, svc, iid, payload.channel or "email")
            except IspInvoiceNotFoundError:
                skipped += 1
                continue
            queued += int(sent)
            skipped += int(not sent)
        return ok(
            request,
            {"queued": queued, "skipped_no_consent": 0, "skipped_no_contact": skipped},
            "Reminders",
        )
    if payload.payment is None:
        from .exceptions import IspPaymentModeInvalidError

        raise IspPaymentModeInvalidError("payment is required for mark_paid")
    paid, skipped_rows = 0, []
    for n, iid in enumerate(payload.invoice_ids, start=1):
        try:
            inv = await svc._invoice(isp, iid)
        except IspInvoiceNotFoundError:
            skipped_rows.append({"invoice_id": str(iid), "reason": "not_found"})
            continue
        if inv.status == "cancelled":
            skipped_rows.append({"invoice_id": str(iid), "reason": "cancelled"})
            continue
        if balance_of(inv) == 0:
            skipped_rows.append({"invoice_id": str(iid), "reason": "already_paid"})
            continue
        ref = (
            f"{payload.payment.reference_prefix}-{n}"
            if payload.payment.reference_prefix
            else None
        )
        await svc.record_payment(
            isp,
            isp_customer_id=inv.customer_organization_id,
            invoice_id=inv.id,
            amount_paise=balance_of(inv),
            mode=payload.payment.mode,
            reference=ref,
            received_at=payload.payment.received_at,
        )
        paid += 1
    return ok(request, {"paid": paid, "skipped": skipped_rows}, "Marked paid")


async def _remind(
    isp: IspContext, svc: IspBillingService, invoice_id: uuid.UUID, channel: str
) -> bool:
    """Email only; SMS waits on founder Q13 (``ISP_SMS_REMINDERS_ENABLED``
    off). Queued through the existing notification outbox with the ISP org."""
    from app.domains.notification.constants import (
        NotificationChannelType,
        NotificationEventType,
    )
    from app.domains.notification.repository import NotificationRepository
    from app.domains.notification.service import NotificationService

    from .billing_models import IspInvoiceReminder

    inv = await svc._invoice(isp, invoice_id)
    customer = await isp.repository.get_organization(inv.customer_organization_id)
    if (
        channel != "email"
        or not customer
        or not customer.contact_email
        or balance_of(inv) == 0
    ):
        return False
    body = (
        f"<p>Dear {html.escape(customer.name)},</p><p>Invoice {inv.number} dated {inv.issue_date:%d %b %Y} "  # noqa: E501
        f"has a balance of Rs {balance_of(inv) / 100:.2f}, due {inv.due_date:%d %b %Y}.</p>"  # noqa: E501
        f"<p>{html.escape(isp.organization.name)}"
        + (
            f", {html.escape(isp.profile.support_phone)}"
            if isp.profile.support_phone
            else ""
        )
        + "</p>"
    )
    outbox = NotificationService(NotificationRepository(svc.session))
    await outbox.enqueue(
        event_type=NotificationEventType.SUBSCRIPTION_RENEWAL_REMINDER,
        channel=NotificationChannelType.EMAIL,
        recipient=customer.contact_email,
        subject=f"{isp.organization.name}: invoice {inv.number} due",
        body=body,
        organization_id=isp.isp_org_id,
    )
    svc.session.add(
        IspInvoiceReminder(
            invoice_id=inv.id,
            channel="email",
            sent_by=isp.user_id,
            sent_at=datetime.now(UTC),
            status="queued",
        )
    )
    await svc.session.flush()
    return True


@billing_router.get(
    "/invoices/{invoice_id}", dependencies=isp_guards(ISP_INVOICES_READ)
)
async def get_invoice(
    request: Request,
    invoice_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
) -> dict:
    return ok(request, await svc.invoice_detail(isp, invoice_id), "Invoice")


@billing_router.get(
    "/invoices/{invoice_id}/pdf", dependencies=isp_guards(ISP_INVOICES_READ)
)
async def get_invoice_pdf(
    invoice_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
) -> Response:
    content, name = await _pdf_for(isp, svc, invoice_id)
    return _file(content, "application/pdf", name)


@billing_router.post(
    "/invoices/{invoice_id}/credit-note",
    status_code=201,
    dependencies=isp_guards(ISP_INVOICES_MANAGE),
)
async def credit_note(
    request: Request,
    invoice_id: uuid.UUID,
    payload: CreditNoteRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
) -> dict:
    note = await svc.credit_note(
        isp, invoice_id, amount_paise=payload.amount_paise, reason=payload.reason
    )
    return ok(request, await svc.invoice_detail(isp, note.id), "Credit note issued")


@billing_router.post(
    "/invoices/{invoice_id}/remind", dependencies=isp_guards(ISP_INVOICES_EXECUTE)
)
async def remind(
    request: Request,
    invoice_id: uuid.UUID,
    payload: RemindRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
) -> dict:
    if payload.channel != "email":
        from .exceptions import IspSmsRemindersUnavailableError

        raise IspSmsRemindersUnavailableError()
    sent = await _remind(isp, svc, invoice_id, payload.channel)
    return ok(request, {"queued": sent, "channel": payload.channel}, "Reminder")


# ---------------------------------------------------------------------------
# /isp/zones
# ---------------------------------------------------------------------------


@billing_router.get("/zones", dependencies=isp_guards(ISP_ZONES_READ))
async def list_zones(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
) -> dict:
    return ok(request, {"items": await svc.list_zones(isp)}, "Zones")


@billing_router.post(
    "/zones", status_code=201, dependencies=isp_guards(ISP_ZONES_MANAGE)
)
async def create_zone(
    request: Request,
    payload: ZoneRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
) -> dict:
    return ok(request, await svc.create_zone(isp, payload.model_dump()), "Zone created")


@billing_router.patch("/zones/{zone_id}", dependencies=isp_guards(ISP_ZONES_MANAGE))
async def update_zone(
    request: Request,
    zone_id: uuid.UUID,
    payload: ZoneUpdateRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
) -> dict:
    return ok(
        request,
        await svc.update_zone(isp, zone_id, payload.model_dump(exclude_unset=True)),
        "Zone updated",
    )


@billing_router.delete("/zones/{zone_id}", dependencies=isp_guards(ISP_ZONES_MANAGE))
async def delete_zone(
    request: Request,
    zone_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspBillingService = Depends(get_billing_service),
) -> dict:
    await svc.delete_zone(isp, zone_id)
    return ok(request, {"deleted": True}, "Zone deleted")
