"""JAZE-4 routes under ``/isp`` (mounted by ``router._include_lanes``).

Guard stack: ``isp_guards(<key>)`` (flag, ISP partner, permission on the ISP
org) plus the JAZE-4 flag for the feature group. Path ids are non-alias names
(``product_id``, ``lease_id``, ``invoice_id``, ``payment_id``, ``zone_id``,
``package_id``, ``subscriber_id``, ``isp_customer_id``).

Keys reused, none added: ``isp_billing.*`` (catalogue, template, leases,
deposits, contacts, automation settings), ``isp_invoices.*`` (email, slips),
``isp_plans.*`` (package billing), ``isp_zones.*`` (zone ledger),
``isp_monitor.*`` (Telegram).
"""

from __future__ import annotations

import html
import uuid
from datetime import date, datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.responses import build_response
from app.core.storage import ObjectStorageProtocol, get_object_storage
from app.database.redis import get_redis_client
from app.database.session import get_db_session
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from . import automation as auto
from .billing_router import _file, _pdf_for
from .constants import (
    ISP_BILLING_EXECUTE,
    ISP_BILLING_EXPORT,
    ISP_BILLING_MANAGE,
    ISP_BILLING_READ,
    ISP_INVOICES_EXECUTE,
    ISP_INVOICES_READ,
    ISP_MONITOR_READ,
    ISP_MONITOR_UPDATE,
    ISP_ZONES_MANAGE,
    ISP_ZONES_READ,
)
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .finance_config import (
    RequireFinanceExtras,
    RequireTelegramAlerts,
    RequireWhatsappAutomation,
    RequireZoneLedger,
)
from .finance_service import IspFinanceService
from .http import ok, request_id
from .views import page as make_page

ISP_PLANS_READ = "isp_plans.read"
ISP_PLANS_UPDATE = "isp_plans.update"

finance_router = APIRouter(tags=["ISP Partner: finance (JAZE-4)"])

_EXTRAS = [Depends(RequireFinanceExtras)]
_ZONES = [Depends(RequireZoneLedger)]
_WA = [Depends(RequireWhatsappAutomation)]
_TG = [Depends(RequireTelegramAlerts)]


def get_finance_service(
    db: AsyncSession = Depends(get_db_session),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> IspFinanceService:
    return IspFinanceService(session=db, audit=audit)


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# ---------------------------------------------------------------------------
# invoice template
# ---------------------------------------------------------------------------


class TemplateRequest(_Body):
    bank_name: str | None = Field(default=None, max_length=100)
    bank_account_name: str | None = Field(default=None, max_length=120)
    bank_account_number: str | None = Field(default=None, max_length=40)
    bank_ifsc: str | None = Field(default=None, max_length=11)
    bank_branch: str | None = Field(default=None, max_length=100)
    website: str | None = Field(default=None, max_length=200)
    care_phone: str | None = Field(default=None, max_length=20)
    care_email: str | None = Field(default=None, max_length=255)
    pan: str | None = Field(default=None, max_length=10)
    licence_number: str | None = Field(default=None, max_length=60)
    terms: str | None = Field(default=None, max_length=2000)
    show_bank_details: bool | None = None
    show_zone_operator: bool | None = None


@finance_router.get(
    "/finance/invoice-template", dependencies=_EXTRAS + isp_guards(ISP_BILLING_READ)
)  # noqa: E501
async def get_template(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFinanceService = Depends(get_finance_service),
) -> dict:  # noqa: E501
    return ok(request, svc.template_view(await svc.template(isp)), "Invoice template")


@finance_router.put(
    "/finance/invoice-template", dependencies=_EXTRAS + isp_guards(ISP_BILLING_MANAGE)
)  # noqa: E501
async def put_template(
    request: Request,
    payload: TemplateRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFinanceService = Depends(get_finance_service),
) -> dict:  # noqa: E501
    out = await svc.put_template(isp, payload.model_dump(exclude_unset=True))
    await svc.session.commit()
    return ok(request, out, "Invoice template saved")


# ---------------------------------------------------------------------------
# products
# ---------------------------------------------------------------------------

Kind = Literal["bandwidth", "static_ip", "installation", "other"]


class ProductRequest(_Body):
    name: str = Field(min_length=1, max_length=120)
    kind: Kind
    sac_code: str = Field(default="998422", pattern=r"^99\d{2}(\d{2})?$")
    default_amount_paise: int = Field(default=0, ge=0, le=10_000_000_00)
    price_includes_gst: bool = False
    active: bool = True


class ProductUpdate(_Body):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    kind: Kind | None = None
    sac_code: str | None = Field(default=None, pattern=r"^99\d{2}(\d{2})?$")
    default_amount_paise: int | None = Field(default=None, ge=0, le=10_000_000_00)
    price_includes_gst: bool | None = None
    active: bool | None = None


@finance_router.get(
    "/finance/products", dependencies=_EXTRAS + isp_guards(ISP_BILLING_READ)
)
async def list_products(
    request: Request,
    active_only: bool = False,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFinanceService = Depends(get_finance_service),
) -> dict:  # noqa: E501
    return ok(
        request,
        {"items": await svc.list_products(isp, include_inactive=not active_only)},
        "Products",
    )  # noqa: E501


@finance_router.post(
    "/finance/products",
    status_code=201,
    dependencies=_EXTRAS + isp_guards(ISP_BILLING_MANAGE),
)  # noqa: E501
async def create_product(
    request: Request,
    payload: ProductRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFinanceService = Depends(get_finance_service),
) -> dict:  # noqa: E501
    out = await svc.create_product(isp, payload.model_dump())
    await svc.session.commit()
    return ok(request, out, "Product created")


@finance_router.post(
    "/finance/products/standard", dependencies=_EXTRAS + isp_guards(ISP_BILLING_MANAGE)
)  # noqa: E501
async def standard_products(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFinanceService = Depends(get_finance_service),
) -> dict:  # noqa: E501
    out = await svc.seed_standard_products(isp)
    await svc.session.commit()
    return ok(request, {"items": out}, "Standard products added")


@finance_router.patch(
    "/finance/products/{product_id}",
    dependencies=_EXTRAS + isp_guards(ISP_BILLING_MANAGE),
)  # noqa: E501
async def update_product(
    request: Request,
    product_id: uuid.UUID,
    payload: ProductUpdate,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFinanceService = Depends(get_finance_service),
) -> dict:  # noqa: E501
    out = await svc.update_product(
        isp, product_id, payload.model_dump(exclude_unset=True)
    )
    await svc.session.commit()
    return ok(request, out, "Product updated")


# ---------------------------------------------------------------------------
# price preview + package billing plan
# ---------------------------------------------------------------------------


@finance_router.get(
    "/finance/price-preview", dependencies=_EXTRAS + isp_guards(ISP_BILLING_READ)
)  # noqa: E501
async def price_preview(
    request: Request,
    amount_paise: int = Query(ge=0, le=10_000_000_00),
    price_includes_gst: bool = False,
    place_of_supply_state_code: str | None = Query(default=None, pattern=r"^\d{2}$"),
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFinanceService = Depends(get_finance_service),
) -> dict:
    return ok(
        request,
        await svc.price_preview(
            isp,
            amount_paise=amount_paise,
            price_includes_gst=price_includes_gst,
            place_of_supply_state_code=place_of_supply_state_code,
        ),
        "Price preview",
    )


class PackageBillingRequest(_Body):
    plan_kind: Literal["prepaid", "postpaid"]
    chargeable_unit: Literal["days", "months"]
    chargeable_count: int = Field(ge=1, le=366)
    invoice_description: str | None = Field(default=None, max_length=255)
    product_id: uuid.UUID | None = None

    @model_validator(mode="after")
    def _months(self) -> PackageBillingRequest:
        if self.chargeable_unit == "months" and self.chargeable_count > 36:
            raise ValueError("chargeable_count is at most 36 months")
        return self


@finance_router.get(
    "/finance/packages/{package_id}/billing",
    dependencies=_EXTRAS + isp_guards(ISP_PLANS_READ),
)  # noqa: E501
async def get_package_billing(
    request: Request,
    package_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFinanceService = Depends(get_finance_service),
) -> dict:  # noqa: E501
    return ok(request, await svc.package_billing(isp, package_id), "Package billing")


@finance_router.put(
    "/finance/packages/{package_id}/billing",
    dependencies=_EXTRAS + isp_guards(ISP_PLANS_UPDATE),
)  # noqa: E501
async def put_package_billing(
    request: Request,
    package_id: uuid.UUID,
    payload: PackageBillingRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFinanceService = Depends(get_finance_service),
) -> dict:  # noqa: E501
    out = await svc.put_package_billing(isp, package_id, payload.model_dump())
    await svc.session.commit()
    return ok(request, out, "Package billing saved")


# ---------------------------------------------------------------------------
# static IP leases
# ---------------------------------------------------------------------------


class LeaseRequest(_Body):
    isp_customer_id: uuid.UUID | None = None
    subscriber_id: uuid.UUID | None = None
    ip_address: str = Field(min_length=3, max_length=45)
    monthly_amount_paise: int = Field(ge=0, le=10_000_000_00)
    price_includes_gst: bool = False
    active_since: date | None = None
    notes: str | None = Field(default=None, max_length=255)


class LeaseEndRequest(_Body):
    active_until: date | None = None


@finance_router.get(
    "/finance/static-ip-leases", dependencies=_EXTRAS + isp_guards(ISP_BILLING_READ)
)  # noqa: E501
async def list_leases(
    request: Request,
    status: Literal["active", "ended"] | None = None,
    subscriber_id: uuid.UUID | None = None,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFinanceService = Depends(get_finance_service),
) -> dict:
    return ok(
        request,
        {
            "items": await svc.list_leases(
                isp, status=status, subscriber_id=subscriber_id
            )
        },
        "Static IP leases",
    )  # noqa: E501


@finance_router.post(
    "/finance/static-ip-leases",
    status_code=201,
    dependencies=_EXTRAS + isp_guards(ISP_BILLING_MANAGE),
)  # noqa: E501
async def create_lease(
    request: Request,
    payload: LeaseRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFinanceService = Depends(get_finance_service),
) -> dict:  # noqa: E501
    out = await svc.create_lease(isp, payload.model_dump())
    await svc.session.commit()
    return ok(request, out, "Lease created")


@finance_router.post(
    "/finance/static-ip-leases/{lease_id}/end",
    dependencies=_EXTRAS + isp_guards(ISP_BILLING_MANAGE),
)  # noqa: E501
async def end_lease(
    request: Request,
    lease_id: uuid.UUID,
    payload: LeaseEndRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFinanceService = Depends(get_finance_service),
) -> dict:  # noqa: E501
    out = await svc.end_lease(isp, lease_id, until=payload.active_until)
    await svc.session.commit()
    return ok(request, out, "Lease ended")


@finance_router.post(
    "/finance/static-ip-leases/bill",
    dependencies=_EXTRAS + isp_guards(ISP_BILLING_EXECUTE),
)  # noqa: E501
async def bill_leases(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFinanceService = Depends(get_finance_service),
) -> dict:  # noqa: E501
    out = await svc.bill_leases(isp)
    await svc.session.commit()
    return ok(request, out, "Lease invoices issued")


# ---------------------------------------------------------------------------
# security deposits
# ---------------------------------------------------------------------------


class DepositRequest(_Body):
    isp_customer_id: uuid.UUID | None = None
    subscriber_id: uuid.UUID | None = None
    entry_kind: Literal["collect", "refund", "forfeit"]
    item: Literal["ont", "router", "stb", "other"]
    item_serial: str | None = Field(default=None, max_length=64)
    amount_paise: int = Field(gt=0, le=10_000_000_00)
    mode: Literal["cash", "upi", "bank_transfer", "adjustment"]
    reference: str | None = Field(default=None, max_length=100)
    note: str | None = Field(default=None, max_length=255)
    occurred_at: datetime | None = None


@finance_router.get(
    "/finance/deposits", dependencies=_EXTRAS + isp_guards(ISP_BILLING_READ)
)
async def list_deposits(
    request: Request,
    isp_customer_id: uuid.UUID | None = None,
    subscriber_id: uuid.UUID | None = None,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFinanceService = Depends(get_finance_service),
) -> dict:
    return ok(
        request,
        await svc.deposits(
            isp, isp_customer_id=isp_customer_id, subscriber_id=subscriber_id
        ),
        "Deposits",
    )  # noqa: E501


@finance_router.get(
    "/finance/deposits/summary", dependencies=_EXTRAS + isp_guards(ISP_BILLING_READ)
)  # noqa: E501
async def deposit_summary(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFinanceService = Depends(get_finance_service),
) -> dict:  # noqa: E501
    return ok(request, {"items": await svc.deposit_summary(isp)}, "Deposits held")


@finance_router.post(
    "/finance/deposits",
    status_code=201,
    dependencies=_EXTRAS + isp_guards(ISP_BILLING_EXECUTE),
)  # noqa: E501
async def add_deposit(
    request: Request,
    payload: DepositRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFinanceService = Depends(get_finance_service),
) -> dict:  # noqa: E501
    out = await svc.add_deposit(isp, payload.model_dump())
    await svc.session.commit()
    return ok(request, out, "Deposit recorded")


# ---------------------------------------------------------------------------
# billing contacts, invoice email, thermal slips
# ---------------------------------------------------------------------------


class ContactRequest(_Body):
    alternate_email: str | None = Field(
        default=None, max_length=255, pattern=r"^$|^[^@\s]+@[^@\s]+\.[^@\s]+$"
    )  # noqa: E501
    alternate_name: str | None = Field(default=None, max_length=120)
    exclude_from_reminders: bool | None = None
    whatsapp_opt_in: bool | None = None


@finance_router.get(
    "/finance/contacts/{subject_kind}/{subject_id}",
    dependencies=_EXTRAS + isp_guards(ISP_BILLING_READ),
)  # noqa: E501
async def get_contact(
    request: Request,
    subject_kind: Literal["customer", "subscriber"],
    subject_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFinanceService = Depends(get_finance_service),
) -> dict:  # noqa: E501
    return ok(
        request, await svc.get_contact(isp, subject_kind, subject_id), "Billing contact"
    )


@finance_router.put(
    "/finance/contacts/{subject_kind}/{subject_id}",
    dependencies=_EXTRAS + isp_guards(ISP_BILLING_MANAGE),
)  # noqa: E501
async def put_contact(
    request: Request,
    subject_kind: Literal["customer", "subscriber"],
    subject_id: uuid.UUID,
    payload: ContactRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFinanceService = Depends(get_finance_service),
) -> dict:  # noqa: E501
    data = payload.model_dump(exclude_unset=True)
    if data.get("alternate_email") == "":
        data["alternate_email"] = None
    out = await svc.put_contact(isp, subject_kind, subject_id, data)
    await svc.session.commit()
    return ok(request, out, "Billing contact saved")


class EmailInvoiceRequest(_Body):
    send_to: Literal["primary", "alternate", "both"] = "primary"
    message: str | None = Field(default=None, max_length=1000)


@finance_router.post(
    "/finance/invoices/{invoice_id}/email",
    dependencies=_EXTRAS + isp_guards(ISP_INVOICES_EXECUTE),
)  # noqa: E501
async def email_invoice(
    request: Request,
    invoice_id: uuid.UUID,
    payload: EmailInvoiceRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFinanceService = Depends(get_finance_service),
    storage: ObjectStorageProtocol = Depends(get_object_storage),
) -> dict:
    from app.domains.notification.constants import (
        NotificationChannelType,
        NotificationEventType,
    )
    from app.domains.notification.repository import NotificationRepository
    from app.domains.notification.service import NotificationService

    inv = await svc.billing._invoice(isp, invoice_id)
    recipients = await svc.invoice_recipients(isp, inv, payload.send_to)
    content, filename = await _pdf_for(isp, svc.billing, invoice_id)
    key = f"isp-invoices/{isp.isp_org_id}/{inv.id}/{uuid.uuid4()}.pdf"
    await storage.upload(key=key, content=content, content_type="application/pdf")
    note = f"<p>{html.escape(payload.message)}</p>" if payload.message else ""
    body = (
        f"<p>Dear {html.escape(inv.bill_to_name)},</p>"
        f"<p>Please find attached invoice {html.escape(inv.number)} dated {inv.issue_date:%d %b %Y} "  # noqa: E501
        f"for Rs {inv.total_paise / 100:,.2f}.</p>{note}"
        f"<p>{html.escape(isp.organization.name)}"
        + (
            f", {html.escape(isp.profile.support_phone)}"
            if isp.profile.support_phone
            else ""
        )
        + "</p>"
    )
    outbox = NotificationService(NotificationRepository(svc.session))
    queued = []
    for to in recipients:
        delivery = await outbox.enqueue(
            event_type=NotificationEventType.SUBSCRIPTION_RENEWAL_REMINDER,
            channel=NotificationChannelType.EMAIL,
            recipient=to,
            subject=f"{isp.organization.name}: invoice {inv.number}",
            body=body,
            organization_id=isp.isp_org_id,
            attachment_storage_key=key,
            attachment_filename=filename,
        )
        svc.session.add(
            auto.log_row(
                isp.isp_org_id,
                channel="email",
                trigger="invoice_email",
                recipient_masked=auto.mask_email(to),
                customer_organization_id=inv.customer_organization_id,
                subscriber_id=inv.subscriber_id,
                invoice_id=inv.id,
                summary=f"Invoice {inv.number} ({payload.send_to})",
                status="queued",
                notification_delivery_id=delivery.id,
            )
        )
        queued.append(auto.mask_email(to))
    await svc._audit(
        isp,
        "isp_invoice_emailed",
        inv.id,
        inv.customer_organization_id,
        send_to=payload.send_to,
    )  # noqa: E501
    await svc.session.commit()
    return ok(
        request, {"queued": queued, "send_to": payload.send_to}, "Invoice emailed"
    )


@finance_router.get(
    "/finance/invoices/{invoice_id}/thermal.pdf",
    dependencies=_EXTRAS + isp_guards(ISP_INVOICES_READ),
)  # noqa: E501
async def thermal_invoice(
    invoice_id: uuid.UUID,
    width: Literal[58, 80] = 80,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFinanceService = Depends(get_finance_service),
) -> Response:  # noqa: E501
    from .thermal_pdf import render_thermal_invoice

    view = await svc.billing.invoice_detail(isp, invoice_id)
    seller = (
        svc.billing.settings_view(await svc.billing.settings(isp)) or {}
    ) | await svc.seller_extras(isp)  # noqa: E501
    pdf = render_thermal_invoice(
        view, seller=seller, isp_name=isp.organization.name, width_mm=width
    )  # noqa: E501
    return _file(
        pdf, "application/pdf", view["number"].replace("/", "-") + f"-{width}mm.pdf"
    )


@finance_router.get(
    "/finance/payments/{payment_id}/thermal.pdf",
    dependencies=_EXTRAS + isp_guards(ISP_BILLING_READ),
)  # noqa: E501
async def thermal_receipt(
    payment_id: uuid.UUID,
    width: Literal[58, 80] = 80,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFinanceService = Depends(get_finance_service),
) -> Response:  # noqa: E501
    from .thermal_pdf import render_thermal_receipt

    pay = await svc.billing._payment(isp, payment_id)
    rows = await svc.billing.payment_rows(isp, [pay])
    view = rows[0]
    seller = svc.billing.settings_view(await svc.billing.settings(isp)) or {}
    pdf = render_thermal_receipt(
        view,
        seller=seller,
        isp_name=isp.organization.name,
        customer_name=view.get("customer_name") or "",
        width_mm=width,  # noqa: E501
    )
    return _file(
        pdf,
        "application/pdf",
        view["receipt_number"].replace("/", "-") + f"-{width}mm.pdf",
    )  # noqa: E501


# ---------------------------------------------------------------------------
# zone ledger (labels only; pending founder confirmation)
# ---------------------------------------------------------------------------


class ZoneProfileRequest(_Body):
    contact_name: str | None = Field(default=None, max_length=120)
    email: str | None = Field(default=None, max_length=255)
    phone: str | None = Field(default=None, max_length=20)
    address: str | None = Field(default=None, max_length=1000)
    pincode: str | None = Field(default=None, max_length=6)
    gstin: str | None = Field(default=None, max_length=15)
    pan: str | None = Field(default=None, max_length=10)
    operator_name: str | None = Field(default=None, max_length=120)
    operator_phone: str | None = Field(default=None, max_length=20)
    revenue_share_bp: int | None = Field(default=None, ge=0, le=10000)
    min_balance_paise: int | None = Field(
        default=None, ge=-10_000_000_00, le=10_000_000_00
    )
    tds_rate_bp: int | None = Field(default=None, ge=0, le=10000)


class ZoneEntryRequest(_Body):
    entry_kind: Literal["add", "reduce", "credit_limit"]
    amount_paise: int | None = Field(default=None, gt=0, le=10_000_000_00)
    credit_limit_paise: int | None = Field(default=None, ge=0, le=10_000_000_00)
    mode: Literal["cash", "upi", "bank_transfer", "cheque", "adjustment"] | None = None
    reference: str | None = Field(default=None, max_length=100)
    note: str | None = Field(default=None, max_length=255)
    occurred_at: datetime | None = None

    @model_validator(mode="after")
    def _shape(self) -> ZoneEntryRequest:
        if self.entry_kind == "credit_limit":
            if self.credit_limit_paise is None:
                raise ValueError("credit_limit_paise is required")
        elif self.amount_paise is None:
            raise ValueError("amount_paise is required")
        return self


@finance_router.get("/finance/zones", dependencies=_ZONES + isp_guards(ISP_ZONES_READ))
async def list_zone_ledgers(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFinanceService = Depends(get_finance_service),
) -> dict:  # noqa: E501
    return ok(
        request,
        {"items": await svc.list_zone_ledgers(isp), "labels_only": True},
        "Zones",
    )


@finance_router.get(
    "/finance/zones/revenue", dependencies=_ZONES + isp_guards(ISP_ZONES_READ)
)
async def zone_revenue(
    request: Request,
    date_from: date,
    date_to: date,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFinanceService = Depends(get_finance_service),
) -> dict:  # noqa: E501
    if date_to < date_from or (date_to - date_from).days > 400:
        return JSONResponse(
            status_code=422,
            content=build_response(
                success=False,
                message="Range must be 0-400 days",
                data={"code": "ISP_FINANCE_INVALID"},
            ),
        )  # noqa: E501
    return ok(
        request,
        {"items": await svc.zone_revenue(isp, date_from=date_from, date_to=date_to)},
        "Zone revenue",
    )  # noqa: E501


@finance_router.get(
    "/finance/zones/tds-194h", dependencies=_ZONES + isp_guards(ISP_ZONES_READ)
)
async def zone_tds(
    request: Request,
    fy: str | None = Query(default=None, pattern=r"^\d{2}-\d{2}$"),
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFinanceService = Depends(get_finance_service),
) -> dict:  # noqa: E501
    return ok(request, await svc.tds_194h(isp, fy=fy), "TDS 194H statement data")


@finance_router.get(
    "/finance/zones/{zone_id}", dependencies=_ZONES + isp_guards(ISP_ZONES_READ)
)
async def zone_ledger(
    request: Request,
    zone_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFinanceService = Depends(get_finance_service),
) -> dict:  # noqa: E501
    return ok(request, await svc.zone_ledger(isp, zone_id), "Zone ledger")


@finance_router.put(
    "/finance/zones/{zone_id}/profile",
    dependencies=_ZONES + isp_guards(ISP_ZONES_MANAGE),
)  # noqa: E501
async def put_zone_profile(
    request: Request,
    zone_id: uuid.UUID,
    payload: ZoneProfileRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFinanceService = Depends(get_finance_service),
) -> dict:  # noqa: E501
    out = await svc.put_zone_profile(
        isp, zone_id, payload.model_dump(exclude_unset=True)
    )
    await svc.session.commit()
    return ok(request, out, "Zone saved")


@finance_router.post(
    "/finance/zones/{zone_id}/entries",
    status_code=201,
    dependencies=_ZONES + isp_guards(ISP_ZONES_MANAGE),
)  # noqa: E501
async def zone_entry(
    request: Request,
    zone_id: uuid.UUID,
    payload: ZoneEntryRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFinanceService = Depends(get_finance_service),
) -> dict:  # noqa: E501
    out = await svc.zone_entry(isp, zone_id, payload.model_dump())
    await svc.session.commit()
    return ok(request, out, "Ledger entry recorded")


# ---------------------------------------------------------------------------
# automation settings, message log, Telegram test, pay links
# ---------------------------------------------------------------------------


class TemplateSpec(_Body):
    template_name: str | None = Field(default=None, max_length=512)
    language: str | None = Field(default="en", max_length=15)


class AutomationRequest(_Body):
    whatsapp_enabled: bool | None = None
    whatsapp_templates: dict[str, TemplateSpec | None] | None = None
    pre_expiry_days: int | None = Field(default=None, ge=0, le=15)
    unpaid_reminder_after_days: int | None = Field(default=None, ge=0, le=60)
    telegram_enabled: bool | None = None
    telegram_bot_token: str | None = Field(
        default=None, max_length=100, pattern=r"^$|^\d{5,12}:[A-Za-z0-9_-]{30,60}$"
    )  # noqa: E501
    telegram_chat_id: str | None = Field(
        default=None, max_length=64, pattern=r"^-?\d{3,20}$|^@[A-Za-z0-9_]{4,60}$"
    )  # noqa: E501
    telegram_debounce_minutes: int | None = Field(default=None, ge=0, le=120)
    telegram_include_aps: bool | None = None


@finance_router.get("/finance/automation", dependencies=isp_guards(ISP_BILLING_READ))
async def get_automation(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:  # noqa: E501
    return ok(
        request,
        auto.settings_view(await auto.automation_settings(db, isp.isp_org_id)),
        "Automation",
    )  # noqa: E501


@finance_router.put("/finance/automation", dependencies=isp_guards(ISP_BILLING_MANAGE))
async def put_automation(
    request: Request,
    payload: AutomationRequest,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:  # noqa: E501
    from .finance_config import get_finance_settings

    data = payload.model_dump(exclude_unset=True)
    flags = get_finance_settings()
    if data.get("whatsapp_enabled") and not flags.whatsapp_automation_enabled:
        raise auto.IspAutomationError("WhatsApp automation is not available yet")
    if data.get("telegram_enabled") and not flags.telegram_alerts_enabled:
        raise auto.IspAutomationError("Telegram alerts are not available yet")
    if "whatsapp_templates" in data and data["whatsapp_templates"] is not None:
        data["whatsapp_templates"] = {
            k: (v.model_dump() if hasattr(v, "model_dump") else v)
            for k, v in payload.whatsapp_templates.items()
        }
    out = await auto.put_settings(db, isp, data)
    await db.commit()
    return ok(request, out, "Automation saved")


@finance_router.post(
    "/finance/automation/telegram/test",
    dependencies=_TG + isp_guards(ISP_MONITOR_UPDATE),
)  # noqa: E501
async def telegram_test(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:  # noqa: E501
    out = await auto.telegram_test(db, isp)
    await db.commit()
    return ok(request, out, "Telegram test")


# RBAC-FIX (founder 2026-11-01): the message log carries recipient phone/email
# and content -> owner/admin/billing (isp_billing.export), like COMMS-2 logs.
@finance_router.get("/finance/messages", dependencies=isp_guards(ISP_BILLING_EXPORT))
async def message_log(
    request: Request,
    channel: Literal["email", "whatsapp", "telegram"] | None = None,
    trigger: str | None = Query(default=None, max_length=16),
    status: Literal["queued", "sent", "failed", "skipped"] | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    items, total = await auto.list_log(
        db,
        isp,
        channel=channel,
        trigger=trigger,
        status=status,
        page=page,
        page_size=page_size,
    )  # noqa: E501
    return ok(request, make_page(items, total, page, page_size), "Messages")


@finance_router.get(
    "/finance/monitor/alerts-state", dependencies=_TG + isp_guards(ISP_MONITOR_READ)
)  # noqa: E501
async def alert_state(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:  # noqa: E501
    from sqlalchemy import select

    from .finance_models import IspAlertDeviceState

    rows = (
        (
            await db.execute(
                select(IspAlertDeviceState).where(
                    IspAlertDeviceState.isp_organization_id == isp.isp_org_id
                )  # noqa: E501
            )
        )
        .scalars()
        .all()
    )
    return ok(
        request,
        {
            "items": [
                {
                    "device_kind": r.device_kind,
                    "device_id": str(r.device_id),
                    "observed_status": r.observed_status,
                    "observed_since": r.observed_since.isoformat(),
                    "notified_status": r.notified_status,
                }
                for r in rows
            ]
        },
        "Alert state",
    )


@finance_router.post(
    "/finance/invoices/{invoice_id}/pay-link",
    dependencies=_WA + isp_guards(ISP_INVOICES_EXECUTE),
)  # noqa: E501
async def make_pay_link(
    request: Request,
    invoice_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFinanceService = Depends(get_finance_service),
) -> dict:  # noqa: E501
    inv = await svc.billing._invoice(isp, invoice_id)
    url = await auto.pay_link_for(svc.session, isp.isp_org_id, inv.id)
    await svc.session.commit()
    return ok(request, {"url": url}, "Pay link")


# -- public: the pay page (no auth; flag-gated; per-IP limited) --------------

public_pay_router = APIRouter(tags=["ISP Partner: public pay page"])


@public_pay_router.get("/public/pay/{token}", dependencies=_WA)
async def public_pay(
    request: Request,
    token: str,
    db: AsyncSession = Depends(get_db_session),
    redis: Any = Depends(get_redis_client),
) -> Any:
    from .portal_support_router import _ip_allowed

    allowed, retry = await _ip_allowed(
        redis, request.client.host if request.client else "-"
    )
    if not allowed:
        return JSONResponse(
            status_code=429,
            content=build_response(
                success=False,
                message="Too many requests",
                data={"code": "RATE_LIMITED"},
                request_id=request_id(request),
            ),
            headers={"Retry-After": str(retry)},
        )  # noqa: E501
    view = await auto.public_pay_view(db, token)
    if view is None:
        return JSONResponse(
            status_code=404,
            content=build_response(
                success=False,
                message="This payment link is not valid or has expired",
                data={"code": "ISP_PAY_LINK_NOT_FOUND"},
                request_id=request_id(request),
            ),
        )  # noqa: E501
    await db.commit()
    return ok(request, view, "Invoice")
