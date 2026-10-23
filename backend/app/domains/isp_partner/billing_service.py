"""ISP billing: cash first (ADDENDUM_01 §B.3) on the unified invoice model
(ADDENDUM_03 Part A, customer invoices).

* Numbers are ``{prefix}/{fy}/{seq}`` from ``isp_invoice_sequences`` under
  ``SELECT ... FOR UPDATE`` in the issuing transaction: gap-free per ISP,
  series and Indian FY, and a rollback takes the increment with it.
* No drafts carry numbers; nothing is ever deleted. Cancelling is a credit
  note (its own series) against the invoice.
* Every read and write resolves the customer through ``IspScope`` first, so
  another ISP's (or an out-of-confinement) invoice or payment is a 404.
* Money is integer paise.
"""

from __future__ import annotations

import calendar
import uuid
from datetime import UTC, date, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import func, or_, select
from sqlalchemy.dialects.postgresql import insert

from app.common.masking import mask_identifier

from .billing_models import (
    IspBillingSettings,
    IspCustomerBilling,
    IspInvoice,
    IspInvoiceLine,
    IspInvoiceReminder,
    IspInvoiceSequence,
    IspPayment,
    IspPaymentAllocation,
    IspZone,
)
from .dependencies import IspContext
from .exceptions import (
    IspBillingNotConfiguredError,
    IspBuyerGstinInvalidError,
    IspCreditExceedsBalanceError,
    IspCustomerNotFoundError,
    IspInvoiceCancelledError,
    IspInvoiceDateOutOfRangeError,
    IspInvoiceNotFoundError,
    IspInvoicePaidError,
    IspInvoicePrefixTooLongError,
    IspPaymentModeInvalidError,
    IspPaymentNotFoundError,
    IspPaymentReferenceRequiredError,
    IspSellerGstinInvalidError,
    IspZoneInUseError,
    IspZoneNotFoundError,
)
from .gst import (
    INVOICE_PREFIX,
    LineTax,
    compute_line,
    document_number,
    fiscal_year,
    fy_start,
    gstin_valid,
    receipt_number,
    sum_lines,
)
from .models import IspCustomerProfile
from .scoping import IspScope

PAYMENT_MODES = frozenset({"cash", "upi", "bank_transfer", "online"})
REFERENCE_REQUIRED = frozenset({"upi", "bank_transfer"})
#: Part B: internal-only mode for coupon activations (never via the API).
PREPAID_COUPON = "prepaid_coupon"
CYCLE_MONTHS = {"monthly": 1, "quarterly": 3, "half_yearly": 6, "yearly": 12}
STATUS_LABELS = {
    "issued": "Unpaid",
    "partially_paid": "Partially paid",
    "paid": "Paid",
    "cancelled": "Cancelled",
}
SETTINGS_FIELDS = (
    "legal_name",
    "gstin",
    "state_code",
    "address",
    "invoice_prefix",
    "credit_note_prefix",
    "receipt_prefix",
    "gst_enabled",
    "gst_rate_bp",
    "sac_code",
    "upi_vpa",
    "payee_name",
    "default_due_days",
    "grace_days",
    "auto_suspend_enabled",
    "auto_suspend_after_days",
    "coupon_invoice_on_activation",
    "reminder_days_before_expiry",
    "invoice_footer",
)
PLAN_FIELDS = (
    "plan_name",
    "amount_paise",
    "price_includes_gst",
    "billing_cycle",
    "anchor_day",
    "next_invoice_date",
    "gst_applicable",
    "place_of_supply_state_code",
    "buyer_gstin",
    "active",
    "notes",
)


def add_months(day: date, months: int, anchor: int | None = None) -> date:
    month = day.month - 1 + months
    year = day.year + month // 12
    month = month % 12 + 1
    target = anchor or day.day
    return date(year, month, min(target, calendar.monthrange(year, month)[1]))


def balance_of(inv: Any) -> int:
    return max(0, inv.total_paise - inv.paid_paise - inv.credit_noted_paise)


def status_for(inv: Any) -> str:
    if inv.status == "cancelled":
        return "cancelled"
    if inv.credit_noted_paise >= inv.total_paise and inv.paid_paise == 0:
        return "cancelled"
    if balance_of(inv) == 0:
        return "paid"
    if inv.paid_paise > 0 or inv.credit_noted_paise > 0:
        return "partially_paid"
    return "issued"


def iso(v: Any) -> Any:
    return v.isoformat() if hasattr(v, "isoformat") else v


class IspBillingService:
    def __init__(self, *, session: Any, audit: Any = None, clock: Any = None) -> None:
        self.session = session
        self.audit = audit
        self._clock = clock or (lambda: datetime.now(UTC))

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def today(self, isp: IspContext) -> date:
        return (
            self._clock()
            .astimezone(ZoneInfo(isp.organization.timezone or "Asia/Kolkata"))
            .date()
        )

    async def _audit(
        self, isp: IspContext, action: str, entity_id, customer_id=None, **meta
    ) -> None:
        if self.audit is None:
            return
        await self.audit.create_audit_log_entry(
            actor_user_id=isp.user_id,
            action=action,
            entity_type="isp_billing",
            entity_id=entity_id,
            description=action.replace("_", " "),
            event_metadata={
                "console": "isp",
                "isp_organization_id": str(isp.isp_org_id),
                **meta,
            },
            organization_id=customer_id or isp.isp_org_id,
            location_id=None,
        )

    async def settings(
        self, isp: IspContext, *, required: bool = True
    ) -> IspBillingSettings | None:
        row = (
            await self.session.execute(
                select(IspBillingSettings).where(
                    IspBillingSettings.isp_organization_id == isp.isp_org_id,
                    IspBillingSettings.is_deleted.is_(False),
                )
            )
        ).scalar_one_or_none()
        if row is None and required:
            raise IspBillingNotConfiguredError()
        return row

    async def _allocate(self, isp_org_id: uuid.UUID, series: str, fy: str) -> int:
        """Gap-free: lock the (isp, series, fy) row, take, increment, all in
        the caller's transaction."""
        now = datetime.now(UTC)
        await self.session.execute(
            insert(IspInvoiceSequence)
            .values(
                id=uuid.uuid4(),
                isp_organization_id=isp_org_id,
                series=series,
                fy=fy,
                next_value=1,
                is_deleted=False,
                version=1,
                created_at=now,
                updated_at=now,
            )
            .on_conflict_do_nothing(
                index_elements=["isp_organization_id", "series", "fy"]
            )
        )
        row = (
            await self.session.execute(
                select(IspInvoiceSequence)
                .where(
                    IspInvoiceSequence.isp_organization_id == isp_org_id,
                    IspInvoiceSequence.series == series,
                    IspInvoiceSequence.fy == fy,
                )
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        ).scalar_one()
        value = row.next_value
        row.next_value = value + 1
        await self.session.flush()
        return value

    async def _customer(self, isp: IspContext, isp_customer_id: uuid.UUID) -> Any:
        return await IspScope.assert_customer(isp, isp_customer_id)

    async def _invoice(self, isp: IspContext, invoice_id: uuid.UUID) -> IspInvoice:
        inv = await self.session.get(IspInvoice, invoice_id)
        if inv is None or inv.is_deleted or inv.isp_organization_id != isp.isp_org_id:
            raise IspInvoiceNotFoundError()
        try:
            await IspScope.assert_customer(isp, inv.customer_organization_id)
        except IspCustomerNotFoundError:
            raise IspInvoiceNotFoundError() from None
        return inv

    async def _payment(self, isp: IspContext, payment_id: uuid.UUID) -> IspPayment:
        pay = await self.session.get(IspPayment, payment_id)
        if pay is None or pay.is_deleted or pay.isp_organization_id != isp.isp_org_id:
            raise IspPaymentNotFoundError()
        try:
            await IspScope.assert_customer(isp, pay.customer_organization_id)
        except IspCustomerNotFoundError:
            raise IspPaymentNotFoundError() from None
        return pay

    # ------------------------------------------------------------------
    # settings / plan / zones
    # ------------------------------------------------------------------
    @staticmethod
    def settings_view(row: IspBillingSettings | None) -> dict | None:
        if row is None:
            return None
        return {f: iso(getattr(row, f)) for f in SETTINGS_FIELDS}

    async def put_settings(self, isp: IspContext, data: dict) -> dict:
        for key in ("invoice_prefix", "credit_note_prefix"):
            if (
                key in data
                and data[key] is not None
                and not INVOICE_PREFIX.match(data[key])
            ):
                raise IspInvoicePrefixTooLongError(field=key)
        if data.get("gstin") and not gstin_valid(data["gstin"]):
            raise IspSellerGstinInvalidError(field="gstin")
        row = await self.settings(isp, required=False)
        if row is None:
            if not data.get("legal_name") or not data.get("state_code"):
                raise IspBillingNotConfiguredError(
                    "legal_name and state_code are required"
                )
            row = IspBillingSettings(
                isp_organization_id=isp.isp_org_id, created_by=isp.user_id
            )
            self.session.add(row)
        nullable = {
            "gstin",
            "address",
            "upi_vpa",
            "payee_name",
            "auto_suspend_after_days",
            "invoice_footer",
        }
        for key in SETTINGS_FIELDS:
            if key in data and (data[key] is not None or key in nullable):
                setattr(row, key, data[key])
        row.updated_by = isp.user_id
        await self.session.flush()
        await self._audit(
            isp, "isp_billing_settings_updated", row.id, fields=sorted(data)
        )
        return self.settings_view(row)

    async def plan(
        self, isp: IspContext, isp_customer_id: uuid.UUID
    ) -> IspCustomerBilling | None:
        await self._customer(isp, isp_customer_id)
        return (
            await self.session.execute(
                select(IspCustomerBilling).where(
                    IspCustomerBilling.customer_organization_id == isp_customer_id,
                    IspCustomerBilling.is_deleted.is_(False),
                )
            )
        ).scalar_one_or_none()

    @staticmethod
    def plan_view(
        row: IspCustomerBilling | None, customer_id: uuid.UUID
    ) -> dict | None:
        """``None`` (200, ``data: null``) when the customer has no plan."""
        if row is None:
            return None
        return {
            "isp_customer_id": str(customer_id),
            **{f: iso(getattr(row, f)) for f in PLAN_FIELDS},
        }

    async def put_plan(
        self, isp: IspContext, isp_customer_id: uuid.UUID, data: dict
    ) -> dict:
        if data.get("buyer_gstin") and not gstin_valid(data["buyer_gstin"]):
            raise IspBuyerGstinInvalidError()
        row = await self.plan(isp, isp_customer_id)
        if row is None:
            row = IspCustomerBilling(
                customer_organization_id=isp_customer_id,
                isp_organization_id=isp.isp_org_id,
                created_by=isp.user_id,
            )
            if "next_invoice_date" not in data:
                data["next_invoice_date"] = self.today(isp)
            self.session.add(row)
        for key, value in data.items():
            if key in PLAN_FIELDS:
                setattr(row, key, value)
        if row.anchor_day is None:
            row.anchor_day = min(28, row.next_invoice_date.day)
        row.updated_by = isp.user_id
        await self.session.flush()
        return self.plan_view(row, isp_customer_id)

    async def list_zones(self, isp: IspContext) -> list[dict]:
        rows = (
            (
                await self.session.execute(
                    select(IspZone)
                    .where(
                        IspZone.isp_organization_id == isp.isp_org_id,
                        IspZone.is_deleted.is_(False),
                    )
                    .order_by(IspZone.name)
                )
            )
            .scalars()
            .all()
        )
        usage = dict(
            (
                await self.session.execute(
                    select(IspCustomerProfile.zone_id, func.count())
                    .where(
                        IspCustomerProfile.isp_organization_id == isp.isp_org_id,
                        IspCustomerProfile.zone_id.is_not(None),
                    )
                    .group_by(IspCustomerProfile.zone_id)
                )
            ).all()
        )
        return [self._zone_view(z, usage.get(z.id, 0)) for z in rows]

    @staticmethod
    def _zone_view(z: IspZone, used: int = 0) -> dict:
        return {
            "id": str(z.id),
            "name": z.name,
            "city": z.city,
            "state_code": z.state_code,
            "notes": z.notes,
            "customers": used,
        }

    async def zone(self, isp: IspContext, zone_id: uuid.UUID) -> IspZone:
        z = await self.session.get(IspZone, zone_id)
        if z is None or z.is_deleted or z.isp_organization_id != isp.isp_org_id:
            raise IspZoneNotFoundError()
        return z

    async def create_zone(self, isp: IspContext, data: dict) -> dict:
        z = IspZone(isp_organization_id=isp.isp_org_id, created_by=isp.user_id, **data)
        self.session.add(z)
        await self.session.flush()
        return self._zone_view(z)

    async def update_zone(
        self, isp: IspContext, zone_id: uuid.UUID, data: dict
    ) -> dict:
        z = await self.zone(isp, zone_id)
        for k, v in data.items():
            setattr(z, k, v)
        await self.session.flush()
        return self._zone_view(z)

    async def delete_zone(self, isp: IspContext, zone_id: uuid.UUID) -> None:
        z = await self.zone(isp, zone_id)
        used = (
            await self.session.execute(
                select(func.count()).where(IspCustomerProfile.zone_id == z.id)
            )
        ).scalar_one()
        invoiced = (
            await self.session.execute(
                select(func.count()).where(IspInvoice.zone_id == z.id)
            )
        ).scalar_one()
        if used or invoiced:
            raise IspZoneInUseError()
        z.mark_deleted()
        await self.session.flush()

    async def set_customer_zone(
        self, isp: IspContext, isp_customer_id: uuid.UUID, zone_id: uuid.UUID | None
    ) -> None:
        await self._customer(isp, isp_customer_id)
        if zone_id is not None:
            await self.zone(isp, zone_id)
        profile = (
            await self.session.execute(
                select(IspCustomerProfile).where(
                    IspCustomerProfile.customer_organization_id == isp_customer_id
                )
            )
        ).scalar_one_or_none()
        if profile is None:
            profile = IspCustomerProfile(
                isp_organization_id=isp.isp_org_id,
                customer_organization_id=isp_customer_id,
            )
            self.session.add(profile)
        profile.zone_id = zone_id
        await self.session.flush()

    # ------------------------------------------------------------------
    # issuing
    # ------------------------------------------------------------------
    async def _place_of_supply(self, settings, customer_id, plan, zone_id) -> str:
        if plan is not None and plan.place_of_supply_state_code:
            return plan.place_of_supply_state_code
        if zone_id is not None:
            z = await self.session.get(IspZone, zone_id)
            if z is not None and z.state_code:
                return z.state_code
        return settings.state_code

    async def _existing_source(
        self, isp: IspContext, source_key: str | None
    ) -> IspInvoice | None:
        if not source_key:
            return None
        return (
            await self.session.execute(
                select(IspInvoice).where(
                    IspInvoice.isp_organization_id == isp.isp_org_id,
                    IspInvoice.source_key == source_key,
                )
            )
        ).scalar_one_or_none()

    def _check_issue_date(self, isp: IspContext, issue_date: date | None) -> date:
        today = self.today(isp)
        issue_date = issue_date or today
        if (
            issue_date > today
            or today - issue_date > timedelta(days=7)
            or fy_start(issue_date) != fy_start(today)
        ):
            raise IspInvoiceDateOutOfRangeError()
        return issue_date

    async def issue_invoice(
        self,
        isp: IspContext,
        isp_customer_id: uuid.UUID,
        *,
        lines: list[dict],
        invoice_kind: str,
        issue_date: date | None = None,
        due_date: date | None = None,
        period_start: date | None = None,
        period_end: date | None = None,
        description: str | None = None,
        po_number: str | None = None,
        buyer_gstin: str | None = None,
        source_key: str | None = None,
    ) -> IspInvoice:
        customer = await self._customer(isp, isp_customer_id)
        settings = await self.settings(isp)
        existing = await self._existing_source(isp, source_key)
        if existing is not None:
            return existing
        issue_date = self._check_issue_date(isp, issue_date)
        if buyer_gstin and not gstin_valid(buyer_gstin):
            raise IspBuyerGstinInvalidError()
        plan = (
            await self.session.execute(
                select(IspCustomerBilling).where(
                    IspCustomerBilling.customer_organization_id == customer.id
                )
            )
        ).scalar_one_or_none()
        profile = (
            await self.session.execute(
                select(IspCustomerProfile).where(
                    IspCustomerProfile.customer_organization_id == customer.id
                )
            )
        ).scalar_one_or_none()
        zone_id = profile.zone_id if profile is not None else None
        pos = await self._place_of_supply(settings, customer.id, plan, zone_id)
        return await self._issue_core(
            isp,
            settings,
            bill_to_kind="customer",
            customer_organization_id=customer.id,
            subscriber=None,
            bill_to_name=customer.legal_name or customer.name,
            bill_to_gstin=buyer_gstin or (plan.buyer_gstin if plan else None),
            bill_to_address=(
                ", ".join(
                    p
                    for p in (
                        getattr(profile, "address_line1", None),
                        getattr(profile, "city", None),
                        getattr(profile, "state_province", None),
                        getattr(profile, "postal_code", None),
                    )
                    if p
                )
                or None
            ),
            pos=pos,
            zone_id=zone_id,
            gst_applied=bool(
                settings.gst_enabled and (plan is None or plan.gst_applicable)
            ),
            lines=lines,
            invoice_kind=invoice_kind,
            issue_date=issue_date,
            due_date=due_date,
            period_start=period_start,
            period_end=period_end,
            description=description,
            po_number=po_number,
            source_key=source_key,
        )

    async def issue_subscriber_invoice(
        self,
        isp: IspContext,
        subscriber: Any,
        *,
        lines: list[dict],
        invoice_kind: str,
        issue_date: date | None = None,
        due_date: date | None = None,
        period_start: date | None = None,
        period_end: date | None = None,
        description: str | None = None,
        po_number: str | None = None,
        buyer_gstin: str | None = None,
        source_key: str | None = None,
    ) -> IspInvoice:
        """ADDENDUM_03 Part B: bill an end subscriber. The caller has already
        resolved ``subscriber`` through IspScope (it belongs to this ISP and
        to a customer the caller may see). ``customer_organization_id`` is
        the subscriber's venue, for scoping only; customer-billing paths
        (ledger, overdue, auto-suspend, advance credit) filter on
        ``bill_to_kind='customer'`` and never see these rows."""
        if subscriber.isp_organization_id != isp.isp_org_id:
            raise IspInvoiceNotFoundError()
        settings = await self.settings(isp)
        existing = await self._existing_source(isp, source_key)
        if existing is not None:
            return existing
        issue_date = self._check_issue_date(isp, issue_date)
        gstin = buyer_gstin or subscriber.gstin
        if gstin and not gstin_valid(gstin):
            raise IspBuyerGstinInvalidError()
        pos = subscriber.state_code or await self._place_of_supply(
            settings, subscriber.customer_organization_id, None, subscriber.zone_id
        )
        name = " ".join(
            p for p in (subscriber.first_name, subscriber.last_name) if p
        ) or (subscriber.display_name or mask_identifier(subscriber.identifier))
        return await self._issue_core(
            isp,
            settings,
            bill_to_kind="subscriber",
            customer_organization_id=subscriber.customer_organization_id,
            subscriber=subscriber,
            bill_to_name=name[:255],
            bill_to_gstin=gstin,
            bill_to_address=subscriber.address,
            pos=pos,
            zone_id=subscriber.zone_id,
            gst_applied=bool(settings.gst_enabled),
            lines=lines,
            invoice_kind=invoice_kind,
            issue_date=issue_date,
            due_date=due_date,
            period_start=period_start,
            period_end=period_end,
            description=description,
            po_number=po_number,
            source_key=source_key,
        )

    async def _issue_core(
        self,
        isp: IspContext,
        settings: IspBillingSettings,
        *,
        bill_to_kind: str,
        customer_organization_id: uuid.UUID,
        subscriber: Any,
        bill_to_name: str,
        bill_to_gstin: str | None,
        bill_to_address: str | None,
        pos: str,
        zone_id: uuid.UUID | None,
        gst_applied: bool,
        lines: list[dict],
        invoice_kind: str,
        issue_date: date,
        due_date: date | None,
        period_start: date | None,
        period_end: date | None,
        description: str | None,
        po_number: str | None,
        source_key: str | None,
    ) -> IspInvoice:
        intra = pos == settings.state_code
        taxes: list[LineTax] = []
        for line in lines:
            taxes.append(
                compute_line(
                    int(line["amount_paise"]) * int(line.get("quantity", 1)),
                    includes_gst=bool(line.get("price_includes_gst", False)),
                    gst_applied=gst_applied,
                    rate_bp=settings.gst_rate_bp,
                    intra_state=intra,
                )
            )
        totals = sum_lines(taxes)
        fy = fiscal_year(issue_date)
        seq = await self._allocate(isp.isp_org_id, "invoice", fy)
        number = document_number(settings.invoice_prefix, fy, seq)
        inv = IspInvoice(
            isp_organization_id=isp.isp_org_id,
            doc_type="invoice",
            bill_to_kind=bill_to_kind,
            customer_organization_id=customer_organization_id,
            subscriber_id=subscriber.id if subscriber is not None else None,
            bill_to_username=(
                mask_identifier(subscriber.identifier)
                if subscriber is not None
                else None
            ),
            circuit_id_snapshot=(
                subscriber.circuit_id if subscriber is not None else None
            ),
            fy=fy,
            seq=seq,
            number=number,
            invoice_kind=invoice_kind,
            source_key=source_key,
            issue_date=issue_date,
            due_date=due_date or issue_date + timedelta(days=settings.default_due_days),
            period_start=period_start,
            period_end=period_end,
            description=description,
            bill_to_name=bill_to_name,
            bill_to_gstin=bill_to_gstin,
            bill_to_address=bill_to_address,
            place_of_supply_state_code=pos,
            seller_state_code=settings.state_code,
            zone_id=zone_id,
            po_number=po_number,
            gst_applied=gst_applied,
            taxable_paise=totals.taxable,
            cgst_paise=totals.cgst,
            sgst_paise=totals.sgst,
            igst_paise=totals.igst,
            total_paise=totals.total,
            paid_paise=0,
            credit_noted_paise=0,
            status="issued",
            created_by=isp.user_id,
        )
        self.session.add(inv)
        await self.session.flush()
        for line, tax in zip(lines, taxes, strict=True):
            self.session.add(
                IspInvoiceLine(
                    invoice_id=inv.id,
                    description=line["description"],
                    sac_code=line.get("sac_code") or settings.sac_code,
                    quantity=int(line.get("quantity", 1)),
                    unit_amount_paise=int(line["amount_paise"]),
                    price_includes_gst=bool(line.get("price_includes_gst", False)),
                    taxable_paise=tax.taxable,
                    cgst_paise=tax.cgst,
                    sgst_paise=tax.sgst,
                    igst_paise=tax.igst,
                    total_paise=tax.total,
                    period_from=line.get("period_from"),
                    period_to=line.get("period_to"),
                    package_id=line.get("package_id"),
                )
            )
        await self.session.flush()
        await self._apply_credit(isp, inv)
        await self._audit(
            isp, "isp_invoice_issued", inv.id, customer_organization_id, number=number
        )
        return inv

    async def _apply_credit(self, isp: IspContext, inv: IspInvoice) -> None:
        """Advances/overpayments (``unallocated_paise``) auto-apply on issue."""
        credits = (
            (
                await self.session.execute(
                    select(IspPayment)
                    .where(
                        IspPayment.isp_organization_id == isp.isp_org_id,
                        # a customer's advance never pays a subscriber's bill
                        # (and vice versa): match the bill-to party exactly
                        (
                            IspPayment.subscriber_id == inv.subscriber_id
                            if inv.subscriber_id is not None
                            else (
                                (
                                    IspPayment.customer_organization_id
                                    == inv.customer_organization_id
                                )
                                & IspPayment.subscriber_id.is_(None)
                            )
                        ),
                        IspPayment.status == "confirmed",
                        IspPayment.unallocated_paise > 0,
                    )
                    .order_by(IspPayment.received_at, IspPayment.id)
                    .with_for_update()
                )
            )
            .scalars()
            .all()
        )
        for pay in credits:
            need = balance_of(inv)
            if need <= 0:
                break
            take = min(need, pay.unallocated_paise)
            self.session.add(
                IspPaymentAllocation(
                    payment_id=pay.id, invoice_id=inv.id, amount_paise=take
                )
            )
            pay.unallocated_paise -= take
            inv.paid_paise += take
        inv.status = status_for(inv)
        await self.session.flush()

    async def generate_due(self, isp: IspContext) -> list[IspInvoice]:
        """Cycle invoices for every active plan with ``next_invoice_date <=
        today``. Idempotent on ``cycle:<customer>:<period_start>``."""
        today = self.today(isp)
        children = set(await isp.child_ids())
        plans = (
            (
                await self.session.execute(
                    select(IspCustomerBilling)
                    .where(
                        IspCustomerBilling.isp_organization_id == isp.isp_org_id,
                        IspCustomerBilling.active.is_(True),
                        IspCustomerBilling.is_deleted.is_(False),
                        IspCustomerBilling.next_invoice_date <= today,
                    )
                    .with_for_update()
                )
            )
            .scalars()
            .all()
        )
        created = []
        for plan in plans:
            if plan.customer_organization_id not in children or plan.amount_paise <= 0:
                continue
            start = plan.next_invoice_date
            end = add_months(
                start, CYCLE_MONTHS.get(plan.billing_cycle, 1), plan.anchor_day
            ) - timedelta(days=1)
            inv = await self.issue_invoice(
                isp,
                plan.customer_organization_id,
                lines=[
                    {
                        "description": f"{plan.plan_name} ({start:%d %b %Y} - {end:%d %b %Y})",  # noqa: E501
                        "amount_paise": plan.amount_paise,
                        "price_includes_gst": plan.price_includes_gst,
                        "period_from": start,
                        "period_to": end,
                    }
                ],
                invoice_kind="cycle",
                issue_date=today,
                period_start=start,
                period_end=end,
                description=plan.plan_name,
                source_key=f"cycle:{plan.customer_organization_id}:{start.isoformat()}",
            )
            plan.next_invoice_date = end + timedelta(days=1)
            created.append(inv)
        await self.session.flush()
        created.extend(await self.generate_subscriber_cycles(isp, children))
        return created

    #: catch-up bound per subscriber per run (a long-dormant postpaid row
    #: never floods the series in one go; the next daily run continues)
    MAX_CYCLES_PER_RUN = 12

    async def generate_subscriber_cycles(
        self, isp: IspContext, children: set
    ) -> list[IspInvoice]:
        """BE-I12: postpaid subscribers whose period ended get the period's
        invoice and roll forward one validity period. Idempotent on
        ``cycle:<subscriber>:<period_start>``. Prepaid never auto-invoices."""
        from .plans_models import IspPackage, IspSubscriber

        now = self._clock()
        tz = ZoneInfo(isp.organization.timezone or "Asia/Kolkata")
        rows = (
            await self.session.execute(
                select(IspSubscriber, IspPackage)
                .join(IspPackage, IspPackage.id == IspSubscriber.package_id)
                .where(
                    IspSubscriber.isp_organization_id == isp.isp_org_id,
                    IspSubscriber.is_deleted.is_(False),
                    IspSubscriber.status != "disabled",
                    IspSubscriber.valid_until.is_not(None),
                    IspSubscriber.valid_until <= now,
                    IspPackage.type == "postpaid",
                )
                .with_for_update(of=IspSubscriber)
            )
        ).all()
        created: list[IspInvoice] = []
        for sub, pkg in rows:
            if sub.customer_organization_id not in children:
                continue
            for _ in range(self.MAX_CYCLES_PER_RUN):
                if sub.valid_until > now:
                    break
                end_at = sub.valid_until
                start_at = end_at - timedelta(days=pkg.validity_days)
                start = start_at.astimezone(tz).date()
                end = (end_at.astimezone(tz) - timedelta(seconds=1)).date()
                if pkg.price_paise > 0:
                    created.append(
                        await self.issue_subscriber_invoice(
                            isp,
                            sub,
                            lines=[
                                {
                                    "description": f"{pkg.name} ({start:%d %b %Y} - {end:%d %b %Y})",  # noqa: E501
                                    "amount_paise": pkg.price_paise,
                                    "price_includes_gst": pkg.price_includes_gst,
                                    "period_from": start,
                                    "period_to": end,
                                    "package_id": pkg.id,
                                }
                            ],
                            invoice_kind="cycle",
                            period_start=start,
                            period_end=end,
                            description=pkg.name,
                            source_key=f"cycle:{sub.id}:{start.isoformat()}",
                        )
                    )
                sub.valid_until = end_at + timedelta(days=pkg.validity_days)
            if sub.valid_until > now and sub.status == "expired":
                sub.status = "active"
        await self.session.flush()
        return created

    async def credit_note(
        self,
        isp: IspContext,
        invoice_id: uuid.UUID,
        *,
        amount_paise: int | None,
        reason: str,
    ) -> IspInvoice:
        inv = await self._invoice(isp, invoice_id)
        if inv.doc_type != "invoice":
            raise IspInvoiceNotFoundError()
        if inv.status == "cancelled":
            raise IspInvoiceCancelledError()
        balance = balance_of(inv)
        amount = balance if amount_paise is None else int(amount_paise)
        if amount <= 0 or amount > balance:
            raise IspCreditExceedsBalanceError()
        settings = await self.settings(isp)
        today = self.today(isp)
        fy = fiscal_year(today)
        seq = await self._allocate(isp.isp_org_id, "credit_note", fy)
        number = document_number(settings.credit_note_prefix, fy, seq)

        # Tax split proportional to the invoice's, remainder to taxable.
        def part(x: int) -> int:
            return (x * amount) // inv.total_paise if inv.total_paise else 0

        cgst, sgst, igst = (
            part(inv.cgst_paise),
            part(inv.sgst_paise),
            part(inv.igst_paise),
        )
        note = IspInvoice(
            isp_organization_id=isp.isp_org_id,
            doc_type="credit_note",
            bill_to_kind=inv.bill_to_kind,
            customer_organization_id=inv.customer_organization_id,
            subscriber_id=inv.subscriber_id,
            bill_to_username=inv.bill_to_username,
            circuit_id_snapshot=inv.circuit_id_snapshot,
            fy=fy,
            seq=seq,
            number=number,
            invoice_kind="manual",
            issue_date=today,
            due_date=today,
            description=f"Against invoice {inv.number}: {reason}"[:255],
            bill_to_name=inv.bill_to_name,
            bill_to_gstin=inv.bill_to_gstin,
            bill_to_address=inv.bill_to_address,
            place_of_supply_state_code=inv.place_of_supply_state_code,
            seller_state_code=inv.seller_state_code,
            zone_id=inv.zone_id,
            gst_applied=inv.gst_applied,
            taxable_paise=amount - cgst - sgst - igst,
            cgst_paise=cgst,
            sgst_paise=sgst,
            igst_paise=igst,
            total_paise=amount,
            paid_paise=0,
            credit_noted_paise=0,
            credit_note_for_invoice_id=inv.id,
            status="paid",
            cancelled_reason=reason,
            created_by=isp.user_id,
        )
        self.session.add(note)
        inv.credit_noted_paise += amount
        inv.status = status_for(inv)
        if inv.status == "cancelled":
            inv.cancelled_reason = reason
        await self.session.flush()
        await self._audit(
            isp,
            "isp_credit_note_issued",
            note.id,
            inv.customer_organization_id,
            invoice=inv.number,
            amount_paise=amount,
        )
        return note

    # ------------------------------------------------------------------
    # payments
    # ------------------------------------------------------------------
    async def subscriber_in_scope(
        self, isp: IspContext, subscriber_id: uuid.UUID
    ) -> Any:
        from .plans_models import IspSubscriber
        from .plans_service import IspSubscriberNotFoundError

        s = await self.session.get(IspSubscriber, subscriber_id)
        if s is None or s.is_deleted or s.isp_organization_id != isp.isp_org_id:
            raise IspSubscriberNotFoundError()
        try:
            await IspScope.assert_customer(isp, s.customer_organization_id)
        except IspCustomerNotFoundError:
            raise IspSubscriberNotFoundError() from None
        return s

    async def record_payment(
        self,
        isp: IspContext,
        *,
        amount_paise: int,
        mode: str,
        isp_customer_id: uuid.UUID | None = None,
        subscriber_id: uuid.UUID | None = None,
        invoice_id: uuid.UUID | None = None,
        reference: str | None = None,
        received_at: datetime | None = None,
        idempotency_key: str | None = None,
        coupon_batch_id: uuid.UUID | None = None,
        _internal_mode: bool = False,
    ) -> IspPayment:
        """Exactly one of ``isp_customer_id`` / ``subscriber_id`` (Part B).
        ``prepaid_coupon`` is never accepted from the API: only the coupon
        activation sync passes ``_internal_mode=True``."""
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
                return repeat
        if mode not in PAYMENT_MODES and not (
            _internal_mode and mode == PREPAID_COUPON
        ):
            raise IspPaymentModeInvalidError()
        if (isp_customer_id is None) == (subscriber_id is None):
            raise IspPaymentModeInvalidError(
                "Give exactly one of isp_customer_id or subscriber_id",
                field="isp_customer_id",
            )
        if mode in REFERENCE_REQUIRED and not (reference or "").strip():
            raise IspPaymentReferenceRequiredError()
        if amount_paise <= 0:
            raise IspPaymentModeInvalidError(
                "Amount must be positive", field="amount_paise"
            )
        subscriber = None
        if subscriber_id is not None:
            subscriber = await self.subscriber_in_scope(isp, subscriber_id)
            customer_id = subscriber.customer_organization_id
        else:
            customer_id = (await self._customer(isp, isp_customer_id)).id
        settings = await self.settings(isp)
        inv = None
        if invoice_id is not None:
            inv = await self._invoice(isp, invoice_id)
            if inv.doc_type != "invoice" or (
                inv.subscriber_id != subscriber_id
                if subscriber is not None
                else (
                    inv.customer_organization_id != customer_id
                    or inv.bill_to_kind != "customer"
                )
            ):
                raise IspInvoiceNotFoundError()
            if inv.status == "cancelled":
                raise IspInvoiceCancelledError()
            if balance_of(inv) == 0:
                raise IspInvoicePaidError()
        when = received_at or self._clock()
        fy = fiscal_year(
            when.astimezone(
                ZoneInfo(isp.organization.timezone or "Asia/Kolkata")
            ).date()
        )
        seq = await self._allocate(isp.isp_org_id, "receipt", fy)
        pay = IspPayment(
            isp_organization_id=isp.isp_org_id,
            customer_organization_id=customer_id,
            subscriber_id=subscriber_id,
            coupon_batch_id=coupon_batch_id,
            amount_paise=amount_paise,
            unallocated_paise=amount_paise,
            mode=mode,
            reference=(reference or None),
            received_at=when,
            recorded_by=isp.user_id,
            receipt_fy=fy,
            receipt_seq=seq,
            receipt_number=receipt_number(settings.receipt_prefix, fy, seq),
            status="confirmed",
            idempotency_key=idempotency_key,
            created_by=isp.user_id,
        )
        self.session.add(pay)
        await self.session.flush()
        if inv is not None:
            take = min(balance_of(inv), amount_paise)
            self.session.add(
                IspPaymentAllocation(
                    payment_id=pay.id, invoice_id=inv.id, amount_paise=take
                )
            )
            inv.paid_paise += take
            inv.status = status_for(inv)
            pay.unallocated_paise = amount_paise - take
            await self.session.flush()
        await self._audit(
            isp,
            "isp_payment_recorded",
            pay.id,
            customer_id,
            receipt=pay.receipt_number,
            mode=mode,
            amount_paise=amount_paise,
        )
        return pay

    async def void_invoice(
        self, isp: IspContext, invoice_id: uuid.UUID, *, reason: str
    ) -> IspInvoice:
        """1b "void": a credit note for the whole remaining balance, and the
        invoice is CANCELLED. Numbers are never reused. Without the explicit
        status, a partly paid invoice ended with balance 0 and read "paid"
        in lists, dues and exports (QA-008). Any payment already received
        stays recorded against it."""
        note = await self.credit_note(isp, invoice_id, amount_paise=None, reason=reason)
        inv = await self._invoice(isp, invoice_id)
        inv.status = "cancelled"
        await self.session.flush()
        return note

    async def void_payment(
        self, isp: IspContext, payment_id: uuid.UUID, *, reason: str
    ) -> IspPayment:
        pay = await self._payment(isp, payment_id)
        if pay.status == "voided":
            return pay
        allocations = (
            (
                await self.session.execute(
                    select(IspPaymentAllocation).where(
                        IspPaymentAllocation.payment_id == pay.id,
                        IspPaymentAllocation.is_deleted.is_(False),
                    )
                )
            )
            .scalars()
            .all()
        )
        for alloc in allocations:
            inv = await self.session.get(IspInvoice, alloc.invoice_id)
            inv.paid_paise -= alloc.amount_paise
            inv.status = status_for(inv)
            alloc.mark_deleted()
        pay.status = "voided"
        pay.voided_reason = reason
        pay.unallocated_paise = 0
        await self.session.flush()
        await self._audit(
            isp,
            "isp_payment_voided",
            pay.id,
            pay.customer_organization_id,
            reason=reason,
        )
        return pay

    # ------------------------------------------------------------------
    # ledger / dues
    # ------------------------------------------------------------------
    async def overdue_invoices(
        self,
        isp: IspContext,
        customer_ids: list[uuid.UUID],
        *,
        as_of: date | None = None,
        min_days: int = 0,
    ) -> list[IspInvoice]:
        if not customer_ids:
            return []
        settings = await self.settings(isp, required=False)
        grace = settings.grace_days if settings else 0
        as_of = as_of or self.today(isp)
        cutoff = as_of - timedelta(days=grace + min_days)
        rows = (
            (
                await self.session.execute(
                    select(IspInvoice).where(
                        IspInvoice.isp_organization_id == isp.isp_org_id,
                        IspInvoice.customer_organization_id.in_(customer_ids),
                        # subscriber bills never drive a customer's dues,
                        # attention or auto-suspend (Part B)
                        IspInvoice.bill_to_kind == "customer",
                        IspInvoice.doc_type == "invoice",
                        IspInvoice.status.in_(["issued", "partially_paid"]),
                        IspInvoice.due_date < cutoff,
                        IspInvoice.is_deleted.is_(False),
                    )
                )
            )
            .scalars()
            .all()
        )
        return [r for r in rows if balance_of(r) > 0]

    async def ledger(
        self, isp: IspContext, isp_customer_id: uuid.UUID, *, cut: bool
    ) -> dict:
        await self._customer(isp, isp_customer_id)
        invoices = (
            (
                await self.session.execute(
                    select(IspInvoice)
                    .where(
                        IspInvoice.isp_organization_id == isp.isp_org_id,
                        IspInvoice.customer_organization_id == isp_customer_id,
                        IspInvoice.bill_to_kind == "customer",
                        IspInvoice.is_deleted.is_(False),
                    )
                    .order_by(IspInvoice.issue_date.desc(), IspInvoice.seq.desc())
                )
            )
            .scalars()
            .all()
        )
        payments = (
            (
                await self.session.execute(
                    select(IspPayment)
                    .where(
                        IspPayment.isp_organization_id == isp.isp_org_id,
                        IspPayment.customer_organization_id == isp_customer_id,
                        IspPayment.subscriber_id.is_(None),
                        IspPayment.is_deleted.is_(False),
                    )
                    .order_by(IspPayment.received_at.desc())
                )
            )
            .scalars()
            .all()
        )
        billed = sum(
            i.total_paise - i.credit_noted_paise
            for i in invoices
            if i.doc_type == "invoice"
        )
        paid = sum(p.amount_paise for p in payments if p.status == "confirmed")
        overdue = await self.overdue_invoices(isp, [isp_customer_id])
        overdue_ids = {i.id for i in overdue}
        overdue_paise = sum(balance_of(i) for i in overdue)
        return {
            "isp_customer_id": str(isp_customer_id),
            "balance_paise": billed - paid,
            "overdue_paise": overdue_paise,
            "overdue_invoice_ids": [str(i.id) for i in overdue],
            "can_resume": cut and overdue_paise == 0,
            "invoices": [
                self.invoice_row(i, overdue=i.id in overdue_ids) for i in invoices
            ],
            "payments": await self.payment_rows(isp, list(payments)),
        }

    # ------------------------------------------------------------------
    # views
    # ------------------------------------------------------------------
    @staticmethod
    def invoice_row(
        inv: IspInvoice,
        customer_name: str | None = None,
        zone: dict | None = None,
        *,
        contact_phone: str | None = None,
        overdue: bool = False,
        subscriber: dict | None = None,
        package: dict | None = None,
    ) -> dict:
        is_sub = inv.bill_to_kind == "subscriber"
        if is_sub and subscriber is None:
            subscriber = {
                "id": str(inv.subscriber_id),
                "username": inv.bill_to_username,
                "first_name": None,
                "last_name": None,
                "circuit_id": inv.circuit_id_snapshot,
            }
        return {
            "id": str(inv.id),
            "display_id": inv.display_id,
            "number": inv.number,
            "doc_type": inv.doc_type,
            "created_at": iso(inv.created_at),
            "invoice_date": iso(inv.issue_date),
            "due_date": iso(inv.due_date),
            "bill_to_kind": inv.bill_to_kind,
            "subscriber": subscriber if is_sub else None,
            "customer": None
            if is_sub
            else {
                "isp_customer_id": str(inv.customer_organization_id),
                "name": customer_name or inv.bill_to_name,
                "contact_phone": contact_phone,
            },
            # subscriber rows: the venue (ISP customer) the subscriber is at
            "isp_customer_id": str(inv.customer_organization_id),
            "customer_name": customer_name or inv.bill_to_name,
            "overdue": overdue,
            "zone": zone,
            "invoice_kind": inv.invoice_kind,
            "package": package,
            "po_number": inv.po_number,
            "buyer_gstin": inv.bill_to_gstin,
            "taxable_paise": inv.taxable_paise,
            "cgst_paise": inv.cgst_paise,
            "sgst_paise": inv.sgst_paise,
            "igst_paise": inv.igst_paise,
            "total_paise": inv.total_paise,
            "paid_paise": inv.paid_paise,
            "credit_noted_paise": inv.credit_noted_paise,
            "balance_paise": balance_of(inv) if inv.doc_type == "invoice" else 0,
            "status": inv.status,
            "status_label": STATUS_LABELS.get(inv.status, inv.status),
            "credit_note_for_invoice_id": (
                str(inv.credit_note_for_invoice_id)
                if inv.credit_note_for_invoice_id
                else None
            ),
        }

    @staticmethod
    def payment_row(
        p: IspPayment,
        *,
        customer_name: str | None = None,
        invoice_number: str | None = None,
        recorded_by_name: str | None = None,
    ) -> dict:
        return {
            "id": str(p.id),
            "customer_name": customer_name,
            "invoice_number": invoice_number,
            "recorded_by_name": recorded_by_name,
            "isp_customer_id": str(p.customer_organization_id),
            "subscriber_id": str(p.subscriber_id) if p.subscriber_id else None,
            "coupon_batch_id": str(p.coupon_batch_id) if p.coupon_batch_id else None,
            "amount_paise": p.amount_paise,
            "unallocated_paise": p.unallocated_paise,
            "mode": p.mode,
            "reference": p.reference,
            "received_at": iso(p.received_at),
            "receipt_number": p.receipt_number,
            "recorded_by": (
                {"id": str(p.recorded_by), "name": recorded_by_name}
                if p.recorded_by
                else None
            ),
            "status": p.status,
            "voided_reason": p.voided_reason,
        }

    async def _user_names(self, ids: list) -> dict:
        from app.domains.auth.models import User

        wanted = [i for i in set(ids) if i]
        if not wanted:
            return {}
        rows = await self.session.execute(
            select(User.id, User.first_name, User.last_name).where(User.id.in_(wanted))
        )
        return {r[0]: f"{r[1]} {r[2]}".strip() for r in rows.all()}

    async def payment_rows(self, isp: IspContext, payments: list) -> list[dict]:
        from app.domains.organization.models import Organization

        names = await isp.repository.names(
            Organization, [p.customer_organization_id for p in payments]
        )
        recorders = await self._user_names([p.recorded_by for p in payments])
        allocs = {}
        if payments:
            rows = await self.session.execute(
                select(IspPaymentAllocation.payment_id, IspInvoice.number)
                .join(IspInvoice, IspInvoice.id == IspPaymentAllocation.invoice_id)
                .where(
                    IspPaymentAllocation.payment_id.in_([p.id for p in payments]),
                    IspPaymentAllocation.is_deleted.is_(False),
                )
            )
            for pid, number in rows.all():
                allocs.setdefault(pid, number)
        return [
            self.payment_row(
                p,
                customer_name=names.get(p.customer_organization_id),
                invoice_number=allocs.get(p.id),
                recorded_by_name=recorders.get(p.recorded_by),
            )
            for p in payments
        ]

    async def row_extras(self, invoices: list) -> tuple[dict, dict]:
        """Subscriber block + package for each invoice (Part B), batched:
        ``({invoice_id: subscriber dict}, {invoice_id: package dict})``."""
        from .plans_models import IspPackage, IspSubscriber

        subs: dict = {}
        sub_ids = list({i.subscriber_id for i in invoices if i.subscriber_id})
        if sub_ids:
            rows = {
                s.id: s
                for s in (
                    await self.session.execute(
                        select(IspSubscriber).where(IspSubscriber.id.in_(sub_ids))
                    )
                )
                .scalars()
                .all()
            }
            for i in invoices:
                s = rows.get(i.subscriber_id)
                if s is not None:
                    subs[i.id] = {
                        "id": str(s.id),
                        "username": i.bill_to_username or mask_identifier(s.identifier),
                        "first_name": s.first_name,
                        "last_name": s.last_name,
                        "circuit_id": i.circuit_id_snapshot or s.circuit_id,
                    }
        packages: dict = {}
        if invoices:
            rows = (
                await self.session.execute(
                    select(IspInvoiceLine.invoice_id, IspPackage.id, IspPackage.name)
                    .join(IspPackage, IspPackage.id == IspInvoiceLine.package_id)
                    .where(IspInvoiceLine.invoice_id.in_([i.id for i in invoices]))
                )
            ).all()
            for inv_id, pid, name in rows:
                packages.setdefault(inv_id, {"id": str(pid), "name": name})
        return subs, packages

    async def invoice_detail(self, isp: IspContext, invoice_id: uuid.UUID) -> dict:
        inv = await self._invoice(isp, invoice_id)
        lines = (
            (
                await self.session.execute(
                    select(IspInvoiceLine)
                    .where(IspInvoiceLine.invoice_id == inv.id)
                    .order_by(IspInvoiceLine.created_at)
                )
            )
            .scalars()
            .all()
        )
        allocs = (
            await self.session.execute(
                select(IspPaymentAllocation, IspPayment)
                .join(IspPayment, IspPayment.id == IspPaymentAllocation.payment_id)
                .where(
                    IspPaymentAllocation.invoice_id == inv.id,
                    IspPaymentAllocation.is_deleted.is_(False),
                )
            )
        ).all()
        notes = (
            (
                await self.session.execute(
                    select(IspInvoice).where(
                        IspInvoice.credit_note_for_invoice_id == inv.id
                    )
                )
            )
            .scalars()
            .all()
        )
        reminders = (
            (
                await self.session.execute(
                    select(IspInvoiceReminder).where(
                        IspInvoiceReminder.invoice_id == inv.id
                    )
                )
            )
            .scalars()
            .all()
        )
        customer = await isp.repository.get_organization(inv.customer_organization_id)
        overdue_ids = {
            i.id
            for i in await self.overdue_invoices(isp, [inv.customer_organization_id])
        }
        subs, packages = await self.row_extras([inv])
        view = self.invoice_row(
            inv,
            customer.name if customer else None,
            contact_phone=customer.contact_phone if customer else None,
            overdue=inv.id in overdue_ids,
            subscriber=subs.get(inv.id),
            package=packages.get(inv.id),
        )
        view["lines"] = [
            {
                "description": li.description,
                "sac_code": li.sac_code,
                "quantity": li.quantity,
                "unit_amount_paise": li.unit_amount_paise,
                "price_includes_gst": li.price_includes_gst,
                "taxable_paise": li.taxable_paise,
                "cgst_paise": li.cgst_paise,
                "sgst_paise": li.sgst_paise,
                "igst_paise": li.igst_paise,
                "total_paise": li.total_paise,
                "period_from": iso(li.period_from),
                "period_to": iso(li.period_to),
                "package_id": str(li.package_id) if li.package_id else None,
            }
            for li in lines
        ]
        view["place_of_supply_state_code"] = inv.place_of_supply_state_code
        view["seller_state_code"] = inv.seller_state_code
        recorders = await self._user_names([p.recorded_by for _, p in allocs])
        view["payments"] = [
            {
                "payment_id": str(p.id),
                "amount_paise": a.amount_paise,
                "mode": p.mode,
                "reference": p.reference,
                "received_at": iso(p.received_at),
                "recorded_by_name": recorders.get(p.recorded_by),
                "receipt_number": p.receipt_number,
                "status": p.status,
            }
            for a, p in allocs
        ]
        view["credit_notes"] = [
            {
                "id": str(n.id),
                "number": n.number,
                "amount_paise": n.total_paise,
                "reason": n.cancelled_reason,
                "created_at": iso(n.created_at),
            }
            for n in notes
        ]
        view["credit_note_for"] = None
        if inv.credit_note_for_invoice_id:
            orig = await self.session.get(IspInvoice, inv.credit_note_for_invoice_id)
            view["credit_note_for"] = (
                {"id": str(orig.id), "number": orig.number} if orig else None
            )
        view["reminders"] = [
            {"channel": r.channel, "status": r.status, "sent_at": iso(r.sent_at)}
            for r in reminders
        ]
        view["payment_link"] = None
        return view

    async def list_invoices(
        self,
        isp: IspContext,
        *,
        isp_customer_id: uuid.UUID | None = None,
        status: str | None = None,
        overdue: bool | None = None,
        zone_id: uuid.UUID | None = None,
        doc_type: str | None = None,
        since: date | None = None,
        until: date | None = None,
        search: str | None = None,
        bill_to_kind: str | None = None,
        subscriber_id: uuid.UUID | None = None,
        package_id: uuid.UUID | None = None,
        username: str | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[IspInvoice], int]:
        if isp_customer_id is not None:
            await self._customer(isp, isp_customer_id)
            ids = [isp_customer_id]
        else:
            ids = await isp.child_ids()
        if not ids:
            return [], 0
        cond = [
            IspInvoice.isp_organization_id == isp.isp_org_id,
            IspInvoice.customer_organization_id.in_(ids),
            IspInvoice.is_deleted.is_(False),
        ]
        if status:
            cond.append(IspInvoice.status == status)
        if doc_type:
            cond.append(IspInvoice.doc_type == doc_type)
        if bill_to_kind:
            cond.append(IspInvoice.bill_to_kind == bill_to_kind)
        if subscriber_id:
            cond.append(IspInvoice.subscriber_id == subscriber_id)
        if package_id:
            cond.append(
                IspInvoice.id.in_(
                    select(IspInvoiceLine.invoice_id).where(
                        IspInvoiceLine.package_id == package_id
                    )
                )
            )
        if username:
            from .plans_models import IspSubscriber

            # the snapshot is masked; match the real identifier, ISP-scoped
            cond.append(
                IspInvoice.subscriber_id.in_(
                    select(IspSubscriber.id).where(
                        IspSubscriber.isp_organization_id == isp.isp_org_id,
                        IspSubscriber.identifier.ilike(f"%{username.strip()}%"),
                    )
                )
            )
        if zone_id:
            cond.append(IspInvoice.zone_id == zone_id)
        if since:
            cond.append(IspInvoice.issue_date >= since)
        if until:
            cond.append(IspInvoice.issue_date <= until)
        if search:
            pattern = f"%{search.strip()}%"
            cond.append(
                or_(
                    IspInvoice.number.ilike(pattern),
                    IspInvoice.bill_to_name.ilike(pattern),
                    IspInvoice.bill_to_username.ilike(pattern),
                )
            )
        if overdue:
            overdue_ids = [i.id for i in await self.overdue_invoices(isp, ids)]
            if not overdue_ids:
                return [], 0
            cond.append(IspInvoice.id.in_(overdue_ids))
        total = (
            await self.session.execute(
                select(func.count()).select_from(IspInvoice).where(*cond)
            )
        ).scalar_one()
        rows = (
            (
                await self.session.execute(
                    select(IspInvoice)
                    .where(*cond)
                    .order_by(
                        IspInvoice.issue_date.desc(), IspInvoice.created_at.desc()
                    )
                    .offset((page - 1) * page_size)
                    .limit(page_size)
                )
            )
            .scalars()
            .all()
        )
        return list(rows), int(total)

    async def invoice_totals(self, isp: IspContext, **filters: Any) -> dict:
        """Totals over the WHOLE filtered set (not one page)."""
        rows, _ = await self.list_invoices(isp, page=1, page_size=1_000_000, **filters)
        invoices = [r for r in rows if r.doc_type == "invoice"]
        return {
            "invoiced_paise": sum(
                r.total_paise - r.credit_noted_paise for r in invoices
            ),
            "collected_paise": sum(r.paid_paise for r in invoices),
            "outstanding_paise": sum(balance_of(r) for r in invoices),
        }

    async def list_payments(
        self,
        isp: IspContext,
        *,
        isp_customer_id: uuid.UUID | None,
        page: int,
        page_size: int,
    ) -> tuple[list[IspPayment], int]:
        if isp_customer_id is not None:
            await self._customer(isp, isp_customer_id)
            ids = [isp_customer_id]
        else:
            ids = await isp.child_ids()
        if not ids:
            return [], 0
        cond = [
            IspPayment.isp_organization_id == isp.isp_org_id,
            IspPayment.customer_organization_id.in_(ids),
            IspPayment.is_deleted.is_(False),
        ]
        total = (
            await self.session.execute(
                select(func.count()).select_from(IspPayment).where(*cond)
            )
        ).scalar_one()
        rows = (
            (
                await self.session.execute(
                    select(IspPayment)
                    .where(*cond)
                    .order_by(IspPayment.received_at.desc())
                    .offset((page - 1) * page_size)
                    .limit(page_size)
                )
            )
            .scalars()
            .all()
        )
        return list(rows), int(total)

    # ------------------------------------------------------------------
    # reports
    # ------------------------------------------------------------------
    async def collections(
        self, isp: IspContext, *, group_by: str, since: date, until: date
    ) -> dict:
        ids = await isp.child_ids()
        rows: dict[str, dict] = {}
        if ids:
            invoices = (
                (
                    await self.session.execute(
                        select(IspInvoice).where(
                            IspInvoice.isp_organization_id == isp.isp_org_id,
                            IspInvoice.customer_organization_id.in_(ids),
                            IspInvoice.doc_type == "invoice",
                            IspInvoice.issue_date >= since,
                            IspInvoice.issue_date <= until,
                        )
                    )
                )
                .scalars()
                .all()
            )
            zone_names = {z["id"]: z["name"] for z in await self.list_zones(isp)}

            def key_inv(i):  # noqa: ANN001, ANN202
                if group_by == "zone":
                    return (
                        zone_names.get(str(i.zone_id), "No zone")
                        if i.zone_id
                        else "No zone"
                    )
                return f"{i.issue_date:%Y-%m}"

            for i in invoices:
                bucket = rows.setdefault(key_inv(i), self._bucket())
                bucket["invoiced_paise"] += i.total_paise - i.credit_noted_paise
                bucket["invoices"] += 1
            pays = (
                (
                    await self.session.execute(
                        select(IspPayment).where(
                            IspPayment.isp_organization_id == isp.isp_org_id,
                            IspPayment.customer_organization_id.in_(ids),
                            IspPayment.status == "confirmed",
                        )
                    )
                )
                .scalars()
                .all()
            )
            tz = ZoneInfo(isp.organization.timezone or "Asia/Kolkata")
            profiles = dict(
                (
                    await self.session.execute(
                        select(
                            IspCustomerProfile.customer_organization_id,
                            IspCustomerProfile.zone_id,
                        ).where(IspCustomerProfile.customer_organization_id.in_(ids))
                    )
                ).all()
            )
            for p in pays:
                day = p.received_at.astimezone(tz).date()
                if not since <= day <= until:
                    continue
                if group_by == "zone":
                    zid = profiles.get(p.customer_organization_id)
                    k = zone_names.get(str(zid), "No zone") if zid else "No zone"
                else:
                    k = f"{day:%Y-%m}"
                bucket = rows.setdefault(k, self._bucket())
                bucket["collected_paise"] += p.amount_paise
                bucket["by_mode"][p.mode] = (
                    bucket["by_mode"].get(p.mode, 0) + p.amount_paise
                )
                bucket["payments"] += 1
        out = [{"key": k, **v} for k, v in sorted(rows.items())]
        totals = self._bucket()
        for r in out:
            totals["invoiced_paise"] += r["invoiced_paise"]
            totals["collected_paise"] += r["collected_paise"]
            totals["invoices"] += r["invoices"]
            totals["payments"] += r["payments"]
            for m, v in r["by_mode"].items():
                totals["by_mode"][m] = totals["by_mode"].get(m, 0) + v
        return {
            "group_by": group_by,
            "since": since.isoformat(),
            "until": until.isoformat(),
            "rows": out,
            "totals": totals,
        }

    @staticmethod
    def _bucket() -> dict:
        return {
            "invoiced_paise": 0,
            "collected_paise": 0,
            "invoices": 0,
            "payments": 0,
            "by_mode": {
                "cash": 0,
                "upi": 0,
                "bank_transfer": 0,
                "online": 0,
                "prepaid_coupon": 0,
            },
        }

    async def outstanding(self, isp: IspContext, *, as_of: date) -> dict:
        ids = await isp.child_ids()
        buckets = {"0_30": 0, "31_60": 0, "61_90": 0, "90_plus": 0}
        debtors: dict[uuid.UUID, dict] = {}
        if ids:
            rows = (
                (
                    await self.session.execute(
                        select(IspInvoice).where(
                            IspInvoice.isp_organization_id == isp.isp_org_id,
                            IspInvoice.customer_organization_id.in_(ids),
                            IspInvoice.doc_type == "invoice",
                            IspInvoice.status.in_(["issued", "partially_paid"]),
                        )
                    )
                )
                .scalars()
                .all()
            )
            for i in rows:
                bal = balance_of(i)
                if bal <= 0 or i.issue_date > as_of:
                    continue
                age = (as_of - i.due_date).days
                key = (
                    "0_30"
                    if age <= 30
                    else "31_60"
                    if age <= 60
                    else "61_90"
                    if age <= 90
                    else "90_plus"
                )
                buckets[key] += bal
                d = debtors.setdefault(
                    i.customer_organization_id,
                    {
                        "customer": {
                            "isp_customer_id": str(i.customer_organization_id),
                            "name": i.bill_to_name,
                        },
                        "balance_paise": 0,
                        "oldest_due": i.due_date,
                    },
                )
                d["balance_paise"] += bal
                d["oldest_due"] = min(d["oldest_due"], i.due_date)
        top = sorted(debtors.values(), key=lambda d: -d["balance_paise"])[:10]
        for d in top:
            d["oldest_due"] = d["oldest_due"].isoformat()
        return {"as_of": as_of.isoformat(), "buckets": buckets, "top_debtors": top}
