"""JAZE-4 finance service: invoice template, product catalogue, package
billing plan + price preview, static-IP leases, security deposits, billing
contacts, invoice email, and the labels-only zone ledger.

Everything is scoped by ``isp.isp_org_id`` and, where a row belongs to a
customer or subscriber, by ``IspScope`` through ``IspBillingService`` (a
confined technician gets 404, another ISP gets 404). Invoices themselves are
only ever created through ``IspBillingService`` (its public API is
unchanged), so numbering, GST and the 1b/Part B rules stay in one place.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import and_, func, select

from app.core.logging import get_logger

from .billing_models import IspInvoice, IspPayment, IspPaymentAllocation, IspZone
from .billing_service import IspBillingService, add_months
from .dependencies import IspContext
from .exceptions import IspError
from .finance_models import (
    IspBillingContact,
    IspBillingProduct,
    IspInvoiceTemplate,
    IspPackageBilling,
    IspSecurityDeposit,
    IspStaticIpLease,
    IspZoneLedgerEntry,
    IspZoneProfile,
)
from .gst import compute_line, fiscal_year, fy_start, gstin_valid

logger = get_logger(__name__)

PAN_RE = re.compile(r"^[A-Z]{5}[0-9]{4}[A-Z]$")
IFSC_RE = re.compile(r"^[A-Z]{4}0[A-Z0-9]{6}$")
PINCODE_RE = re.compile(r"^[1-9][0-9]{5}$")
#: Section 194H threshold per financial year (Finance Act 2025: Rs 20,000).
TDS_194H_THRESHOLD_PAISE = 20_000_00


def lease_period(
    active_since: date,
    start: date,
    monthly_paise: int,
    *,
    active_until: date | None = None,
) -> tuple[date, int]:
    """BE-HARDEN: ``(period_end, amount_paise)`` of the lease period that
    starts on ``start``.

    Periods run anniversary to anniversary on ``active_since``'s day of month.
    Each anniversary is counted from ``active_since`` itself, never from the
    previous period, so a short month cannot drift the day. A lease from
    31 Jan bills 31 Jan-27 Feb, 28 Feb-30 Mar, 31 Mar-29 Apr, 30 Apr-30 May.
    The old rule stayed on the 28th forever.

    A full period bills the monthly amount. A partial one bills pro rata:
    days billed over the length of that anniversary period, rounded half up
    to the paisa. A period is partial when it is the last one, cut short by
    ``active_until``, or when it starts off-anniversary (a row billed under
    the old rule).
    """
    from .gst import round_half_up

    anchor = active_since.day
    k = 0
    lo = active_since
    hi = add_months(active_since, 1, anchor)
    while hi <= start:
        k += 1
        lo, hi = hi, add_months(active_since, k + 1, anchor)
    full_end = hi - timedelta(days=1)
    end = min(full_end, active_until) if active_until else full_end
    if start == lo and end == full_end:
        return end, int(monthly_paise)
    days = (end - start).days + 1
    return end, round_half_up(int(monthly_paise) * days, (hi - lo).days)


class IspFinanceNotFoundError(IspError):
    code = "ISP_FINANCE_NOT_FOUND"
    status_code_default = 404
    default_message = "Not found"


class IspFinanceValidationError(IspError):
    code = "ISP_FINANCE_INVALID"
    status_code_default = 422
    default_message = "Invalid value"


class IspStaticIpInUseError(IspError):
    code = "ISP_STATIC_IP_IN_USE"
    status_code_default = 409
    default_message = "That IP already has an active lease"


class IspDepositExceedsBalanceError(IspError):
    code = "ISP_DEPOSIT_EXCEEDS_BALANCE"
    status_code_default = 409
    default_message = "A refund or forfeit cannot exceed the deposit held"


class IspZoneCreditExceededError(IspError):
    code = "ISP_ZONE_CREDIT_EXCEEDED"
    status_code_default = 409
    default_message = "This debit would take the zone below its credit limit"


class IspNoRecipientError(IspError):
    code = "ISP_NO_RECIPIENT"
    status_code_default = 422
    default_message = "No email address on file for that choice"


def pan_valid(pan: str) -> bool:
    return bool(PAN_RE.match((pan or "").strip().upper()))


def _iso(v: Any) -> Any:
    return v.isoformat() if isinstance(v, date | datetime) else v


def _upper_or_none(v: str | None) -> str | None:
    v = (v or "").strip().upper()
    return v or None


class IspFinanceService:
    def __init__(self, *, session: Any, audit: Any = None, clock: Any = None) -> None:
        self.session = session
        self.billing = IspBillingService(session=session, audit=audit, clock=clock)
        self._clock = clock or (lambda: datetime.now(UTC))

    async def _audit(
        self, isp: IspContext, action: str, entity_id, customer_id=None, **meta
    ) -> None:  # noqa: ANN001,E501
        await self.billing._audit(isp, action, entity_id, customer_id, **meta)

    # ------------------------------------------------------------------
    # invoice template (bank details etc.)
    # ------------------------------------------------------------------
    TEMPLATE_FIELDS = (
        "bank_name",
        "bank_account_name",
        "bank_account_number",
        "bank_ifsc",
        "bank_branch",
        "website",
        "care_phone",
        "care_email",
        "pan",
        "licence_number",
        "terms",
        "show_bank_details",
        "show_zone_operator",
    )

    async def template(self, isp: IspContext) -> IspInvoiceTemplate | None:
        return (
            await self.session.execute(
                select(IspInvoiceTemplate).where(
                    IspInvoiceTemplate.isp_organization_id == isp.isp_org_id,
                    IspInvoiceTemplate.is_deleted.is_(False),
                )
            )
        ).scalar_one_or_none()

    def template_view(self, row: IspInvoiceTemplate | None) -> dict:
        if row is None:
            return {f: None for f in self.TEMPLATE_FIELDS} | {
                "show_bank_details": True,
                "show_zone_operator": True,
                "configured": False,
            }
        return {f: getattr(row, f) for f in self.TEMPLATE_FIELDS} | {
            "configured": True,
            "updated_at": _iso(row.updated_at),
        }

    async def put_template(self, isp: IspContext, data: dict) -> dict:
        if data.get("bank_ifsc"):
            data["bank_ifsc"] = data["bank_ifsc"].strip().upper()
            if not IFSC_RE.match(data["bank_ifsc"]):
                raise IspFinanceValidationError(
                    "IFSC must look like ABCD0123456", field="bank_ifsc"
                )
        if data.get("pan"):
            data["pan"] = data["pan"].strip().upper()
            if not pan_valid(data["pan"]):
                raise IspFinanceValidationError(
                    "PAN must look like ABCDE1234F", field="pan"
                )
        if data.get("bank_account_number"):
            acct = re.sub(r"\s", "", data["bank_account_number"])
            if not re.fullmatch(r"[0-9A-Za-z]{6,34}", acct):
                raise IspFinanceValidationError(
                    "Account number must be 6-34 letters or digits",
                    field="bank_account_number",
                )
            data["bank_account_number"] = acct
        row = await self.template(isp)
        if row is None:
            row = IspInvoiceTemplate(
                isp_organization_id=isp.isp_org_id, created_by=isp.user_id
            )
            self.session.add(row)
        for k, v in data.items():
            if k in self.TEMPLATE_FIELDS:
                setattr(row, k, v)
        row.updated_by = isp.user_id
        await self.session.flush()
        await self._audit(isp, "isp_invoice_template_updated", row.id)
        return self.template_view(row)

    async def seller_extras(self, isp: IspContext, invoice: Any | None = None) -> dict:
        """Extra fields merged into the PDF ``seller`` dict: bank details,
        contact fields, and -- for an invoice with a zone -- the zone's
        operator name/phone. Empty dict when nothing is configured, so the
        PDF is byte-identical for an ISP that never set a template."""
        row = await self.template(isp)
        out: dict[str, Any] = {}
        if row is not None:
            if row.show_bank_details and (row.bank_account_number or row.bank_name):
                out["bank"] = {
                    "name": row.bank_name,
                    "account_name": row.bank_account_name,
                    "account_number": row.bank_account_number,
                    "ifsc": row.bank_ifsc,
                    "branch": row.bank_branch,
                }
            for f in (
                "website",
                "care_phone",
                "care_email",
                "pan",
                "licence_number",
                "terms",
            ):
                if getattr(row, f):
                    out[f] = getattr(row, f)
        show_op = row is None or row.show_zone_operator
        zone_id = getattr(invoice, "zone_id", None) if invoice is not None else None
        if getattr(invoice, "bill_to_kind", None) == "zone":
            zone_id = None  # FINISH: the zone is the buyer, not the operator
        if show_op and zone_id is not None:
            prof = await self._zone_profile_row(isp, zone_id)
            if prof is not None and (prof.operator_name or prof.operator_phone):
                out["operator"] = {
                    "name": prof.operator_name,
                    "phone": prof.operator_phone,
                }
        return out

    # ------------------------------------------------------------------
    # products
    # ------------------------------------------------------------------
    @staticmethod
    def product_view(p: IspBillingProduct) -> dict:
        return {
            "id": str(p.id),
            "name": p.name,
            "kind": p.kind,
            "sac_code": p.sac_code,
            "default_amount_paise": p.default_amount_paise,
            "price_includes_gst": p.price_includes_gst,
            "active": p.active,
        }

    async def list_products(
        self, isp: IspContext, *, include_inactive: bool = True
    ) -> list[dict]:
        q = select(IspBillingProduct).where(
            IspBillingProduct.isp_organization_id == isp.isp_org_id,
            IspBillingProduct.is_deleted.is_(False),
        )
        if not include_inactive:
            q = q.where(IspBillingProduct.active.is_(True))
        rows = (
            (await self.session.execute(q.order_by(IspBillingProduct.name)))
            .scalars()
            .all()
        )
        return [self.product_view(p) for p in rows]

    async def _product(
        self, isp: IspContext, product_id: uuid.UUID
    ) -> IspBillingProduct:
        p = await self.session.get(IspBillingProduct, product_id)
        if p is None or p.is_deleted or p.isp_organization_id != isp.isp_org_id:
            raise IspFinanceNotFoundError("Product not found")
        return p

    async def _name_taken(
        self, isp: IspContext, name: str, exclude: uuid.UUID | None
    ) -> bool:
        q = select(IspBillingProduct.id).where(
            IspBillingProduct.isp_organization_id == isp.isp_org_id,
            IspBillingProduct.is_deleted.is_(False),
            func.lower(IspBillingProduct.name) == name.strip().lower(),
        )
        if exclude is not None:
            q = q.where(IspBillingProduct.id != exclude)
        return (await self.session.execute(q)).first() is not None

    async def create_product(self, isp: IspContext, data: dict) -> dict:
        if await self._name_taken(isp, data["name"], None):
            raise IspFinanceValidationError(
                "A product with that name exists", field="name"
            )
        p = IspBillingProduct(
            isp_organization_id=isp.isp_org_id, created_by=isp.user_id, **data
        )
        self.session.add(p)
        await self.session.flush()
        await self._audit(isp, "isp_billing_product_created", p.id, name=p.name)
        return self.product_view(p)

    async def update_product(
        self, isp: IspContext, product_id: uuid.UUID, data: dict
    ) -> dict:
        p = await self._product(isp, product_id)
        if "name" in data and await self._name_taken(isp, data["name"], p.id):
            raise IspFinanceValidationError(
                "A product with that name exists", field="name"
            )
        for k, v in data.items():
            setattr(p, k, v)
        p.updated_by = isp.user_id
        await self.session.flush()
        return self.product_view(p)

    async def seed_standard_products(self, isp: IspContext) -> list[dict]:
        """Quick action: the four standard lines, skipping names that exist.
        Nothing is ever seeded automatically."""
        for name, kind in (
            ("Bandwidth", "bandwidth"),
            ("Static IP", "static_ip"),
            ("Installation", "installation"),
            ("Other charges", "other"),
        ):
            if not await self._name_taken(isp, name, None):
                self.session.add(
                    IspBillingProduct(
                        isp_organization_id=isp.isp_org_id,
                        name=name,
                        kind=kind,
                        created_by=isp.user_id,
                    )
                )
        await self.session.flush()
        return await self.list_products(isp)

    # ------------------------------------------------------------------
    # price preview (base + GST = total)
    # ------------------------------------------------------------------
    async def price_preview(
        self,
        isp: IspContext,
        *,
        amount_paise: int,
        price_includes_gst: bool,
        place_of_supply_state_code: str | None,
    ) -> dict:
        settings = await self.billing.settings(isp, required=False)
        gst_on = bool(settings and settings.gst_enabled)
        rate = settings.gst_rate_bp if settings else 1800
        seller_state = settings.state_code if settings else None
        pos = place_of_supply_state_code or seller_state
        intra = pos is None or pos == seller_state
        t = compute_line(
            amount_paise,
            includes_gst=price_includes_gst,
            gst_applied=gst_on,
            rate_bp=rate,
            intra_state=intra,
        )
        return {
            "gst_applied": gst_on,
            "gst_rate_bp": rate if gst_on else 0,
            "intra_state": intra,
            "taxable_paise": t.taxable,
            "cgst_paise": t.cgst,
            "sgst_paise": t.sgst,
            "igst_paise": t.igst,
            "total_paise": t.total,
            "billing_configured": settings is not None,
        }

    # ------------------------------------------------------------------
    # package billing plan
    # ------------------------------------------------------------------
    async def _package(self, isp: IspContext, package_id: uuid.UUID) -> Any:
        from .plans_models import IspPackage

        pkg = await self.session.get(IspPackage, package_id)
        if pkg is None or pkg.is_deleted or pkg.isp_organization_id != isp.isp_org_id:
            raise IspFinanceNotFoundError("Package not found")
        return pkg

    async def _package_billing_row(
        self, package_id: uuid.UUID
    ) -> IspPackageBilling | None:
        return (
            await self.session.execute(
                select(IspPackageBilling).where(
                    IspPackageBilling.package_id == package_id,
                    IspPackageBilling.is_deleted.is_(False),
                )
            )
        ).scalar_one_or_none()

    async def package_billing(self, isp: IspContext, package_id: uuid.UUID) -> dict:
        pkg = await self._package(isp, package_id)
        row = await self._package_billing_row(pkg.id)
        preview = await self.price_preview(
            isp,
            amount_paise=int(pkg.price_paise or 0),
            price_includes_gst=bool(pkg.price_includes_gst),
            place_of_supply_state_code=None,
        )
        view: dict[str, Any] = {
            "package_id": str(pkg.id),
            "package_name": pkg.name,
            "price_paise": int(pkg.price_paise or 0),
            "price_includes_gst": bool(pkg.price_includes_gst),
            "validity_days": pkg.validity_days,
            "configured": row is not None,
            "plan_kind": row.plan_kind
            if row
            else ("postpaid" if pkg.type == "postpaid" else "prepaid"),
            "chargeable_unit": row.chargeable_unit if row else "days",
            "chargeable_count": row.chargeable_count if row else pkg.validity_days,
            "invoice_description": (row.invoice_description if row else None)
            or pkg.name,
            "product_id": str(row.product_id) if row and row.product_id else None,
            "preview": preview,
        }
        return view

    async def put_package_billing(
        self, isp: IspContext, package_id: uuid.UUID, data: dict
    ) -> dict:
        pkg = await self._package(isp, package_id)
        if data.get("product_id"):
            await self._product(isp, data["product_id"])
        row = await self._package_billing_row(pkg.id)
        if row is None:
            row = IspPackageBilling(
                isp_organization_id=isp.isp_org_id,
                package_id=pkg.id,
                created_by=isp.user_id,
                **data,
            )
            self.session.add(row)
        else:
            for k, v in data.items():
                setattr(row, k, v)
            row.updated_by = isp.user_id
        await self.session.flush()
        await self._audit(
            isp, "isp_package_billing_updated", pkg.id, plan_kind=row.plan_kind
        )
        return await self.package_billing(isp, pkg.id)

    # ------------------------------------------------------------------
    # static IP leases
    # ------------------------------------------------------------------
    @staticmethod
    def lease_view(
        lease: IspStaticIpLease,
        *,
        sub_name: str | None = None,
        customer_name: str | None = None,
    ) -> dict:  # noqa: E501
        return {
            "id": str(lease.id),
            "isp_customer_id": str(lease.customer_organization_id),
            "customer_name": customer_name,
            "subscriber_id": str(lease.subscriber_id) if lease.subscriber_id else None,
            "subscriber_name": sub_name,
            "ip_address": lease.ip_address,
            "monthly_amount_paise": lease.monthly_amount_paise,
            "price_includes_gst": lease.price_includes_gst,
            "active_since": _iso(lease.active_since),
            "active_until": _iso(lease.active_until),
            "billed_through": _iso(lease.billed_through),
            "status": lease.status,
            "notes": lease.notes,
        }

    async def _lease(self, isp: IspContext, lease_id: uuid.UUID) -> IspStaticIpLease:
        lease = await self.session.get(IspStaticIpLease, lease_id)
        if (
            lease is None
            or lease.is_deleted
            or lease.isp_organization_id != isp.isp_org_id
        ):
            raise IspFinanceNotFoundError("Lease not found")
        try:
            await self.billing._customer(isp, lease.customer_organization_id)
        except IspError:
            raise IspFinanceNotFoundError("Lease not found") from None
        return lease

    async def _subject(
        self,
        isp: IspContext,
        *,
        isp_customer_id: uuid.UUID | None,
        subscriber_id: uuid.UUID | None,
    ) -> tuple[uuid.UUID, Any]:
        """(customer org id, subscriber or None), both through IspScope."""
        if subscriber_id is not None:
            sub = await self.billing.subscriber_in_scope(isp, subscriber_id)
            if (
                isp_customer_id is not None
                and isp_customer_id != sub.customer_organization_id
            ):
                raise IspFinanceValidationError(
                    "The subscriber is not under that customer", field="isp_customer_id"
                )
            return sub.customer_organization_id, sub
        if isp_customer_id is None:
            raise IspFinanceValidationError(
                "isp_customer_id or subscriber_id is required",
                reason="ISP_TARGET_REQUIRED",
            )
        customer = await self.billing._customer(isp, isp_customer_id)
        return customer.id, None

    async def list_leases(
        self,
        isp: IspContext,
        *,
        status: str | None = None,
        subscriber_id: uuid.UUID | None = None,
    ) -> list[dict]:  # noqa: E501
        children = await isp.child_ids()
        if not children:
            return []
        q = select(IspStaticIpLease).where(
            IspStaticIpLease.isp_organization_id == isp.isp_org_id,
            IspStaticIpLease.is_deleted.is_(False),
            IspStaticIpLease.customer_organization_id.in_(children),
        )
        if status:
            q = q.where(IspStaticIpLease.status == status)
        if subscriber_id:
            q = q.where(IspStaticIpLease.subscriber_id == subscriber_id)
        rows = (
            (await self.session.execute(q.order_by(IspStaticIpLease.ip_address)))
            .scalars()
            .all()
        )
        names = await self._names(rows)
        return [
            self.lease_view(
                r,
                sub_name=names["subs"].get(r.subscriber_id),
                customer_name=names["orgs"].get(r.customer_organization_id),
            )
            for r in rows
        ]

    async def _names(self, rows: list) -> dict:
        from app.domains.organization.models import Organization

        from .plans_models import IspSubscriber

        org_ids = {
            r.customer_organization_id
            for r in rows
            if getattr(r, "customer_organization_id", None)
        }
        sub_ids = {r.subscriber_id for r in rows if getattr(r, "subscriber_id", None)}
        orgs: dict = {}
        subs: dict = {}
        if org_ids:
            for o in (
                await self.session.execute(
                    select(Organization).where(Organization.id.in_(org_ids))
                )
            ).scalars():  # noqa: E501
                orgs[o.id] = o.name
        if sub_ids:
            for s in (
                await self.session.execute(
                    select(IspSubscriber).where(IspSubscriber.id.in_(sub_ids))
                )
            ).scalars():  # noqa: E501
                subs[s.id] = (
                    " ".join(p for p in (s.first_name, s.last_name) if p)
                    or s.display_name
                    or s.identifier
                )  # noqa: E501
        return {"orgs": orgs, "subs": subs}

    async def create_lease(self, isp: IspContext, data: dict) -> dict:
        import ipaddress

        try:
            ip = str(ipaddress.ip_address(data["ip_address"].strip()))
        except ValueError:
            raise IspFinanceValidationError(
                "Not a valid IP address", field="ip_address"
            ) from None
        customer_id, sub = await self._subject(
            isp,
            isp_customer_id=data.get("isp_customer_id"),
            subscriber_id=data.get("subscriber_id"),
        )
        taken = (
            await self.session.execute(
                select(IspStaticIpLease.id).where(
                    IspStaticIpLease.isp_organization_id == isp.isp_org_id,
                    IspStaticIpLease.ip_address == ip,
                    IspStaticIpLease.status == "active",
                    IspStaticIpLease.is_deleted.is_(False),
                )
            )
        ).first()
        if taken:
            raise IspStaticIpInUseError()
        lease = IspStaticIpLease(
            isp_organization_id=isp.isp_org_id,
            customer_organization_id=customer_id,
            subscriber_id=sub.id if sub is not None else None,
            ip_address=ip,
            monthly_amount_paise=data["monthly_amount_paise"],
            price_includes_gst=data.get("price_includes_gst", False),
            active_since=data.get("active_since") or self.billing.today(isp),
            status="active",
            notes=data.get("notes"),
            created_by=isp.user_id,
        )
        self.session.add(lease)
        await self.session.flush()
        await self._audit(
            isp, "isp_static_ip_lease_created", lease.id, customer_id, ip=ip
        )
        return self.lease_view(lease)

    async def end_lease(
        self, isp: IspContext, lease_id: uuid.UUID, *, until: date | None
    ) -> dict:
        lease = await self._lease(isp, lease_id)
        if lease.status == "ended":
            return self.lease_view(lease)
        lease.status = "ended"
        lease.active_until = until or self.billing.today(isp)
        lease.updated_by = isp.user_id
        await self.session.flush()
        await self._audit(
            isp, "isp_static_ip_lease_ended", lease.id, lease.customer_organization_id
        )
        return self.lease_view(lease)

    async def bill_leases(self, isp: IspContext, *, as_of: date | None = None) -> dict:
        """Invoice every lease month that has started and not been billed,
        up to ``as_of``. One invoice per lease-month, idempotent through the
        invoice ``source_key`` (``sip:<lease>:<period start>``)."""
        today = as_of or self.billing.today(isp)
        leases = (
            (
                await self.session.execute(
                    select(IspStaticIpLease).where(
                        IspStaticIpLease.isp_organization_id == isp.isp_org_id,
                        IspStaticIpLease.is_deleted.is_(False),
                    )
                )
            )
            .scalars()
            .all()
        )
        issued = 0
        settings = await self.billing.settings(isp)
        for lease in leases:
            # BE-REVIEW R4: one SAVEPOINT per lease. A lease that cannot be
            # billed (archived customer, subscriber out of reach, bad GSTIN)
            # used to roll back every other lease of the ISP, every day.
            n, lease_id = 0, lease.id
            try:
                async with self.session.begin_nested():
                    start = (
                        lease.billed_through + timedelta(days=1)
                        if lease.billed_through
                        else lease.active_since
                    )
                    end_cap = lease.active_until or today
                    guard = 0
                    while start <= min(today, end_cap) and guard < 24:
                        guard += 1
                        period_end, amount = lease_period(
                            lease.active_since,
                            start,
                            lease.monthly_amount_paise,
                            active_until=lease.active_until,
                        )
                        line = {
                            "description": f"Static IP {lease.ip_address}",
                            "sac_code": settings.sac_code,
                            "amount_paise": amount,
                            "price_includes_gst": lease.price_includes_gst,
                            "period_from": start,
                            "period_to": period_end,
                        }
                        key = f"sip:{lease.id}:{start.isoformat()}"
                        if lease.subscriber_id:
                            sub = await self.billing.subscriber_in_scope(
                                isp, lease.subscriber_id
                            )
                            await self.billing.issue_subscriber_invoice(
                                isp,
                                sub,
                                lines=[line],
                                invoice_kind="cycle",
                                period_start=start,
                                period_end=period_end,
                                description=line["description"],
                                source_key=key,
                            )
                        else:
                            await self.billing.issue_invoice(
                                isp,
                                lease.customer_organization_id,
                                lines=[line],
                                invoice_kind="cycle",
                                period_start=start,
                                period_end=period_end,
                                description=line["description"],
                                source_key=key,
                            )
                        n += 1
                        lease.billed_through = period_end
                        start = period_end + timedelta(days=1)
                issued += n
            except Exception:  # noqa: BLE001 -- logged, the rest still bill
                logger.warning(
                    "isp_lease_billing_row_failed",
                    exc_info=True,
                    extra={"lease": str(lease_id)},
                )
        await self.session.flush()
        return {"invoices_issued": issued}

    # ------------------------------------------------------------------
    # security deposits
    # ------------------------------------------------------------------
    @staticmethod
    def deposit_view(d: IspSecurityDeposit) -> dict:
        return {
            "id": str(d.id),
            "isp_customer_id": str(d.customer_organization_id),
            "subscriber_id": str(d.subscriber_id) if d.subscriber_id else None,
            "entry_kind": d.entry_kind,
            "item": d.item,
            "item_serial": d.item_serial,
            "amount_paise": d.amount_paise,
            "mode": d.mode,
            "reference": d.reference,
            "note": d.note,
            "occurred_at": _iso(d.occurred_at),
            "recorded_by": str(d.created_by) if d.created_by else None,
        }

    async def _deposit_rows(
        self,
        isp: IspContext,
        *,
        customer_id: uuid.UUID | None,
        subscriber_id: uuid.UUID | None,
    ) -> list[IspSecurityDeposit]:  # noqa: E501
        q = select(IspSecurityDeposit).where(
            IspSecurityDeposit.isp_organization_id == isp.isp_org_id,
            IspSecurityDeposit.is_deleted.is_(False),
        )
        if subscriber_id is not None:
            q = q.where(IspSecurityDeposit.subscriber_id == subscriber_id)
        elif customer_id is not None:
            q = q.where(
                IspSecurityDeposit.customer_organization_id == customer_id,
                IspSecurityDeposit.subscriber_id.is_(None),
            )
        else:
            children = await isp.child_ids()
            if not children:
                return []
            q = q.where(IspSecurityDeposit.customer_organization_id.in_(children))
        return list(
            (
                await self.session.execute(q.order_by(IspSecurityDeposit.occurred_at))
            ).scalars()
        )  # noqa: E501

    @staticmethod
    def _held(rows: list[IspSecurityDeposit]) -> int:
        return sum(
            r.amount_paise if r.entry_kind == "collect" else -r.amount_paise
            for r in rows
        )

    async def deposits(
        self,
        isp: IspContext,
        *,
        isp_customer_id: uuid.UUID | None,
        subscriber_id: uuid.UUID | None,
    ) -> dict:  # noqa: E501
        customer_id = None
        if subscriber_id is not None or isp_customer_id is not None:
            customer_id, _ = await self._subject(
                isp, isp_customer_id=isp_customer_id, subscriber_id=subscriber_id
            )  # noqa: E501
        rows = await self._deposit_rows(
            isp, customer_id=customer_id, subscriber_id=subscriber_id
        )
        return {
            "held_paise": self._held(rows)
            if (subscriber_id or isp_customer_id)
            else None,
            "items": [self.deposit_view(r) for r in reversed(rows)],
        }

    async def deposit_summary(self, isp: IspContext) -> list[dict]:
        """Per subscriber/customer: collected, refunded, forfeited, held.
        Report data for JAZE-3 ("customer with security deposit")."""
        rows = await self._deposit_rows(isp, customer_id=None, subscriber_id=None)
        agg: dict[tuple, dict] = {}
        for r in rows:
            key = (r.customer_organization_id, r.subscriber_id)
            a = agg.setdefault(key, {"collected": 0, "refunded": 0, "forfeited": 0})
            a[
                {"collect": "collected", "refund": "refunded", "forfeit": "forfeited"}[
                    r.entry_kind
                ]
            ] += r.amount_paise  # noqa: E501
        names = await self._names(rows)
        return [
            {
                "isp_customer_id": str(c),
                "customer_name": names["orgs"].get(c),
                "subscriber_id": str(s) if s else None,
                "subscriber_name": names["subs"].get(s) if s else None,
                "collected_paise": a["collected"],
                "refunded_paise": a["refunded"],
                "forfeited_paise": a["forfeited"],
                "held_paise": a["collected"] - a["refunded"] - a["forfeited"],
            }
            for (c, s), a in agg.items()
        ]

    async def add_deposit(self, isp: IspContext, data: dict) -> dict:
        customer_id, sub = await self._subject(
            isp,
            isp_customer_id=data.get("isp_customer_id"),
            subscriber_id=data.get("subscriber_id"),
        )
        if data["entry_kind"] != "collect":
            rows = await self._deposit_rows(
                isp, customer_id=customer_id, subscriber_id=sub.id if sub else None
            )
            if data["amount_paise"] > self._held(rows):
                raise IspDepositExceedsBalanceError()
        d = IspSecurityDeposit(
            isp_organization_id=isp.isp_org_id,
            customer_organization_id=customer_id,
            subscriber_id=sub.id if sub else None,
            entry_kind=data["entry_kind"],
            item=data["item"],
            item_serial=data.get("item_serial"),
            amount_paise=data["amount_paise"],
            mode=data["mode"],
            reference=data.get("reference"),
            note=data.get("note"),
            occurred_at=data.get("occurred_at") or self._clock(),
            created_by=isp.user_id,
        )
        self.session.add(d)
        await self.session.flush()
        await self._audit(
            isp,
            f"isp_security_deposit_{d.entry_kind}",
            d.id,
            customer_id,
            amount_paise=d.amount_paise,
        )
        return self.deposit_view(d)

    # ------------------------------------------------------------------
    # billing contacts + invoice email
    # ------------------------------------------------------------------
    async def contact_row(
        self, isp: IspContext, kind: str, subject_id: uuid.UUID
    ) -> IspBillingContact | None:  # noqa: E501
        return (
            await self.session.execute(
                select(IspBillingContact).where(
                    IspBillingContact.isp_organization_id == isp.isp_org_id,
                    IspBillingContact.subject_kind == kind,
                    IspBillingContact.subject_id == subject_id,
                    IspBillingContact.is_deleted.is_(False),
                )
            )
        ).scalar_one_or_none()

    async def _resolve_contact_subject(
        self, isp: IspContext, kind: str, subject_id: uuid.UUID
    ) -> tuple[str | None, str]:  # noqa: E501
        """(primary email, display name), with the scope check."""
        if kind == "subscriber":
            sub = await self.billing.subscriber_in_scope(isp, subject_id)
            name = (
                " ".join(p for p in (sub.first_name, sub.last_name) if p)
                or sub.display_name
                or ""
            )
            return sub.email, name
        customer = await self.billing._customer(isp, subject_id)
        return customer.contact_email, customer.name

    async def get_contact(
        self, isp: IspContext, kind: str, subject_id: uuid.UUID
    ) -> dict:
        primary, name = await self._resolve_contact_subject(isp, kind, subject_id)
        row = await self.contact_row(isp, kind, subject_id)
        return {
            "subject_kind": kind,
            "subject_id": str(subject_id),
            "name": name,
            "primary_email": primary,
            "alternate_email": row.alternate_email if row else None,
            "alternate_name": row.alternate_name if row else None,
            "exclude_from_reminders": bool(row and row.exclude_from_reminders),
        }

    async def put_contact(
        self, isp: IspContext, kind: str, subject_id: uuid.UUID, data: dict
    ) -> dict:  # noqa: E501
        await self._resolve_contact_subject(isp, kind, subject_id)
        row = await self.contact_row(isp, kind, subject_id)
        if row is None:
            row = IspBillingContact(
                isp_organization_id=isp.isp_org_id,
                subject_kind=kind,
                subject_id=subject_id,
                created_by=isp.user_id,
            )
            self.session.add(row)
        for k, v in data.items():
            setattr(row, k, v)
        row.updated_by = isp.user_id
        await self.session.flush()
        return await self.get_contact(isp, kind, subject_id)

    async def invoice_recipients(
        self, isp: IspContext, inv: IspInvoice, send_to: str
    ) -> list[str]:
        if inv.bill_to_kind == "zone":
            # FINISH: the zone profile's email (no billing-contact row)
            prof = await self._zone_profile_row(isp, inv.zone_id)
            if prof is None or not prof.email or send_to == "alternate":
                raise IspNoRecipientError()
            return [prof.email]
        if inv.bill_to_kind == "subscriber" and inv.subscriber_id:
            kind, sid = "subscriber", inv.subscriber_id
        else:
            kind, sid = "customer", inv.customer_organization_id
        primary, _ = await self._resolve_contact_subject(isp, kind, sid)
        row = await self.contact_row(isp, kind, sid)
        alternate = row.alternate_email if row else None
        wanted = {
            "primary": [primary],
            "alternate": [alternate],
            "both": [primary, alternate],
        }[send_to]
        out: list[str] = []
        for e in wanted:
            if e and e.lower() not in {x.lower() for x in out}:
                out.append(e)
        if not out:
            raise IspNoRecipientError()
        return out

    # ------------------------------------------------------------------
    # zone ledger (labels only)
    # ------------------------------------------------------------------
    ZONE_FIELDS = (
        "contact_name",
        "email",
        "phone",
        "address",
        "pincode",
        "gstin",
        "pan",
        "operator_name",
        "operator_phone",
        "revenue_share_bp",
        "min_balance_paise",
        "tds_rate_bp",
    )

    async def _zone(self, isp: IspContext, zone_id: uuid.UUID) -> IspZone:
        return await self.billing.zone(isp, zone_id)

    async def _zone_profile_row(
        self, isp: IspContext, zone_id: uuid.UUID
    ) -> IspZoneProfile | None:
        return (
            await self.session.execute(
                select(IspZoneProfile).where(
                    IspZoneProfile.isp_organization_id == isp.isp_org_id,
                    IspZoneProfile.zone_id == zone_id,
                    IspZoneProfile.is_deleted.is_(False),
                )
            )
        ).scalar_one_or_none()

    async def _zone_balance(self, zone_id: uuid.UUID) -> int:
        v = (
            await self.session.execute(
                select(
                    func.coalesce(func.sum(IspZoneLedgerEntry.amount_paise), 0)
                ).where(
                    IspZoneLedgerEntry.zone_id == zone_id,
                    IspZoneLedgerEntry.is_deleted.is_(False),
                )
            )
        ).scalar_one()
        return int(v)

    def _zone_view(
        self, zone: IspZone, prof: IspZoneProfile | None, balance: int
    ) -> dict:
        credit = prof.credit_limit_paise if prof else 0
        min_bal = prof.min_balance_paise if prof else 0
        return {
            "zone_id": str(zone.id),
            "name": zone.name,
            "city": zone.city,
            "state_code": zone.state_code,
            **{f: (getattr(prof, f) if prof else None) for f in self.ZONE_FIELDS},
            "revenue_share_bp": prof.revenue_share_bp if prof else 0,
            "tds_rate_bp": prof.tds_rate_bp if prof else 200,
            "min_balance_paise": min_bal,
            "credit_limit_paise": credit,
            "balance_paise": balance,
            "available_paise": balance + credit,
            #: PAID when the balance is at or above the minimum; UNPAID when
            #: it is below (into credit, or under the warning threshold).
            "standing": "paid" if balance >= min_bal else "unpaid",
            "labels_only": True,
        }

    async def list_zone_ledgers(self, isp: IspContext) -> list[dict]:
        zones = (
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
        out = []
        for z in zones:
            out.append(
                self._zone_view(
                    z,
                    await self._zone_profile_row(isp, z.id),
                    await self._zone_balance(z.id),
                )
            )
        return out

    async def zone_ledger(
        self, isp: IspContext, zone_id: uuid.UUID, *, limit: int = 200
    ) -> dict:
        zone = await self._zone(isp, zone_id)
        prof = await self._zone_profile_row(isp, zone.id)
        entries = (
            (
                await self.session.execute(
                    select(IspZoneLedgerEntry)
                    .where(
                        IspZoneLedgerEntry.zone_id == zone.id,
                        IspZoneLedgerEntry.is_deleted.is_(False),
                    )
                    .order_by(
                        IspZoneLedgerEntry.occurred_at.desc(),
                        IspZoneLedgerEntry.created_at.desc(),
                    )
                    .limit(limit)
                )
            )
            .scalars()
            .all()
        )
        users = await self.billing._user_names(
            [e.created_by for e in entries if e.created_by]
        )
        return {
            "zone": self._zone_view(zone, prof, await self._zone_balance(zone.id)),
            "entries": [
                {
                    "id": str(e.id),
                    "entry_kind": e.entry_kind,
                    "amount_paise": e.amount_paise,
                    "balance_after_paise": e.balance_after_paise,
                    "mode": e.mode,
                    "reference": e.reference,
                    "note": e.note,
                    "detail": e.detail,
                    "occurred_at": _iso(e.occurred_at),
                    "recorded_by": users.get(e.created_by) if e.created_by else None,
                }
                for e in entries
            ],
        }

    async def put_zone_profile(
        self, isp: IspContext, zone_id: uuid.UUID, data: dict
    ) -> dict:
        zone = await self._zone(isp, zone_id)
        if data.get("gstin"):
            data["gstin"] = data["gstin"].strip().upper()
            if not gstin_valid(data["gstin"]):
                raise IspFinanceValidationError(
                    "GSTIN is not valid (format or check digit)", field="gstin"
                )  # noqa: E501
        if data.get("pan"):
            data["pan"] = data["pan"].strip().upper()
            if not pan_valid(data["pan"]):
                raise IspFinanceValidationError(
                    "PAN must look like ABCDE1234F", field="pan"
                )
        if data.get("gstin") and data.get("pan") and data["gstin"][2:12] != data["pan"]:
            raise IspFinanceValidationError(
                "The GSTIN does not contain this PAN", field="pan"
            )
        if data.get("pincode") and not PINCODE_RE.match(data["pincode"]):
            raise IspFinanceValidationError("Pincode must be 6 digits", field="pincode")
        prof = await self._zone_profile_row(isp, zone.id)
        if prof is None:
            prof = IspZoneProfile(
                isp_organization_id=isp.isp_org_id,
                zone_id=zone.id,
                created_by=isp.user_id,
            )  # noqa: E501
            self.session.add(prof)
        for k, v in data.items():
            if k in self.ZONE_FIELDS:
                setattr(prof, k, v)
        prof.updated_by = isp.user_id
        await self.session.flush()
        await self._audit(isp, "isp_zone_profile_updated", zone.id)
        return self._zone_view(zone, prof, await self._zone_balance(zone.id))

    async def _lock_zone(self, zone_id: uuid.UUID) -> None:
        # Serialise ledger writes per zone so balance_after is exact.
        await self.session.execute(
            select(IspZone.id).where(IspZone.id == zone_id).with_for_update()
        )

    async def zone_entry(self, isp: IspContext, zone_id: uuid.UUID, data: dict) -> dict:
        zone = await self._zone(isp, zone_id)
        await self._lock_zone(zone.id)
        prof = await self._zone_profile_row(isp, zone.id)
        if prof is None:
            prof = IspZoneProfile(
                isp_organization_id=isp.isp_org_id,
                zone_id=zone.id,
                created_by=isp.user_id,
            )  # noqa: E501
            self.session.add(prof)
            await self.session.flush()
        balance = await self._zone_balance(zone.id)
        kind = data["entry_kind"]
        detail: dict[str, Any] = {}
        if kind == "credit_limit":
            new_limit = int(data["credit_limit_paise"])
            detail = {
                "old_credit_limit_paise": prof.credit_limit_paise,
                "new_credit_limit_paise": new_limit,
            }  # noqa: E501
            prof.credit_limit_paise = new_limit
            amount = 0
        elif kind == "add":
            amount = int(data["amount_paise"])
        else:
            amount = -int(data["amount_paise"])
            if balance + amount < -prof.credit_limit_paise:
                raise IspZoneCreditExceededError(
                    available_paise=balance + prof.credit_limit_paise
                )
        e = IspZoneLedgerEntry(
            isp_organization_id=isp.isp_org_id,
            zone_id=zone.id,
            entry_kind=kind,
            amount_paise=amount,
            balance_after_paise=balance + amount,
            mode=data.get("mode"),
            reference=data.get("reference"),
            note=data.get("note"),
            detail=detail,
            occurred_at=data.get("occurred_at") or self._clock(),
            created_by=isp.user_id,
        )
        self.session.add(e)
        await self.session.flush()
        await self._audit(
            isp,
            f"isp_zone_ledger_{kind}",
            e.id,
            None,
            zone_id=str(zone.id),
            amount_paise=amount,
        )  # noqa: E501
        return await self.zone_ledger(isp, zone.id)

    async def zone_revenue(
        self, isp: IspContext, *, date_from: date, date_to: date
    ) -> list[dict]:
        """Per zone: invoiced, collected (payment allocations to the zone's
        invoices in the window), the zone's share and the ISP's share.
        Confinement applies: a confined caller sees only its customers'
        invoices in each zone."""
        children = await isp.child_ids()
        zones = {z["zone_id"]: z for z in await self.list_zone_ledgers(isp)}
        out = {
            zid: {
                "zone_id": zid,
                "name": z["name"],
                "revenue_share_bp": z["revenue_share_bp"],
                "invoiced_paise": 0,
                "collected_paise": 0,
            }
            for zid, z in zones.items()
        }
        if not children:
            return list(out.values())
        inv_rows = (
            await self.session.execute(
                select(IspInvoice.zone_id, func.sum(IspInvoice.total_paise))
                .where(
                    IspInvoice.isp_organization_id == isp.isp_org_id,
                    IspInvoice.is_deleted.is_(False),
                    IspInvoice.doc_type == "invoice",
                    IspInvoice.status != "cancelled",
                    IspInvoice.zone_id.is_not(None),
                    IspInvoice.customer_organization_id.in_(children),
                    IspInvoice.issue_date >= date_from,
                    IspInvoice.issue_date <= date_to,
                )
                .group_by(IspInvoice.zone_id)
            )
        ).all()
        for zid, total in inv_rows:
            if str(zid) in out:
                out[str(zid)]["invoiced_paise"] = int(total or 0)
        start = datetime.combine(date_from, datetime.min.time(), tzinfo=UTC)
        end = datetime.combine(
            date_to + timedelta(days=1), datetime.min.time(), tzinfo=UTC
        )
        col_rows = (
            await self.session.execute(
                select(IspInvoice.zone_id, func.sum(IspPaymentAllocation.amount_paise))
                .join(IspInvoice, IspInvoice.id == IspPaymentAllocation.invoice_id)
                .join(IspPayment, IspPayment.id == IspPaymentAllocation.payment_id)
                .where(
                    IspInvoice.isp_organization_id == isp.isp_org_id,
                    IspInvoice.zone_id.is_not(None),
                    IspInvoice.customer_organization_id.in_(children),
                    IspPayment.status == "confirmed",
                    and_(IspPayment.received_at >= start, IspPayment.received_at < end),
                )
                .group_by(IspInvoice.zone_id)
            )
        ).all()
        for zid, total in col_rows:
            if str(zid) in out:
                out[str(zid)]["collected_paise"] = int(total or 0)
        for r in out.values():
            share = r["collected_paise"] * r["revenue_share_bp"] // 10000
            r["zone_share_paise"] = share
            r["isp_share_paise"] = r["collected_paise"] - share
        return list(out.values())

    async def tds_194h(self, isp: IspContext, *, fy: str | None = None) -> dict:
        """Data for a Section 194H statement: per zone and quarter, the
        commission (zone share of collections) and TDS at the zone's rate.
        The FY threshold is applied per zone; below it, TDS is 0. This is
        statement DATA, not a filed return -- the ISP's accountant files."""
        today = self.billing.today(isp)
        fy = fy or fiscal_year(today)
        start_year = 2000 + int(fy.split("-")[0])
        fy_from = date(start_year, 4, 1)
        quarters = [
            ("Q1", date(start_year, 4, 1), date(start_year, 6, 30)),
            ("Q2", date(start_year, 7, 1), date(start_year, 9, 30)),
            ("Q3", date(start_year, 10, 1), date(start_year, 12, 31)),
            ("Q4", date(start_year + 1, 1, 1), date(start_year + 1, 3, 31)),
        ]
        zones = {z["zone_id"]: z for z in await self.list_zone_ledgers(isp)}
        rows: dict[str, dict] = {
            zid: {
                "zone_id": zid,
                "name": z["name"],
                "pan": z["pan"],
                "tds_rate_bp": z["tds_rate_bp"],
                "quarters": {},
                "commission_paise": 0,
            }
            for zid, z in zones.items()
        }
        for qname, qf, qt in quarters:
            if qf > today:
                continue
            for r in await self.zone_revenue(isp, date_from=qf, date_to=min(qt, today)):
                rows[r["zone_id"]]["quarters"][qname] = {
                    "commission_paise": r["zone_share_paise"]
                }
                rows[r["zone_id"]]["commission_paise"] += r["zone_share_paise"]
        for r in rows.values():
            over = r["commission_paise"] > TDS_194H_THRESHOLD_PAISE
            r["threshold_crossed"] = over
            total_tds = 0
            for q in r["quarters"].values():
                q["tds_paise"] = (
                    q["commission_paise"] * r["tds_rate_bp"] // 10000 if over else 0
                )
                total_tds += q["tds_paise"]
            r["tds_paise"] = total_tds
            r["pan_missing"] = not r["pan"]
        return {
            "fy": fy,
            "fy_start": fy_from.isoformat(),
            "threshold_paise": TDS_194H_THRESHOLD_PAISE,
            "section": "194H",
            "zones": list(rows.values()),
            "note": "Statement data only. The rate and threshold are the zone's settings; confirm with your accountant before filing.",  # noqa: E501
        }


__all__ = [
    "IspDepositExceedsBalanceError",
    "IspFinanceNotFoundError",
    "IspFinanceService",
    "IspFinanceValidationError",
    "IspNoRecipientError",
    "IspStaticIpInUseError",
    "IspZoneCreditExceededError",
    "fy_start",
    "pan_valid",
]
