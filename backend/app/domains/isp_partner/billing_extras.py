"""BILL-2 (ADDENDUM_06): invoice PDF extras + per-zone invoice branding.

Only used while ``ISP_BILL2_ENABLED`` is on; off, ``billing_router`` never
calls :func:`pdf_extras` and the PDF is byte-identical to before.

* **Account block**: customer id (subscriber identifier), circuit id,
  installation address, static IP yes/no, billing period, next bill date.
* **Dues block**: previous balance (this bill-to's other open invoices issued
  before this one), this invoice's balance, total due.
* **Zone branding** (``isp_zone_branding``): an invoice name ("billed through")
  and bank details that replace the ISP's bank block on that zone's invoices.
  The supplier header (legal name, GSTIN) stays the ISP's: the ISP is the
  supplier for GST, the zone is its operator.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import and_, or_, select

from .bill2_models import IspZoneBranding
from .billing_models import IspInvoice, IspZone
from .billing_service import balance_of

__all__ = ["pdf_extras", "zone_branding_row"]


async def zone_branding_row(
    session: Any, isp_org_id: uuid.UUID, zone_id: uuid.UUID
) -> IspZoneBranding | None:
    return (
        await session.execute(
            select(IspZoneBranding).where(
                IspZoneBranding.isp_organization_id == isp_org_id,
                IspZoneBranding.zone_id == zone_id,
                IspZoneBranding.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()


def _install_address(p: Any) -> str | None:
    if p is None:
        return None
    if p.install_same_as_billing:
        return None  # shown as the bill-to address already
    parts = [
        p.install_building,
        p.install_address,
        p.install_area,
        p.install_city,
        p.install_pincode,
    ]
    text = ", ".join(x.strip() for x in parts if x and x.strip())
    return text or None


async def _previous_balance(session: Any, inv: Any) -> int:
    if inv.doc_type != "invoice":
        return 0
    same_bill_to = (
        IspInvoice.subscriber_id == inv.subscriber_id
        if inv.subscriber_id is not None
        else and_(
            IspInvoice.subscriber_id.is_(None),
            IspInvoice.customer_organization_id == inv.customer_organization_id,
        )
    )
    rows = (
        (
            await session.execute(
                select(IspInvoice).where(
                    IspInvoice.isp_organization_id == inv.isp_organization_id,
                    IspInvoice.doc_type == "invoice",
                    IspInvoice.status != "cancelled",
                    IspInvoice.id != inv.id,
                    same_bill_to,
                    or_(
                        IspInvoice.issue_date < inv.issue_date,
                        and_(
                            IspInvoice.issue_date == inv.issue_date,
                            IspInvoice.seq < inv.seq,
                        ),
                    ),
                )
            )
        )
        .scalars()
        .all()
    )
    return sum(balance_of(r) for r in rows)


async def pdf_extras(session: Any, isp: Any, inv: Any) -> dict[str, Any]:
    """The ``seller["bill2"]`` dict ``billing_pdf`` renders, plus optional
    ``bank`` / ``branding`` overrides from the invoice's zone."""
    from .enforcement_models import IspSubscriberIpBinding
    from .plans_models import IspSubscriber
    from .subscriber360_models import IspSubscriberProfile

    account: dict[str, Any] = {}
    sub = None
    if inv.subscriber_id is not None:
        sub = await session.get(IspSubscriber, inv.subscriber_id)
    if sub is not None:
        account["customer_id"] = sub.identifier
        account["circuit_id"] = inv.circuit_id_snapshot or sub.circuit_id
        prof = (
            await session.execute(
                select(IspSubscriberProfile).where(
                    IspSubscriberProfile.subscriber_id == sub.id
                )
            )
        ).scalar_one_or_none()
        account["install_address"] = _install_address(prof)
        ips = (
            (
                await session.execute(
                    select(IspSubscriberIpBinding.ip).where(
                        IspSubscriberIpBinding.subscriber_id == sub.id,
                        IspSubscriberIpBinding.is_deleted.is_(False),
                    )
                )
            )
            .scalars()
            .all()
        )
        account["static_ip"] = ", ".join(str(i) for i in ips) if ips else "No"
        if sub.valid_until is not None and inv.doc_type == "invoice":
            from zoneinfo import ZoneInfo

            tz = getattr(isp.organization, "timezone", None) or "Asia/Kolkata"
            account["next_bill_date"] = (
                sub.valid_until.astimezone(ZoneInfo(tz)).date().isoformat()
            )
    if inv.period_start and inv.period_end:
        account["billing_period"] = f"{inv.period_start} to {inv.period_end}"
    prev = await _previous_balance(session, inv)
    this_bal = balance_of(inv) if inv.doc_type == "invoice" else 0
    out: dict[str, Any] = {
        "bill2": {
            "account": {k: v for k, v in account.items() if v},
            "dues": None
            if inv.doc_type != "invoice"
            else {
                "previous_balance_paise": prev,
                "this_invoice_paise": this_bal,
                "total_due_paise": prev + this_bal,
            },
        }
    }
    if inv.zone_id is not None:
        b = await zone_branding_row(session, isp.isp_org_id, inv.zone_id)
        if b is not None:
            zone = await session.get(IspZone, inv.zone_id)
            name = b.invoice_name or (zone.name if zone else None)
            if name:
                out["bill2"]["billed_through"] = name
            if b.bank_account_number or b.bank_name:
                out["bank"] = {
                    "name": b.bank_name,
                    "account_name": b.bank_account_name,
                    "account_number": b.bank_account_number,
                    "ifsc": b.bank_ifsc,
                    "branch": b.bank_branch,
                }
            if b.upi_vpa:
                out["upi_vpa"] = b.upi_vpa
                out["payee_name"] = b.bank_account_name or name
    return out
