"""FINISH (founder-approved): a zone billed through the regular invoice engine.

A FRANCHISE-2 settlement's "ISP share of renewals + zone charges" becomes a
real GST tax invoice: the ISP is the seller (its GSTIN, state, invoice series
and SAC), the zone profile is the buyer (legal name = zone name, GSTIN,
address), and the place of supply is the zone's GSTIN state, else the zone's
state code, else the ISP's own state -- so CGST/SGST vs IGST follows the
same rule as every other invoice. The billed amount came out of
tax-inclusive subscriber totals, so the line is tax-inclusive.

Rows are ``bill_to_kind='zone'`` with ``zone_id`` set and no customer /
subscriber. Every customer/subscriber path filters by customer id, subscriber
id or ``bill_to_kind`` and so never sees them (invoice list, ledgers, dues,
overdue, auto-suspend, advances, dashboards, reminders); GSTR-1, AGR and
the compliance invoice reports include them, as real tax invoices must be.

Idempotent per settlement (``source_key = zone_settlement:<id>``); the ZS
number stays on the settlement and is quoted on the invoice for audit.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select

from .billing_models import IspInvoice, IspZone
from .gst import gstin_valid

ZONE_KIND = "zone"
SETTLEMENT_KIND = "settlement"


def place_of_supply(
    gstin: str | None, zone_state: str | None, seller_state: str
) -> str:
    """The buyer's GSTIN state code wins, then the zone's state, then the
    seller's own state (intra-state)."""
    if gstin and len(gstin) >= 2 and gstin[:2].isdigit():
        return gstin[:2]
    return zone_state or seller_state


async def zone_profile(session: Any, isp_org_id: uuid.UUID, zone_id: uuid.UUID) -> Any:
    from .finance_models import IspZoneProfile

    return (
        await session.execute(
            select(IspZoneProfile).where(
                IspZoneProfile.isp_organization_id == isp_org_id,
                IspZoneProfile.zone_id == zone_id,
                IspZoneProfile.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()


async def issue_zone_invoice(
    billing: Any,
    isp: Any,
    zone: IspZone,
    *,
    lines: list[dict],
    invoice_kind: str,
    source_key: str,
    description: str | None = None,
    period_start: Any = None,
    period_end: Any = None,
) -> IspInvoice:
    """Bill ``zone`` (already resolved inside the caller's ISP) through the
    invoice engine. Raises ISP_BILLING_NOT_CONFIGURED without billing setup."""
    from .exceptions import IspBuyerGstinInvalidError

    if zone.isp_organization_id != isp.isp_org_id:
        from .exceptions import IspZoneNotFoundError

        raise IspZoneNotFoundError()
    settings = await billing.settings(isp)
    existing = await billing._existing_source(isp, source_key)
    if existing is not None:
        return existing
    prof = await zone_profile(billing.session, isp.isp_org_id, zone.id)
    gstin = (getattr(prof, "gstin", None) or "").strip().upper() or None
    if gstin and not gstin_valid(gstin):
        raise IspBuyerGstinInvalidError()
    address = ", ".join(
        p for p in (getattr(prof, "address", None), getattr(prof, "pincode", None)) if p
    )
    return await billing._issue_core(
        isp,
        settings,
        bill_to_kind=ZONE_KIND,
        customer_organization_id=None,
        subscriber=None,
        bill_to_name=zone.name[:255],
        bill_to_gstin=gstin,
        bill_to_address=address or None,
        pos=place_of_supply(gstin, zone.state_code, settings.state_code),
        zone_id=zone.id,
        gst_applied=bool(settings.gst_enabled),
        lines=lines,
        invoice_kind=invoice_kind,
        issue_date=billing._check_issue_date(isp, None),
        due_date=None,
        period_start=period_start,
        period_end=period_end,
        description=description,
        po_number=None,
        source_key=source_key,
    )


async def invoice_for_settlement(billing: Any, isp: Any, settlement: Any) -> Any:
    """The tax invoice for one settlement: issued once, linked back, ZS number
    quoted. None when nothing was billed (no ISP share in the period)."""
    if settlement.invoice_id is not None:
        return await billing.session.get(IspInvoice, settlement.invoice_id)
    if settlement.billed_paise <= 0:
        return None
    zone = await billing.session.get(IspZone, settlement.zone_id)
    period = (
        f"{settlement.period_from.isoformat()} to {settlement.period_to.isoformat()}"
    )
    inv = await issue_zone_invoice(
        billing,
        isp,
        zone,
        lines=[
            {
                "description": (
                    f"ISP share of renewals and zone charges, {period} "
                    f"(settlement {settlement.number})"
                )[:255],
                "amount_paise": int(settlement.billed_paise),
                "quantity": 1,
                "price_includes_gst": True,
                "period_from": settlement.period_from,
                "period_to": settlement.period_to,
            }
        ],
        invoice_kind=SETTLEMENT_KIND,
        source_key=f"zone_settlement:{settlement.id}",
        description=f"Zone settlement {settlement.number}"[:255],
        period_start=settlement.period_from,
        period_end=settlement.period_to,
    )
    settlement.invoice_id = inv.id
    settlement.snapshot = {**(settlement.snapshot or {}), "invoice_number": inv.number}
    await billing.session.flush()
    return inv


def invoice_brief(inv: Any) -> dict | None:
    if inv is None:
        return None
    return {
        "id": str(inv.id),
        "number": inv.number,
        "issue_date": inv.issue_date.isoformat(),
        "taxable_paise": inv.taxable_paise,
        "cgst_paise": inv.cgst_paise,
        "sgst_paise": inv.sgst_paise,
        "igst_paise": inv.igst_paise,
        "total_paise": inv.total_paise,
        "place_of_supply_state_code": inv.place_of_supply_state_code,
        "buyer_gstin": inv.bill_to_gstin,
        "status": inv.status,
    }


__all__ = [
    "SETTLEMENT_KIND",
    "ZONE_KIND",
    "invoice_brief",
    "invoice_for_settlement",
    "issue_zone_invoice",
    "place_of_supply",
]
