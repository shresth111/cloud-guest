"""SMALL-2: DISCOUNT-WIRE codes on ISP-issued customer (venue) invoices.

Same flag as DISCOUNT-WIRE (``ISP_DISCOUNT_APPLY_ENABLED``; off + a code ->
422 ``ISP_DISCOUNT_APPLY_OFF``, nothing written; no code = unchanged), same
maths, same JAZE-5 quote / redemption, same 422 ``ISP_DISCOUNT_INVALID``.

Where a code is accepted (the two hand-made invoice paths):

* ``POST /isp/billing/invoices`` (1b one-line invoice, ``discount_code``);
* ``POST /isp/invoices`` (manual multi-line, ``discount_code``; bill_to
  customer, and bill_to subscriber for the same body).

Where it is NOT, and why (documented in LANE_NOTES [SMALL-2]):

* ``generate_due`` cycle invoices and static-IP lease cycle invoices are
  issued by the daily job with no request to carry a code; a code there
  would be a standing per-customer discount (a lower plan amount does that
  today) and would burn one use per cycle. Not built.

Rules for a customer invoice:

* **GST basis.** A customer invoice applies GST only when the ISP bills GST
  AND the customer's billing plan has ``gst_applicable`` (as
  ``issue_invoice`` decides). The taxable gross the code is quoted on uses
  that same decision, so a GST-inclusive price on a GST-exempt customer is
  not reduced by 18 % before quoting.
* **Whole invoice.** The code is quoted once on the sum of every line's
  taxable gross (minimum amount = the invoice's), then split across lines
  in proportion to their taxable gross (largest remainder, to the paisa),
  so the lines add up to exactly the quote. Each line stores
  ``discount_paise`` + ``discount_label``; ``_issue_core`` taxes
  ``gross - discount`` per line (CGST+SGST or IGST by place of supply).
* **Packages.** Manual lines carry no package, so a code limited to
  packages is refused (``This code does not apply to this package``).
* **Redemption** in the same transaction (code row locked, last use races
  to one winner); ``customer_org_id`` = the venue, ``subscriber_id`` only
  for a subscriber bill.
* **Release.** Voiding / fully crediting a discounted customer invoice
  gives the use back (the listener below; DISCOUNT-WIRE's own listener
  covers subscriber invoices only and is not edited).
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import event, select
from sqlalchemy.orm import Session

from .discount_wire import (
    IspDiscountApplyOffError,
    _release,
    get_discount_apply_settings,
    taxable_gross,
)


def split_discount(grosses: list[int], amount: int) -> list[int]:
    """Split ``amount`` over lines by their taxable gross (largest remainder;
    ties to the earlier line). Sum is exactly ``amount``; no line gets more
    than its gross."""
    total = sum(grosses)
    if amount <= 0 or total <= 0:
        return [0] * len(grosses)
    amount = min(amount, total)
    base = [g * amount // total for g in grosses]
    rema = [(g * amount) % total for g in grosses]
    left = amount - sum(base)
    order = sorted(range(len(grosses)), key=lambda i: (-rema[i], i))
    for i in order[:left]:
        base[i] += 1
    return base


async def customer_gst_applied(
    session: Any, settings: Any, customer_id: uuid.UUID | None
) -> bool:
    """``issue_invoice``'s own rule: ISP GST on and the plan not exempt."""
    if not settings.gst_enabled:
        return False
    if customer_id is None:
        return True
    from .billing_models import IspCustomerBilling

    plan = (
        await session.execute(
            select(IspCustomerBilling).where(
                IspCustomerBilling.customer_organization_id == customer_id
            )
        )
    ).scalar_one_or_none()
    return plan is None or bool(plan.gst_applicable)


async def apply_to_lines(
    session: Any,
    isp: Any,
    billing: Any,
    lines: list[dict],
    code: str,
    *,
    customer_id: uuid.UUID | None,
    gst_applied: bool | None = None,
) -> Any:
    """Quote ``code`` on the whole invoice and write each line's share.
    Raises before anything is written. Returns the quote for ``record``.

    ``gst_applied``: pass for a subscriber bill (ISP GST setting); omitted =
    the customer rule."""
    from .apps_discounts import evaluate_discount

    if not get_discount_apply_settings().discount_apply_enabled:
        raise IspDiscountApplyOffError()
    settings = await billing.settings(isp)
    if gst_applied is None:
        gst_applied = await customer_gst_applied(session, settings, customer_id)
    grosses = [
        taxable_gross(
            int(line["amount_paise"]) * int(line.get("quantity", 1)),
            includes_gst=bool(line.get("price_includes_gst", False)),
            gst_applied=gst_applied,
            rate_bp=settings.gst_rate_bp,
        )
        for line in lines
    ]
    quote = await evaluate_discount(
        session, isp.isp_org_id, code, gross_paise=sum(grosses), package_id=None
    )
    for line, share in zip(
        lines, split_discount(grosses, quote.amount_paise), strict=True
    ):
        if share:
            line["discount_paise"] = share
            line["discount_label"] = quote.label[:120]
    return quote


async def record(
    session: Any, quote: Any, invoice: Any, *, subscriber: Any = None
) -> None:
    from .apps_discounts import record_redemption

    await record_redemption(
        session,
        quote,
        invoice_id=invoice.id,
        subscriber_id=subscriber.id if subscriber is not None else None,
        customer_org_id=invoice.customer_organization_id,
        isp_org_id=invoice.isp_organization_id,
    )


@event.listens_for(Session, "before_flush")
def _release_customer_on_cancel(session: Session, _ctx: Any, _inst: Any) -> None:
    if not get_discount_apply_settings().discount_apply_enabled:
        return
    from sqlalchemy import inspect

    from .billing_models import IspInvoice

    dirty = [
        o
        for o in session.dirty
        if isinstance(o, IspInvoice)
        and o.doc_type == "invoice"
        and o.bill_to_kind == "customer"
        and o.status == "cancelled"
    ]
    if not dirty:
        return
    with session.no_autoflush:
        for inv in dirty:
            if "cancelled" in (inspect(inv).attrs.status.history.added or ()):
                _release(session, inv.id)


__all__ = ["apply_to_lines", "customer_gst_applied", "record", "split_discount"]
