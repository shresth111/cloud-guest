"""DISCOUNT-WIRE: JAZE-5 discount codes on renew, recharge, queued renewal
and onboarding. Flag ``ISP_DISCOUNT_APPLY_ENABLED`` (default OFF: a request
that carries ``discount_code`` is refused with 422 ``ISP_DISCOUNT_APPLY_OFF``;
requests without one are untouched).

* **Math.** The discount is a pre-tax reduction: the line's taxable value
  (gross, with GST taken out first when the price includes GST) minus the
  discount is what GST is charged on. JAZE-5 ``evaluate_discount`` is called
  with that taxable gross, so percent codes, minimum amounts and caps read
  the same number the invoice shows. The line keeps its unit price and
  quantity and records ``discount_paise`` / ``discount_label``; GSTR-1 and
  the AGR read the reduced taxable value from the invoice as they always do.
* **Redemption.** ``record_redemption`` runs in the same transaction, after
  the invoice row exists. It locks the code row and re-checks ``max_uses``,
  so two requests racing for the last use cannot both win: the loser gets
  the existing 422 and its whole request (invoice included) rolls back.
* **Idempotency.** The callers' replay checks (``idempotency_key`` /
  ``source_key``) return the first invoice before a code is evaluated, and
  ``record_redemption`` is idempotent per invoice.
* **Release.** When a discounted subscriber invoice is cancelled (a full
  credit note, as a JAZE-1 revert or a queued-renewal cancel issues, or a
  void), a ``before_flush`` listener soft-deletes its redemption and gives
  the use back (``used_count - 1``). A partial credit note keeps the use.
"""

from __future__ import annotations

from datetime import UTC, datetime
from functools import lru_cache
from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import event, select
from sqlalchemy.orm import Session

from .exceptions import _err
from .gst import LineTax, compute_line


class IspDiscountApplySettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="ISP_", case_sensitive=False, extra="ignore"
    )

    discount_apply_enabled: bool = Field(default=False)


@lru_cache(maxsize=1)
def get_discount_apply_settings() -> IspDiscountApplySettings:
    return IspDiscountApplySettings()


IspDiscountApplyOffError = _err(
    "IspDiscountApplyOffError",
    "ISP_DISCOUNT_APPLY_OFF",
    422,
    "Discount codes cannot be applied to invoices yet",
)


def taxable_gross(
    gross_paise: int, *, includes_gst: bool, gst_applied: bool, rate_bp: int
) -> int:
    """The line's taxable value before any discount."""
    return compute_line(
        gross_paise,
        includes_gst=includes_gst,
        gst_applied=gst_applied,
        rate_bp=rate_bp,
        intra_state=True,
    ).taxable


def line_tax_after_discount(
    gross_paise: int,
    discount_paise: int,
    *,
    includes_gst: bool,
    gst_applied: bool,
    rate_bp: int,
    intra_state: bool,
) -> LineTax:
    """Taxable = taxable gross - discount (never below 0); GST on that."""
    base = taxable_gross(
        gross_paise, includes_gst=includes_gst, gst_applied=gst_applied, rate_bp=rate_bp
    )
    return compute_line(
        max(0, base - max(0, discount_paise)),
        includes_gst=False,
        gst_applied=gst_applied,
        rate_bp=rate_bp,
        intra_state=intra_state,
    )


async def apply_to_line(
    session: Any, isp: Any, billing: Any, line: dict, code: str, *, package_id: Any
) -> Any:
    """Quote ``code`` against ``line`` (one invoice line dict as the billing
    service takes it) and write the discount onto the line. Raises the JAZE-5
    422 for an unknown / expired / used-up / wrong-package code, before
    anything is written. Returns the quote for ``record``."""
    from .apps_discounts import evaluate_discount

    if not get_discount_apply_settings().discount_apply_enabled:
        raise IspDiscountApplyOffError()
    settings = await billing.settings(isp)
    base = taxable_gross(
        int(line["amount_paise"]) * int(line.get("quantity", 1)),
        includes_gst=bool(line.get("price_includes_gst", False)),
        gst_applied=bool(settings.gst_enabled),
        rate_bp=settings.gst_rate_bp,
    )
    quote = await evaluate_discount(
        session, isp.isp_org_id, code, gross_paise=base, package_id=package_id
    )
    line["discount_paise"] = quote.amount_paise
    line["discount_label"] = quote.label[:120]
    return quote


async def record(session: Any, quote: Any, invoice: Any, subscriber: Any) -> None:
    """Count the use against the invoice (same transaction; locks the code)."""
    from .apps_discounts import record_redemption

    await record_redemption(
        session,
        quote,
        invoice_id=invoice.id,
        subscriber_id=subscriber.id,
        customer_org_id=subscriber.customer_organization_id,
        isp_org_id=invoice.isp_organization_id,
    )


def _release(session: Session, invoice_id: Any) -> None:
    from .apps_models import IspDiscountCode, IspDiscountRedemption

    rows = (
        session.execute(
            select(IspDiscountRedemption).where(
                IspDiscountRedemption.invoice_id == invoice_id,
                IspDiscountRedemption.is_deleted.is_(False),
            )
        )
        .scalars()
        .all()
    )
    for r in rows:
        code = session.execute(
            select(IspDiscountCode)
            .where(IspDiscountCode.id == r.discount_id)
            .with_for_update()
        ).scalar_one()
        code.used_count = max(0, (code.used_count or 0) - 1)
        r.is_deleted = True
        r.deleted_at = datetime.now(UTC)


@event.listens_for(Session, "before_flush")
def _release_on_cancel(session: Session, _ctx: Any, _instances: Any) -> None:
    if not get_discount_apply_settings().discount_apply_enabled:
        return
    from sqlalchemy import inspect

    from .billing_models import IspInvoice

    dirty = [
        o
        for o in session.dirty
        if isinstance(o, IspInvoice)
        and o.doc_type == "invoice"
        and o.bill_to_kind == "subscriber"
        and o.status == "cancelled"
    ]
    if not dirty:
        return
    with session.no_autoflush:
        for inv in dirty:
            hist = inspect(inv).attrs.status.history
            if "cancelled" in (hist.added or ()):
                _release(session, inv.id)


__all__ = [
    "IspDiscountApplyOffError",
    "apply_to_line",
    "get_discount_apply_settings",
    "line_tax_after_discount",
    "record",
    "taxable_gross",
]
