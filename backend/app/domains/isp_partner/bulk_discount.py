"""SMALL-1: a discount code on DIR-2 bulk renew (``POST /subscriber-bulk/renew``).

Behind both existing flags: DIR-2 (``ISP_DIR2_ENABLED``, the route) and
DISCOUNT-WIRE (``ISP_DISCOUNT_APPLY_ENABLED``: a request that carries
``discount_code`` while it is off is refused with 422
``ISP_DISCOUNT_APPLY_OFF``, before anything is read or written). Without a
code the bulk renew is unchanged.

* **Code-level checks, whole request.** Unknown (or another ISP's), switched
  off, not valid yet or expired -> the existing 422 ``ISP_DISCOUNT_INVALID``.
* **Per-subscriber checks, a skip reason each** (shown by the dry run, and
  the same subscribers are skipped, not renewed, when applied):
  ``discount_not_for_package`` (package allow-list), ``discount_below_minimum``
  (min bill on the taxable gross), ``discount_nothing_to_discount`` (price 0),
  ``discount_used_up`` (the code's remaining uses are handed out in selection
  order; a subscriber past the last one is skipped).
* **Quote** = DISCOUNT-WIRE's own maths: ``taxable_gross`` of
  price x cycles (360 override price first, as the 360 renew bills; GST taken
  out of a GST-inclusive price) and JAZE-5 ``quote_discount`` on it.
* **Apply.** Each eligible subscriber goes through the existing 360 renew with
  ``discount_code`` (DISCOUNT-WIRE hook: pre-tax line discount + redemption
  in the same savepoint). A retried batch (same ``bulk_key``): subscribers
  already renewed under that key replay their first invoice, are not
  re-quoted and do not use up the code again.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from .apps_common import IspDiscountInvalidError
from .apps_discounts import _by_code, quote_discount
from .discount_wire import (
    IspDiscountApplyOffError,
    get_discount_apply_settings,
    taxable_gross,
)
from .exceptions import IspError

SKIP_NOT_FOR_PACKAGE = "discount_not_for_package"
SKIP_BELOW_MINIMUM = "discount_below_minimum"
SKIP_NOTHING = "discount_nothing_to_discount"
SKIP_USED_UP = "discount_used_up"


def bulk_idempotency_key(bulk_key: str, sid: uuid.UUID) -> str:
    """The per-subscriber renew key DIR-2 has always used."""
    return f"bulk-{bulk_key}-{sid.hex[:12]}"[:64]


async def load_code(session: Any, isp: Any, code: str, *, at: datetime) -> Any:
    """The ISP's code row, or the whole-request 422s."""
    if not get_discount_apply_settings().discount_apply_enabled:
        raise IspDiscountApplyOffError()
    d = await _by_code(session, isp.isp_org_id, code)
    if d is None:
        raise IspDiscountInvalidError("Unknown discount code")
    if not d.active:
        raise IspDiscountInvalidError("This discount code is switched off")
    if d.valid_from and at < d.valid_from:
        raise IspDiscountInvalidError("This discount code is not valid yet")
    if d.valid_until and at > d.valid_until:
        raise IspDiscountInvalidError("This discount code has expired")
    return d


def classify(
    d: Any, *, gross_paise: int, package_id: uuid.UUID | None, remaining: int | None
) -> tuple[Any, str | None]:
    """(quote, None) or (None, skip reason) for one subscriber. Pure."""
    allowed = {str(p) for p in d.package_ids or ()}
    if allowed and (package_id is None or str(package_id) not in allowed):
        return None, SKIP_NOT_FOR_PACKAGE
    if gross_paise <= 0:
        return None, SKIP_NOTHING
    if d.min_amount_paise is not None and gross_paise < d.min_amount_paise:
        return None, SKIP_BELOW_MINIMUM
    if remaining is not None and remaining <= 0:
        return None, SKIP_USED_UP
    try:
        return quote_discount(d, gross_paise=gross_paise, package_id=package_id), None
    except IspDiscountInvalidError:  # the real counter says used up
        return None, SKIP_USED_UP


@dataclass
class BulkDiscountPlan:
    """Per-request state: the code, its remaining uses and each quote."""

    code: Any
    remaining: int | None
    gst_enabled: bool
    gst_rate_bp: int
    quotes: list[dict] = field(default_factory=list)
    remaining_before: int | None = None

    def summary(self) -> dict:
        return {
            "code": self.code.code,
            "kind": self.code.kind,
            "value": self.code.value,
            "remaining_uses_before": self.remaining_before,
            "subscribers_discounted": sum(1 for q in self.quotes if not q["replay"]),
            "total_discount_paise": sum(
                q["discount_paise"] for q in self.quotes if not q["replay"]
            ),
            "per_subscriber": self.quotes,
        }


async def start(svc: Any, isp: Any, code: str) -> BulkDiscountPlan:
    d = await load_code(svc.session, isp, code, at=datetime.now(UTC))
    st = await svc.plans._billing().settings(isp, required=False)
    remaining = None if d.max_uses is None else max(0, d.max_uses - d.used_count)
    plan = BulkDiscountPlan(
        code=d,
        remaining=remaining,
        gst_enabled=bool(st and st.gst_enabled),
        gst_rate_bp=int(st.gst_rate_bp) if st else 0,
        remaining_before=remaining,
    )
    return plan


async def _already_renewed(svc: Any, s: Any, key: str) -> bool:
    from .subscriber360_models import IspSubscriberEvent

    return (
        await svc.session.execute(
            select(IspSubscriberEvent.id)
            .where(
                IspSubscriberEvent.subscriber_id == s.id,
                IspSubscriberEvent.kind == "renewed",
                IspSubscriberEvent.detail["idempotency_key"].astext == key,
            )
            .limit(1)
        )
    ).scalar_one_or_none() is not None


async def check(
    plan: BulkDiscountPlan,
    svc: Any,
    isp: Any,
    s: Any,
    p: Any,
    *,
    package_id: uuid.UUID | None,
    cycles: int,
    bulk_key: str | None,
) -> str | None:
    """Skip reason for subscriber ``s`` (profile ``p``) or None; records the
    quote and consumes one of the remaining uses when it passes."""
    sid = s.id
    if bulk_key and await _already_renewed(svc, s, bulk_idempotency_key(bulk_key, sid)):
        plan.quotes.append(
            {
                "id": str(sid),
                "identifier": s.identifier,
                "replay": True,
                "discount_paise": 0,
                "label": None,
            }
        )
        return None
    pkg_id = package_id or s.package_id
    if pkg_id is None:
        return None  # renew_skip already said no_package
    try:
        pkg = await svc.plans.package(isp, pkg_id)
    except IspError:
        return "package_not_found"
    price = (
        p.override_price_paise
        if p is not None and p.override_price_paise is not None
        else pkg.price_paise
    )
    gross = taxable_gross(
        int(price or 0) * cycles,
        includes_gst=bool(pkg.price_includes_gst),
        gst_applied=plan.gst_enabled,
        rate_bp=plan.gst_rate_bp,
    )
    quote, reason = classify(
        plan.code, gross_paise=gross, package_id=pkg.id, remaining=plan.remaining
    )
    if reason:
        return reason
    if plan.remaining is not None:
        plan.remaining -= 1
    plan.quotes.append(
        {
            "id": str(sid),
            "identifier": s.identifier,
            "replay": False,
            "package_id": str(pkg.id),
            "taxable_before_paise": gross,
            "discount_paise": quote.amount_paise,
            "taxable_after_paise": gross - quote.amount_paise,
            "label": quote.label,
        }
    )
    return None


__all__ = [
    "SKIP_BELOW_MINIMUM",
    "SKIP_NOTHING",
    "SKIP_NOT_FOR_PACKAGE",
    "SKIP_USED_UP",
    "BulkDiscountPlan",
    "bulk_idempotency_key",
    "check",
    "classify",
    "load_code",
    "start",
]
