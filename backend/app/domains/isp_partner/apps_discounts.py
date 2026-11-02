"""J16 discount codes for ISP invoices.

A code is ``percent`` (``value`` in basis points, 1000 = 10%) or ``flat``
(``value`` in paise), optionally capped (``max_discount_paise``), with a
minimum bill, a validity window, a use limit and a package allow-list.

The discount is a reduction of the taxable value agreed before supply, so
GST is charged on ``gross - discount``. The billing lane (JAZE-4) owns
``billing_service``. This module only offers:

* ``quote_discount(code_row, gross_paise, package_id, at)``: pure maths +
  rules, raises ``IspDiscountInvalidError``;
* ``evaluate_discount(session, isp_org_id, code, ...)``: loads the code and
  quotes it;
* ``record_redemption(session, quote, ...)``: bumps ``used_count`` under a
  row lock and writes the redemption (idempotent per invoice).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select

from .apps_common import (
    IspAppsConflictError,
    IspAppsNotFoundError,
    IspDiscountInvalidError,
)
from .apps_models import IspDiscountCode, IspDiscountRedemption


@dataclass(frozen=True)
class DiscountQuote:
    discount_id: uuid.UUID
    code: str
    amount_paise: int
    label: str


def normalise_code(code: str) -> str:
    return code.strip().upper()


def _label(d: Any) -> str:
    if d.kind == "percent":
        pct = d.value / 100
        txt = f"{pct:g}% off"
    else:
        txt = f"₹{d.value / 100:,.2f} off"
    return f"Discount {d.code} ({txt})"


def quote_discount(
    d: Any,
    *,
    gross_paise: int,
    package_id: uuid.UUID | None = None,
    at: datetime | None = None,
) -> DiscountQuote:
    at = at or datetime.now(UTC)
    if not d.active or getattr(d, "is_deleted", False):
        raise IspDiscountInvalidError(
            "This discount code is switched off", reason="ISP_DISCOUNT_OFF"
        )
    if d.valid_from and at < d.valid_from:
        raise IspDiscountInvalidError(
            "This discount code is not valid yet", reason="ISP_DISCOUNT_NOT_STARTED"
        )
    if d.valid_until and at > d.valid_until:
        raise IspDiscountInvalidError(
            "This discount code has expired", reason="ISP_DISCOUNT_EXPIRED"
        )
    if d.max_uses is not None and d.used_count >= d.max_uses:
        raise IspDiscountInvalidError(
            "This discount code has been used up", reason="ISP_DISCOUNT_USED_UP"
        )
    if d.min_amount_paise is not None and gross_paise < d.min_amount_paise:
        raise IspDiscountInvalidError(
            "The bill is below this code's minimum amount",
            reason="ISP_DISCOUNT_BELOW_MINIMUM",
        )
    allowed = {str(p) for p in d.package_ids or ()}
    if allowed and (package_id is None or str(package_id) not in allowed):
        raise IspDiscountInvalidError(
            "This code does not apply to this package",
            reason="ISP_DISCOUNT_WRONG_PACKAGE",
        )
    if gross_paise <= 0:
        raise IspDiscountInvalidError(
            "Nothing to discount", reason="ISP_DISCOUNT_NOTHING_TO_DISCOUNT"
        )
    # percent: half-up rounding to the paisa
    amount = (gross_paise * d.value + 5000) // 10000 if d.kind == "percent" else d.value
    if d.max_discount_paise is not None:
        amount = min(amount, d.max_discount_paise)
    amount = max(0, min(amount, gross_paise))
    return DiscountQuote(
        discount_id=d.id, code=d.code, amount_paise=int(amount), label=_label(d)
    )


async def _by_code(
    session: Any, isp_org_id: uuid.UUID, code: str
) -> IspDiscountCode | None:
    return (
        await session.execute(
            select(IspDiscountCode).where(
                IspDiscountCode.isp_organization_id == isp_org_id,
                IspDiscountCode.is_deleted.is_(False),
                IspDiscountCode.code == normalise_code(code),
            )
        )
    ).scalar_one_or_none()


async def evaluate_discount(
    session: Any,
    isp_org_id: uuid.UUID,
    code: str,
    *,
    gross_paise: int,
    package_id: uuid.UUID | None = None,
    at: datetime | None = None,
) -> DiscountQuote:
    d = await _by_code(session, isp_org_id, code)
    if d is None:
        raise IspDiscountInvalidError(
            "Unknown discount code", reason="ISP_DISCOUNT_UNKNOWN"
        )
    return quote_discount(d, gross_paise=gross_paise, package_id=package_id, at=at)


async def record_redemption(
    session: Any,
    quote: DiscountQuote,
    *,
    customer_org_id: uuid.UUID,
    invoice_id: uuid.UUID | None = None,
    subscriber_id: uuid.UUID | None = None,
    isp_org_id: uuid.UUID | None = None,
) -> IspDiscountRedemption:
    """Count one use of ``quote``'s code. Idempotent per ``invoice_id``.

    Matches the LANE_NOTES contract for JAZE-4
    (``record_redemption(session, quote, *, invoice_id, subscriber_id=None,
    customer_org_id)``). ``isp_org_id`` is optional: when given it must own
    the code; when omitted it is taken from the code itself.
    """
    d = (
        await session.execute(
            select(IspDiscountCode)
            .where(IspDiscountCode.id == quote.discount_id)
            .with_for_update()
        )
    ).scalar_one()
    if isp_org_id is not None and d.isp_organization_id != isp_org_id:
        raise IspAppsNotFoundError("Discount not found")
    isp_org_id = d.isp_organization_id
    if invoice_id is not None:
        existing = (
            await session.execute(
                select(IspDiscountRedemption).where(
                    IspDiscountRedemption.discount_id == d.id,
                    IspDiscountRedemption.invoice_id == invoice_id,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            return existing
    if d.max_uses is not None and d.used_count >= d.max_uses:
        raise IspDiscountInvalidError(
            "This discount code has been used up", reason="ISP_DISCOUNT_USED_UP"
        )
    d.used_count += 1
    r = IspDiscountRedemption(
        discount_id=d.id,
        isp_organization_id=isp_org_id,
        customer_organization_id=customer_org_id,
        subscriber_id=subscriber_id,
        invoice_id=invoice_id,
        amount_paise=quote.amount_paise,
        at=datetime.now(UTC),
    )
    session.add(r)
    await session.flush()
    return r


class DiscountService:
    def __init__(self, session: Any) -> None:
        self.session = session

    @staticmethod
    def view(d: Any) -> dict:
        return {
            "id": d.id,
            "code": d.code,
            "description": d.description,
            "kind": d.kind,
            "value": d.value,
            "max_discount_paise": d.max_discount_paise,
            "min_amount_paise": d.min_amount_paise,
            "max_uses": d.max_uses,
            "used_count": d.used_count,
            "valid_from": d.valid_from,
            "valid_until": d.valid_until,
            "package_ids": d.package_ids,
            "active": d.active,
            "label": _label(d),
        }

    async def _get(self, isp: Any, discount_id: uuid.UUID) -> IspDiscountCode:
        d = await self.session.get(IspDiscountCode, discount_id)
        if d is None or d.is_deleted or d.isp_organization_id != isp.isp_org_id:
            raise IspAppsNotFoundError("Discount not found")
        return d

    async def create(self, isp: Any, data: dict) -> dict:
        data = dict(data)
        data["code"] = normalise_code(data["code"])
        if await _by_code(self.session, isp.isp_org_id, data["code"]):
            raise IspAppsConflictError("A discount with this code exists")
        if data.get("package_ids") is not None:
            data["package_ids"] = [str(p) for p in data["package_ids"]] or None
        d = IspDiscountCode(isp_organization_id=isp.isp_org_id, used_count=0, **data)
        self.session.add(d)
        await self.session.flush()
        return self.view(d)

    async def update(self, isp: Any, discount_id: uuid.UUID, data: dict) -> dict:
        d = await self._get(isp, discount_id)
        if "package_ids" in data and data["package_ids"] is not None:
            data["package_ids"] = [str(p) for p in data["package_ids"]] or None
        for k, v in data.items():
            setattr(d, k, v)
        await self.session.flush()
        return self.view(d)

    async def list(
        self, isp: Any, *, active: bool | None, page: int, page_size: int
    ) -> tuple[list[dict], int]:
        conds: list[Any] = [
            IspDiscountCode.isp_organization_id == isp.isp_org_id,
            IspDiscountCode.is_deleted.is_(False),
        ]
        if active is not None:
            conds.append(IspDiscountCode.active.is_(active))
        total = int(
            (
                await self.session.execute(
                    select(func.count()).select_from(IspDiscountCode).where(*conds)
                )
            ).scalar_one()
        )
        rows = (
            (
                await self.session.execute(
                    select(IspDiscountCode)
                    .where(*conds)
                    .order_by(IspDiscountCode.created_at.desc())
                    .offset((page - 1) * page_size)
                    .limit(page_size)
                )
            )
            .scalars()
            .all()
        )
        return [self.view(r) for r in rows], total

    async def redemptions(self, isp: Any, discount_id: uuid.UUID) -> list[dict]:
        d = await self._get(isp, discount_id)
        visible = set(await isp.child_ids())
        rows = (
            (
                await self.session.execute(
                    select(IspDiscountRedemption)
                    .where(
                        IspDiscountRedemption.discount_id == d.id,
                        # DISCOUNT-WIRE: a cancelled invoice gives its use back
                        IspDiscountRedemption.is_deleted.is_(False),
                    )
                    .order_by(IspDiscountRedemption.at.desc())
                )
            )
            .scalars()
            .all()
        )
        return [
            {
                "isp_customer_id": r.customer_organization_id,
                "subscriber_id": r.subscriber_id,
                "invoice_id": r.invoice_id,
                "amount_paise": r.amount_paise,
                "at": r.at,
            }
            for r in rows
            if r.customer_organization_id in visible
        ]
