"""DISCOUNT-WIRE FE probe: ``GET /isp/billing/discount-apply`` (404 while
``ISP_DISCOUNT_APPLY_ENABLED`` is off). Kept out of ``discount_wire`` because
that module is imported from ``models.py`` (listener registration) and must
not pull in the dependency stack."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session

from .dependencies import IspContext, RequireIspPartner, isp_guards
from .discount_wire import get_discount_apply_settings
from .exceptions import IspFeatureDisabledError
from .http import ok


async def RequireDiscountApplyEnabled() -> None:
    if not get_discount_apply_settings().discount_apply_enabled:
        raise IspFeatureDisabledError()


discount_wire_router = APIRouter(tags=["ISP Partner: discount codes on invoices"])


@discount_wire_router.get(
    "/billing/discount-apply",
    dependencies=[
        Depends(RequireDiscountApplyEnabled),
        *isp_guards("isp_invoices.read"),
    ],
)
async def discount_apply_status(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    """200 while ISP_DISCOUNT_APPLY_ENABLED is on (404 off). ``gst_*`` let the
    FE turn a GST-inclusive price into the taxable gross it previews on."""
    from .billing_models import IspBillingSettings

    st = (
        await db.execute(
            select(IspBillingSettings).where(
                IspBillingSettings.isp_organization_id == isp.isp_org_id,
                IspBillingSettings.is_deleted.is_(False),
            )
        )
    ).scalar_one_or_none()
    return ok(
        request,
        {
            "enabled": True,
            "gst_enabled": bool(st and st.gst_enabled),
            "gst_rate_bp": int(st.gst_rate_bp) if st else 0,
        },
        "Discount codes apply to invoices",
    )
