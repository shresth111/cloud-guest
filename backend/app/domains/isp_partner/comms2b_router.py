"""COMMS-2b: ``GET /isp/finance/email-senders`` -- the email senders a manual
invoice email can go through. The platform outbox is always there; the
ISP's own SMTP/SES sender is listed only when it is enabled and verified.
``choice_available`` is true only with more than one sender, so the console
hides the choice otherwise. Read-only; no configuration is returned."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session

from .comms2b import email_senders
from .constants import ISP_INVOICES_EXECUTE
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .finance_config import RequireFinanceExtras
from .http import ok

comms2b_router = APIRouter(tags=["ISP Partner: email senders (COMMS-2b)"])


@comms2b_router.get(
    "/finance/email-senders",
    dependencies=[Depends(RequireFinanceExtras)] + isp_guards(ISP_INVOICES_EXECUTE),
)
async def list_email_senders(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    db: AsyncSession = Depends(get_db_session),
) -> dict:
    return ok(request, await email_senders(db, isp.isp_org_id), "Email senders")


__all__ = ["comms2b_router"]
