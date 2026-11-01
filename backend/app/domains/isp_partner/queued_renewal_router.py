"""QUEUED-RENEWAL routes, behind ``ISP_QUEUED_RENEWAL_ENABLED`` (default OFF).

Same keys as the JAZE-1 renew/revert they wrap: create = isp_invoices.create
(+ isp_billing.execute when paid now), cancel = isp_invoices.manage (+
isp_billing.manage when the bill was paid and its receipt must be voided).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from app.domains.rbac.authorization import AccessValidator
from app.domains.rbac.dependencies import get_access_validator, get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .dependencies import IspContext, RequireIspPartner, isp_guards
from .http import ok
from .plans_router import RechargePayment
from .queued_renewal_config import RequireQueuedRenewalEnabled
from .queued_renewal_service import IspQueuedRenewalService
from .subscriber360_router import _require, get_subscriber360_service
from .subscriber360_service import IspSubscriber360Service

INVOICES_CREATE = "isp_invoices.create"
INVOICES_MANAGE = "isp_invoices.manage"
SUBS_READ = "isp_subscribers.read"
BILLING_EXECUTE = "isp_billing.execute"
BILLING_MANAGE = "isp_billing.manage"

queued_renewal_router = APIRouter(tags=["ISP Partner: queued renewals"])
_ON = [Depends(RequireQueuedRenewalEnabled)]


def get_queued_service(
    s360: IspSubscriber360Service = Depends(get_subscriber360_service),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> IspQueuedRenewalService:
    return IspQueuedRenewalService(s360=s360, audit=audit)


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class QueueRenewalRequest(_Body):
    package_id: uuid.UUID
    cycles: int = Field(default=1, ge=1, le=12)
    paid_now: bool = False
    payment: RechargePayment | None = None
    po_number: str | None = Field(default=None, max_length=40)
    idempotency_key: str = Field(min_length=8, max_length=64)
    # DISCOUNT-WIRE: a JAZE-5 code (ISP_DISCOUNT_APPLY_ENABLED; else 422).
    discount_code: str | None = Field(default=None, min_length=1, max_length=40)


class QueueCancelRequest(_Body):
    reason: str = Field(min_length=3, max_length=200)


@queued_renewal_router.get("/queued-renewals", dependencies=_ON + isp_guards(SUBS_READ))
async def list_pending(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    status: str = Query(default="pending", pattern="^(pending|active|cancelled|all)$"),
    q: str | None = Query(default=None, max_length=100),
    package_id: uuid.UUID | None = None,
    starts_within_days: int | None = Query(default=None, ge=1, le=366),
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspQueuedRenewalService = Depends(get_queued_service),
) -> dict:
    """ISP-wide queued renewals (P3-SWEEP: filters + subscriber names; the
    default is still pending only). Cancel stays the per-subscriber route."""
    return ok(
        request,
        await svc.list_pending(
            isp,
            page,
            page_size,
            status=status,
            q=q,
            package_id=package_id,
            starts_within_days=starts_within_days,
        ),
        "Queued renewals",
    )


@queued_renewal_router.get(
    "/subscribers/{subscriber_id}/queued-renewals",
    dependencies=_ON + isp_guards(SUBS_READ),
)
async def list_for_subscriber(
    request: Request,
    subscriber_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspQueuedRenewalService = Depends(get_queued_service),
) -> dict:
    return ok(request, await svc.list_for(isp, subscriber_id), "Queued renewals")


@queued_renewal_router.post(
    "/subscribers/{subscriber_id}/queued-renewals",
    status_code=201,
    dependencies=_ON + isp_guards(INVOICES_CREATE),
)
async def queue_renewal(
    request: Request,
    subscriber_id: uuid.UUID,
    body: QueueRenewalRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspQueuedRenewalService = Depends(get_queued_service),
    av: AccessValidator = Depends(get_access_validator),
) -> dict:
    if body.paid_now:
        await _require(isp, av, BILLING_EXECUTE)
    data = body.model_dump(exclude_none=True)
    data["payment"] = body.payment.model_dump() if body.payment else None
    out = await svc.create(isp, subscriber_id, data)
    await svc.session.commit()
    return ok(request, out, "Next plan queued")


@queued_renewal_router.post(
    "/subscribers/{subscriber_id}/queued-renewals/{queue_id}/cancel",
    dependencies=_ON + isp_guards(INVOICES_MANAGE),
)
async def cancel_queued(
    request: Request,
    subscriber_id: uuid.UUID,
    queue_id: uuid.UUID,
    body: QueueCancelRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspQueuedRenewalService = Depends(get_queued_service),
    av: AccessValidator = Depends(get_access_validator),
) -> dict:
    from .router import effective_isp_permissions

    may_void = BILLING_MANAGE in await effective_isp_permissions(isp, av)
    out = await svc.cancel(
        isp, subscriber_id, queue_id, reason=body.reason, may_void_payments=may_void
    )
    await svc.session.commit()
    return ok(request, out, "Queued renewal cancelled")


__all__ = ["queued_renewal_router"]
