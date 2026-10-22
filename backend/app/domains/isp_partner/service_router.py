"""``/isp/customers/{isp_customer_id}/service*`` (ADDENDUM_01 §A.8).

The only input is ``isp_customer_id``; no route takes a router or NAS id.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Header, Request
from pydantic import BaseModel, ConfigDict, Field

from .constants import ISP_PARTNER_MANAGE, ISP_PARTNER_READ
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .http import ok
from .providers import get_service_control
from .scoping import IspScope
from .service_control import IspServiceControl

service_router = APIRouter(tags=["ISP Partner: service control"])


class SuspendServiceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(pattern="^(non_payment|customer_request|abuse|other)$")
    note: str | None = Field(default=None, max_length=255)
    show_suspended_page: bool = True


class ResumeServiceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    note: str | None = Field(default=None, max_length=255)


@service_router.get(
    "/customers/{isp_customer_id}/service", dependencies=isp_guards(ISP_PARTNER_READ)
)
async def get_service_state(
    request: Request,
    isp_customer_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    control: IspServiceControl = Depends(get_service_control),
) -> dict:
    customer = await IspScope.assert_customer(isp, isp_customer_id)
    # Lazy retry, at most once a minute per customer (A.4).
    await control.retry(isp.isp_org_id, customer.id)
    return ok(request, await control.view(customer), "Service state")


@service_router.post(
    "/customers/{isp_customer_id}/service/suspend",
    dependencies=isp_guards(ISP_PARTNER_MANAGE),
)
async def suspend_service(
    request: Request,
    isp_customer_id: uuid.UUID,
    payload: SuspendServiceRequest,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key", max_length=100),
    isp: IspContext = Depends(RequireIspPartner),
    control: IspServiceControl = Depends(get_service_control),
) -> dict:
    customer = await IspScope.assert_customer(isp, isp_customer_id)
    data = await control.suspend(
        isp.isp_org_id,
        customer,
        actor=isp.user_id,
        reason=payload.reason,
        note=payload.note,
        show_suspended_page=payload.show_suspended_page,
        idempotency_key=idempotency_key,
        support_line=isp.profile.support_phone,
        isp_name=isp.organization.name,
    )
    return ok(request, data, "Service suspended")


@service_router.post(
    "/customers/{isp_customer_id}/service/resume",
    dependencies=isp_guards(ISP_PARTNER_MANAGE),
)
async def resume_service(
    request: Request,
    isp_customer_id: uuid.UUID,
    payload: ResumeServiceRequest | None = None,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key", max_length=100),
    isp: IspContext = Depends(RequireIspPartner),
    control: IspServiceControl = Depends(get_service_control),
) -> dict:
    customer = await IspScope.assert_customer(isp, isp_customer_id)
    data = await control.resume(
        isp.isp_org_id,
        customer,
        actor=isp.user_id,
        note=payload.note if payload else None,
        idempotency_key=idempotency_key,
    )
    return ok(request, data, "Service resumed")


@service_router.post(
    "/customers/{isp_customer_id}/service/retry",
    dependencies=isp_guards(ISP_PARTNER_MANAGE),
)
async def retry_service(
    request: Request,
    isp_customer_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    control: IspServiceControl = Depends(get_service_control),
) -> dict:
    customer = await IspScope.assert_customer(isp, isp_customer_id)
    await control.retry(isp.isp_org_id, customer.id, force=True)
    return ok(request, await control.view(customer), "Retried")
