"""``/isp/tr069/*`` (API_CONTRACT §5). Same guard stack as every ``/isp``
route, plus ``RequireTr069Enabled`` (503 ``TR069_NOT_ENABLED`` while
``TR069_ENABLED`` is off; with ``ISP_PARTNER_ENABLED`` off it is a 404 first).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.isp_partner.config import RequireIspFeatureEnabled
from app.domains.isp_partner.constants import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    TR069_EXECUTE,
    TR069_MANAGE,
    TR069_READ,
)
from app.domains.isp_partner.dependencies import IspContext, RequireIspPartner, isp_guards
from app.domains.isp_partner.http import ok
from app.domains.rbac.authorization import AccessValidator
from app.domains.rbac.dependencies import get_access_validator, get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .config import RequireTr069Enabled
from .nbi_client import NbiClient, get_nbi_client
from .service import Tr069Service
from .sync import sync_on_read

tr069_router = APIRouter(
    prefix="/isp/tr069",
    tags=["ISP Partner: TR-069"],
    dependencies=[Depends(RequireIspFeatureEnabled), Depends(RequireTr069Enabled)],
)


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EnabledRequest(_Body):
    enabled: bool


class LocationTr069Request(_Body):
    enabled: bool
    periodic_inform_interval_s: int | None = Field(default=None, ge=60, le=86400)


class DeviceUpdateRequest(_Body):
    isp_customer_id: uuid.UUID | None = None
    isp_location_id: uuid.UUID | None = None
    label: str | None = Field(default=None, max_length=200)


def get_tr069_service(
    db: AsyncSession = Depends(get_db_session),
    nbi: NbiClient = Depends(get_nbi_client),
    audit: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> Tr069Service:
    return Tr069Service(session=db, nbi=nbi, audit=audit)


@tr069_router.get("/acs", dependencies=isp_guards(TR069_MANAGE))
async def get_acs(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    service: Tr069Service = Depends(get_tr069_service),
) -> dict:
    return ok(request, await service.isp_acs(isp), "ACS credential")


@tr069_router.post("/acs/rotate", dependencies=isp_guards(TR069_MANAGE))
async def rotate_acs(
    request: Request,
    isp: IspContext = Depends(RequireIspPartner),
    service: Tr069Service = Depends(get_tr069_service),
) -> dict:
    return ok(request, await service.rotate_isp(isp), "ACS credential rotated")


@tr069_router.get("/customers/{isp_customer_id}", dependencies=isp_guards(TR069_READ))
async def get_customer_tr069(
    request: Request,
    isp_customer_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    access_validator: AccessValidator = Depends(get_access_validator),
    service: Tr069Service = Depends(get_tr069_service),
) -> dict:
    from app.domains.isp_partner.router import effective_isp_permissions

    show = TR069_MANAGE in await effective_isp_permissions(isp, access_validator)
    data = await service.customer_state(isp, isp_customer_id, show_password=show)
    return ok(request, data, "Customer TR-069")


@tr069_router.put("/customers/{isp_customer_id}", dependencies=isp_guards(TR069_MANAGE))
async def put_customer_tr069(
    request: Request,
    isp_customer_id: uuid.UUID,
    payload: EnabledRequest,
    isp: IspContext = Depends(RequireIspPartner),
    service: Tr069Service = Depends(get_tr069_service),
) -> dict:
    data = await service.set_customer_enabled(isp, isp_customer_id, payload.enabled)
    return ok(request, data, "Customer TR-069 updated")


@tr069_router.post(
    "/customers/{isp_customer_id}/rotate", dependencies=isp_guards(TR069_MANAGE)
)
async def rotate_customer_tr069(
    request: Request,
    isp_customer_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    service: Tr069Service = Depends(get_tr069_service),
) -> dict:
    return ok(request, await service.rotate_customer(isp, isp_customer_id), "Rotated")


@tr069_router.get("/locations/{isp_location_id}", dependencies=isp_guards(TR069_READ))
async def get_location_tr069(
    request: Request,
    isp_location_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    service: Tr069Service = Depends(get_tr069_service),
) -> dict:
    return ok(request, await service.location_state(isp, isp_location_id), "Location TR-069")


@tr069_router.put("/locations/{isp_location_id}", dependencies=isp_guards(TR069_MANAGE))
async def put_location_tr069(
    request: Request,
    isp_location_id: uuid.UUID,
    payload: LocationTr069Request,
    isp: IspContext = Depends(RequireIspPartner),
    service: Tr069Service = Depends(get_tr069_service),
) -> dict:
    data = await service.set_location(
        isp,
        isp_location_id,
        enabled=payload.enabled,
        interval_s=payload.periodic_inform_interval_s,
    )
    return ok(request, data, "Location TR-069 updated")


@tr069_router.get(
    "/routers/{isp_router_id}/script",
    response_class=PlainTextResponse,
    dependencies=isp_guards(TR069_MANAGE),
)
async def get_router_script(
    isp_router_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    service: Tr069Service = Depends(get_tr069_service),
) -> PlainTextResponse:
    """RouterOS text. Carries the ACS password: ``Cache-Control: no-store``,
    audited (``tr069_script_generated``)."""
    script = await service.router_script(isp, isp_router_id)
    return PlainTextResponse(script, headers={"Cache-Control": "no-store"})


@tr069_router.get("/devices", dependencies=isp_guards(TR069_READ))
async def list_devices(
    request: Request,
    isp_customer_id: uuid.UUID | None = Query(default=None),
    assigned: bool | None = Query(default=None),
    online: bool | None = Query(default=None),
    search: str | None = Query(default=None, max_length=200),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    isp: IspContext = Depends(RequireIspPartner),
    service: Tr069Service = Depends(get_tr069_service),
) -> dict:
    await sync_on_read(isp, nbi=service.nbi)
    data = await service.list_devices(
        isp,
        isp_customer_id=isp_customer_id,
        assigned=assigned,
        online=online,
        search=search,
        page_no=page,
        page_size=page_size,
    )
    return ok(request, data, "TR-069 devices")


@tr069_router.get("/devices/{cpe_id}", dependencies=isp_guards(TR069_READ))
async def get_device(
    request: Request,
    cpe_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    service: Tr069Service = Depends(get_tr069_service),
) -> dict:
    return ok(request, await service.device_detail(isp, cpe_id), "TR-069 device")


@tr069_router.patch("/devices/{cpe_id}", dependencies=isp_guards(TR069_MANAGE))
async def patch_device(
    request: Request,
    cpe_id: uuid.UUID,
    payload: DeviceUpdateRequest,
    isp: IspContext = Depends(RequireIspPartner),
    service: Tr069Service = Depends(get_tr069_service),
) -> dict:
    data = await service.assign_device(isp, cpe_id, payload.model_dump(exclude_unset=True))
    return ok(request, data, "TR-069 device updated")


@tr069_router.post(
    "/devices/{cpe_id}/refresh",
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=isp_guards(TR069_EXECUTE),
)
async def refresh_device(
    request: Request,
    cpe_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    service: Tr069Service = Depends(get_tr069_service),
) -> dict:
    return ok(request, await service.queue_task(isp, cpe_id, "refresh_params"), "Refresh")


@tr069_router.post(
    "/devices/{cpe_id}/reboot",
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=isp_guards(TR069_EXECUTE),
)
async def reboot_device(
    request: Request,
    cpe_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    service: Tr069Service = Depends(get_tr069_service),
) -> dict:
    return ok(request, await service.queue_task(isp, cpe_id, "reboot"), "Reboot")


@tr069_router.get("/devices/{cpe_id}/tasks", dependencies=isp_guards(TR069_READ))
async def list_device_tasks(
    request: Request,
    cpe_id: uuid.UUID,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    isp: IspContext = Depends(RequireIspPartner),
    service: Tr069Service = Depends(get_tr069_service),
) -> dict:
    data = await service.list_tasks(isp, cpe_id, page_no=page, page_size=page_size)
    return ok(request, data, "TR-069 tasks")
