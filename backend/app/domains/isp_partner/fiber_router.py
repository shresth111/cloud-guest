"""``/isp/fiber/*``: J22 fiber plant registry (ADDENDUM_05 §7, JAZE-6 B).

Same guard stack as every ``/isp`` route (``isp_guards``, keys pinned at
ORGANIZATION), plus ``RequireIspFiberEnabled`` (``ISP_FIBER_ENABLED``,
default OFF -> 404). Existing keys only, no new RBAC rows:

* read  -> ``isp_partner.read``   (every ISP role)
* add / edit / port assignment -> ``isp_partner.update`` (owner, admin,
  technician: the field installer records the plant)
* delete -> ``isp_partner.manage`` (owner, admin)

Path ids are ``fiber_node_id``, ``port_no`` and ``subscriber_id``; none is an
RBAC scope alias.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Path, Query, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session

from .constants import (
    DEFAULT_PAGE_SIZE,
    ISP_PARTNER_MANAGE,
    ISP_PARTNER_READ,
    ISP_PARTNER_UPDATE,
    MAX_PAGE_SIZE,
)
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .fiber_service import IspFiberService, RequireIspFiberEnabled
from .http import ok
from .views import page as make_page

__all__ = ["fiber_router"]

fiber_router = APIRouter(
    prefix="/fiber",
    tags=["ISP Partner: fiber plant"],
    dependencies=[Depends(RequireIspFiberEnabled)],
)

_KIND = "^(olt|pole|splitter|joint_closure|ont|other)$"
_STATUS = "^(active|planned|retired)$"
_Port = Path(ge=1, le=1024)


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class _IspFiberGeo(_Body):
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)

    @model_validator(mode="after")
    def _both_or_neither(self) -> _IspFiberGeo:
        fields = self.model_fields_set
        if ("latitude" in fields) != ("longitude" in fields):
            raise ValueError("send latitude and longitude together")
        if (self.latitude is None) != (self.longitude is None):
            raise ValueError("send latitude and longitude together")
        return self


class IspFiberNodeCreateRequest(_IspFiberGeo):
    kind: str = Field(pattern=_KIND)
    name: str = Field(min_length=1, max_length=120)
    code: str | None = Field(default=None, max_length=40)
    address: str | None = Field(default=None, max_length=500)
    parent_id: uuid.UUID | None = None
    parent_port: int | None = Field(default=None, ge=1, le=1024)
    port_count: int | None = Field(default=None, ge=1, le=1024)
    spec: str | None = Field(default=None, max_length=120)
    status: str = Field(default="active", pattern=_STATUS)
    isp_customer_id: uuid.UUID | None = None
    notes: str | None = Field(default=None, max_length=5000)


class IspFiberNodePatch(_IspFiberGeo):
    kind: str | None = Field(default=None, pattern=_KIND)
    name: str | None = Field(default=None, min_length=1, max_length=120)
    code: str | None = Field(default=None, max_length=40)
    address: str | None = Field(default=None, max_length=500)
    parent_id: uuid.UUID | None = None
    parent_port: int | None = Field(default=None, ge=1, le=1024)
    port_count: int | None = Field(default=None, ge=1, le=1024)
    spec: str | None = Field(default=None, max_length=120)
    status: str | None = Field(default=None, pattern=_STATUS)
    isp_customer_id: uuid.UUID | None = None
    notes: str | None = Field(default=None, max_length=5000)

    @model_validator(mode="after")
    def _no_null_required(self) -> IspFiberNodePatch:
        for f in ("kind", "name", "status"):
            if f in self.model_fields_set and getattr(self, f) is None:
                raise ValueError(f"{f} cannot be null")
        return self


class IspFiberPortAssignRequest(_Body):
    subscriber_id: uuid.UUID
    notes: str | None = Field(default=None, max_length=500)


def _fiber(db: AsyncSession = Depends(get_db_session)) -> IspFiberService:
    return IspFiberService(db)


@fiber_router.get("/nodes", dependencies=isp_guards(ISP_PARTNER_READ))
async def list_fiber_nodes(
    request: Request,
    kind: str | None = Query(default=None, pattern=_KIND),
    parent_id: uuid.UUID | None = Query(default=None),
    roots_only: bool = Query(default=False),
    isp_customer_id: uuid.UUID | None = Query(default=None),
    status: str | None = Query(default=None, pattern=_STATUS),
    search: str | None = Query(default=None, max_length=100),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFiberService = Depends(_fiber),
) -> dict:
    items, total = await svc.list(
        isp,
        kind=kind,
        parent_id=parent_id,
        roots_only=roots_only,
        isp_customer_id=isp_customer_id,
        status=status,
        search=search,
        page=page,
        page_size=page_size,
    )
    return ok(request, make_page(items, total, page, page_size), "Fiber nodes")


@fiber_router.post(
    "/nodes", status_code=201, dependencies=isp_guards(ISP_PARTNER_UPDATE)
)
async def create_fiber_node(
    request: Request,
    payload: IspFiberNodeCreateRequest,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFiberService = Depends(_fiber),
) -> dict:
    return ok(request, await svc.create(isp, payload.model_dump()), "Fiber node added")


@fiber_router.get(
    "/subscribers/{subscriber_id}", dependencies=isp_guards(ISP_PARTNER_READ)
)
async def fiber_subscriber_location(
    request: Request,
    subscriber_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFiberService = Depends(_fiber),
) -> dict:
    return ok(
        request,
        await svc.subscriber_location(isp, subscriber_id),
        "Subscriber fiber route",
    )


@fiber_router.get("/nodes/{fiber_node_id}", dependencies=isp_guards(ISP_PARTNER_READ))
async def get_fiber_node(
    request: Request,
    fiber_node_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFiberService = Depends(_fiber),
) -> dict:
    return ok(request, await svc.detail(isp, fiber_node_id), "Fiber node")


@fiber_router.patch(
    "/nodes/{fiber_node_id}", dependencies=isp_guards(ISP_PARTNER_UPDATE)
)
async def update_fiber_node(
    request: Request,
    fiber_node_id: uuid.UUID,
    payload: IspFiberNodePatch,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFiberService = Depends(_fiber),
) -> dict:
    return ok(
        request,
        await svc.update(isp, fiber_node_id, payload.model_dump(exclude_unset=True)),
        "Fiber node updated",
    )


@fiber_router.delete(
    "/nodes/{fiber_node_id}", dependencies=isp_guards(ISP_PARTNER_MANAGE)
)
async def delete_fiber_node(
    request: Request,
    fiber_node_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFiberService = Depends(_fiber),
) -> dict:
    await svc.delete(isp, fiber_node_id)
    return ok(request, None, "Fiber node deleted")


@fiber_router.get(
    "/nodes/{fiber_node_id}/route", dependencies=isp_guards(ISP_PARTNER_READ)
)
async def fiber_node_route(
    request: Request,
    fiber_node_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFiberService = Depends(_fiber),
) -> dict:
    return ok(request, await svc.route(isp, fiber_node_id), "Fiber route")


@fiber_router.get(
    "/nodes/{fiber_node_id}/downstream", dependencies=isp_guards(ISP_PARTNER_READ)
)
async def fiber_node_downstream(
    request: Request,
    fiber_node_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFiberService = Depends(_fiber),
) -> dict:
    return ok(request, await svc.downstream(isp, fiber_node_id), "Affected subscribers")


@fiber_router.get(
    "/nodes/{fiber_node_id}/ports", dependencies=isp_guards(ISP_PARTNER_READ)
)
async def fiber_node_ports(
    request: Request,
    fiber_node_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFiberService = Depends(_fiber),
) -> dict:
    return ok(request, await svc.ports(isp, fiber_node_id), "Ports")


@fiber_router.put(
    "/nodes/{fiber_node_id}/ports/{port_no}",
    dependencies=isp_guards(ISP_PARTNER_UPDATE),
)
async def assign_fiber_port(
    request: Request,
    fiber_node_id: uuid.UUID,
    payload: IspFiberPortAssignRequest,
    port_no: int = _Port,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFiberService = Depends(_fiber),
) -> dict:
    return ok(
        request,
        await svc.assign_port(
            isp, fiber_node_id, port_no, payload.subscriber_id, payload.notes
        ),
        "Port assigned",
    )


@fiber_router.delete(
    "/nodes/{fiber_node_id}/ports/{port_no}",
    dependencies=isp_guards(ISP_PARTNER_UPDATE),
)
async def release_fiber_port(
    request: Request,
    fiber_node_id: uuid.UUID,
    port_no: int = _Port,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspFiberService = Depends(_fiber),
) -> dict:
    await svc.release_port(isp, fiber_node_id, port_no)
    return ok(request, None, "Port freed")
