"""Phase 2b PPPoE HTTP surface (JAZE-6). Mounted under ``/isp`` (so
``ISP_PARTNER_ENABLED`` applies) and additionally behind
``ISP_PPPOE_ENABLED``.

* ``pppoe_router`` -- ISP staff routes, full ``isp_guards`` stack.
* ``pppoe_internal_router`` -- ``/isp/internal/pppoe/*``, FreeRADIUS only:
  ``CurrentNas`` (existing NAS shared-secret auth, imported unchanged) plus
  the ``ISP_PPPOE_REST_SECRET`` header, and refused outright when the
  request came through the public nginx (it carries X-Forwarded-For /
  X-Real-IP; FreeRADIUS on the box calls the API port directly).
"""

from __future__ import annotations

import secrets
import uuid

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.guest.dependencies import CurrentNas
from app.domains.rbac.dependencies import get_rbac_repository

from .constants import ISP_PARTNER_EXECUTE, ISP_PARTNER_READ, SETUP_SCRIPT_ROLES
from .dependencies import IspContext, RequireIspPartner, isp_guards
from .exceptions import IspSetupNotAllowedError
from .http import ok
from .pppoe_config import RequireIspPppoeEnabled, get_isp_pppoe_settings
from .pppoe_service import IspPppoeService
from .views import page as make_page

__all__ = ["pppoe_internal_router", "pppoe_router"]

SUBS_READ, SUBS_UPDATE = "isp_subscribers.read", "isp_subscribers.update"

pppoe_router = APIRouter(dependencies=[Depends(RequireIspPppoeEnabled)])
pppoe_internal_router = APIRouter(
    prefix="/internal/pppoe", dependencies=[Depends(RequireIspPppoeEnabled)]
)


def get_pppoe_service(
    db: AsyncSession = Depends(get_db_session),
    audit=Depends(get_rbac_repository),  # noqa: B008
) -> IspPppoeService:
    return IspPppoeService(session=db, audit=audit)


# ---------------------------------------------------------------------------
# FreeRADIUS-facing
# ---------------------------------------------------------------------------

REST_SECRET_HEADER = "X-Wyfy-Pppoe-Rest-Secret"


async def RequirePppoeRestCaller(request: Request) -> None:
    from fastapi import HTTPException

    expected = get_isp_pppoe_settings().rest_secret
    given = request.headers.get(REST_SECRET_HEADER) or ""
    proxied = request.headers.get("x-forwarded-for") or request.headers.get("x-real-ip")
    if not expected or proxied or not secrets.compare_digest(given, expected):
        # Same body as a missing route: nothing to probe.
        raise HTTPException(status_code=404, detail="Not Found")


class PppoeAuthorizeBody(BaseModel):
    model_config = ConfigDict(extra="ignore")
    username: str = Field(default="", max_length=253)
    calling_station_id: str | None = Field(default=None, max_length=64)
    nas_port_id: str | None = Field(default=None, max_length=64)


class PppoeAccountingBody(BaseModel):
    model_config = ConfigDict(extra="ignore")
    status_type: str = Field(max_length=32)
    username: str = Field(default="", max_length=253)
    calling_station_id: str | None = Field(default=None, max_length=64)
    session_id: str = Field(default="", max_length=253)
    bytes_uploaded_total: int = Field(default=0, ge=0)
    bytes_downloaded_total: int = Field(default=0, ge=0)
    disconnect_reason: str | None = Field(default=None, max_length=64)
    framed_ip: str | None = Field(default=None, max_length=64)
    framed_ipv6_prefix: str | None = Field(default=None, max_length=64)
    delegated_ipv6_prefix: str | None = Field(default=None, max_length=64)
    nas_port_id: str | None = Field(default=None, max_length=64)


@pppoe_internal_router.post(
    "/authorize", dependencies=[Depends(RequirePppoeRestCaller)]
)
async def pppoe_authorize(
    payload: PppoeAuthorizeBody,
    nas_client=Depends(CurrentNas),  # noqa: B008
    svc: IspPppoeService = Depends(get_pppoe_service),
) -> dict:
    """rlm_rest attribute-name JSON (see ``guest.router.radius_authorize``)."""
    return await svc.authorize(
        nas_client=nas_client,
        username=payload.username,
        calling_station_id=payload.calling_station_id,
        nas_port_id=payload.nas_port_id,
    )


@pppoe_internal_router.post(
    "/accounting", dependencies=[Depends(RequirePppoeRestCaller)]
)
async def pppoe_accounting(
    payload: PppoeAccountingBody,
    nas_client=Depends(CurrentNas),  # noqa: B008
    svc: IspPppoeService = Depends(get_pppoe_service),
) -> dict:
    return await svc.accounting(nas_client=nas_client, payload=payload.model_dump())


# ---------------------------------------------------------------------------
# ISP staff
# ---------------------------------------------------------------------------

_Page = Query(default=1, ge=1)
_PageSize = Query(default=50, ge=1, le=200)


class PppoeCredentialBody(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    username: str | None = Field(default=None, max_length=64)
    password: str | None = Field(default=None, max_length=64)
    generate_password: bool = False
    static_ip: str | None = Field(default=None, max_length=45)
    ip_pool_name: str | None = Field(default=None, max_length=64)


@pppoe_router.get(
    "/subscribers/{subscriber_id}/pppoe", dependencies=isp_guards(SUBS_READ)
)
async def get_pppoe_credential(
    request: Request,
    subscriber_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPppoeService = Depends(get_pppoe_service),
) -> dict:
    return ok(request, await svc.credential_view(isp, subscriber_id), "PPPoE login")


@pppoe_router.put(
    "/subscribers/{subscriber_id}/pppoe", dependencies=isp_guards(SUBS_UPDATE)
)
async def put_pppoe_credential(
    request: Request,
    subscriber_id: uuid.UUID,
    payload: PppoeCredentialBody,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPppoeService = Depends(get_pppoe_service),
) -> dict:
    data = await svc.set_credential(
        isp, subscriber_id, payload.model_dump(exclude_unset=True)
    )
    return ok(request, data, "PPPoE login saved")


@pppoe_router.post(
    "/subscribers/{subscriber_id}/pppoe/disable", dependencies=isp_guards(SUBS_UPDATE)
)
async def disable_pppoe(
    request: Request,
    subscriber_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPppoeService = Depends(get_pppoe_service),
) -> dict:
    data = await svc.set_credential_status(isp, subscriber_id, False)
    return ok(request, data, "PPPoE login disabled")


@pppoe_router.post(
    "/subscribers/{subscriber_id}/pppoe/enable", dependencies=isp_guards(SUBS_UPDATE)
)
async def enable_pppoe(
    request: Request,
    subscriber_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPppoeService = Depends(get_pppoe_service),
) -> dict:
    data = await svc.set_credential_status(isp, subscriber_id, True)
    return ok(request, data, "PPPoE login enabled")


@pppoe_router.post(
    "/subscribers/{subscriber_id}/pppoe/disconnect",
    dependencies=isp_guards(SUBS_UPDATE),
)
async def disconnect_pppoe_subscriber(
    request: Request,
    subscriber_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPppoeService = Depends(get_pppoe_service),
) -> dict:
    data = await svc.disconnect_subscriber(isp, subscriber_id)
    return ok(request, data, "Disconnect sent")


@pppoe_router.get("/pppoe/sessions", dependencies=isp_guards(SUBS_READ))
async def list_pppoe_sessions(
    request: Request,
    isp_customer_id: uuid.UUID | None = Query(default=None),
    status: str | None = Query(default=None, pattern="^(active|closed)$"),
    search: str | None = Query(default=None, max_length=100),
    page: int = _Page,
    page_size: int = _PageSize,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPppoeService = Depends(get_pppoe_service),
) -> dict:
    items, total = await svc.list_sessions(
        isp,
        isp_customer_id=isp_customer_id,
        status=status,
        search=search,
        page=page,
        page_size=page_size,
    )
    return ok(request, make_page(items, total, page, page_size), "PPPoE sessions")


@pppoe_router.post(
    "/pppoe/sessions/{pppoe_session_id}/disconnect",
    dependencies=isp_guards(SUBS_UPDATE),
)
async def disconnect_pppoe_session(
    request: Request,
    pppoe_session_id: uuid.UUID,
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPppoeService = Depends(get_pppoe_service),
) -> dict:
    return ok(request, await svc.disconnect(isp, pppoe_session_id), "Disconnect sent")


@pppoe_router.get(
    "/pppoe/routers/{isp_router_id}/script",
    response_class=PlainTextResponse,
    dependencies=isp_guards(ISP_PARTNER_EXECUTE),
)
async def get_pppoe_router_script(
    isp_router_id: uuid.UUID,
    interface: str | None = Query(default=None, max_length=64),
    local_address: str | None = Query(default=None, max_length=45),
    pool_range: str | None = Query(default=None, max_length=100),
    pool_cidr: str | None = Query(default=None, max_length=50),
    dns_servers: str | None = Query(default=None, max_length=200),
    isp: IspContext = Depends(RequireIspPartner),
    svc: IspPppoeService = Depends(get_pppoe_service),
) -> PlainTextResponse:
    """RouterOS text. Carries the router's NAS secret: same role gate as the
    main setup script (``SETUP_SCRIPT_ROLES``), ``no-store``, audited."""
    if isp.role_slug not in SETUP_SCRIPT_ROLES:
        raise IspSetupNotAllowedError()
    text = await svc.router_script(
        isp,
        isp_router_id,
        {
            "interface": interface,
            "local_address": local_address,
            "pool_range": pool_range,
            "pool_cidr": pool_cidr,
            "dns_servers": dns_servers,
        },
    )
    return PlainTextResponse(text, headers={"Cache-Control": "no-store"})


@pppoe_router.get("/pppoe/status", dependencies=isp_guards(ISP_PARTNER_READ))
async def pppoe_status(request: Request) -> dict:
    """Tells the FE the PPPoE feature is on (this route 404s when it is off)."""
    s = get_isp_pppoe_settings()
    return ok(
        request,
        {
            "enabled": True,
            "defaults": {
                "interface": "bridge1",
                "local_address": s.default_local_address,
                "pool_range": s.default_pool_range,
                "pool_cidr": s.default_pool_cidr,
            },
        },
        "PPPoE",
    )
