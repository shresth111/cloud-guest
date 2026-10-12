"""Master console HTTP surface for traffic flow. Every route is pinned to
``ScopeType.GLOBAL`` on the GLOBAL-only ``traffic_flows`` module -- never
left to scope inference (see the scope-inference trap in the RBAC docs). No
customer-facing route exists, by design (DESIGN.md §7)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession
from wyfy_device_gateway.contract import DeviceCredentials, DeviceVendor
from wyfy_device_gateway.mikrotik_adapter import MikroTikAdapter

from app.common.responses import ApiResponse, build_response
from app.core.config import Settings, get_settings
from app.database.session import get_db_session
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentUser,
    RequirePermission,
    get_rbac_repository,
)
from app.domains.rbac.enums import ScopeType
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.router.dependencies import get_router_service
from app.domains.router.models import Router
from app.domains.router.service import RouterService

from .constants import MAX_LIST_LIMIT, MAX_TIMELINE_SERIES
from .findings_router import traffic_flow_findings_platform_router
from .geo_router import traffic_flow_geo_platform_router
from .service import (
    TrafficFlowDeviceService,
    TrafficFlowOverviewService,
    TrafficFlowRepository,
    TrafficFlowStatusService,
    TrafficFlowSummaryService,
)

__all__ = ["traffic_flow_platform_router"]

traffic_flow_platform_router = APIRouter(
    prefix="/platform/traffic-flow", tags=["Traffic flow (platform)"]
)

_READ = RequirePermission("traffic_flows.read", scope=ScopeType.GLOBAL)
_UPDATE = RequirePermission("traffic_flows.update", scope=ScopeType.GLOBAL)


class TrafficFlowApplyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: True = export ON to the hub collector; False = export OFF, target removed.
    enabled: bool = True
    #: Default True: read the router and return the planned writes only.
    dry_run: bool = True


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _credentials(router: Router, secret: str) -> DeviceCredentials:
    return DeviceCredentials(
        vendor=DeviceVendor.MIKROTIK,
        host=str(router.management_ip_address or router.public_ip_address),
        username=str(router.api_username),
        secret=secret,
        port=getattr(router, "api_port", None),
    )


def get_traffic_flow_device_service(
    session: AsyncSession = Depends(get_db_session),
    router_service: RouterService = Depends(get_router_service),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    settings: Settings = Depends(get_settings),
) -> TrafficFlowDeviceService:
    return TrafficFlowDeviceService(
        TrafficFlowRepository(session),
        router_service,
        settings,
        adapter_factory=MikroTikAdapter,
        credentials_factory=_credentials,
        audit_writer=audit_repository,
    )


def get_traffic_flow_overview_service(
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings),
) -> TrafficFlowOverviewService:
    return TrafficFlowOverviewService(TrafficFlowRepository(session), settings)


def get_traffic_flow_status_service(
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings),
) -> TrafficFlowStatusService:
    return TrafficFlowStatusService(TrafficFlowRepository(session), settings)


def get_traffic_flow_summary_service(
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings),
) -> TrafficFlowSummaryService:
    return TrafficFlowSummaryService(TrafficFlowRepository(session), settings)


@traffic_flow_platform_router.get(
    "/status",
    response_model=ApiResponse[dict[str, Any]],
    dependencies=[Depends(_READ)],
)
async def get_traffic_flow_status(
    request: Request,
    service: TrafficFlowStatusService = Depends(get_traffic_flow_status_service),
) -> dict[str, Any]:
    """Master: every router in the fleet with its state (``feature_off``,
    ``unsupported_vendor``, ``not_configured``, ``awaiting_first_data``,
    ``receiving``, ``silent``), the last read-back verdict, the newest window
    held, and collector health including exporters that match no router."""
    data = await service.status()
    return build_response(
        success=True,
        message="Traffic flow status",
        data=data,
        request_id=_request_id(request),
    )


@traffic_flow_platform_router.get(
    "/summary",
    response_model=ApiResponse[dict[str, Any]],
    dependencies=[Depends(_READ)],
)
async def get_traffic_flow_summary(
    request: Request,
    router_id: uuid.UUID | None = Query(default=None),
    location_id: uuid.UUID | None = Query(default=None),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    limit: int | None = Query(default=None, ge=1, le=MAX_LIST_LIMIT),
    series: int | None = Query(default=None, ge=1, le=MAX_TIMELINE_SERIES),
    service: TrafficFlowSummaryService = Depends(get_traffic_flow_summary_service),
) -> dict[str, Any]:
    """Master: one venue or router over a range (default the last hour, at
    most 7 days): totals, a per-service timeline, and three independent
    lists -- services (exact), devices and destinations (lower bounds, said
    so in ``list_accuracy``). ``measured: false`` means no data exists for
    the range, which is not the same as measured zero. No response pairs a
    device with a destination or a service."""
    data = await service.summary(
        router_id=router_id,
        location_id=location_id,
        since=since,
        until=until,
        limit=limit,
        series=series,
    )
    return build_response(
        success=True,
        message="Traffic flow summary",
        data=data,
        request_id=_request_id(request),
    )


@traffic_flow_platform_router.get(
    "/overview",
    response_model=ApiResponse[dict[str, Any]],
    dependencies=[Depends(_READ)],
)
async def get_traffic_flow_overview(
    request: Request,
    minutes: int = Query(default=60, ge=5, le=1440),
    service: TrafficFlowOverviewService = Depends(get_traffic_flow_overview_service),
) -> dict[str, Any]:
    """Master: per-router top talkers and top destinations over the last
    ``minutes``, each router with an explicit state (``disabled``,
    ``not_allowlisted`` (data held but export not switched on),
    ``collector_unreachable``, ``no_windows``, ``stale``,
    ``ok``). Lists are merged from stored per-window top-N and flagged
    ``approximate``."""
    data = await service.overview(minutes=minutes)
    return build_response(
        success=True,
        message="Traffic flow overview",
        data=data,
        request_id=_request_id(request),
    )


@traffic_flow_platform_router.get(
    "/routers/{router_id}/config",
    response_model=ApiResponse[dict[str, Any]],
    dependencies=[Depends(_READ)],
)
async def get_traffic_flow_config(
    router_id: uuid.UUID,
    request: Request,
    service: TrafficFlowDeviceService = Depends(get_traffic_flow_device_service),
) -> dict[str, Any]:
    """Master: the RouterOS lines the generator would render for this router
    and every reason it is not eligible yet. Reads the database only."""
    data = await service.preview(router_id)
    return build_response(
        success=True,
        message="Traffic flow config",
        data=data,
        request_id=_request_id(request),
    )


@traffic_flow_platform_router.post(
    "/routers/{router_id}/apply",
    response_model=ApiResponse[dict[str, Any]],
    dependencies=[Depends(_UPDATE)],
)
async def apply_traffic_flow_config(
    router_id: uuid.UUID,
    payload: TrafficFlowApplyRequest,
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    service: TrafficFlowDeviceService = Depends(get_traffic_flow_device_service),
) -> dict[str, Any]:
    """Master: turn export on (or off) on one MikroTik over 8728.
    ``dry_run`` (the default) reads the router and returns the planned writes
    without writing or recording anything. A real apply writes only differing
    fields, reads back, records the verdict on the per-router switch and
    returns it (``ok`` / ``detail`` / ``state``)."""
    data = await service.apply(
        router_id,
        enabled=payload.enabled,
        dry_run=payload.dry_run,
        actor_user_id=uuid.UUID(str(user.id)),
    )
    return build_response(
        success=True,
        message="Traffic flow plan" if payload.dry_run else "Traffic flow applied",
        data=data,
        request_id=_request_id(request),
    )


@traffic_flow_platform_router.post(
    "/routers/{router_id}/remove",
    response_model=ApiResponse[dict[str, Any]],
    dependencies=[Depends(_UPDATE)],
)
async def remove_traffic_flow_config(
    router_id: uuid.UUID,
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    service: TrafficFlowDeviceService = Depends(get_traffic_flow_device_service),
) -> dict[str, Any]:
    """Master: switch export off on the router and remove the platform's
    target, read back that it is gone, and clear the per-router switch.
    Needs no tunnel. Data already collected stays until it ages out."""
    data = await service.remove(router_id, actor_user_id=uuid.UUID(str(user.id)))
    return build_response(
        success=True,
        message="Traffic flow removed",
        data=data,
        request_id=_request_id(request),
    )


# Geo Location (``GET /geo``): its own module, same prefix, same GLOBAL pin.
traffic_flow_platform_router.include_router(traffic_flow_geo_platform_router)

# Findings (``GET /findings``): its own module, same prefix, same GLOBAL pin.
traffic_flow_platform_router.include_router(traffic_flow_findings_platform_router)
