"""HTTP surface for the Aruba AP + MikroTik gateway hybrid (``speed_gateway``).

Two routers, two scopes, never mixed:

``speed_gateway_platform_router`` -- ``/platform/instant-on/routers/
{router_id}/speed-gateway`` (GET/PUT/DELETE). Master console only, every route
**pinned** to ``ScopeType.GLOBAL`` with the same permissions as the rest of
``/platform/instant-on`` (``network_integrations.*`` is held at organization
scope by venue owners, so scope inference would let them in). Keyed on the
NAS-only router. The PUT body carries only the gateway's id; organization and
location come from the NAS-only router, and the gateway must already share
both (``SpeedGatewayService.link``).

``speed_gateway_customer_router`` -- ``/network-integrations/locations/
{location_id}/speed-control`` (GET). ``locations.read`` at
``ScopeType.ORGANIZATION``. Answers one boolean. The organization is applied in
the query, and a location outside the caller's location grants reads as
``false`` -- the same answer as an unlinked location, so it discloses nothing.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.responses import ApiResponse, build_response
from app.core.config import get_settings
from app.database.session import get_db_session
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)
from app.domains.rbac.enums import ScopeType
from app.domains.rbac.location_scope import CallerLocationScope, LocationScope
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService

from .dependencies import get_queue_management_service
from .service import QueueManagementService
from .speed_gateway import SpeedGatewayRepository, SpeedGatewayService

__all__ = ["speed_gateway_customer_router", "speed_gateway_platform_router"]

speed_gateway_platform_router = APIRouter(
    prefix="/platform/instant-on", tags=["Instant On (platform)"]
)
speed_gateway_customer_router = APIRouter(
    prefix="/network-integrations", tags=["Instant On (customer)"]
)

_PLATFORM_READ = RequirePermission("network_integrations.read", scope=ScopeType.GLOBAL)
_PLATFORM_UPDATE = RequirePermission(
    "network_integrations.update", scope=ScopeType.GLOBAL
)
_CUSTOMER_PERMISSION = RequirePermission("locations.read", scope=ScopeType.ORGANIZATION)


class SpeedGatewayRouterSummary(BaseModel):
    router_id: str
    name: str | None = None
    model: str | None = None
    status: str | None = None
    has_api_credentials: bool


class SpeedGatewayStatus(BaseModel):
    router_id: str
    location_id: str
    feature_enabled: bool
    gateway: SpeedGatewayRouterSummary | None = None
    #: Why a linked gateway is not usable right now (e.g.
    #: ``SPEED_GATEWAY_NO_CREDENTIALS``), ``None`` when it is or nothing is
    #: linked.
    gateway_problem: str | None = None
    per_guest_speed_active: bool
    candidates: list[SpeedGatewayRouterSummary] = Field(default_factory=list)


class SpeedGatewayLinkRequest(BaseModel):
    gateway_router_id: uuid.UUID


class SpeedControlView(BaseModel):
    per_guest_speed: bool
    #: Aruba Instant On only: every Instant On cloud-control gate is open for
    #: this location's access point (global flag, router allowlist, write
    #: account, site mapping), so the dashboard may offer the device block,
    #: the guest network's speed cap and the mid-session data-cap cut.
    #: ``False`` everywhere else, and for a location outside the caller's
    #: grants -- the same answer, so it discloses nothing.
    instant_on_cloud_control: bool = False


def _request_id(request: Request) -> str:
    return request.headers.get("X-Request-ID", "") or str(
        getattr(getattr(request, "state", None), "request_id", "")
    )


def get_speed_gateway_service(
    db: AsyncSession = Depends(get_db_session),
    router_service: RouterService = Depends(get_router_service),
    queue_service: QueueManagementService = Depends(get_queue_management_service),
) -> SpeedGatewayService:
    return SpeedGatewayService(
        SpeedGatewayRepository(db),
        router_service,
        queue_service=queue_service,
        enabled=get_settings().aruba_hybrid_speed_gateway_enabled,
    )


def _status_payload(data: dict[str, Any]) -> dict[str, Any]:
    return SpeedGatewayStatus.model_validate(data).model_dump(mode="json")


@speed_gateway_platform_router.get(
    "/routers/{router_id}/speed-gateway",
    response_model=ApiResponse[SpeedGatewayStatus],
    dependencies=[Depends(_PLATFORM_READ)],
)
async def get_speed_gateway(
    router_id: uuid.UUID,
    request: Request,
    service: SpeedGatewayService = Depends(get_speed_gateway_service),
) -> dict[str, Any]:
    """Master: the MikroTik speed gateway linked to this Aruba Instant On
    access point, whether per-guest speed is live, and the MikroTik routers
    at the same location that could be linked."""
    return build_response(
        success=True,
        message="Speed gateway",
        data=_status_payload(await service.status(router_id)),
        request_id=_request_id(request),
    )


@speed_gateway_platform_router.put(
    "/routers/{router_id}/speed-gateway",
    response_model=ApiResponse[SpeedGatewayStatus],
    dependencies=[Depends(_PLATFORM_UPDATE)],
)
async def link_speed_gateway(
    router_id: uuid.UUID,
    payload: SpeedGatewayLinkRequest,
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    service: SpeedGatewayService = Depends(get_speed_gateway_service),
) -> dict[str, Any]:
    """Master: link a MikroTik of the same customer and location as this
    access point's speed gateway. Writes only this platform's database; the
    first queue is written when a guest next comes online."""
    data = await service.link(
        nas_router_id=router_id,
        gateway_router_id=payload.gateway_router_id,
        actor_user_id=uuid.UUID(str(user.id)),
    )
    return build_response(
        success=True,
        message="Speed gateway linked",
        data=_status_payload(data),
        request_id=_request_id(request),
    )


@speed_gateway_platform_router.delete(
    "/routers/{router_id}/speed-gateway",
    response_model=ApiResponse[SpeedGatewayStatus],
    dependencies=[Depends(_PLATFORM_UPDATE)],
)
async def unlink_speed_gateway(
    router_id: uuid.UUID,
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    service: SpeedGatewayService = Depends(get_speed_gateway_service),
) -> dict[str, Any]:
    """Master: unlink the speed gateway. Removes the per-guest queues this
    link put on the gateway (best-effort, logged per row)."""
    data = await service.unlink(
        nas_router_id=router_id, actor_user_id=uuid.UUID(str(user.id))
    )
    return build_response(
        success=True,
        message="Speed gateway unlinked",
        data=_status_payload(data),
        request_id=_request_id(request),
    )


@speed_gateway_customer_router.get(
    "/locations/{location_id}/speed-control",
    response_model=ApiResponse[SpeedControlView],
    dependencies=[Depends(_CUSTOMER_PERMISSION)],
)
async def get_location_speed_control(
    location_id: uuid.UUID,
    request: Request,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    caller_location_scope: LocationScope = Depends(CallerLocationScope),
    service: SpeedGatewayService = Depends(get_speed_gateway_service),
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Whether guests at this location get a per-guest speed limit from a
    Wyfy gateway router (the Aruba AP + MikroTik hybrid), and whether
    Instant On cloud control is switched on for its access point."""
    from app.domains.network_integration.instant_on_control import (
        instant_on_control_present,
    )

    allowed = caller_location_scope is None or location_id in caller_location_scope
    per_guest = allowed and await service.customer_per_guest_speed(
        location_id=location_id, organization_id=requesting_organization_id
    )
    cloud = bool(
        allowed
        and requesting_organization_id is not None
        and await instant_on_control_present(
            db, location_id=location_id, organization_id=requesting_organization_id
        )
    )
    return build_response(
        success=True,
        message="Speed control",
        data=SpeedControlView(
            per_guest_speed=per_guest, instant_on_cloud_control=cloud
        ).model_dump(mode="json"),
        request_id=_request_id(request),
    )
