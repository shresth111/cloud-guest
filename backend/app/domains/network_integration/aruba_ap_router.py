"""HTTP surface for Aruba Instant On multi-AP sites.

``aruba_ap_customer_router`` -- ``GET /locations/{location_id}/access-points``.
``locations.read`` pinned at ``ScopeType.ORGANIZATION`` (the permission the
Instant On customer reads use). The organization is the caller's
``CurrentOrganization`` and is in every WHERE clause; the caller's location
confinement is applied to the path location. Another tenant's location, and
every MikroTik / Omada location, answers ``applicable: false`` with no items
-- the same body, so the route reveals nothing about which ids exist.

``aruba_ap_platform_router`` -- ``/platform/instant-on/routers/{router_id}/
ap-registry``. Master only, every route pinned to ``ScopeType.GLOBAL``.
Writes only this platform's ``aruba_access_points`` table; nothing here
writes to Instant On. (``.../access-points`` on the same prefix is the
existing read of Instant On's own inventory snapshot, hence ``ap-registry``.)
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.responses import ApiResponse, build_response
from app.database.session import get_db_session
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)
from app.domains.rbac.enums import ScopeType
from app.domains.rbac.location_scope import (
    CallerLocationScope,
    LocationScope,
    enforce_entity_location,
)
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService

from .aruba_access_points import ArubaAccessPointService
from .aruba_ap_schemas import (
    ArubaAccessPointCreateRequest,
    ArubaAccessPointRecord,
    ArubaAccessPointRegistryResponse,
    ArubaAccessPointUpdateRequest,
    LocationAccessPointsResponse,
)
from .dependencies import get_instant_on_read_service
from .exceptions import CrossLocationNetworkIntegrationAccessError
from .instant_on_service import InstantOnKind, InstantOnReadService

__all__ = ["aruba_ap_customer_router", "aruba_ap_platform_router"]

aruba_ap_customer_router = APIRouter(tags=["Aruba access points (customer)"])
aruba_ap_platform_router = APIRouter(
    prefix="/platform/instant-on", tags=["Aruba access points (platform)"]
)

_CUSTOMER_PERMISSION = RequirePermission("locations.read", scope=ScopeType.ORGANIZATION)
_PLATFORM_READ = RequirePermission("network_integrations.read", scope=ScopeType.GLOBAL)
_PLATFORM_UPDATE = RequirePermission(
    "network_integrations.update", scope=ScopeType.GLOBAL
)

# Same bounds as /guest-analytics/dashboard-series.
_MIN_TZ, _MAX_TZ = -720, 840


def _request_id(request: Request) -> str:
    return request.headers.get("X-Request-ID", "") or str(
        getattr(getattr(request, "state", None), "request_id", "")
    )


def get_aruba_ap_service(
    db: AsyncSession = Depends(get_db_session),
) -> ArubaAccessPointService:
    return ArubaAccessPointService(db)


# ============================================================================
# Customer
# ============================================================================


@aruba_ap_customer_router.get(
    "/locations/{location_id}/access-points",
    response_model=ApiResponse[LocationAccessPointsResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(_CUSTOMER_PERMISSION)],
)
async def get_location_access_points(
    location_id: uuid.UUID,
    request: Request,
    tz_offset_minutes: int = Query(default=0, ge=_MIN_TZ, le=_MAX_TZ),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    caller_location_scope: LocationScope = Depends(CallerLocationScope),
    service: ArubaAccessPointService = Depends(get_aruba_ap_service),
    instant_on: InstantOnReadService = Depends(get_instant_on_read_service),
) -> dict[str, Any]:
    """The access points of an Aruba Instant On venue, with live guest
    counts and today's data from RADIUS accounting. ``applicable: false``
    for any other venue."""
    enforce_entity_location(
        entity_location_id=location_id,
        caller_location_scope=caller_location_scope,
        error=CrossLocationNetworkIntegrationAccessError(),
    )
    instant_on_items = None
    if requesting_organization_id is not None:
        view = await instant_on.customer_view(
            location_id=location_id,
            organization_id=requesting_organization_id,
            kind=InstantOnKind.ACCESS_POINTS,
        )
        if view.status == "ok":
            instant_on_items = view.items
    body = await service.location_access_points(
        organization_id=requesting_organization_id,
        location_id=location_id,
        tz_offset_minutes=tz_offset_minutes,
        instant_on_items=instant_on_items,
    )
    return build_response(
        success=True,
        message="Access points",
        data=LocationAccessPointsResponse.model_validate(body).model_dump(
            mode="json"
        ),
        request_id=_request_id(request),
    )


# ============================================================================
# Master (GLOBAL, pinned)
# ============================================================================


def _registry_payload(router_id: uuid.UUID, records: list[dict[str, Any]]) -> dict:
    return ArubaAccessPointRegistryResponse(
        router_id=router_id,
        items=[ArubaAccessPointRecord.model_validate(r) for r in records],
    ).model_dump(mode="json")


@aruba_ap_platform_router.get(
    "/routers/{router_id}/ap-registry",
    response_model=ApiResponse[ArubaAccessPointRegistryResponse],
    dependencies=[Depends(_PLATFORM_READ)],
)
async def list_aruba_ap_registry(
    router_id: uuid.UUID,
    request: Request,
    service: ArubaAccessPointService = Depends(get_aruba_ap_service),
    router_service: RouterService = Depends(get_router_service),
) -> dict[str, Any]:
    """Master: every access point of this Instant On site -- approved,
    pending (seen in RADIUS and refused) and rejected."""
    router = await router_service.get_router(router_id)
    records = await service.list_registry(router)
    return build_response(
        success=True,
        message="Access point registry",
        data=_registry_payload(router.id, records),
        request_id=_request_id(request),
    )


@aruba_ap_platform_router.post(
    "/routers/{router_id}/ap-registry",
    response_model=ApiResponse[ArubaAccessPointRecord],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(_PLATFORM_UPDATE)],
)
async def add_aruba_ap(
    router_id: uuid.UUID,
    payload: ArubaAccessPointCreateRequest,
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    service: ArubaAccessPointService = Depends(get_aruba_ap_service),
    router_service: RouterService = Depends(get_router_service),
) -> dict[str, Any]:
    """Master: add (and approve) an access point by MAC."""
    router = await router_service.get_router(router_id)
    record = await service.add(
        router,
        mac=payload.mac,
        name=payload.name,
        actor_user_id=uuid.UUID(str(user.id)),
    )
    return build_response(
        success=True,
        message="Access point added",
        data=ArubaAccessPointRecord.model_validate(record).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@aruba_ap_platform_router.patch(
    "/routers/{router_id}/ap-registry/{ap_id}",
    response_model=ApiResponse[ArubaAccessPointRecord],
    dependencies=[Depends(_PLATFORM_UPDATE)],
)
async def update_aruba_ap(
    router_id: uuid.UUID,
    ap_id: uuid.UUID,
    payload: ArubaAccessPointUpdateRequest,
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    service: ArubaAccessPointService = Depends(get_aruba_ap_service),
    router_service: RouterService = Depends(get_router_service),
) -> dict[str, Any]:
    """Master: approve / reject / rename one access point."""
    router = await router_service.get_router(router_id)
    record = await service.update(
        router,
        ap_id,
        status=payload.status,
        name=payload.name,
        actor_user_id=uuid.UUID(str(user.id)),
    )
    return build_response(
        success=True,
        message="Access point updated",
        data=ArubaAccessPointRecord.model_validate(record).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@aruba_ap_platform_router.delete(
    "/routers/{router_id}/ap-registry/{ap_id}",
    response_model=ApiResponse[dict],
    dependencies=[Depends(_PLATFORM_UPDATE)],
)
async def delete_aruba_ap(
    router_id: uuid.UUID,
    ap_id: uuid.UUID,
    request: Request,
    service: ArubaAccessPointService = Depends(get_aruba_ap_service),
    router_service: RouterService = Depends(get_router_service),
) -> dict[str, Any]:
    """Master: remove (soft-delete) one access point. Its MAC is refused
    again from the next RADIUS packet (and re-listed as pending)."""
    router = await router_service.get_router(router_id)
    await service.delete(router, ap_id)
    return build_response(
        success=True,
        message="Access point removed",
        data={"id": str(ap_id)},
        request_id=_request_id(request),
    )
