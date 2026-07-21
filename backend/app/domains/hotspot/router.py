"""FastAPI routes for the Hotspot Settings domain: per-router hotspot
user-profile CRUD.

Responses use the project's standard envelope (``ApiResponse``/
``build_response``), matching every other domain's router. Every endpoint
is gated by RBAC's existing ``RequirePermission`` dependency against the
already-seeded ``hotspot.*`` permission key (see ``app.domains.rbac.seed``
-- ``PermissionModule.HOTSPOT``, pre-seeded ahead of any domain claiming
it, the same reuse posture ``app.domains.dhcp``/``app.domains
.port_forwarding`` established for ``PermissionModule.DHCP``/
``FIREWALL``) and resolves ``CurrentOrganization`` (``X-Organization-Id``),
passed through to ``HotspotService`` as ``requesting_organization_id`` --
the same tenant-scoping posture every other domain's router already
enforces.

**Route ordering matters.** ``GET /hotspot-profiles`` is registered
before ``GET /hotspot-profiles/{profile_id}`` so Starlette's
first-match-wins routing resolves the literal path first, mirroring the
same discipline ``app.domains.dhcp.router`` already follows.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.database.utils.pagination import PaginationMeta
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)

from .dependencies import get_hotspot_service
from .models import HotspotProfile
from .schemas import (
    HotspotProfileCreateRequest,
    HotspotProfileListResponse,
    HotspotProfileResponse,
    HotspotProfileUpdateRequest,
    MessageResponse,
)
from .service import HotspotService

router = APIRouter(prefix="/hotspot-profiles", tags=["Hotspot Settings"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _pagination_fields(meta: PaginationMeta) -> dict[str, int | bool]:
    return {
        "page": meta.page,
        "page_size": meta.page_size,
        "total_items": meta.total_items,
        "total_pages": meta.total_pages,
        "has_next": meta.has_next,
        "has_previous": meta.has_previous,
    }


def _profile_response(profile: HotspotProfile) -> HotspotProfileResponse:
    return HotspotProfileResponse(
        id=str(profile.id),
        router_id=str(profile.router_id),
        organization_id=str(profile.organization_id),
        location_id=str(profile.location_id),
        name=profile.name,
        session_timeout_minutes=profile.session_timeout_minutes,
        idle_timeout_minutes=profile.idle_timeout_minutes,
        upload_limit_kbps=profile.upload_limit_kbps,
        download_limit_kbps=profile.download_limit_kbps,
        walled_garden_hosts=profile.walled_garden_hosts,
        is_enabled=profile.is_enabled,
        created_at=profile.created_at,
    )


@router.post(
    "",
    response_model=ApiResponse[HotspotProfileResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("hotspot.create"))],
)
async def create_hotspot_profile(
    request: Request,
    payload: HotspotProfileCreateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: HotspotService = Depends(get_hotspot_service),
):
    profile = await service.create_profile(
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        router_id=uuid.UUID(payload.router_id),
        name=payload.name,
        session_timeout_minutes=payload.session_timeout_minutes,
        idle_timeout_minutes=payload.idle_timeout_minutes,
        upload_limit_kbps=payload.upload_limit_kbps,
        download_limit_kbps=payload.download_limit_kbps,
        walled_garden_hosts=payload.walled_garden_hosts,
        is_enabled=payload.is_enabled,
    )
    return build_response(
        success=True,
        message="Hotspot profile created",
        data=_profile_response(profile).model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "",
    response_model=ApiResponse[HotspotProfileListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("hotspot.read"))],
)
async def list_hotspot_profiles(
    request: Request,
    router_id: uuid.UUID | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: HotspotService = Depends(get_hotspot_service),
):
    profiles, meta = await service.list_profiles(
        requesting_organization_id=requesting_organization_id,
        router_id=router_id,
        page=page,
        page_size=page_size,
    )
    payload = HotspotProfileListResponse(
        items=[_profile_response(profile) for profile in profiles],
        **_pagination_fields(meta),
    )
    return build_response(
        success=True,
        message="Hotspot profiles retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/{profile_id}",
    response_model=ApiResponse[HotspotProfileResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("hotspot.read"))],
)
async def get_hotspot_profile(
    request: Request,
    profile_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: HotspotService = Depends(get_hotspot_service),
):
    profile = await service.get_profile(
        profile_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Hotspot profile retrieved",
        data=_profile_response(profile).model_dump(),
        request_id=_request_id(request),
    )


@router.put(
    "/{profile_id}",
    response_model=ApiResponse[HotspotProfileResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("hotspot.update"))],
)
async def update_hotspot_profile(
    request: Request,
    profile_id: uuid.UUID,
    payload: HotspotProfileUpdateRequest,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: HotspotService = Depends(get_hotspot_service),
):
    fields = {k: v for k, v in payload.model_dump().items() if v is not None}
    profile = await service.update_profile(
        profile_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
        **fields,
    )
    return build_response(
        success=True,
        message="Hotspot profile updated",
        data=_profile_response(profile).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/{profile_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("hotspot.delete"))],
)
async def delete_hotspot_profile(
    request: Request,
    profile_id: uuid.UUID,
    actor: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: HotspotService = Depends(get_hotspot_service),
):
    await service.delete_profile(
        profile_id,
        actor_user_id=uuid.UUID(actor.id),
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Hotspot profile deleted",
        data=MessageResponse(message="Hotspot profile deleted").model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]
