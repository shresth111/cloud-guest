"""FastAPI routes for the Location domain: site CRUD and lifecycle management.

Responses use the project's standard envelope (``ApiResponse`` /
``build_response``), matching ``app/domains/organization/router.py``. Every
mutating (and cross-tenant-sensitive read) endpoint is gated by RBAC's
existing ``RequirePermission`` dependency against the already-seeded
``locations.*`` permission keys -- this domain defines no permission keys of
its own.

``organization_id`` appears in the path for the two collection endpoints
(list/create, nested under ``/organizations/{organization_id}/locations``)
since a location is always created within a specific organization; the
remaining endpoints address a location directly by its own id. Every
endpoint additionally resolves ``CurrentOrganization`` (``X-Organization-Id``)
and passes it to ``LocationService`` as ``requesting_organization_id`` so
tenant scoping (a caller acting within organization A may only touch A's own
locations, or its MSP children's) is enforced the same way
``OrganizationService`` enforces it for organizations themselves -- not just
left to the permission check, which only verifies *what* the caller can do,
not *which tenant's data* they are doing it to.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentOrganization,
    CurrentUser,
    RequirePermission,
)

from .dependencies import get_location_service
from .enums import LocationStatus
from .models import Location
from .schemas import (
    LocationCreateRequest,
    LocationListResponse,
    LocationResponse,
    LocationUpdateRequest,
    MessageResponse,
)
from .service import LocationService

router = APIRouter(tags=["Locations"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _location_response(location: Location) -> LocationResponse:
    return LocationResponse(
        id=str(location.id),
        organization_id=str(location.organization_id),
        name=location.name,
        slug=location.slug,
        status=LocationStatus(location.status),
        address_line1=location.address_line1,
        address_line2=location.address_line2,
        city=location.city,
        state_province=location.state_province,
        postal_code=location.postal_code,
        country=location.country,
        timezone=location.timezone,
        latitude=location.latitude,
        longitude=location.longitude,
        contact_name=location.contact_name,
        contact_phone=location.contact_phone,
        contact_email=location.contact_email,
        settings=location.settings,
        created_at=location.created_at,
        updated_at=location.updated_at,
    )


# ============================================================================
# Collection endpoints (nested under an organization)
# ============================================================================


@router.get(
    "/organizations/{organization_id}/locations",
    response_model=ApiResponse[LocationListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("locations.read"))],
)
async def list_locations(
    request: Request,
    organization_id: uuid.UUID,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    search: str | None = Query(default=None, max_length=200),
    location_status: LocationStatus | None = Query(default=None),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    location_service: LocationService = Depends(get_location_service),
):
    locations, meta = await location_service.list_locations(
        organization_id=organization_id,
        requesting_organization_id=requesting_organization_id,
        page=page,
        page_size=page_size,
        search=search,
        status=location_status,
    )
    payload = LocationListResponse(
        items=[_location_response(location) for location in locations],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="Locations retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/organizations/{organization_id}/locations",
    response_model=ApiResponse[LocationResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("locations.create"))],
)
async def create_location(
    request: Request,
    organization_id: uuid.UUID,
    payload: LocationCreateRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    location_service: LocationService = Depends(get_location_service),
):
    location = await location_service.create_location(
        actor_user_id=uuid.UUID(user.id),
        organization_id=organization_id,
        requesting_organization_id=requesting_organization_id,
        name=payload.name,
        slug=payload.slug,
        status=payload.status,
        address_line1=payload.address_line1,
        address_line2=payload.address_line2,
        city=payload.city,
        state_province=payload.state_province,
        postal_code=payload.postal_code,
        country=payload.country,
        timezone=payload.timezone,
        latitude=payload.latitude,
        longitude=payload.longitude,
        contact_name=payload.contact_name,
        contact_phone=payload.contact_phone,
        contact_email=payload.contact_email,
        settings=payload.settings,
    )
    return build_response(
        success=True,
        message="Location created",
        data=_location_response(location).model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Direct location endpoints
# ============================================================================


@router.get(
    "/locations/{location_id}",
    response_model=ApiResponse[LocationResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("locations.read"))],
)
async def get_location(
    request: Request,
    location_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    location_service: LocationService = Depends(get_location_service),
):
    location = await location_service.get_location(
        location_id, requesting_organization_id=requesting_organization_id
    )
    return build_response(
        success=True,
        message="Location retrieved",
        data=_location_response(location).model_dump(),
        request_id=_request_id(request),
    )


@router.put(
    "/locations/{location_id}",
    response_model=ApiResponse[LocationResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("locations.update"))],
)
async def update_location(
    request: Request,
    location_id: uuid.UUID,
    payload: LocationUpdateRequest,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    location_service: LocationService = Depends(get_location_service),
):
    data = payload.model_dump(exclude_unset=True)
    location = await location_service.update_location(
        actor_user_id=uuid.UUID(user.id),
        location_id=location_id,
        requesting_organization_id=requesting_organization_id,
        data=data,
    )
    return build_response(
        success=True,
        message="Location updated",
        data=_location_response(location).model_dump(),
        request_id=_request_id(request),
    )


@router.delete(
    "/locations/{location_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("locations.delete"))],
)
async def archive_location(
    request: Request,
    location_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    location_service: LocationService = Depends(get_location_service),
):
    await location_service.archive_location(
        actor_user_id=uuid.UUID(user.id),
        location_id=location_id,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Location archived",
        data=MessageResponse(message="Location archived").model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/locations/{location_id}/suspend",
    response_model=ApiResponse[LocationResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("locations.manage"))],
)
async def suspend_location(
    request: Request,
    location_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    location_service: LocationService = Depends(get_location_service),
):
    location = await location_service.suspend_location(
        actor_user_id=uuid.UUID(user.id),
        location_id=location_id,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Location suspended",
        data=_location_response(location).model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/locations/{location_id}/activate",
    response_model=ApiResponse[LocationResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("locations.manage"))],
)
async def activate_location(
    request: Request,
    location_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    location_service: LocationService = Depends(get_location_service),
):
    location = await location_service.activate_location(
        actor_user_id=uuid.UUID(user.id),
        location_id=location_id,
        requesting_organization_id=requesting_organization_id,
    )
    return build_response(
        success=True,
        message="Location activated",
        data=_location_response(location).model_dump(),
        request_id=_request_id(request),
    )
