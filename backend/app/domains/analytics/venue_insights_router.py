"""``GET /analytics/venue-insights/*`` -- customer-dashboard business
insights. See ``venue_insights.py`` for the definitions and tenant-scoping
rules.

RBAC: ``analytics.read`` with an explicit ``scope=`` on every route (never
inferred from whatever headers the caller chose to send).

* The three single-venue routes take ``location_id`` as a query parameter
  and check at ``ScopeType.LOCATION``. ``_current_scope_context`` derives the
  checked organization from the location's real owner, so a location from
  another tenant fails the permission check; the service then re-proves the
  location belongs to the header organization and 404s if not, and
  ``enforce_target_location`` stops a site-scoped caller reading a sibling
  site.
* ``/locations`` compares every site in the organization, so it checks at
  ``ScopeType.ORGANIZATION``: a caller whose grant covers one site cannot
  see the others.

``RequireOrganization`` (not ``CurrentOrganization``) on every route: a
global caller asking for "all organizations" gets a 400 rather than a
cross-tenant aggregate.

These handlers write nothing -- no audit rows, no caches.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.responses import ApiResponse, build_response
from app.database.session import get_db_session
from app.domains.location.scoping import enforce_target_location
from app.domains.rbac.dependencies import (
    CurrentLocation,
    RequireOrganization,
    RequirePermission,
)
from app.domains.rbac.enums import ScopeType

from .venue_insight_schemas import (
    GuestMixResponse,
    LocationComparisonResponse,
    LoginFunnelResponse,
    PeakHoursResponse,
)
from .venue_insights import (
    VenueInsightsRepository,
    VenueInsightsService,
    resolve_window,
)

router = APIRouter(prefix="/analytics/venue-insights", tags=["Analytics"])

PERMISSION = "analytics.read"


def get_venue_insights_service(
    db: AsyncSession = Depends(get_db_session),
) -> VenueInsightsService:
    return VenueInsightsService(VenueInsightsRepository(db))


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


_START = Query(default=None, description="Inclusive window start (UTC if naive).")
_END = Query(default=None, description="Exclusive window end; at most 92 days.")


@router.get(
    "/peak-hours",
    response_model=ApiResponse[PeakHoursResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission(PERMISSION, scope=ScopeType.LOCATION))],
)
async def get_peak_hours(
    request: Request,
    location_id: uuid.UUID = Query(...),
    start_date: datetime | None = _START,
    end_date: datetime | None = _END,
    organization_id: uuid.UUID = Depends(RequireOrganization),
    scope_location_id: uuid.UUID | None = Depends(CurrentLocation),
    service: VenueInsightsService = Depends(get_venue_insights_service),
):
    enforce_target_location(
        target_location_id=location_id,
        scope_location_id=scope_location_id,
        requesting_organization_id=organization_id,
    )
    start, end = resolve_window(start_date, end_date)
    payload = await service.get_peak_hours(
        organization_id=organization_id, location_id=location_id, start=start, end=end
    )
    return build_response(
        success=True,
        message="Peak hours retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/guest-mix",
    response_model=ApiResponse[GuestMixResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission(PERMISSION, scope=ScopeType.LOCATION))],
)
async def get_guest_mix(
    request: Request,
    location_id: uuid.UUID = Query(...),
    start_date: datetime | None = _START,
    end_date: datetime | None = _END,
    organization_id: uuid.UUID = Depends(RequireOrganization),
    scope_location_id: uuid.UUID | None = Depends(CurrentLocation),
    service: VenueInsightsService = Depends(get_venue_insights_service),
):
    enforce_target_location(
        target_location_id=location_id,
        scope_location_id=scope_location_id,
        requesting_organization_id=organization_id,
    )
    start, end = resolve_window(start_date, end_date)
    payload = await service.get_guest_mix(
        organization_id=organization_id, location_id=location_id, start=start, end=end
    )
    return build_response(
        success=True,
        message="Guest mix retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/login-funnel",
    response_model=ApiResponse[LoginFunnelResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission(PERMISSION, scope=ScopeType.LOCATION))],
)
async def get_login_funnel(
    request: Request,
    location_id: uuid.UUID = Query(...),
    start_date: datetime | None = _START,
    end_date: datetime | None = _END,
    organization_id: uuid.UUID = Depends(RequireOrganization),
    scope_location_id: uuid.UUID | None = Depends(CurrentLocation),
    service: VenueInsightsService = Depends(get_venue_insights_service),
):
    enforce_target_location(
        target_location_id=location_id,
        scope_location_id=scope_location_id,
        requesting_organization_id=organization_id,
    )
    start, end = resolve_window(start_date, end_date)
    payload = await service.get_login_funnel(
        organization_id=organization_id, location_id=location_id, start=start, end=end
    )
    return build_response(
        success=True,
        message="Login funnel retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/locations",
    response_model=ApiResponse[LocationComparisonResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission(PERMISSION, scope=ScopeType.ORGANIZATION))],
)
async def get_location_comparison(
    request: Request,
    start_date: datetime | None = _START,
    end_date: datetime | None = _END,
    organization_id: uuid.UUID = Depends(RequireOrganization),
    service: VenueInsightsService = Depends(get_venue_insights_service),
):
    start, end = resolve_window(start_date, end_date)
    payload = await service.get_location_comparison(
        organization_id=organization_id, start=start, end=end
    )
    return build_response(
        success=True,
        message="Location comparison retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


__all__ = ["get_venue_insights_service", "router"]
