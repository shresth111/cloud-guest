"""Customer-dashboard HTTP surface for Geo Location: one venue, read-only.

Same three guards, in the same order, as the customer venue routes
(``customer_router.py``) -- the list itself is imported from there, so the
add-on key and the permission cannot drift apart:

1. ``RequireOrganization``;
2. ``RequireFeature(TRAFFIC_FLOW)`` -- the per-customer add-on (402);
3. ``RequirePermission("venue_traffic.read", scope=LOCATION)``.

A path id alone is never trusted. The header check is the same
``_same_venue``; then ``CustomerGeoService`` loads the venue against the
caller's organisation and venue grants, puts the organisation on every
statement, and applies the small-venue rule to networks (a window with fewer
than five devices names no network). None of that is a route's to forget.

No address, no device, and nothing about how the data is gathered.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.responses import ApiResponse, build_response
from app.core.config import Settings, get_settings
from app.database.session import get_db_session
from app.domains.rbac.dependencies import CurrentLocation, RequireOrganization

from .customer_router import _GUARDS, _same_venue
from .dependencies import get_traffic_flow_customer_service
from .geo import MAX_GEO_COUNTRIES, MAX_GEO_NETWORKS, get_geo_lookup
from .geo_service import (
    CustomerGeoService,
    TrafficFlowGeoRepository,
    TrafficFlowGeoService,
)
from .service import TrafficFlowCustomerService

__all__ = ["traffic_flow_geo_customer_router"]

traffic_flow_geo_customer_router = APIRouter(
    prefix="/traffic-flow", tags=["Traffic flow (customer)"]
)


def get_customer_geo_service(
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings),
    venues: TrafficFlowCustomerService = Depends(get_traffic_flow_customer_service),
) -> CustomerGeoService:
    return CustomerGeoService(
        TrafficFlowGeoService(
            TrafficFlowGeoRepository(session),
            settings,
            get_geo_lookup(settings.traffic_flow_geo_data_dir),
        ),
        venues,
    )


@traffic_flow_geo_customer_router.get(
    "/locations/{location_id}/geo",
    response_model=ApiResponse[dict[str, Any]],
    dependencies=_GUARDS,
)
async def get_venue_traffic_geo(
    location_id: uuid.UUID,
    request: Request,
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    limit: int | None = Query(default=None, ge=1, le=MAX_GEO_COUNTRIES),
    networks: int | None = Query(default=None, ge=1, le=MAX_GEO_NETWORKS),
    router_id: uuid.UUID | None = Query(default=None),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    header_location_id: uuid.UUID | None = Depends(CurrentLocation),
    service: CustomerGeoService = Depends(get_customer_geo_service),
) -> dict[str, Any]:
    """One venue over a range (default the last hour, at most 7 days):
    traffic by the country of the outside address, with the largest networks
    inside each country. For the venue as a whole. Country totals are always
    shown; a window with fewer than five devices names no network, and
    ``networks_withheld_windows`` counts those. ``attribution`` must be shown
    wherever the result is."""
    _same_venue(location_id, header_location_id)
    data = await service.by_country(
        location_id,
        organization_id=organization_id,
        since=since,
        until=until,
        limit=limit,
        networks=networks,
        router_id=router_id,
    )
    return build_response(
        success=True,
        message="Venue traffic by country",
        data=data,
        request_id=str(getattr(request.state, "request_id", "")),
    )
