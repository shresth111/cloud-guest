"""Master console HTTP surface for Geo Location. Its own ``APIRouter``,
included by ``router.py`` into ``traffic_flow_platform_router`` (so it is
served under ``/platform/traffic-flow`` and is covered by that router's
"every route is pinned GLOBAL" test). Pinned to ``ScopeType.GLOBAL`` on
``traffic_flows.read`` -- never left to scope inference."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.responses import ApiResponse, build_response
from app.core.config import Settings, get_settings
from app.database.session import get_db_session
from app.domains.rbac.dependencies import RequirePermission
from app.domains.rbac.enums import ScopeType

from .geo import MAX_GEO_COUNTRIES, MAX_GEO_NETWORKS, get_geo_lookup
from .geo_service import TrafficFlowGeoRepository, TrafficFlowGeoService

__all__ = ["traffic_flow_geo_platform_router"]

traffic_flow_geo_platform_router = APIRouter()

_READ = RequirePermission("traffic_flows.read", scope=ScopeType.GLOBAL)


def get_traffic_flow_geo_service(
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings),
) -> TrafficFlowGeoService:
    return TrafficFlowGeoService(
        TrafficFlowGeoRepository(session),
        settings,
        get_geo_lookup(settings.traffic_flow_geo_data_dir),
    )


@traffic_flow_geo_platform_router.get(
    "/geo",
    response_model=ApiResponse[dict[str, Any]],
    dependencies=[Depends(_READ)],
)
async def get_traffic_flow_geo(
    request: Request,
    router_id: uuid.UUID | None = Query(default=None),
    location_id: uuid.UUID | None = Query(default=None),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    limit: int | None = Query(default=None, ge=1, le=MAX_GEO_COUNTRIES),
    networks: int | None = Query(default=None, ge=1, le=MAX_GEO_NETWORKS),
    service: TrafficFlowGeoService = Depends(get_traffic_flow_geo_service),
) -> dict[str, Any]:
    """Master: one venue or router over a range (default the last hour, at
    most 7 days), client traffic by the country of the outside address, with
    the largest networks (AS names -- networks, not applications) inside each
    country. Exact sums: "other" and "unknown" are explicit. ``measured:
    false`` = no traffic data in the range; ``geo_measured: false`` = traffic
    was measured but not looked up; ``geo_available: false`` = the server has
    no geo data files, so nothing is being looked up. ``attribution`` must be
    shown wherever the result is."""
    data = await service.by_country(
        router_id=router_id,
        location_id=location_id,
        since=since,
        until=until,
        limit=limit,
        networks=networks,
    )
    return build_response(
        success=True,
        message="Traffic flow by country",
        data=data,
        request_id=str(getattr(request.state, "request_id", "")),
    )
