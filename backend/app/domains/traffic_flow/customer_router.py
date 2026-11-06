"""Customer-dashboard HTTP surface for traffic flow: one venue, read-only.

Separate from ``router.py`` (the Master console) on purpose: nothing here
can switch collection on or off, and nothing here returns an exporter or
tunnel address, a read-back verdict or collector health.

Every route carries the same three guards, in this order:

1. ``RequireOrganization`` -- the request is about exactly one organization,
   the caller's, as the request context resolved it;
2. ``RequireFeature(TRAFFIC_FLOW)`` -- the per-customer add-on, off for
   every organization until the Master console unlocks it (402 otherwise);
3. ``RequirePermission("venue_traffic.read", scope=LOCATION)``.

``location_id`` is in the path, and a path id alone is never trusted: the
permission check can run against an ``X-Location-Id`` header instead (the
header wins when both are present), so a check that passed says nothing
about the venue named in the URL. The service therefore loads that venue,
compares its organization with the caller's, applies the caller's location
grants, and filters every read on the loaded venue's id
(``TrafficFlowCustomerService._own_location``). A header naming a different
venue than the path is refused outright.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request

from app.common.responses import ApiResponse, build_response
from app.domains.billing.constants import PlanFeatureKey
from app.domains.billing.dependencies import RequireFeature
from app.domains.rbac.dependencies import (
    CurrentLocation,
    RequireOrganization,
    RequirePermission,
)
from app.domains.rbac.enums import ScopeType

from .constants import MAX_LIST_LIMIT, MAX_TIMELINE_SERIES
from .dependencies import get_traffic_flow_customer_service
from .service import TrafficFlowCrossLocationError, TrafficFlowCustomerService

__all__ = ["traffic_flow_customer_router"]

traffic_flow_customer_router = APIRouter(
    prefix="/traffic-flow", tags=["Traffic flow (customer)"]
)

_GUARDS: list[Any] = [
    Depends(RequireOrganization),
    Depends(RequireFeature(PlanFeatureKey.TRAFFIC_FLOW)),
    Depends(RequirePermission("venue_traffic.read", scope=ScopeType.LOCATION)),
]


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _same_venue(location_id: uuid.UUID, header_location_id: uuid.UUID | None) -> None:
    """The permission check ran against the header when one was sent. If it
    names another venue, the check was about that one, not this one."""
    if header_location_id is not None and header_location_id != location_id:
        raise TrafficFlowCrossLocationError()


@traffic_flow_customer_router.get(
    "/locations/{location_id}/status",
    response_model=ApiResponse[dict[str, Any]],
    dependencies=_GUARDS,
)
async def get_venue_traffic_status(
    location_id: uuid.UUID,
    request: Request,
    organization_id: uuid.UUID = Depends(RequireOrganization),
    header_location_id: uuid.UUID | None = Depends(CurrentLocation),
    service: TrafficFlowCustomerService = Depends(get_traffic_flow_customer_service),
) -> dict[str, Any]:
    """Is traffic being collected for this venue: ``collecting``,
    ``not_collecting_yet`` or ``not_available``, and when the newest and
    oldest data are from. No traffic figures."""
    _same_venue(location_id, header_location_id)
    data = await service.status(location_id, organization_id=organization_id)
    return build_response(
        success=True,
        message="Venue traffic status",
        data=data,
        request_id=_request_id(request),
    )


@traffic_flow_customer_router.get(
    "/locations/{location_id}/summary",
    response_model=ApiResponse[dict[str, Any]],
    dependencies=_GUARDS,
)
async def get_venue_traffic_summary(
    location_id: uuid.UUID,
    request: Request,
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    limit: int | None = Query(default=None, ge=1, le=MAX_LIST_LIMIT),
    series: int | None = Query(default=None, ge=1, le=MAX_TIMELINE_SERIES),
    router_id: uuid.UUID | None = Query(default=None),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    header_location_id: uuid.UUID | None = Depends(CurrentLocation),
    service: TrafficFlowCustomerService = Depends(get_traffic_flow_customer_service),
) -> dict[str, Any]:
    """One venue over a range (default the last hour, at most 7 days):
    totals, a per-service timeline, the protocol breakdown, and three
    independent lists -- services, devices, destinations. Never a device
    beside a destination. ``measured: false`` means no data for the range,
    which is not the same as measured zero."""
    _same_venue(location_id, header_location_id)
    data = await service.summary(
        location_id,
        organization_id=organization_id,
        since=since,
        until=until,
        limit=limit,
        series=series,
        router_id=router_id,
    )
    return build_response(
        success=True,
        message="Venue traffic summary",
        data=data,
        request_id=_request_id(request),
    )
