"""Customer-dashboard HTTP surface for the Destinations table and the
service drill-down: one venue, read-only, audited.

Same three guards, in the same order, as the customer venue routes
(``customer_router.py``) -- the list itself is imported from there, so the
add-on key and the permission cannot drift apart:

1. ``RequireOrganization``;
2. ``RequireFeature(TRAFFIC_FLOW)`` -- the per-customer add-on (402);
3. ``RequirePermission("venue_traffic.read", scope=LOCATION)``.

A path id alone is never trusted. The header check is the same
``_same_venue``; then ``CustomerDestinationService`` loads the venue against
the caller's organisation and venue grants, puts the organisation on every
statement, and applies the small-venue rule (a window with fewer than five
devices contributes no record). None of that is a route's to forget.

Venue-level: no parameter, row or column names a device.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.responses import ApiResponse, build_response
from app.core.config import Settings, get_settings
from app.database.session import get_db_session
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import (
    CurrentLocation,
    CurrentUser,
    RequireOrganization,
    get_rbac_repository,
)
from app.domains.rbac.repository import RBACRepositoryProtocol

from .constants import MAX_LIST_LIMIT
from .customer_router import _GUARDS, _same_venue
from .dependencies import get_traffic_flow_customer_service
from .destinations import (
    CustomerDestinationService,
    DestinationRepository,
    DestinationService,
)
from .service import TrafficFlowCustomerService

__all__ = ["traffic_flow_destinations_customer_router"]

traffic_flow_destinations_customer_router = APIRouter(
    prefix="/traffic-flow", tags=["Traffic flow (customer)"]
)

#: Not sent to a customer: the platform switch is not theirs to know about.
_MASTER_ONLY_FIELDS = {"feature_enabled"}


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def get_customer_destination_service(
    session: AsyncSession = Depends(get_db_session),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    settings: Settings = Depends(get_settings),
    venues: TrafficFlowCustomerService = Depends(get_traffic_flow_customer_service),
) -> CustomerDestinationService:
    return CustomerDestinationService(
        DestinationService(
            DestinationRepository(session), settings, audit_writer=audit_repository
        ),
        venues,
    )


@traffic_flow_destinations_customer_router.get(
    "/locations/{location_id}/destinations",
    response_model=ApiResponse[dict[str, Any]],
    dependencies=_GUARDS,
)
async def search_venue_destinations(
    location_id: uuid.UUID,
    request: Request,
    router_id: uuid.UUID | None = Query(default=None),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    address: str | None = Query(default=None, max_length=64),
    protocol: int | None = Query(default=None, ge=0, le=255),
    port: int | None = Query(default=None, ge=0, le=65535),
    direction: str | None = Query(default=None, max_length=8),
    sort: str | None = Query(default=None, max_length=16),
    order: str | None = Query(default=None, max_length=8),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    header_location_id: uuid.UUID | None = Depends(CurrentLocation),
    user: AuthUser = Depends(CurrentUser),
    service: CustomerDestinationService = Depends(get_customer_destination_service),
) -> dict[str, Any]:
    """The venue's destination records for a range: one row per (5-minute
    window, outside address, protocol, outside port), filtered and sorted,
    one page of at most 1000 with the number that matched. For the venue as
    a whole; windows with fewer than five devices are withheld and counted
    in ``windows_withheld``. Audited."""
    _same_venue(location_id, header_location_id)
    data = await service.search(
        location_id,
        organization_id=organization_id,
        actor_user_id=uuid.UUID(str(user.id)),
        router_id=router_id,
        since=since,
        until=until,
        address=address,
        protocol=protocol,
        port=port,
        direction=direction,
        sort=sort,
        order=order,
    )
    return build_response(
        success=True,
        message="Venue traffic destinations",
        data=data.model_dump(exclude=_MASTER_ONLY_FIELDS),
        request_id=_request_id(request),
    )


@traffic_flow_destinations_customer_router.get(
    "/locations/{location_id}/destinations/export",
    dependencies=_GUARDS,
)
async def export_venue_destinations(
    location_id: uuid.UUID,
    router_id: uuid.UUID | None = Query(default=None),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    address: str | None = Query(default=None, max_length=64),
    protocol: int | None = Query(default=None, ge=0, le=255),
    port: int | None = Query(default=None, ge=0, le=65535),
    direction: str | None = Query(default=None, max_length=8),
    sort: str | None = Query(default=None, max_length=16),
    order: str | None = Query(default=None, max_length=8),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    header_location_id: uuid.UUID | None = Depends(CurrentLocation),
    user: AuthUser = Depends(CurrentUser),
    service: CustomerDestinationService = Depends(get_customer_destination_service),
) -> Response:
    """The same search as a CSV attachment (raw ``text/csv``), capped; a cut
    file says so in ``X-Export-Truncated``. The small-venue rule applies to
    the file exactly as to the search. Audited."""
    _same_venue(location_id, header_location_id)
    export = await service.export_csv(
        location_id,
        organization_id=organization_id,
        actor_user_id=uuid.UUID(str(user.id)),
        router_id=router_id,
        since=since,
        until=until,
        address=address,
        protocol=protocol,
        port=port,
        direction=direction,
        sort=sort,
        order=order,
    )
    headers = {
        "Content-Disposition": f'attachment; filename="{export.filename}"',
        "X-Total-Rows": str(export.total),
        "X-Export-Rows": str(export.rows),
        "Cache-Control": "no-store",
    }
    if export.truncated:
        headers["X-Export-Truncated"] = "true"
    return Response(content=export.text, media_type="text/csv", headers=headers)


@traffic_flow_destinations_customer_router.get(
    "/locations/{location_id}/services/destinations",
    response_model=ApiResponse[dict[str, Any]],
    dependencies=_GUARDS,
)
async def get_venue_service_destinations(
    location_id: uuid.UUID,
    request: Request,
    protocol: int = Query(ge=0, le=255),
    port: int = Query(ge=0, le=65535),
    router_id: uuid.UUID | None = Query(default=None),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    limit: int | None = Query(default=None, ge=1, le=MAX_LIST_LIMIT),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    header_location_id: uuid.UUID | None = Depends(CurrentLocation),
    user: AuthUser = Depends(CurrentUser),
    service: CustomerDestinationService = Depends(get_customer_destination_service),
) -> dict[str, Any]:
    """For one service (protocol and outside port) of the venue, its top
    outside addresses in the range with their share of the service. Lower
    bounds, said so. For the venue as a whole; the small-venue rule applies.
    Audited."""
    _same_venue(location_id, header_location_id)
    data = await service.service_destinations(
        location_id,
        organization_id=organization_id,
        actor_user_id=uuid.UUID(str(user.id)),
        protocol=protocol,
        port=port,
        router_id=router_id,
        since=since,
        until=until,
        limit=limit,
    )
    return build_response(
        success=True,
        message="Venue traffic service destinations",
        data=data.model_dump(exclude=_MASTER_ONLY_FIELDS),
        request_id=_request_id(request),
    )
