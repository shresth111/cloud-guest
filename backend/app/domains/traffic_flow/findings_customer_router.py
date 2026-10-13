"""Customer-dashboard HTTP surface for venue findings: one venue, read-only.

Same three guards, in the same order, as the customer venue routes
(``customer_router.py``) -- the list itself is imported from there, so the
add-on key and the permission cannot drift apart:

1. ``RequireOrganization``;
2. ``RequireFeature(TRAFFIC_FLOW)`` -- the per-customer add-on (402);
3. ``RequirePermission("venue_traffic.read", scope=LOCATION)``.

A path id alone is never trusted. The header check is the same
``_same_venue``; then ``CustomerFindingsService`` loads the venue against
the caller's organisation and venue grants, puts the organisation on every
statement, and applies the small-venue rule to the one finding that names a
destination. None of that is a route's to forget.

A finding names a device or a destination, never both, and nothing about
how the data is gathered.
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
from .findings_router import build_findings_service
from .findings_service import CustomerFindingsService
from .service import TrafficFlowCustomerService

__all__ = ["traffic_flow_findings_customer_router"]

traffic_flow_findings_customer_router = APIRouter(
    prefix="/traffic-flow", tags=["Traffic flow (customer)"]
)


def get_customer_findings_service(
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings),
    venues: TrafficFlowCustomerService = Depends(get_traffic_flow_customer_service),
) -> CustomerFindingsService:
    return CustomerFindingsService(build_findings_service(session, settings), venues)


@traffic_flow_findings_customer_router.get(
    "/locations/{location_id}/findings",
    response_model=ApiResponse[dict[str, Any]],
    dependencies=_GUARDS,
)
async def get_venue_traffic_findings(
    location_id: uuid.UUID,
    request: Request,
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    header_location_id: uuid.UUID | None = Depends(CurrentLocation),
    service: CustomerFindingsService = Depends(get_customer_findings_service),
) -> dict[str, Any]:
    """One venue over a range (default the last hour, at most 7 days): five
    checks, each ``flagged``, ``clear`` or ``could_not_check`` with a
    reason. For the venue as a whole. The check that names outside
    addresses leaves out every 5-minute window with fewer than five devices
    and says how many (``windows_withheld``)."""
    _same_venue(location_id, header_location_id)
    data = await service.findings(
        location_id, organization_id=organization_id, since=since, until=until
    )
    return build_response(
        success=True,
        message="Venue traffic findings",
        data=data,
        request_id=str(getattr(request.state, "request_id", "")),
    )
