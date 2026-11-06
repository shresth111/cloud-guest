"""Customer-dashboard HTTP surface for flow records: the caller's own venue,
read-only, audited.

Guards, in this order:

1. ``RequireOrganization`` -- exactly one organisation, the caller's;
2. ``RequireFeature(TRAFFIC_FLOW_RECORDS)`` -- the SECOND add-on, off for
   every customer until the Master console unlocks it for that customer.
   It depends on ``TRAFFIC_FLOW`` (``FEATURE_REQUIRES``), so it is also off
   whenever Traffic Lens itself is locked. 402 otherwise;
3. ``RequirePermission("venue_traffic.read", scope=LOCATION)`` -- held by
   the Organization Owner only among customer roles.

A path id alone is never trusted: the header check is the venue routes'
``_same_venue``, and ``CustomerFlowRecordService`` then loads the venue
against the caller's organisation and venue grants and puts both on every
statement. Every call writes an audit row naming the user and the venue.

A row here puts a device's address beside the address it reached. Nothing
about the platform's own equipment is returned (no exporter).
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
from app.domains.billing.constants import PlanFeatureKey
from app.domains.billing.dependencies import RequireFeature
from app.domains.rbac.dependencies import (
    CurrentLocation,
    CurrentUser,
    RequireOrganization,
    RequirePermission,
    get_rbac_repository,
)
from app.domains.rbac.enums import ScopeType
from app.domains.rbac.repository import RBACRepositoryProtocol

from .customer_router import _same_venue
from .dependencies import get_traffic_flow_customer_service
from .flow_records import (
    CustomerFlowRecordService,
    FlowRecordRepository,
    FlowRecordService,
)
from .service import TrafficFlowCustomerService

__all__ = ["traffic_flow_records_customer_router"]

traffic_flow_records_customer_router = APIRouter(
    prefix="/traffic-flow", tags=["Traffic flow (customer)"]
)

_GUARDS: list[Any] = [
    Depends(RequireOrganization),
    Depends(RequireFeature(PlanFeatureKey.TRAFFIC_FLOW_RECORDS)),
    Depends(RequirePermission("venue_traffic.read", scope=ScopeType.LOCATION)),
]


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def get_customer_flow_record_service(
    session: AsyncSession = Depends(get_db_session),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    settings: Settings = Depends(get_settings),
    venues: TrafficFlowCustomerService = Depends(get_traffic_flow_customer_service),
) -> CustomerFlowRecordService:
    return CustomerFlowRecordService(
        FlowRecordService(
            FlowRecordRepository(session), settings, audit_writer=audit_repository
        ),
        venues,
    )


def _query(
    router_id: uuid.UUID | None = Query(default=None),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    address: str | None = Query(default=None, max_length=64),
    src_address: str | None = Query(default=None, max_length=64),
    dst_address: str | None = Query(default=None, max_length=64),
    port: int | None = Query(default=None, ge=0, le=65535),
    src_port: int | None = Query(default=None, ge=0, le=65535),
    dst_port: int | None = Query(default=None, ge=0, le=65535),
    protocol: int | None = Query(default=None, ge=0, le=255),
    sort: str | None = Query(default=None, max_length=16),
    order: str | None = Query(default=None, max_length=8),
) -> dict[str, Any]:
    """The filters both routes share. No venue and no organisation: the
    venue is the path's, the organisation the request context's."""
    return {
        "router_id": router_id,
        "since": since,
        "until": until,
        "address": address,
        "src_address": src_address,
        "dst_address": dst_address,
        "port": port,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "sort": sort,
        "order": order,
    }


@traffic_flow_records_customer_router.get(
    "/locations/{location_id}/flows",
    response_model=ApiResponse[dict[str, Any]],
    dependencies=_GUARDS,
)
async def search_venue_flow_records(
    location_id: uuid.UUID,
    request: Request,
    query: dict[str, Any] = Depends(_query),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    header_location_id: uuid.UUID | None = Depends(CurrentLocation),
    user: AuthUser = Depends(CurrentUser),
    service: CustomerFlowRecordService = Depends(get_customer_flow_record_service),
) -> dict[str, Any]:
    """Flow records of the caller's own venue for a range to the minute,
    filtered by address, port and protocol, sorted, one page of at most 1000
    with the number that matched. Says "records incomplete since ..." when
    the daily limit stopped storage in the range. Audited."""
    _same_venue(location_id, header_location_id)
    data = await service.search(
        location_id,
        organization_id=organization_id,
        actor_user_id=uuid.UUID(str(user.id)),
        **query,
    )
    return build_response(
        success=True,
        message="Venue flow records",
        data=data,
        request_id=_request_id(request),
    )


@traffic_flow_records_customer_router.get(
    "/locations/{location_id}/flows/export",
    dependencies=_GUARDS,
)
async def export_venue_flow_records(
    location_id: uuid.UUID,
    query: dict[str, Any] = Depends(_query),
    organization_id: uuid.UUID = Depends(RequireOrganization),
    header_location_id: uuid.UUID | None = Depends(CurrentLocation),
    user: AuthUser = Depends(CurrentUser),
    service: CustomerFlowRecordService = Depends(get_customer_flow_record_service),
) -> Response:
    """The same search as a CSV attachment, capped; a cut file and an
    incomplete range are said in response headers. Audited."""
    _same_venue(location_id, header_location_id)
    export = await service.export_csv(
        location_id,
        organization_id=organization_id,
        actor_user_id=uuid.UUID(str(user.id)),
        **query,
    )
    headers = {
        "Content-Disposition": f'attachment; filename="{export.filename}"',
        "X-Total-Rows": str(export.total),
        "X-Export-Rows": str(export.rows),
        "Cache-Control": "no-store",
    }
    if export.truncated:
        headers["X-Export-Truncated"] = "true"
    if export.incomplete_since:
        headers["X-Records-Incomplete-Since"] = export.incomplete_since
    return Response(content=export.text, media_type="text/csv", headers=headers)
