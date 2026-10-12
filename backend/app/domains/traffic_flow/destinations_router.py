"""Master console HTTP surface for the Destinations table and the service
drill-down. Every route is pinned to ``ScopeType.GLOBAL`` on the GLOBAL-only
``traffic_flows`` module, never left to scope inference.

Its own router (same ``/platform/traffic-flow`` prefix as ``router.py``) so
the two files change independently.

Every route here is venue-level: ``location_id`` is required, and no
parameter, row or column names a device. Every call writes an audit row
(``destinations.DestinationService``).

No customer route exists yet: see the "Customer routes -- PENDING" section
of the API notes. ``DestinationService`` already takes the caller's
organisation and the small-venue threshold for when they are added.
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
    CurrentUser,
    RequirePermission,
    get_rbac_repository,
)
from app.domains.rbac.enums import ScopeType
from app.domains.rbac.repository import RBACRepositoryProtocol

from .constants import MAX_LIST_LIMIT
from .destinations import DestinationRepository, DestinationService

__all__ = ["traffic_flow_destinations_platform_router"]

traffic_flow_destinations_platform_router = APIRouter(
    prefix="/platform/traffic-flow", tags=["Traffic flow (platform)"]
)

_READ = RequirePermission("traffic_flows.read", scope=ScopeType.GLOBAL)


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def get_destination_service(
    session: AsyncSession = Depends(get_db_session),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    settings: Settings = Depends(get_settings),
) -> DestinationService:
    return DestinationService(
        DestinationRepository(session), settings, audit_writer=audit_repository
    )


@traffic_flow_destinations_platform_router.get(
    "/destinations",
    response_model=ApiResponse[dict[str, Any]],
    dependencies=[Depends(_READ)],
)
async def search_traffic_flow_destinations(
    request: Request,
    location_id: uuid.UUID = Query(),
    router_id: uuid.UUID | None = Query(default=None),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    address: str | None = Query(default=None, max_length=64),
    protocol: int | None = Query(default=None, ge=0, le=255),
    port: int | None = Query(default=None, ge=0, le=65535),
    direction: str | None = Query(default=None, max_length=8),
    sort: str | None = Query(default=None, max_length=16),
    order: str | None = Query(default=None, max_length=8),
    user: AuthUser = Depends(CurrentUser),
    service: DestinationService = Depends(get_destination_service),
) -> dict[str, Any]:
    """Master: the venue's destination records for a range -- one row per
    (5-minute window, outside address, protocol, outside port) -- filtered
    and sorted, one page of at most 1000 with the number that matched and
    the database time. Venue-level: no record says which device. Audited."""
    data = await service.search(
        location_id=location_id,
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
        message="Traffic flow destinations",
        data=data.model_dump(),
        request_id=_request_id(request),
    )


@traffic_flow_destinations_platform_router.get(
    "/destinations/export",
    dependencies=[Depends(_READ)],
)
async def export_traffic_flow_destinations(
    location_id: uuid.UUID = Query(),
    router_id: uuid.UUID | None = Query(default=None),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    address: str | None = Query(default=None, max_length=64),
    protocol: int | None = Query(default=None, ge=0, le=255),
    port: int | None = Query(default=None, ge=0, le=65535),
    direction: str | None = Query(default=None, max_length=8),
    sort: str | None = Query(default=None, max_length=16),
    order: str | None = Query(default=None, max_length=8),
    user: AuthUser = Depends(CurrentUser),
    service: DestinationService = Depends(get_destination_service),
) -> Response:
    """Master: the same search as a CSV attachment (raw ``text/csv``, no
    envelope), capped; a cut file says so in ``X-Export-Truncated``.
    Audited."""
    export = await service.export_csv(
        location_id=location_id,
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


@traffic_flow_destinations_platform_router.get(
    "/services/destinations",
    response_model=ApiResponse[dict[str, Any]],
    dependencies=[Depends(_READ)],
)
async def get_traffic_flow_service_destinations(
    request: Request,
    location_id: uuid.UUID = Query(),
    protocol: int = Query(ge=0, le=255),
    port: int = Query(ge=0, le=65535),
    router_id: uuid.UUID | None = Query(default=None),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    limit: int | None = Query(default=None, ge=1, le=MAX_LIST_LIMIT),
    user: AuthUser = Depends(CurrentUser),
    service: DestinationService = Depends(get_destination_service),
) -> dict[str, Any]:
    """Master: for one service (protocol and outside port) of a venue, its
    top outside addresses in the range with their share of the service.
    Lower bounds, said so in the response. Venue-level. Audited."""
    data = await service.service_destinations(
        location_id=location_id,
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
        message="Traffic flow service destinations",
        data=data.model_dump(),
        request_id=_request_id(request),
    )
