"""Master console HTTP surface for the flow table (per-flow records).

Two routes, both pinned to ``ScopeType.GLOBAL`` on the GLOBAL-only
``traffic_flows`` module, never left to scope inference. Its own router so
this file and its neighbours change independently.

These are the only readers of ``traffic_flow_records``, the one table of
the domain in which a device sits beside the address it reached. There is no
customer route and none belongs in this file: see ``flow_records.py`` for
the safeguards that go with the table. Every call writes an audit row.
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

from .flow_records import FlowRecordRepository, FlowRecordService

__all__ = ["traffic_flow_records_platform_router"]

traffic_flow_records_platform_router = APIRouter(
    prefix="/platform/traffic-flow", tags=["Traffic flow (platform)"]
)

_READ = RequirePermission("traffic_flows.read", scope=ScopeType.GLOBAL)


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def get_flow_record_service(
    session: AsyncSession = Depends(get_db_session),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    settings: Settings = Depends(get_settings),
) -> FlowRecordService:
    return FlowRecordService(
        FlowRecordRepository(session), settings, audit_writer=audit_repository
    )


def _query(
    location_id: uuid.UUID | None = Query(default=None),
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
    """The one parameter list both routes share, so the download can never
    filter differently from the search."""
    return {
        "location_id": location_id,
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


@traffic_flow_records_platform_router.get(
    "/flows",
    response_model=ApiResponse[dict[str, Any]],
    dependencies=[Depends(_READ)],
)
async def search_traffic_flow_records(
    request: Request,
    query: dict[str, Any] = Depends(_query),
    user: AuthUser = Depends(CurrentUser),
    service: FlowRecordService = Depends(get_flow_record_service),
) -> dict[str, Any]:
    """Master: flow records of one venue or router for a range to the
    minute, filtered by address, port and protocol, sorted, one page of at
    most 1000 with the number that matched and the database time. Says
    "records incomplete since ..." when the daily cap stopped storage in the
    range, and which fields the collector did not record. Audited."""
    data = await service.search(actor_user_id=uuid.UUID(str(user.id)), **query)
    return build_response(
        success=True,
        message="Traffic flow records",
        data=data.model_dump(),
        request_id=_request_id(request),
    )


@traffic_flow_records_platform_router.get(
    "/flows/export",
    dependencies=[Depends(_READ)],
)
async def export_traffic_flow_records(
    query: dict[str, Any] = Depends(_query),
    user: AuthUser = Depends(CurrentUser),
    service: FlowRecordService = Depends(get_flow_record_service),
) -> Response:
    """Master: the same search as a CSV attachment (raw ``text/csv``),
    capped; a cut file says so in ``X-Export-Truncated`` and a range the
    daily cap left incomplete in ``X-Records-Incomplete-Since``. Audited."""
    export = await service.export_csv(actor_user_id=uuid.UUID(str(user.id)), **query)
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
