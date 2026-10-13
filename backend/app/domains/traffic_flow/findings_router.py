"""Master console HTTP surface for venue findings. Its own ``APIRouter``,
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

from .findings_service import FindingsRepository, TrafficFlowFindingsService
from .service import TrafficFlowRepository, TrafficFlowSummaryService
from .threat_list import get_threat_list

__all__ = ["build_findings_service", "traffic_flow_findings_platform_router"]

traffic_flow_findings_platform_router = APIRouter()

_READ = RequirePermission("traffic_flows.read", scope=ScopeType.GLOBAL)


def build_findings_service(
    session: AsyncSession, settings: Settings
) -> TrafficFlowFindingsService:
    return TrafficFlowFindingsService(
        FindingsRepository(session),
        TrafficFlowSummaryService(TrafficFlowRepository(session), settings),
        settings,
        get_threat_list(settings.traffic_flow_threat_data_dir),
    )


def get_traffic_flow_findings_service(
    session: AsyncSession = Depends(get_db_session),
    settings: Settings = Depends(get_settings),
) -> TrafficFlowFindingsService:
    return build_findings_service(session, settings)


@traffic_flow_findings_platform_router.get(
    "/findings",
    response_model=ApiResponse[dict[str, Any]],
    dependencies=[Depends(_READ)],
)
async def get_traffic_flow_findings(
    request: Request,
    location_id: uuid.UUID = Query(),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    service: TrafficFlowFindingsService = Depends(get_traffic_flow_findings_service),
) -> dict[str, Any]:
    """Master: the five venue-level findings for one venue and period
    (default the last hour, at most 7 days). Each rule answers ``flagged``,
    ``clear`` or ``could_not_check`` with a reason. Computed on read from
    the existing rollups; nothing is stored and nothing is notified. A
    finding names a device or a destination, never both."""
    data = await service.findings(location_id=location_id, since=since, until=until)
    return build_response(
        success=True,
        message="Traffic flow findings",
        data=data,
        request_id=str(getattr(request.state, "request_id", "")),
    )
