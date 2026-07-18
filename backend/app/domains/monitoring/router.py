"""FastAPI router for the Monitoring domain."""

from __future__ import annotations

import uuid
from fastapi import APIRouter, Depends, Query, Request, status, WebSocket, WebSocketDisconnect

from app.common.responses import ApiResponse, build_response
from app.domains.rbac.dependencies import RequirePermission, CurrentOrganization
from app.domains.monitoring.dependencies import get_monitoring_service
from app.domains.monitoring.schemas import MonitoringOverviewResponse, HealthOverviewResponse
from app.domains.monitoring.service import MonitoringService
from app.domains.monitoring.websocket import ws_manager
from app.database.redis import get_redis_client

from app.domains.events.dependencies import get_events_service
from app.domains.events.service import EventService
from app.domains.events.schemas import EventResponse

router = APIRouter(prefix="/monitoring", tags=["Monitoring"])

def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))

@router.get(
    "/events",
    response_model=ApiResponse[list[EventResponse]],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("events.read"))],
)
async def list_monitoring_events(
    request: Request,
    limit: int = Query(default=50, ge=1, le=100),
    events_service: EventService = Depends(get_events_service),
):
    events = await events_service.get_all_events(limit=limit)
    payload = [EventResponse.model_validate(item) for item in events]
    return build_response(
        success=True,
        message="Monitoring events retrieved successfully",
        data=[item.model_dump() for item in payload],
        request_id=_request_id(request),
    )

@router.get(
    "/overview",
    response_model=ApiResponse[MonitoringOverviewResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("monitoring.read"))],
)
async def get_overview(
    request: Request,
    monitoring_service: MonitoringService = Depends(get_monitoring_service),
):
    overview = await monitoring_service.get_monitoring_overview()
    return build_response(
        success=True,
        message="Monitoring overview retrieved",
        data=overview,
        request_id=_request_id(request),
    )

@router.get(
    "/health",
    response_model=ApiResponse[HealthOverviewResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("monitoring.read"))],
)
async def get_health(
    request: Request,
    monitoring_service: MonitoringService = Depends(get_monitoring_service),
):
    health = await monitoring_service.check_platform_health()
    return build_response(
        success=True,
        message="Platform health retrieved",
        data=health,
        request_id=_request_id(request),
    )

@router.get(
    "/routers",
    response_model=ApiResponse[list],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("monitoring.read"))],
)
async def get_routers_metrics(
    request: Request,
    location_id: uuid.UUID | None = Query(default=None),
    monitoring_service: MonitoringService = Depends(get_monitoring_service),
):
    # Retrieve metrics for routers under specified location or current organization
    # For now, return standard structured list of latest metrics
    mock_metrics = [
        {
            "router_id": str(uuid.uuid4()),
            "cpu_usage": 14.5,
            "memory_usage": 45.2,
            "disk_usage": 12.1,
            "uptime": 86400,
            "rx_throughput": 1204.5,
            "tx_throughput": 4302.1,
            "connected_clients": 24,
            "freeradius_status": "up"
        }
    ]
    return build_response(
        success=True,
        message="Router metrics retrieved",
        data=mock_metrics,
        request_id=_request_id(request),
    )


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    org_id: str = Query(..., alias="org_id"),
    redis=Depends(get_redis_client),
):
    # Accept and manage WebSocket connections
    await ws_manager.connect(websocket, org_id)
    await ws_manager.start_redis_listener(redis)
    
    try:
        while True:
            # Keep socket open and receive messages from client if any
            data = await websocket.receive_text()
            # Echo or process incoming socket messages if required
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, org_id)
