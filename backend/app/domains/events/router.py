"""FastAPI router for the Events domain."""

from __future__ import annotations

import uuid
from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.rbac.dependencies import RequirePermission
from app.domains.events.dependencies import get_events_service
from app.domains.events.schemas import EventResponse
from app.domains.events.service import EventService

router = APIRouter(prefix="/events", tags=["Events"])

def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))

@router.get(
    "",
    response_model=ApiResponse[list[EventResponse]],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("events.read"))],
)
async def list_events(
    request: Request,
    limit: int = Query(default=50, ge=1, le=100),
    events_service: EventService = Depends(get_events_service),
):
    events = await events_service.get_all_events(limit=limit)
    payload = [EventResponse.model_validate(item) for item in events]
    return build_response(
        success=True,
        message="System events retrieved successfully",
        data=[item.model_dump() for item in payload],
        request_id=_request_id(request),
    )
