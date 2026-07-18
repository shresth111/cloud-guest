"""FastAPI router for the Alerts domain."""

from __future__ import annotations

import uuid
from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.rbac.dependencies import RequirePermission, CurrentUser
from app.domains.auth.models import AuthUser
from app.domains.alerts.dependencies import get_alerts_service
from app.domains.alerts.schemas import AlertResponse
from app.domains.alerts.service import AlertService

router = APIRouter(prefix="/alerts", tags=["Alerts"])

def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))

@router.get(
    "",
    response_model=ApiResponse[list[AlertResponse]],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("alerts.read"))],
)
async def list_alerts(
    request: Request,
    limit: int = Query(default=50, ge=1, le=100),
    alerts_service: AlertService = Depends(get_alerts_service),
):
    alerts = await alerts_service.get_alerts_history(limit=limit)
    payload = [AlertResponse.model_validate(alert) for alert in alerts]
    return build_response(
        success=True,
        message="Alerts retrieved successfully",
        data=[item.model_dump() for item in payload],
        request_id=_request_id(request),
    )

@router.get(
    "/{id}",
    response_model=ApiResponse[AlertResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("alerts.read"))],
)
async def get_alert(
    request: Request,
    id: uuid.UUID,
    alerts_service: AlertService = Depends(get_alerts_service),
):
    alert = await alerts_service.repository.get_by_id(id)
    if not alert:
        return build_response(
            success=False,
            message=f"Alert {id} not found",
            status_code=status.HTTP_404_NOT_FOUND,
            request_id=_request_id(request),
        )
    return build_response(
        success=True,
        message="Alert retrieved successfully",
        data=AlertResponse.model_validate(alert).model_dump(),
        request_id=_request_id(request),
    )

@router.post(
    "/{id}/acknowledge",
    response_model=ApiResponse[AlertResponse],
    status_code=status.HTTP_200_OK,
)
async def acknowledge_alert(
    request: Request,
    id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    alerts_service: AlertService = Depends(get_alerts_service),
):
    alert = await alerts_service.acknowledge_alert(id, uuid.UUID(user.id))
    return build_response(
        success=True,
        message="Alert acknowledged successfully",
        data=AlertResponse.model_validate(alert).model_dump(),
        request_id=_request_id(request),
    )

@router.post(
    "/{id}/resolve",
    response_model=ApiResponse[AlertResponse],
    status_code=status.HTTP_200_OK,
)
async def resolve_alert(
    request: Request,
    id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    alerts_service: AlertService = Depends(get_alerts_service),
):
    alert = await alerts_service.resolve_alert(id, uuid.UUID(user.id))
    return build_response(
        success=True,
        message="Alert resolved successfully",
        data=AlertResponse.model_validate(alert).model_dump(),
        request_id=_request_id(request),
    )
