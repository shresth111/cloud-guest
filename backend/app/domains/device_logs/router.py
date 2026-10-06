"""Device Logs HTTP surface.

``device_logs_ingest_router`` -- ``POST /internal/device-logs/ingest``. The
collector's endpoint. No RBAC (there is no platform user): authenticated by
the ``X-Device-Logs-Secret`` shared secret, compared in constant time, and
**404 while the feature flag is off** so the route does not even exist from
the outside until it is switched on. An empty configured secret refuses
everything. Allowlisted in ``test_route_permission_coverage`` with that
reason.

``device_logs_platform_router`` -- ``/platform/device-logs/...``. Master
console only: every route pins ``ScopeType.GLOBAL`` (never inferred from
the caller's headers -- the scope-inference trap), ``device_logs.read`` for
reads and ``device_logs.manage`` for the two routes that write to a router.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.core.config import get_settings
from app.domains.auth.models import AuthUser
from app.domains.rbac.dependencies import CurrentUser, RequirePermission
from app.domains.rbac.enums import ScopeType

from .constants import INGEST_SECRET_HEADER, MAX_PAGE_SIZE
from .dependencies import get_device_logs_service
from .schemas import (
    DeviceLogPage,
    DeviceLogsOverview,
    IngestRequest,
    IngestResult,
    RouterLoggingDetail,
)
from .service import DeviceLogsService

__all__ = ["device_logs_ingest_router", "device_logs_platform_router"]

device_logs_ingest_router = APIRouter(
    prefix="/internal/device-logs", tags=["Device Logs (collector)"]
)
device_logs_platform_router = APIRouter(
    prefix="/platform/device-logs", tags=["Device Logs (platform)"]
)

_READ = RequirePermission("device_logs.read", scope=ScopeType.GLOBAL)
_MANAGE = RequirePermission("device_logs.manage", scope=ScopeType.GLOBAL)


def _request_id(request: Request) -> str:
    return request.headers.get("X-Request-ID", "") or str(
        getattr(getattr(request, "state", None), "request_id", "")
    )


def require_ingest_secret(
    secret: str | None = Header(default=None, alias=INGEST_SECRET_HEADER),
) -> None:
    settings = get_settings()
    if not settings.device_logs_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    expected = settings.device_logs_ingest_secret
    if not expected or not secret or not secrets.compare_digest(secret, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized"
        )


@device_logs_ingest_router.post(
    "/ingest",
    response_model=ApiResponse[IngestResult],
    dependencies=[Depends(require_ingest_secret)],
)
async def ingest_device_logs(
    payload: IngestRequest,
    request: Request,
    service: DeviceLogsService = Depends(get_device_logs_service),
) -> dict[str, Any]:
    result = await service.ingest(payload.events)
    return build_response(
        success=True,
        message="Ingested",
        data=IngestResult.model_validate(result).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@device_logs_platform_router.get(
    "",
    response_model=ApiResponse[DeviceLogPage],
    dependencies=[Depends(_READ)],
)
async def list_device_logs(
    request: Request,
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    organization_id: uuid.UUID | None = Query(default=None),
    location_id: uuid.UUID | None = Query(default=None),
    router_id: uuid.UUID | None = Query(default=None),
    max_severity: int | None = Query(default=None, ge=0, le=7),
    q: str | None = Query(default=None, max_length=200),
    unattributed: bool = Query(default=False),
    cursor: str | None = Query(default=None, max_length=200),
    limit: int | None = Query(default=None, ge=1, le=MAX_PAGE_SIZE),
    service: DeviceLogsService = Depends(get_device_logs_service),
) -> dict[str, Any]:
    """Master: device log lines, newest first, keyset-paginated."""
    data = await service.list_events(
        since=since,
        until=until,
        organization_id=organization_id,
        location_id=location_id,
        router_id=router_id,
        max_severity=max_severity,
        text=q,
        unattributed_only=unattributed,
        cursor=cursor,
        limit=limit,
    )
    return build_response(
        success=True,
        message="Device logs",
        data=DeviceLogPage.model_validate(data).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@device_logs_platform_router.get(
    "/status",
    response_model=ApiResponse[DeviceLogsOverview],
    dependencies=[Depends(_READ)],
)
async def device_logs_status(
    request: Request,
    service: DeviceLogsService = Depends(get_device_logs_service),
) -> dict[str, Any]:
    """Master: is the feature on, which routers Wyfy configured, and whether
    each is actually being heard from."""
    data = await service.overview()
    return build_response(
        success=True,
        message="Device logs status",
        data=DeviceLogsOverview.model_validate(data).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@device_logs_platform_router.get(
    "/routers/{router_id}",
    response_model=ApiResponse[RouterLoggingDetail],
    dependencies=[Depends(_READ)],
)
async def router_device_logging(
    router_id: uuid.UUID,
    request: Request,
    service: DeviceLogsService = Depends(get_device_logs_service),
) -> dict[str, Any]:
    """Master: one router's remote-logging state, blocker (if any), and the
    backend-rendered paste script."""
    data = await service.router_detail(router_id)
    return build_response(
        success=True,
        message="Router remote logging",
        data=RouterLoggingDetail.model_validate(data).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@device_logs_platform_router.post(
    "/routers/{router_id}/apply",
    response_model=ApiResponse[RouterLoggingDetail],
    dependencies=[Depends(_MANAGE)],
)
async def apply_router_device_logging(
    router_id: uuid.UUID,
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    service: DeviceLogsService = Depends(get_device_logs_service),
) -> dict[str, Any]:
    """Master: write remote logging onto the router over the RouterOS API,
    then read it back. 409 while the feature flag is off."""
    data = await service.apply(router_id, actor_user_id=uuid.UUID(str(user.id)))
    return build_response(
        success=True,
        message="Remote logging applied",
        data=RouterLoggingDetail.model_validate(data).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@device_logs_platform_router.post(
    "/routers/{router_id}/remove",
    response_model=ApiResponse[RouterLoggingDetail],
    dependencies=[Depends(_MANAGE)],
)
async def remove_router_device_logging(
    router_id: uuid.UUID,
    request: Request,
    user: AuthUser = Depends(CurrentUser),
    service: DeviceLogsService = Depends(get_device_logs_service),
) -> dict[str, Any]:
    """Master: remove Wyfy's remote logging action and rules from the
    router, then read back that they are gone."""
    data = await service.remove(router_id, actor_user_id=uuid.UUID(str(user.id)))
    return build_response(
        success=True,
        message="Remote logging removed",
        data=RouterLoggingDetail.model_validate(data).model_dump(mode="json"),
        request_id=_request_id(request),
    )
