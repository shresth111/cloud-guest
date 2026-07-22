"""FastAPI routes for the Controller Logs domain: six real log
categories, each with its own list + CSV export endpoint.

Responses use the project's standard envelope (``ApiResponse``/
``build_response``) for list endpoints, matching every other domain's
router -- except the ``*/export`` endpoints, which deliberately return a
raw CSV ``Response`` (mirrors
``app.domains.voucher.router.export_voucher_batch``'s identical "a file
someone opens directly cannot usefully be JSON-wrapped" reasoning).
Every endpoint is gated by RBAC's existing ``RequirePermission``
dependency against the already-seeded ``audit_logs.*`` permission keys
(this domain reuses the pre-existing ``PermissionModule.AUDIT_LOGS``
key -- log viewing/export is exactly what that module was seeded for,
the same reuse posture ``app.domains.dhcp``/``app.domains
.port_forwarding`` established for ``PermissionModule.DHCP``/
``FIREWALL``) and resolves ``CurrentOrganization`` where the underlying
source is genuinely tenant-scoped (see ``service.py``'s own module
docstring for which categories are, and which are honestly platform-wide).

CSV export is bounded to the most recent
``constants.MAX_EXPORT_ROWS`` rows -- a real, documented limit, never a
silent truncation.
"""

from __future__ import annotations

import csv
import io
import uuid

from fastapi import APIRouter, Depends, Query, Request, Response, status

from app.common.responses import ApiResponse, build_response
from app.database.utils.pagination import PaginationMeta
from app.domains.auth.models import LoginAttempt
from app.domains.guest.models import GuestLoginHistory
from app.domains.monitoring.constants import HealthComponent
from app.domains.monitoring.models import HealthCheck
from app.domains.provisioning_engine.models import ProvisionLog
from app.domains.rbac.dependencies import CurrentOrganization, RequirePermission
from app.domains.router_provisioning.models import ConfigVersion, RouterEvent

from .constants import MAX_EXPORT_ROWS
from .dependencies import get_controller_logs_service
from .schemas import (
    ConfigVersionLogListResponse,
    ConfigVersionLogResponse,
    GuestLoginHistoryLogListResponse,
    GuestLoginHistoryLogResponse,
    HealthCheckLogListResponse,
    HealthCheckLogResponse,
    LoginAttemptLogListResponse,
    LoginAttemptLogResponse,
    ProvisionLogEntryResponse,
    ProvisionLogListResponse,
    RouterEventLogListResponse,
    RouterEventLogResponse,
)
from .service import ControllerLogsService

router = APIRouter(prefix="/controller-logs", tags=["Controller Logs"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _pagination_fields(meta: PaginationMeta) -> dict[str, int | bool]:
    return {
        "page": meta.page,
        "page_size": meta.page_size,
        "total_items": meta.total_items,
        "total_pages": meta.total_pages,
        "has_next": meta.has_next,
        "has_previous": meta.has_previous,
    }


def _csv_response(
    rows: list[list[object]], *, header: list[str], filename: str
) -> Response:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(header)
    writer.writerows(rows)
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ============================================================================
# Response builders
# ============================================================================


def _provision_log_response(entry: ProvisionLog) -> ProvisionLogEntryResponse:
    return ProvisionLogEntryResponse(
        id=str(entry.id),
        job_id=str(entry.job_id),
        step_id=str(entry.step_id) if entry.step_id else None,
        level=entry.level,
        message=entry.message,
        logged_at=entry.logged_at,
    )


def _config_version_response(version: ConfigVersion) -> ConfigVersionLogResponse:
    return ConfigVersionLogResponse(
        id=str(version.id),
        router_id=str(version.router_id),
        version_number=version.version_number,
        status=version.status,
        applied_at=version.applied_at,
        rollback_of_version_id=(
            str(version.rollback_of_version_id)
            if version.rollback_of_version_id
            else None
        ),
        is_backup=version.is_backup,
        created_at=version.created_at,
    )


def _router_event_response(event: RouterEvent) -> RouterEventLogResponse:
    return RouterEventLogResponse(
        id=str(event.id),
        router_id=str(event.router_id),
        event_type=event.event_type,
        message=event.message,
        occurred_at=event.occurred_at,
        metadata=event.event_metadata,
    )


def _login_attempt_response(attempt: LoginAttempt) -> LoginAttemptLogResponse:
    return LoginAttemptLogResponse(
        id=str(attempt.id),
        user_id=str(attempt.user_id) if attempt.user_id else None,
        email=attempt.email,
        ip_address=attempt.ip_address,
        user_agent=attempt.user_agent,
        success=attempt.success,
        failure_reason=attempt.failure_reason,
        created_at=attempt.created_at,
    )


def _guest_login_history_response(
    entry: GuestLoginHistory,
) -> GuestLoginHistoryLogResponse:
    return GuestLoginHistoryLogResponse(
        id=str(entry.id),
        guest_id=str(entry.guest_id) if entry.guest_id else None,
        organization_id=str(entry.organization_id) if entry.organization_id else None,
        location_id=str(entry.location_id) if entry.location_id else None,
        identifier=entry.identifier,
        auth_method=entry.auth_method,
        success=entry.success,
        failure_reason=entry.failure_reason,
        attempted_at=entry.attempted_at,
        ip_address=entry.ip_address,
    )


def _health_check_response(check: HealthCheck) -> HealthCheckLogResponse:
    return HealthCheckLogResponse(
        id=str(check.id),
        component=check.component,
        status=check.status,
        checked_at=check.checked_at,
        response_time_ms=check.response_time_ms,
        error_message=check.error_message,
    )


# ============================================================================
# Provision Logs
# ============================================================================


@router.get(
    "/provision/{router_id}",
    response_model=ApiResponse[ProvisionLogListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("audit_logs.read"))],
)
async def list_provision_logs(
    request: Request,
    router_id: uuid.UUID,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ControllerLogsService = Depends(get_controller_logs_service),
):
    entries, meta = await service.list_provision_logs(
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
        page=page,
        page_size=page_size,
    )
    payload = ProvisionLogListResponse(
        items=[_provision_log_response(entry) for entry in entries],
        **_pagination_fields(meta),
    )
    return build_response(
        success=True,
        message="Provision logs retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/provision/{router_id}/export",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("audit_logs.export"))],
)
async def export_provision_logs(
    router_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ControllerLogsService = Depends(get_controller_logs_service),
) -> Response:
    entries, _ = await service.list_provision_logs(
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
        page=1,
        page_size=MAX_EXPORT_ROWS,
    )
    rows = [
        [str(e.id), str(e.job_id), e.level, e.message, e.logged_at.isoformat()]
        for e in entries
    ]
    return _csv_response(
        rows,
        header=["id", "job_id", "level", "message", "logged_at"],
        filename="provision_logs.csv",
    )


# ============================================================================
# Configuration Logs
# ============================================================================


@router.get(
    "/configuration/{router_id}",
    response_model=ApiResponse[ConfigVersionLogListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("audit_logs.read"))],
)
async def list_configuration_logs(
    request: Request,
    router_id: uuid.UUID,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ControllerLogsService = Depends(get_controller_logs_service),
):
    versions, meta = await service.list_configuration_logs(
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
        page=page,
        page_size=page_size,
    )
    payload = ConfigVersionLogListResponse(
        items=[_config_version_response(v) for v in versions],
        **_pagination_fields(meta),
    )
    return build_response(
        success=True,
        message="Configuration logs retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/configuration/{router_id}/export",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("audit_logs.export"))],
)
async def export_configuration_logs(
    router_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ControllerLogsService = Depends(get_controller_logs_service),
) -> Response:
    versions, _ = await service.list_configuration_logs(
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
        page=1,
        page_size=MAX_EXPORT_ROWS,
    )
    rows = [
        [
            str(v.id),
            v.version_number,
            v.status,
            v.applied_at.isoformat() if v.applied_at else "",
            v.created_at.isoformat(),
        ]
        for v in versions
    ]
    return _csv_response(
        rows,
        header=["id", "version_number", "status", "applied_at", "created_at"],
        filename="configuration_logs.csv",
    )


# ============================================================================
# Router Logs
# ============================================================================


@router.get(
    "/router/{router_id}",
    response_model=ApiResponse[RouterEventLogListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("audit_logs.read"))],
)
async def list_router_logs(
    request: Request,
    router_id: uuid.UUID,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ControllerLogsService = Depends(get_controller_logs_service),
):
    events, meta = await service.list_router_logs(
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
        page=page,
        page_size=page_size,
    )
    payload = RouterEventLogListResponse(
        items=[_router_event_response(e) for e in events], **_pagination_fields(meta)
    )
    return build_response(
        success=True,
        message="Router logs retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/router/{router_id}/export",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("audit_logs.export"))],
)
async def export_router_logs(
    router_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ControllerLogsService = Depends(get_controller_logs_service),
) -> Response:
    events, _ = await service.list_router_logs(
        router_id=router_id,
        requesting_organization_id=requesting_organization_id,
        page=1,
        page_size=MAX_EXPORT_ROWS,
    )
    rows = [
        [str(e.id), e.event_type, e.message or "", e.occurred_at.isoformat()]
        for e in events
    ]
    return _csv_response(
        rows,
        header=["id", "event_type", "message", "occurred_at"],
        filename="router_logs.csv",
    )


# ============================================================================
# Authentication Logs -- admin/user (platform-wide, see service.py)
# ============================================================================


@router.get(
    "/authentication/admin",
    response_model=ApiResponse[LoginAttemptLogListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("audit_logs.read"))],
)
async def list_admin_authentication_logs(
    request: Request,
    email: str | None = Query(default=None),
    success: bool | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    service: ControllerLogsService = Depends(get_controller_logs_service),
):
    attempts, meta = await service.list_admin_authentication_logs(
        email=email, success=success, page=page, page_size=page_size
    )
    payload = LoginAttemptLogListResponse(
        items=[_login_attempt_response(a) for a in attempts], **_pagination_fields(meta)
    )
    return build_response(
        success=True,
        message="Admin authentication logs retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/authentication/admin/export",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("audit_logs.export"))],
)
async def export_admin_authentication_logs(
    service: ControllerLogsService = Depends(get_controller_logs_service),
) -> Response:
    attempts, _ = await service.list_admin_authentication_logs(
        page=1, page_size=MAX_EXPORT_ROWS
    )
    rows = [
        [str(a.id), a.email, a.ip_address, a.success, a.created_at.isoformat()]
        for a in attempts
    ]
    return _csv_response(
        rows,
        header=["id", "email", "ip_address", "success", "created_at"],
        filename="admin_authentication_logs.csv",
    )


# ============================================================================
# Authentication Logs -- guest (tenant-scoped)
# ============================================================================


@router.get(
    "/authentication/guest",
    response_model=ApiResponse[GuestLoginHistoryLogListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("audit_logs.read"))],
)
async def list_guest_authentication_logs(
    request: Request,
    location_id: uuid.UUID | None = Query(default=None),
    guest_id: uuid.UUID | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ControllerLogsService = Depends(get_controller_logs_service),
):
    entries, meta = await service.list_guest_authentication_logs(
        requesting_organization_id=requesting_organization_id,
        location_id=location_id,
        guest_id=guest_id,
        page=page,
        page_size=page_size,
    )
    payload = GuestLoginHistoryLogListResponse(
        items=[_guest_login_history_response(e) for e in entries],
        **_pagination_fields(meta),
    )
    return build_response(
        success=True,
        message="Guest authentication logs retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/authentication/guest/export",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("audit_logs.export"))],
)
async def export_guest_authentication_logs(
    requesting_organization_id: uuid.UUID | None = Depends(CurrentOrganization),
    service: ControllerLogsService = Depends(get_controller_logs_service),
) -> Response:
    entries, _ = await service.list_guest_authentication_logs(
        requesting_organization_id=requesting_organization_id,
        page=1,
        page_size=MAX_EXPORT_ROWS,
    )
    rows = [
        [
            str(e.id),
            e.identifier,
            e.auth_method,
            e.success,
            e.attempted_at.isoformat(),
        ]
        for e in entries
    ]
    return _csv_response(
        rows,
        header=["id", "identifier", "auth_method", "success", "attempted_at"],
        filename="guest_authentication_logs.csv",
    )


# ============================================================================
# System Logs -- platform component health (see service.py)
# ============================================================================


@router.get(
    "/system",
    response_model=ApiResponse[HealthCheckLogListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("audit_logs.read"))],
)
async def list_system_logs(
    request: Request,
    component: HealthComponent = Query(...),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    service: ControllerLogsService = Depends(get_controller_logs_service),
):
    checks, meta = await service.list_system_logs(
        component=component, page=page, page_size=page_size
    )
    payload = HealthCheckLogListResponse(
        items=[_health_check_response(c) for c in checks], **_pagination_fields(meta)
    )
    return build_response(
        success=True,
        message="System logs retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/system/export",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("audit_logs.export"))],
)
async def export_system_logs(
    component: HealthComponent = Query(...),
    service: ControllerLogsService = Depends(get_controller_logs_service),
) -> Response:
    checks, _ = await service.list_system_logs(
        component=component, page=1, page_size=MAX_EXPORT_ROWS
    )
    rows = [
        [str(c.id), c.component, c.status, c.checked_at.isoformat(), c.response_time_ms]
        for c in checks
    ]
    return _csv_response(
        rows,
        header=["id", "component", "status", "checked_at", "response_time_ms"],
        filename="system_logs.csv",
    )


__all__ = ["router"]
