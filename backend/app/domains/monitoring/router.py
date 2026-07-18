"""FastAPI routes for the Monitoring domain (BE-011 Part 1: Health Engine +
Event Engine).

## RBAC permission-key reuse

There is no dedicated "events" permission module in
``app.domains.rbac.enums.PermissionModule`` -- only ``MONITORING`` (already
seeded with ``read``/``view``/``manage`` actions, see
``app.domains.rbac.seed``). This module deliberately reuses
``monitoring.read``/``monitoring.manage`` for **both** the health endpoints
and the event-timeline endpoint, rather than inventing a parallel
``events.*`` permission module for what is, conceptually, the exact same
"observability" surface a platform operator is granted or denied as one
unit. ``GET`` endpoints (dashboard summary, health history, event timeline)
require ``monitoring.read``; the on-demand health-check trigger
(``POST /monitoring/health/run``) requires ``monitoring.manage`` -- an
admin-gated action, since triggering a real (if cheap) round-trip against
every platform dependency on demand is a operational action, not a plain
read.

All responses use the standard ``ApiResponse``/``build_response`` envelope.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query, Request, status

from app.common.responses import ApiResponse, build_response
from app.domains.rbac.dependencies import RequirePermission

from .constants import (
    DEFAULT_EVENT_TIMELINE_LIMIT,
    DEFAULT_HEALTH_HISTORY_PAGE,
    DEFAULT_HEALTH_HISTORY_PAGE_SIZE,
    MAX_EVENT_TIMELINE_LIMIT,
    EventCategory,
    EventSeverity,
    HealthComponent,
)
from .dependencies import get_monitoring_service
from .models import HealthCheck, ServiceHealth
from .schemas import (
    DashboardSummaryResponse,
    EventTimelineResponse,
    HealthCheckResponse,
    HealthCheckRunResponse,
    HealthHistoryResponse,
    ServiceHealthResponse,
    TimelineEntryResponse,
)
from .service import HealthCheckResult, MonitoringService, TimelineEntry

router = APIRouter(tags=["Monitoring"])


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _service_health_response(row: ServiceHealth) -> ServiceHealthResponse:
    return ServiceHealthResponse(
        component=row.component,
        status=row.status,
        last_checked_at=row.last_checked_at,
        consecutive_failure_count=row.consecutive_failure_count,
        updated_at=row.updated_at,
    )


def _health_check_response(row: HealthCheck) -> HealthCheckResponse:
    return HealthCheckResponse(
        component=row.component,
        status=row.status,
        checked_at=row.checked_at,
        response_time_ms=row.response_time_ms,
        details=row.details,
        error_message=row.error_message,
    )


def _result_response(
    result: HealthCheckResult, *, checked_at: datetime
) -> HealthCheckResponse:
    """Builds a response row for a just-executed (not yet re-queried)
    :class:`~.service.HealthCheckResult`. ``checked_at`` is the single
    timestamp the caller stamped all of one ``run_all_health_checks`` batch
    with -- ``run_all_health_checks`` itself persists each row with its own
    precise, independently-captured ``datetime.now(UTC)`` (see
    ``service.py``'s ``_persist_result``); this is purely a response-shape
    convenience for the synchronous "here's what just ran" reply."""
    return HealthCheckResponse(
        component=result.component.value,
        status=result.status.value,
        checked_at=checked_at,
        response_time_ms=result.response_time_ms,
        details=result.details,
        error_message=result.error_message,
    )


def _timeline_entry_response(entry: TimelineEntry) -> TimelineEntryResponse:
    return TimelineEntryResponse(
        occurred_at=entry.occurred_at,
        category=entry.category,
        severity=entry.severity,
        event_type=entry.event_type,
        source_domain=entry.source_domain,
        message=entry.message,
        organization_id=str(entry.organization_id) if entry.organization_id else None,
        location_id=str(entry.location_id) if entry.location_id else None,
        router_id=str(entry.router_id) if entry.router_id else None,
        metadata=entry.metadata,
    )


# ============================================================================
# Health Engine endpoints
# ============================================================================


@router.get(
    "/monitoring/health",
    response_model=ApiResponse[DashboardSummaryResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("monitoring.read"))],
)
async def get_health_dashboard(
    request: Request,
    service: MonitoringService = Depends(get_monitoring_service),
):
    summary = await service.get_dashboard_summary()
    payload = DashboardSummaryResponse(
        overall_status=summary.overall_status.value,
        components=[_service_health_response(row) for row in summary.components],
    )
    return build_response(
        success=True,
        message="Health dashboard retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/monitoring/health/{component}",
    response_model=ApiResponse[HealthHistoryResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("monitoring.read"))],
)
async def get_health_history(
    request: Request,
    component: HealthComponent,
    page: int = Query(default=DEFAULT_HEALTH_HISTORY_PAGE, ge=1),
    page_size: int = Query(default=DEFAULT_HEALTH_HISTORY_PAGE_SIZE, ge=1, le=100),
    service: MonitoringService = Depends(get_monitoring_service),
):
    items, meta = await service.get_health_history(
        component=component, page=page, page_size=page_size
    )
    payload = HealthHistoryResponse(
        items=[_health_check_response(item) for item in items],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="Health check history retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


@router.post(
    "/monitoring/health/run",
    response_model=ApiResponse[HealthCheckRunResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("monitoring.manage"))],
)
async def run_health_checks(
    request: Request,
    service: MonitoringService = Depends(get_monitoring_service),
):
    results = await service.run_all_health_checks()
    checked_at = datetime.now(UTC)
    payload = HealthCheckRunResponse(
        results=[_result_response(result, checked_at=checked_at) for result in results]
    )
    return build_response(
        success=True,
        message="Health checks executed",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


# ============================================================================
# Event Engine endpoint
# ============================================================================


@router.get(
    "/events",
    response_model=ApiResponse[EventTimelineResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("monitoring.read"))],
)
async def get_event_timeline(
    request: Request,
    organization_id: uuid.UUID | None = Query(default=None),
    category: list[EventCategory] | None = Query(default=None),
    severity: list[EventSeverity] | None = Query(default=None),
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
    limit: int = Query(
        default=DEFAULT_EVENT_TIMELINE_LIMIT, ge=1, le=MAX_EVENT_TIMELINE_LIMIT
    ),
    service: MonitoringService = Depends(get_monitoring_service),
):
    entries = await service.get_event_timeline(
        organization_id=organization_id,
        categories=category,
        severities=severity,
        start=start_date,
        end=end_date,
        limit=limit,
    )
    payload = EventTimelineResponse(
        items=[_timeline_entry_response(entry) for entry in entries]
    )
    return build_response(
        success=True,
        message="Event timeline retrieved",
        data=payload.model_dump(),
        request_id=_request_id(request),
    )


__all__ = ["router"]
