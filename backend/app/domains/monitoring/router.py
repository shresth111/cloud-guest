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
from app.domains.auth.models import AuthUser
from app.domains.auth.schemas import MessageResponse
from app.domains.rbac.dependencies import CurrentUser, RequirePermission

from .constants import (
    DEFAULT_EVENT_TIMELINE_LIMIT,
    DEFAULT_HEALTH_HISTORY_PAGE,
    DEFAULT_HEALTH_HISTORY_PAGE_SIZE,
    DEFAULT_LIST_PAGE,
    DEFAULT_LIST_PAGE_SIZE,
    MAX_EVENT_TIMELINE_LIMIT,
    AlertStatus,
    EventCategory,
    EventSeverity,
    HealthComponent,
    IncidentStatus,
)
from .dependencies import (
    get_alert_service,
    get_incident_service,
    get_monitoring_service,
    get_notification_service,
    get_sla_service,
)
from .models import (
    Alert,
    AlertRule,
    HealthCheck,
    Incident,
    NotificationChannel,
    NotificationLog,
    ServiceHealth,
    SlaReport,
    SlaTarget,
)
from .schemas import (
    AlertListResponse,
    AlertResponse,
    AlertRuleCreateRequest,
    AlertRuleListResponse,
    AlertRuleResponse,
    AlertRuleUpdateRequest,
    DashboardSummaryResponse,
    EventTimelineResponse,
    HealthCheckResponse,
    HealthCheckRunResponse,
    HealthHistoryResponse,
    IncidentAlertAttachRequest,
    IncidentCreateRequest,
    IncidentListResponse,
    IncidentResponse,
    IncidentUpdateRequest,
    NotificationChannelCreateRequest,
    NotificationChannelListResponse,
    NotificationChannelResponse,
    NotificationChannelUpdateRequest,
    NotificationLogListResponse,
    NotificationLogResponse,
    ServiceHealthResponse,
    SlaReportGenerateRequest,
    SlaReportListResponse,
    SlaReportResponse,
    SlaTargetCreateRequest,
    SlaTargetListResponse,
    SlaTargetResponse,
    SlaTargetWithLatestReportResponse,
    TimelineEntryResponse,
)
from .service import (
    AlertService,
    HealthCheckResult,
    IncidentService,
    MonitoringService,
    NotificationService,
    SlaService,
    TimelineEntry,
)

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


# ============================================================================
# Alert Engine response builders
# ============================================================================


def _alert_rule_response(rule: AlertRule) -> AlertRuleResponse:
    return AlertRuleResponse.model_validate(rule)


def _alert_response(alert: Alert) -> AlertResponse:
    return AlertResponse.model_validate(alert)


def _notification_channel_response(
    channel: NotificationChannel,
) -> NotificationChannelResponse:
    return NotificationChannelResponse.model_validate(channel)


def _notification_log_response(log: NotificationLog) -> NotificationLogResponse:
    return NotificationLogResponse.model_validate(log)


def _incident_response(incident: Incident) -> IncidentResponse:
    return IncidentResponse.model_validate(incident)


def _sla_target_response(target: SlaTarget) -> SlaTargetResponse:
    return SlaTargetResponse.model_validate(target)


def _sla_report_response(report: SlaReport) -> SlaReportResponse:
    return SlaReportResponse.model_validate(report)


# ============================================================================
# Alert Engine endpoints
#
# RBAC key reuse: app.domains.rbac.enums.PermissionModule.ALERTS is seeded
# (see app.domains.rbac.seed.MODULE_ACTIONS) with read/update/delete/view/
# manage -- there is no seeded "create" action for this module. Alert-rule
# *creation* therefore uses "alerts.manage" (the closest seeded action for
# an admin-gated write with no dedicated create grant); update/delete reuse
# their own precise seeded actions ("alerts.update"/"alerts.delete"). Every
# GET uses "alerts.read". See docs/monitoring/FLOW.md for the full write-up.
# ============================================================================


@router.post(
    "/alerts/rules",
    response_model=ApiResponse[AlertRuleResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("alerts.manage"))],
)
async def create_alert_rule(
    request: Request,
    payload: AlertRuleCreateRequest,
    service: AlertService = Depends(get_alert_service),
):
    rule = await service.create_alert_rule(
        name=payload.name,
        description=payload.description,
        organization_id=payload.organization_id,
        trigger_type=payload.trigger_type,
        target_component=payload.target_component,
        condition_config=payload.condition_config,
        severity=payload.severity.value,
        is_active=payload.is_active,
        notification_channel_ids=payload.notification_channel_ids,
    )
    return build_response(
        success=True,
        message="Alert rule created",
        data=_alert_rule_response(rule).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/alerts/rules",
    response_model=ApiResponse[AlertRuleListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("alerts.read"))],
)
async def list_alert_rules(
    request: Request,
    organization_id: uuid.UUID | None = Query(default=None),
    is_active: bool | None = Query(default=None),
    page: int = Query(default=DEFAULT_LIST_PAGE, ge=1),
    page_size: int = Query(default=DEFAULT_LIST_PAGE_SIZE, ge=1, le=100),
    service: AlertService = Depends(get_alert_service),
):
    items, meta = await service.list_alert_rules(
        organization_id=organization_id,
        is_active=is_active,
        page=page,
        page_size=page_size,
    )
    payload = AlertRuleListResponse(
        items=[_alert_rule_response(item) for item in items],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="Alert rules retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/alerts/rules/{rule_id}",
    response_model=ApiResponse[AlertRuleResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("alerts.read"))],
)
async def get_alert_rule(
    request: Request,
    rule_id: uuid.UUID,
    service: AlertService = Depends(get_alert_service),
):
    rule = await service.get_alert_rule(rule_id)
    return build_response(
        success=True,
        message="Alert rule retrieved",
        data=_alert_rule_response(rule).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.put(
    "/alerts/rules/{rule_id}",
    response_model=ApiResponse[AlertRuleResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("alerts.update"))],
)
async def update_alert_rule(
    request: Request,
    rule_id: uuid.UUID,
    payload: AlertRuleUpdateRequest,
    service: AlertService = Depends(get_alert_service),
):
    data = payload.model_dump(exclude_unset=True, exclude={"notification_channel_ids"})
    if "trigger_type" in data and payload.trigger_type is not None:
        data["trigger_type"] = payload.trigger_type.value
    if "severity" in data and payload.severity is not None:
        data["severity"] = payload.severity.value
    rule = await service.update_alert_rule(
        rule_id, data=data, notification_channel_ids=payload.notification_channel_ids
    )
    return build_response(
        success=True,
        message="Alert rule updated",
        data=_alert_rule_response(rule).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.delete(
    "/alerts/rules/{rule_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("alerts.delete"))],
)
async def delete_alert_rule(
    request: Request,
    rule_id: uuid.UUID,
    service: AlertService = Depends(get_alert_service),
):
    await service.delete_alert_rule(rule_id)
    return build_response(
        success=True,
        message="Alert rule deleted",
        data=MessageResponse(message="Alert rule deleted").model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/alerts",
    response_model=ApiResponse[AlertListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("alerts.read"))],
)
async def list_alerts(
    request: Request,
    organization_id: uuid.UUID | None = Query(default=None),
    router_id: uuid.UUID | None = Query(default=None),
    alert_status: AlertStatus | None = Query(default=None, alias="status"),
    severity: str | None = Query(default=None),
    page: int = Query(default=DEFAULT_LIST_PAGE, ge=1),
    page_size: int = Query(default=DEFAULT_LIST_PAGE_SIZE, ge=1, le=100),
    service: AlertService = Depends(get_alert_service),
):
    items, meta = await service.list_alerts(
        organization_id=organization_id,
        status=alert_status.value if alert_status is not None else None,
        severity=severity,
        router_id=router_id,
        page=page,
        page_size=page_size,
    )
    payload = AlertListResponse(
        items=[_alert_response(item) for item in items],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="Alerts retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/alerts/{alert_id}",
    response_model=ApiResponse[AlertResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("alerts.read"))],
)
async def get_alert(
    request: Request,
    alert_id: uuid.UUID,
    service: AlertService = Depends(get_alert_service),
):
    alert = await service.get_alert(alert_id)
    return build_response(
        success=True,
        message="Alert retrieved",
        data=_alert_response(alert).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/alerts/{alert_id}/acknowledge",
    response_model=ApiResponse[AlertResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("alerts.update"))],
)
async def acknowledge_alert(
    request: Request,
    alert_id: uuid.UUID,
    user: AuthUser = Depends(CurrentUser),
    service: AlertService = Depends(get_alert_service),
):
    alert = await service.acknowledge_alert(alert_id, user_id=uuid.UUID(user.id))
    return build_response(
        success=True,
        message="Alert acknowledged",
        data=_alert_response(alert).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/alerts/{alert_id}/resolve",
    response_model=ApiResponse[AlertResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("alerts.update"))],
)
async def resolve_alert(
    request: Request,
    alert_id: uuid.UUID,
    service: AlertService = Depends(get_alert_service),
):
    alert = await service.resolve_alert(alert_id)
    return build_response(
        success=True,
        message="Alert resolved",
        data=_alert_response(alert).model_dump(mode="json"),
        request_id=_request_id(request),
    )


# ============================================================================
# Notification Engine endpoints
#
# RBAC key reuse: PermissionModule.NOTIFICATIONS is seeded with read/update/
# delete/manage -- no "create" action either, so channel creation uses
# "notifications.manage"; update/delete reuse their own seeded actions.
# ============================================================================


@router.post(
    "/notifications/channels",
    response_model=ApiResponse[NotificationChannelResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("notifications.manage"))],
)
async def create_notification_channel(
    request: Request,
    payload: NotificationChannelCreateRequest,
    service: NotificationService = Depends(get_notification_service),
):
    channel = await service.create_channel(
        organization_id=payload.organization_id,
        channel_type=payload.channel_type,
        name=payload.name,
        config=payload.config,
        is_active=payload.is_active,
    )
    return build_response(
        success=True,
        message="Notification channel created",
        data=_notification_channel_response(channel).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/notifications/channels",
    response_model=ApiResponse[NotificationChannelListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("notifications.read"))],
)
async def list_notification_channels(
    request: Request,
    organization_id: uuid.UUID | None = Query(default=None),
    is_active: bool | None = Query(default=None),
    page: int = Query(default=DEFAULT_LIST_PAGE, ge=1),
    page_size: int = Query(default=DEFAULT_LIST_PAGE_SIZE, ge=1, le=100),
    service: NotificationService = Depends(get_notification_service),
):
    items, meta = await service.list_channels(
        organization_id=organization_id,
        is_active=is_active,
        page=page,
        page_size=page_size,
    )
    payload = NotificationChannelListResponse(
        items=[_notification_channel_response(item) for item in items],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="Notification channels retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/notifications/channels/{channel_id}",
    response_model=ApiResponse[NotificationChannelResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("notifications.read"))],
)
async def get_notification_channel(
    request: Request,
    channel_id: uuid.UUID,
    service: NotificationService = Depends(get_notification_service),
):
    channel = await service.get_channel(channel_id)
    return build_response(
        success=True,
        message="Notification channel retrieved",
        data=_notification_channel_response(channel).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.put(
    "/notifications/channels/{channel_id}",
    response_model=ApiResponse[NotificationChannelResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("notifications.update"))],
)
async def update_notification_channel(
    request: Request,
    channel_id: uuid.UUID,
    payload: NotificationChannelUpdateRequest,
    service: NotificationService = Depends(get_notification_service),
):
    data = payload.model_dump(exclude_unset=True, exclude={"config"})
    channel = await service.update_channel(channel_id, data=data, config=payload.config)
    return build_response(
        success=True,
        message="Notification channel updated",
        data=_notification_channel_response(channel).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.delete(
    "/notifications/channels/{channel_id}",
    response_model=ApiResponse[MessageResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("notifications.delete"))],
)
async def delete_notification_channel(
    request: Request,
    channel_id: uuid.UUID,
    service: NotificationService = Depends(get_notification_service),
):
    await service.delete_channel(channel_id)
    return build_response(
        success=True,
        message="Notification channel deleted",
        data=MessageResponse(message="Notification channel deleted").model_dump(),
        request_id=_request_id(request),
    )


@router.get(
    "/notifications/logs",
    response_model=ApiResponse[NotificationLogListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("notifications.read"))],
)
async def list_notification_logs(
    request: Request,
    channel_id: uuid.UUID | None = Query(default=None),
    alert_id: uuid.UUID | None = Query(default=None),
    log_status: str | None = Query(default=None, alias="status"),
    page: int = Query(default=DEFAULT_LIST_PAGE, ge=1),
    page_size: int = Query(default=DEFAULT_LIST_PAGE_SIZE, ge=1, le=100),
    service: NotificationService = Depends(get_notification_service),
):
    items, meta = await service.list_logs(
        channel_id=channel_id,
        alert_id=alert_id,
        status=log_status,
        page=page,
        page_size=page_size,
    )
    payload = NotificationLogListResponse(
        items=[_notification_log_response(item) for item in items],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="Notification logs retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


# ============================================================================
# Incident Engine endpoints
#
# RBAC key reuse: there is no dedicated "incidents" PermissionModule among
# the seeded 36 -- incidents are closely related to alerts (an incident is
# simply a human-managed grouping of Alert rows), so this module reuses
# "alerts.*" throughout rather than inventing a new PermissionModule enum
# value. Creation uses "alerts.manage" (no seeded "create" action);
# update/attach reuse "alerts.update"; reads use "alerts.read".
# ============================================================================


@router.post(
    "/incidents",
    response_model=ApiResponse[IncidentResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("alerts.manage"))],
)
async def create_incident(
    request: Request,
    payload: IncidentCreateRequest,
    service: IncidentService = Depends(get_incident_service),
):
    incident = await service.create_incident(
        title=payload.title,
        description=payload.description,
        severity=payload.severity.value,
        organization_id=payload.organization_id,
        assigned_to_user_id=payload.assigned_to_user_id,
    )
    return build_response(
        success=True,
        message="Incident created",
        data=_incident_response(incident).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/incidents",
    response_model=ApiResponse[IncidentListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("alerts.read"))],
)
async def list_incidents(
    request: Request,
    organization_id: uuid.UUID | None = Query(default=None),
    incident_status: IncidentStatus | None = Query(default=None, alias="status"),
    severity: str | None = Query(default=None),
    page: int = Query(default=DEFAULT_LIST_PAGE, ge=1),
    page_size: int = Query(default=DEFAULT_LIST_PAGE_SIZE, ge=1, le=100),
    service: IncidentService = Depends(get_incident_service),
):
    items, meta = await service.list_incidents(
        organization_id=organization_id,
        status=incident_status.value if incident_status is not None else None,
        severity=severity,
        page=page,
        page_size=page_size,
    )
    payload = IncidentListResponse(
        items=[_incident_response(item) for item in items],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="Incidents retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/incidents/{incident_id}",
    response_model=ApiResponse[IncidentResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("alerts.read"))],
)
async def get_incident(
    request: Request,
    incident_id: uuid.UUID,
    service: IncidentService = Depends(get_incident_service),
):
    incident = await service.get_incident(incident_id)
    return build_response(
        success=True,
        message="Incident retrieved",
        data=_incident_response(incident).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.put(
    "/incidents/{incident_id}",
    response_model=ApiResponse[IncidentResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("alerts.update"))],
)
async def update_incident(
    request: Request,
    incident_id: uuid.UUID,
    payload: IncidentUpdateRequest,
    service: IncidentService = Depends(get_incident_service),
):
    incident = await service.update_incident(
        incident_id,
        status=payload.status,
        title=payload.title,
        description=payload.description,
        assigned_to_user_id=payload.assigned_to_user_id,
        resolution_notes=payload.resolution_notes,
    )
    return build_response(
        success=True,
        message="Incident updated",
        data=_incident_response(incident).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/incidents/{incident_id}/alerts",
    response_model=ApiResponse[IncidentResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("alerts.update"))],
)
async def attach_alert_to_incident(
    request: Request,
    incident_id: uuid.UUID,
    payload: IncidentAlertAttachRequest,
    service: IncidentService = Depends(get_incident_service),
):
    incident = await service.attach_alert(incident_id, payload.alert_id)
    return build_response(
        success=True,
        message="Alert attached to incident",
        data=_incident_response(incident).model_dump(mode="json"),
        request_id=_request_id(request),
    )


# ============================================================================
# SLA Monitoring endpoints
#
# RBAC key reuse: there is no dedicated "sla" PermissionModule among the
# seeded 36 -- SLA percentages are fundamentally a reporting/analytics
# concern, so this module reuses "reports.*" (seeded with read/export/view/
# manage, no "create") throughout: reads use "reports.read", writes
# (creating a target, generating an on-demand report) use "reports.manage".
# ============================================================================


@router.get(
    "/sla",
    response_model=ApiResponse[SlaTargetListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("reports.read"))],
)
async def list_sla_targets(
    request: Request,
    organization_id: uuid.UUID | None = Query(default=None),
    service: SlaService = Depends(get_sla_service),
):
    pairs = await service.list_targets_with_latest_report(
        organization_id=organization_id
    )
    payload = SlaTargetListResponse(
        items=[
            SlaTargetWithLatestReportResponse(
                target=_sla_target_response(target),
                latest_report=(
                    _sla_report_response(report) if report is not None else None
                ),
            )
            for target, report in pairs
        ]
    )
    return build_response(
        success=True,
        message="SLA targets retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/sla/targets",
    response_model=ApiResponse[SlaTargetResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("reports.manage"))],
)
async def create_sla_target(
    request: Request,
    payload: SlaTargetCreateRequest,
    service: SlaService = Depends(get_sla_service),
):
    target = await service.create_target(
        organization_id=payload.organization_id,
        component=payload.component,
        target_percentage=payload.target_percentage,
        measurement_window_days=payload.measurement_window_days,
    )
    return build_response(
        success=True,
        message="SLA target created",
        data=_sla_target_response(target).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/sla/{target_id}/reports",
    response_model=ApiResponse[SlaReportListResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("reports.read"))],
)
async def list_sla_reports(
    request: Request,
    target_id: uuid.UUID,
    page: int = Query(default=DEFAULT_LIST_PAGE, ge=1),
    page_size: int = Query(default=DEFAULT_LIST_PAGE_SIZE, ge=1, le=100),
    service: SlaService = Depends(get_sla_service),
):
    items, meta = await service.list_reports(target_id, page=page, page_size=page_size)
    payload = SlaReportListResponse(
        items=[_sla_report_response(item) for item in items],
        page=meta.page,
        page_size=meta.page_size,
        total_items=meta.total_items,
        total_pages=meta.total_pages,
        has_next=meta.has_next,
        has_previous=meta.has_previous,
    )
    return build_response(
        success=True,
        message="SLA reports retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.post(
    "/sla/{target_id}/generate-report",
    response_model=ApiResponse[SlaReportResponse],
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RequirePermission("reports.manage"))],
)
async def generate_sla_report(
    request: Request,
    target_id: uuid.UUID,
    payload: SlaReportGenerateRequest,
    service: SlaService = Depends(get_sla_service),
):
    report = await service.generate_report(target_id, period_days=payload.period_days)
    return build_response(
        success=True,
        message="SLA report generated",
        data=_sla_report_response(report).model_dump(mode="json"),
        request_id=_request_id(request),
    )


__all__ = ["router"]
