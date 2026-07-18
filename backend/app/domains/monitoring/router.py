"""FastAPI routes for the Monitoring domain (BE-011 Part 1: Health Engine +
Event Engine; Part 3: Real-Time WebSockets + ZTP Monitoring Dashboard +
Analytics).

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

Part 3 continues this same reuse discipline (no new "realtime"/"ztp"/
"dashboard" ``PermissionModule`` was added): ``WS /monitoring/ws/dashboard``,
``GET /monitoring/dashboard``, ``GET /monitoring/devices``, and
``GET /ztp/dashboard`` all require ``monitoring.read`` (the same
observability surface Part 1 already gates this way); ``WS
/monitoring/ws/sessions`` requires ``guest_sessions.read`` (a live guest
session feed is conceptually a ``GUEST_SESSIONS`` concern, not a platform
``MONITORING`` one); ``GET /ztp/analytics`` requires ``analytics.read``
(statistics/reports, matching ``PermissionModule.ANALYTICS``'s own
semantic, distinct from the live-status ``monitoring.read`` surface).

## WebSocket design (BE-011 Part 3)

**Two endpoints sharing one Redis channel, not one channel per message
type.** Every real-time-producing write path (``MonitoringService``'s
health-status transitions, ``AlertService``'s trigger/resolve,
``GuestService``'s login-start hook) publishes a single, uniformly-shaped
JSON message (``{"type": ..., "payload": ..., "occurred_at": ...}``) to one
shared Redis pub/sub channel, ``constants.MONITORING_LIVE_CHANNEL``. Each
WebSocket endpoint subscribes to that same channel and filters by
``message["type"]`` down to the subset it cares about
(``_DASHBOARD_MESSAGE_TYPES``/``_SESSION_MESSAGE_TYPES`` below) before
relaying to its connected client. This was chosen over one Redis channel
per message type because: (a) every publisher already knows exactly what
kind of event it is producing (no ambiguity about which channel to publish
to), (b) a single channel means a single ``PUBLISH``/subscribe surface to
reason about operationally, and (c) splitting the *client-facing* concern
(a dashboard widget wants health+alerts, a live-sessions widget wants guest
churn) from the *transport* concern (one channel) means adding a third
WebSocket endpoint with a third filter set later needs zero publisher-side
changes.

**Authentication: JWT via `?token=` query parameter.** A browser's native
``WebSocket`` API cannot set custom request headers (unlike ``fetch``/
``XMLHttpRequest``), so the conventional, widely-used pattern for
browser-originated WebSocket auth is a bearer token passed as a query
parameter, validated with the exact same
``app.domains.auth.jwt.JWTManager.validate_token`` this codebase's HTTP
``Authorization: Bearer`` flow already uses (composed, not reimplemented --
see ``_authenticate_websocket`` below). **Known, documented tradeoff:** a
token in a URL can end up recorded in server access logs, browser history,
proxy logs, and ``Referer`` headers of any subsequent same-origin request
made from a page that embeds the socket URL -- a real exposure surface a
header-based credential does not have. The alternative considered was a
**first-message auth handshake** (accept the connection unauthenticated,
require the client's first WebSocket *message* to carry the token before
subscribing to anything) -- genuinely more secure against the log-leakage
class of exposure, at the cost of a slightly more complex client (every
consumer must implement a two-step "connect, then send auth, then wait for
ack" protocol instead of a single ``new WebSocket(url + "?token=...")``
call) and a connection that briefly exists in an unauthenticated state.
The query-param pattern was chosen for this iteration as the simpler,
more conventional approach (matching how most production WebSocket APIs
that must support plain browser clients actually do this, e.g. Socket.IO's
own documented query-auth pattern) -- this is a documented, revisitable
choice, not an oversight; a deployment with strict log-hygiene requirements
(e.g. ensuring access logs are not persisted with query strings, or a
reverse proxy configured to strip/redact the ``token`` param before
logging) is the standard mitigation, and switching to the first-message
handshake later requires no change to any publisher or to
``MONITORING_LIVE_CHANNEL``'s message shape -- only to
``_authenticate_websocket``'s call site.

**Connection lifecycle.** Each endpoint subscribes to
``MONITORING_LIVE_CHANNEL`` via ``redis_client.pubsub()`` and runs two
concurrent ``asyncio`` tasks: one relaying from ``pubsub.listen()`` to
``websocket.send_json``, one awaiting ``websocket.receive()`` purely to
detect a client-initiated disconnect even when the server has nothing to
send (a pure server-push socket would otherwise never notice the client
went away until its next send attempt failed). Whichever finishes first
wins; the other is cancelled, and the Redis subscription is always
unsubscribed and the ``PubSub`` object always closed in a ``finally`` block
-- no leaked Redis subscriptions, no leaked ``asyncio`` tasks, on either a
clean client disconnect or an unexpected error.

All HTTP responses use the standard ``ApiResponse``/``build_response``
envelope; WebSocket messages are relayed verbatim as the JSON object a
publisher constructed (see ``service._publish_live_message``).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import (
    APIRouter,
    Depends,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from redis.asyncio import Redis

from app.common.responses import ApiResponse, build_response
from app.database.redis import get_redis_client
from app.domains.auth.dependencies import get_auth_repository
from app.domains.auth.jwt import InvalidTokenError, JWTManager, TokenExpiredError
from app.domains.auth.models import AuthUser
from app.domains.auth.repository import AuthRepositoryProtocol
from app.domains.auth.schemas import MessageResponse
from app.domains.guest.dependencies import get_guest_analytics_service
from app.domains.guest.service import GuestAnalyticsService
from app.domains.rbac.authorization import AccessValidator
from app.domains.rbac.dependencies import (
    CurrentUser,
    RequirePermission,
    get_access_validator,
)
from app.domains.rbac.enums import ScopeType

from .constants import (
    DEFAULT_EVENT_TIMELINE_LIMIT,
    DEFAULT_FAILURE_SAMPLE_LIMIT,
    DEFAULT_HEALTH_HISTORY_PAGE,
    DEFAULT_HEALTH_HISTORY_PAGE_SIZE,
    DEFAULT_LIST_PAGE,
    DEFAULT_LIST_PAGE_SIZE,
    DEFAULT_ZTP_PAGE,
    DEFAULT_ZTP_PAGE_SIZE,
    MAX_EVENT_TIMELINE_LIMIT,
    MONITORING_LIVE_CHANNEL,
    AlertStatus,
    EventCategory,
    EventSeverity,
    HealthComponent,
    IncidentStatus,
    RealtimeMessageType,
)
from .dependencies import (
    get_alert_service,
    get_incident_service,
    get_monitoring_service,
    get_notification_service,
    get_platform_dashboard_service,
    get_sla_service,
    get_ztp_monitoring_service,
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
    PlatformDashboardResponse,
    ProvisioningFailureBreakdownResponse,
    ProvisioningFailureSampleResponse,
    RetryJobEntryResponse,
    RouterLifecycleEntryResponse,
    ServiceHealthResponse,
    SlaReportGenerateRequest,
    SlaReportListResponse,
    SlaReportResponse,
    SlaTargetCreateRequest,
    SlaTargetListResponse,
    SlaTargetResponse,
    SlaTargetWithLatestReportResponse,
    TimelineEntryResponse,
    ZtpAnalyticsResponse,
    ZtpDashboardResponse,
)
from .service import (
    AlertService,
    HealthCheckResult,
    IncidentService,
    MonitoringService,
    NotificationService,
    PlatformDashboardService,
    RouterLifecycleEntry,
    SlaService,
    TimelineEntry,
    ZtpAnalyticsResult,
    ZtpDashboardResult,
    ZtpMonitoringService,
)

router = APIRouter(tags=["Monitoring"])

# The message ``"type"`` values (see constants.RealtimeMessageType) each
# WebSocket endpoint relays -- see module docstring's "one shared channel,
# two purpose-filtered endpoints" write-up.
_DASHBOARD_MESSAGE_TYPES = frozenset(
    {
        RealtimeMessageType.HEALTH_TRANSITION.value,
        RealtimeMessageType.ALERT_TRIGGERED.value,
        RealtimeMessageType.ALERT_RESOLVED.value,
    }
)
_SESSION_MESSAGE_TYPES = frozenset(
    {
        RealtimeMessageType.GUEST_SESSION_STARTED.value,
        RealtimeMessageType.GUEST_SESSION_ENDED.value,
    }
)


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


# ============================================================================
# Real-Time (BE-011 Part 3): WebSocket auth + Redis pub/sub relay
# ============================================================================


async def _authenticate_websocket(
    websocket: WebSocket,
    *,
    token: str | None,
    permission_key: str,
    auth_repository: AuthRepositoryProtocol,
    access_validator: AccessValidator,
) -> AuthUser | None:
    """Authenticates + authorizes a WebSocket connection *before*
    ``websocket.accept()`` is ever called, closing with a private-use close
    code (RFC 6455 range 3000-4999, never a bare TCP drop) on any failure.
    See module docstring's "WebSocket design" section for the query-param-
    JWT scheme choice and its documented tradeoff. Composes with
    ``app.domains.auth.jwt.JWTManager``'s existing token-decode logic and
    ``app.domains.rbac.authorization.AccessValidator``'s existing
    permission-check logic -- neither is reimplemented here."""
    if not token:
        await websocket.close(code=4401, reason="Missing token query parameter")
        return None
    try:
        payload = JWTManager.validate_token(token, expected_type="access")
    except (InvalidTokenError, TokenExpiredError):
        await websocket.close(code=4401, reason="Invalid or expired token")
        return None
    try:
        user_id = uuid.UUID(str(payload["sub"]))
    except (KeyError, ValueError):
        await websocket.close(code=4401, reason="Malformed token subject")
        return None
    user = await auth_repository.get_user_by_id(user_id)
    if user is None or not user.is_active:
        await websocket.close(code=4401, reason="User is not active")
        return None
    allowed = await access_validator.has_permission(
        user_id, permission_key, scope_type=ScopeType.GLOBAL
    )
    if not allowed:
        await websocket.close(code=4403, reason="Permission denied")
        return None
    return AuthUser.from_model(user)


async def _relay_redis_to_websocket(
    websocket: WebSocket,
    pubsub,
    allowed_types: frozenset[str],
) -> None:
    """Reads ``MONITORING_LIVE_CHANNEL`` messages via ``pubsub.listen()``
    and forwards the ones matching ``allowed_types`` to the connected
    client -- the "simple asyncio task reading from redis.pubsub() and
    forwarding via websocket.send_json" the module brief asked for."""
    async for message in pubsub.listen():
        if message.get("type") != "message":
            continue
        raw = message.get("data")
        try:
            data = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if data.get("type") not in allowed_types:
            continue
        await websocket.send_json(data)


async def _watch_for_websocket_disconnect(websocket: WebSocket) -> None:
    """Awaits ``websocket.receive()`` purely to detect a client-initiated
    disconnect promptly -- necessary because a pure server-push socket with
    nothing to send would otherwise never notice the client went away until
    its next ``send_json`` attempt happened to fail."""
    while True:
        message = await websocket.receive()
        if message.get("type") == "websocket.disconnect":
            return


async def _run_live_relay(
    websocket: WebSocket,
    redis_client: Redis,
    allowed_types: frozenset[str],
) -> None:
    """Subscribes to ``MONITORING_LIVE_CHANNEL``, relays matching messages
    until either the client disconnects or the relay itself ends, then
    unsubscribes and closes the ``PubSub`` -- guarantees no leaked Redis
    subscription and no leaked ``asyncio`` task on any exit path (clean
    disconnect, error, or server-side cancellation)."""
    pubsub = redis_client.pubsub()
    await pubsub.subscribe(MONITORING_LIVE_CHANNEL)
    relay_task = asyncio.create_task(
        _relay_redis_to_websocket(websocket, pubsub, allowed_types)
    )
    disconnect_task = asyncio.create_task(_watch_for_websocket_disconnect(websocket))
    try:
        done, pending = await asyncio.wait(
            {relay_task, disconnect_task}, return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
        for task in pending:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        for task in done:
            if task is relay_task and task.exception() is not None:
                exc = task.exception()
                if not isinstance(exc, WebSocketDisconnect):
                    raise exc
    except WebSocketDisconnect:
        pass
    finally:
        with contextlib.suppress(Exception):
            await pubsub.unsubscribe(MONITORING_LIVE_CHANNEL)
        with contextlib.suppress(Exception):
            await pubsub.aclose()


@router.websocket("/monitoring/ws/dashboard")
async def monitoring_dashboard_websocket(
    websocket: WebSocket,
    token: str | None = Query(default=None),
    redis_client: Redis = Depends(get_redis_client),
    auth_repository: AuthRepositoryProtocol = Depends(get_auth_repository),
    access_validator: AccessValidator = Depends(get_access_validator),
) -> None:
    """Broadcasts health-status transitions and alert trigger/resolve
    events -- requires ``monitoring.read`` (see module docstring's RBAC
    write-up)."""
    user = await _authenticate_websocket(
        websocket,
        token=token,
        permission_key="monitoring.read",
        auth_repository=auth_repository,
        access_validator=access_validator,
    )
    if user is None:
        return
    await websocket.accept()
    await _run_live_relay(websocket, redis_client, _DASHBOARD_MESSAGE_TYPES)


@router.websocket("/monitoring/ws/sessions")
async def monitoring_sessions_websocket(
    websocket: WebSocket,
    token: str | None = Query(default=None),
    redis_client: Redis = Depends(get_redis_client),
    auth_repository: AuthRepositoryProtocol = Depends(get_auth_repository),
    access_validator: AccessValidator = Depends(get_access_validator),
) -> None:
    """Broadcasts live guest-session start/end events -- requires
    ``guest_sessions.read`` (see module docstring's RBAC write-up)."""
    user = await _authenticate_websocket(
        websocket,
        token=token,
        permission_key="guest_sessions.read",
        auth_repository=auth_repository,
        access_validator=access_validator,
    )
    if user is None:
        return
    await websocket.accept()
    await _run_live_relay(websocket, redis_client, _SESSION_MESSAGE_TYPES)


# ============================================================================
# Dashboard Statistics + ZTP Monitoring Dashboard/Analytics (BE-011 Part 3)
# ============================================================================


def _lifecycle_entry_response(
    entry: RouterLifecycleEntry,
) -> RouterLifecycleEntryResponse:
    return RouterLifecycleEntryResponse(
        router_id=entry.router_id,
        enrollment_id=entry.enrollment_id,
        serial_number=entry.serial_number,
        mac_address=entry.mac_address,
        model=entry.model,
        name=entry.name,
        organization_id=entry.organization_id,
        location_id=entry.location_id,
        router_status=entry.router_status,
        enrollment_status=entry.enrollment_status,
        lifecycle_stage=entry.lifecycle_stage.value,
        last_seen_at=entry.last_seen_at,
        latest_job_type=entry.latest_job_type,
        latest_job_status=entry.latest_job_status,
        latest_job_attempts=entry.latest_job_attempts,
        latest_job_max_attempts=entry.latest_job_max_attempts,
    )


def _ztp_dashboard_response(result: ZtpDashboardResult) -> ZtpDashboardResponse:
    return ZtpDashboardResponse(
        stage_counts=result.stage_counts,
        pending_enrollment_count=result.pending_enrollment_count,
        items=[_lifecycle_entry_response(item) for item in result.items],
        page=result.page,
        page_size=result.page_size,
        total_items=result.total_items,
        total_pages=result.total_pages,
        has_next=result.has_next,
        has_previous=result.has_previous,
    )


def _ztp_analytics_response(result: ZtpAnalyticsResult) -> ZtpAnalyticsResponse:
    return ZtpAnalyticsResponse(
        success_rate_percentage=result.success_rate_percentage,
        succeeded_job_count=result.succeeded_job_count,
        terminal_job_count=result.terminal_job_count,
        failure_breakdown=[
            ProvisioningFailureBreakdownResponse(
                job_type=item.job_type, failure_count=item.failure_count
            )
            for item in result.failure_breakdown
        ],
        failure_samples=[
            ProvisioningFailureSampleResponse(
                job_id=item.job_id,
                router_id=item.router_id,
                job_type=item.job_type,
                attempts=item.attempts,
                max_attempts=item.max_attempts,
                error_message=item.error_message,
                scheduled_at=item.scheduled_at,
            )
            for item in result.failure_samples
        ],
        retry_jobs=[
            RetryJobEntryResponse(
                job_id=item.job_id,
                router_id=item.router_id,
                job_type=item.job_type,
                status=item.status,
                attempts=item.attempts,
                max_attempts=item.max_attempts,
                attempts_remaining=item.attempts_remaining,
                scheduled_at=item.scheduled_at,
            )
            for item in result.retry_jobs
        ],
        average_activation_seconds=result.average_activation_seconds,
        activation_sample_size=result.activation_sample_size,
    )


@router.get(
    "/monitoring/dashboard",
    response_model=ApiResponse[PlatformDashboardResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("monitoring.read"))],
)
async def get_platform_dashboard(
    request: Request,
    organization_id: uuid.UUID | None = Query(default=None),
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
    service: PlatformDashboardService = Depends(get_platform_dashboard_service),
    guest_analytics_service: GuestAnalyticsService = Depends(
        get_guest_analytics_service
    ),
):
    """The overall dashboard-statistics summary -- health/alerts/devices/
    provisioning (and, when ``organization_id`` is supplied, visitors) at a
    glance. Defaults to the trailing 24 hours when no date range is given.
    ``guest_analytics_service`` is resolved here (not inside
    ``dependencies.get_platform_dashboard_service``) to avoid a circular
    import between ``app.domains.monitoring.dependencies`` and
    ``app.domains.guest.dependencies`` -- see that factory's own docstring.
    """
    end = end_date or datetime.now(UTC)
    start = start_date or (end - timedelta(hours=24))
    result = await service.get_dashboard_statistics(
        organization_id=organization_id,
        start=start,
        end=end,
        guest_visitor_lookup=guest_analytics_service,
    )
    payload = PlatformDashboardResponse(
        overall_health_status=result.overall_health_status,
        health_components=[
            _service_health_response(row) for row in result.health_components
        ],
        alert_counts_by_severity=result.alert_counts_by_severity,
        alert_counts_by_status=result.alert_counts_by_status,
        device_counts_by_status=result.device_counts_by_status,
        lifecycle_stage_counts=result.lifecycle_stage_counts,
        pending_enrollment_count=result.pending_enrollment_count,
        average_response_time_ms=result.average_response_time_ms,
        availability_percentage=result.availability_percentage,
        visitors=result.visitors,
        unique_guests=result.unique_guests,
    )
    return build_response(
        success=True,
        message="Platform dashboard statistics retrieved",
        data=payload.model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/monitoring/devices",
    response_model=ApiResponse[ZtpDashboardResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("monitoring.read"))],
)
async def get_device_statistics(
    request: Request,
    organization_id: uuid.UUID | None = Query(default=None),
    page: int = Query(default=DEFAULT_ZTP_PAGE, ge=1),
    page_size: int = Query(default=DEFAULT_ZTP_PAGE_SIZE, ge=1, le=100),
    service: ZtpMonitoringService = Depends(get_ztp_monitoring_service),
):
    """Device statistics + per-router lifecycle-stage listing. Calls the
    exact same ``ZtpMonitoringService.get_dashboard`` as
    ``GET /ztp/dashboard`` below (this endpoint is that data framed for the
    monitoring dashboard's device tab) -- deliberately not a second
    implementation, per this module's "compose, don't duplicate" discipline.
    """
    result = await service.get_dashboard(
        organization_id=organization_id, page=page, page_size=page_size
    )
    return build_response(
        success=True,
        message="Device statistics retrieved",
        data=_ztp_dashboard_response(result).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/ztp/dashboard",
    response_model=ApiResponse[ZtpDashboardResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("monitoring.read"))],
)
async def get_ztp_dashboard(
    request: Request,
    organization_id: uuid.UUID | None = Query(default=None),
    page: int = Query(default=DEFAULT_ZTP_PAGE, ge=1),
    page_size: int = Query(default=DEFAULT_ZTP_PAGE_SIZE, ge=1, le=100),
    service: ZtpMonitoringService = Depends(get_ztp_monitoring_service),
):
    """Provisioning dashboard/status/progress: the unified "where does every
    router currently sit" view (read-only aggregation over
    ``app.domains.router_provisioning``'s own existing data -- see
    ``service.ZtpMonitoringService``'s own docstring)."""
    result = await service.get_dashboard(
        organization_id=organization_id, page=page, page_size=page_size
    )
    return build_response(
        success=True,
        message="ZTP provisioning dashboard retrieved",
        data=_ztp_dashboard_response(result).model_dump(mode="json"),
        request_id=_request_id(request),
    )


@router.get(
    "/ztp/analytics",
    response_model=ApiResponse[ZtpAnalyticsResponse],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(RequirePermission("analytics.read"))],
)
async def get_ztp_analytics(
    request: Request,
    organization_id: uuid.UUID | None = Query(default=None),
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
    retry_page: int = Query(default=DEFAULT_ZTP_PAGE, ge=1),
    retry_page_size: int = Query(default=DEFAULT_ZTP_PAGE_SIZE, ge=1, le=100),
    failure_sample_limit: int = Query(
        default=DEFAULT_FAILURE_SAMPLE_LIMIT, ge=1, le=50
    ),
    service: ZtpMonitoringService = Depends(get_ztp_monitoring_service),
):
    """Provisioning Success Rate + Failure Reports + Retry Dashboard +
    Router Activation timing. Defaults to the trailing 30 days when no date
    range is given (mirrors ``DEFAULT_SLA_MEASUREMENT_WINDOW_DAYS``'s
    identical default window)."""
    end = end_date or datetime.now(UTC)
    start = start_date or (end - timedelta(days=30))
    result = await service.get_analytics(
        organization_id=organization_id,
        start=start,
        end=end,
        failure_sample_limit=failure_sample_limit,
        retry_page=retry_page,
        retry_page_size=retry_page_size,
    )
    return build_response(
        success=True,
        message="ZTP provisioning analytics retrieved",
        data=_ztp_analytics_response(result).model_dump(mode="json"),
        request_id=_request_id(request),
    )


__all__ = ["router"]
