"""Unit tests for BE-011 Part 2 (Alert Engine + Notification Engine +
Incident Engine + SLA Monitoring) -- everything added to
``app.domains.monitoring`` on top of Part 1's Health Engine + Event Engine
(``tests/unit/test_monitoring.py``).

Follows this project's established convention (see that file's own
docstring): plain ``assert``/native ``async def`` tests exercised against
small, hand-rolled in-memory fakes -- there is no live Postgres/Redis in
this environment, and every real outbound HTTP POST (Slack/Teams/Discord/
generic Webhook) is faked via ``httpx.MockTransport`` rather than making a
real network call.

Coverage:
* Alert rule evaluation for all three trigger types (health-status-change
  against both a platform ``ServiceHealth`` component and a per-router
  ``Router.health_status``, threshold, event-occurred), including the
  de-duplication key and the auto-recovery design.
* Alert status-transition validation.
* Notification dispatch to every channel type (email/sms/whatsapp real-vs-
  logging-only, slack/teams/discord/webhook real HTTP payload shapes), plus
  the resilience guarantee that a delivery failure never raises.
* Notification channel config encryption round-trip and validation.
* Incident lifecycle transitions and alert attachment (idempotent).
* SLA report computation (the simple check-count-ratio formula) and its
  "insufficient data" honesty guard.
* RBAC permission-key reuse for every new endpoint (introspected directly
  off the registered FastAPI routes -- this codebase's established
  convention is service-layer-only testing, see ``test_monitoring.py``; no
  route ever gets exercised via a real HTTP call/``TestClient`` anywhere in
  this codebase, so permission-key coverage is verified the same way this
  test suite verifies everything else: directly, without inventing a new
  HTTP-level testing pattern only for this domain).
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.domains.monitoring.constants import (
    ALERT_TARGET_ROUTER,
    AlertSeverity,
    AlertStatus,
    AlertTriggerType,
    IncidentStatus,
    NotificationChannelType,
    NotificationStatus,
)
from app.domains.monitoring.exceptions import (
    AlertNotFoundError,
    AlertRuleNotFoundError,
    IncidentNotFoundError,
    InsufficientSlaDataError,
    InvalidAlertRuleConfigError,
    InvalidAlertStatusTransitionError,
    InvalidIncidentStatusTransitionError,
    InvalidNotificationChannelConfigError,
    InvalidSlaTargetConfigError,
    NotificationChannelNotFoundError,
    SlaTargetNotFoundError,
)
from app.domains.monitoring.models import (
    Alert,
    AlertRule,
    Incident,
    IncidentAlert,
    NotificationChannel,
    NotificationLog,
    PlatformEvent,
    ServiceHealth,
    SlaReport,
    SlaTarget,
)
from app.domains.monitoring.service import (
    AlertService,
    IncidentService,
    NotificationService,
    SlaService,
)
from app.domains.monitoring.validators import (
    validate_alert_rule_condition_config,
    validate_notification_channel_config,
    validate_sla_target_config,
)
from app.domains.router.crypto import decrypt_secret

# ============================================================================
# Shared test doubles
# ============================================================================


def _now() -> datetime:
    return datetime.now(UTC)


def _base_fields(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": uuid.uuid4(),
        "created_at": _now(),
        "updated_at": _now(),
        "deleted_at": None,
        "is_deleted": False,
        "created_by": None,
        "updated_by": None,
        "version": 1,
    }
    base.update(overrides)
    return base


@dataclass
class FakeRouter:
    """Duck-typed stand-in for ``app.domains.router.models.Router`` -- only
    the four attributes ``AlertService`` actually reads."""

    id: uuid.UUID
    organization_id: uuid.UUID
    location_id: uuid.UUID
    name: str
    health_status: str | None


@dataclass
class FakeSnapshot:
    """Duck-typed stand-in for
    ``app.domains.router_provisioning.models.RouterHealthSnapshot``."""

    cpu_usage_percent: float | None = None
    memory_usage_percent: float | None = None
    uptime_seconds: int | None = None
    connected_clients_count: int | None = None


@dataclass
class FakeRepository:
    """Stand-in for ``MonitoringRepositoryProtocol``'s BE-011 Part 2 surface
    -- covers every method ``AlertService``/``NotificationService``/
    ``IncidentService``/``SlaService`` call. Shared across services in a
    test so e.g. an ``AlertService`` and its composed ``NotificationService``
    see the same in-memory channel/log state."""

    alert_rules: dict[uuid.UUID, AlertRule] = field(default_factory=dict)
    rule_channels: dict[uuid.UUID, list[uuid.UUID]] = field(default_factory=dict)
    alerts: dict[uuid.UUID, Alert] = field(default_factory=dict)
    routers: list[FakeRouter] = field(default_factory=list)
    snapshots: dict[uuid.UUID, FakeSnapshot] = field(default_factory=dict)
    service_health_rows: dict[str, ServiceHealth] = field(default_factory=dict)
    platform_events: list[PlatformEvent] = field(default_factory=list)
    notification_channels: dict[uuid.UUID, NotificationChannel] = field(
        default_factory=dict
    )
    notification_logs: list[NotificationLog] = field(default_factory=list)
    incidents: dict[uuid.UUID, Incident] = field(default_factory=dict)
    incident_alerts: list[IncidentAlert] = field(default_factory=list)
    sla_targets: dict[uuid.UUID, SlaTarget] = field(default_factory=dict)
    sla_reports: list[SlaReport] = field(default_factory=list)
    health_check_stats: tuple[int, int, float | None] = (0, 0, None)
    average_provisioning_duration_seconds: float | None = None

    # -- alert rules ---------------------------------------------------------
    async def create_alert_rule(self, **fields: object) -> AlertRule:
        rule = AlertRule(**_base_fields(**fields))
        self.alert_rules[rule.id] = rule
        return rule

    async def get_alert_rule(self, rule_id: uuid.UUID) -> AlertRule | None:
        rule = self.alert_rules.get(rule_id)
        return rule if rule is not None and not rule.is_deleted else None

    async def update_alert_rule(
        self, rule: AlertRule, data: dict[str, object]
    ) -> AlertRule:
        for key, value in data.items():
            if value is not None:
                setattr(rule, key, value)
        return rule

    async def soft_delete_alert_rule(self, rule: AlertRule) -> AlertRule:
        rule.is_deleted = True
        return rule

    async def list_alert_rules(self, **kwargs: object):
        raise NotImplementedError("not exercised by these unit tests")

    async def list_active_alert_rules(self) -> list[AlertRule]:
        return [
            r for r in self.alert_rules.values() if r.is_active and not r.is_deleted
        ]

    async def add_alert_rule_notification_channel(
        self, alert_rule_id: uuid.UUID, notification_channel_id: uuid.UUID
    ) -> None:
        self.rule_channels.setdefault(alert_rule_id, []).append(notification_channel_id)

    async def replace_alert_rule_notification_channels(
        self, alert_rule_id: uuid.UUID, notification_channel_ids: list[uuid.UUID]
    ) -> None:
        self.rule_channels[alert_rule_id] = list(notification_channel_ids)

    async def list_notification_channel_ids_for_rule(
        self, alert_rule_id: uuid.UUID
    ) -> list[uuid.UUID]:
        return list(self.rule_channels.get(alert_rule_id, []))

    # -- alerts ----------------------------------------------------------------
    async def create_alert(self, **fields: object) -> Alert:
        alert = Alert(**_base_fields(**fields))
        self.alerts[alert.id] = alert
        return alert

    async def get_alert(self, alert_id: uuid.UUID) -> Alert | None:
        return self.alerts.get(alert_id)

    async def update_alert(self, alert: Alert, data: dict[str, object]) -> Alert:
        for key, value in data.items():
            setattr(alert, key, value)
        return alert

    async def list_alerts(self, **kwargs: object):
        raise NotImplementedError("not exercised by these unit tests")

    async def find_active_alert(
        self,
        *,
        rule_id: uuid.UUID,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        router_id: uuid.UUID | None,
    ) -> Alert | None:
        for alert in self.alerts.values():
            if (
                alert.rule_id == rule_id
                and alert.status != AlertStatus.RESOLVED.value
                and alert.organization_id == organization_id
                and alert.location_id == location_id
                and alert.router_id == router_id
            ):
                return alert
        return None

    async def find_alert_by_related_event(
        self, *, rule_id: uuid.UUID, related_event_id: uuid.UUID
    ) -> Alert | None:
        for alert in self.alerts.values():
            if alert.rule_id == rule_id and alert.related_event_id == related_event_id:
                return alert
        return None

    # -- evaluation composition -----------------------------------------------
    async def list_routers(
        self, *, organization_id: uuid.UUID | None = None
    ) -> list[FakeRouter]:
        if organization_id is None:
            return list(self.routers)
        return [r for r in self.routers if r.organization_id == organization_id]

    async def get_latest_router_health_snapshot(
        self, router_id: uuid.UUID
    ) -> FakeSnapshot | None:
        return self.snapshots.get(router_id)

    async def list_recent_platform_events(
        self,
        *,
        event_type: str,
        organization_id: uuid.UUID | None = None,
        since: datetime,
    ) -> list[PlatformEvent]:
        return [
            e
            for e in self.platform_events
            if e.event_type == event_type and e.occurred_at >= since
        ]

    async def get_service_health(self, component: str) -> ServiceHealth | None:
        return self.service_health_rows.get(component)

    # -- notification channels -----------------------------------------------
    async def create_notification_channel(
        self, **fields: object
    ) -> NotificationChannel:
        channel = NotificationChannel(**_base_fields(**fields))
        self.notification_channels[channel.id] = channel
        return channel

    async def get_notification_channel(
        self, channel_id: uuid.UUID
    ) -> NotificationChannel | None:
        channel = self.notification_channels.get(channel_id)
        return channel if channel is not None and not channel.is_deleted else None

    async def update_notification_channel(
        self, channel: NotificationChannel, data: dict[str, object]
    ) -> NotificationChannel:
        for key, value in data.items():
            if value is not None:
                setattr(channel, key, value)
        return channel

    async def soft_delete_notification_channel(
        self, channel: NotificationChannel
    ) -> NotificationChannel:
        channel.is_deleted = True
        return channel

    async def list_notification_channels(self, **kwargs: object):
        raise NotImplementedError("not exercised by these unit tests")

    async def get_notification_channels_by_ids(
        self, channel_ids: list[uuid.UUID]
    ) -> list[NotificationChannel]:
        return [
            self.notification_channels[cid]
            for cid in channel_ids
            if cid in self.notification_channels
        ]

    # -- notification logs ---------------------------------------------------
    async def create_notification_log(self, **fields: object) -> NotificationLog:
        log = NotificationLog(**_base_fields(**fields))
        self.notification_logs.append(log)
        return log

    async def list_notification_logs(self, **kwargs: object):
        raise NotImplementedError("not exercised by these unit tests")

    # -- incidents ---------------------------------------------------------------
    async def create_incident(self, **fields: object) -> Incident:
        incident = Incident(**_base_fields(**fields))
        self.incidents[incident.id] = incident
        return incident

    async def get_incident(self, incident_id: uuid.UUID) -> Incident | None:
        return self.incidents.get(incident_id)

    async def update_incident(
        self, incident: Incident, data: dict[str, object]
    ) -> Incident:
        for key, value in data.items():
            setattr(incident, key, value)
        return incident

    async def list_incidents(self, **kwargs: object):
        raise NotImplementedError("not exercised by these unit tests")

    async def incident_alert_exists(
        self, incident_id: uuid.UUID, alert_id: uuid.UUID
    ) -> bool:
        return any(
            ia.incident_id == incident_id and ia.alert_id == alert_id
            for ia in self.incident_alerts
        )

    async def attach_alert_to_incident(
        self, incident_id: uuid.UUID, alert_id: uuid.UUID
    ) -> IncidentAlert:
        row = IncidentAlert(**_base_fields(incident_id=incident_id, alert_id=alert_id))
        self.incident_alerts.append(row)
        return row

    async def list_alerts_for_incident(self, incident_id: uuid.UUID) -> list[Alert]:
        alert_ids = {
            ia.alert_id for ia in self.incident_alerts if ia.incident_id == incident_id
        }
        return [a for a in self.alerts.values() if a.id in alert_ids]

    # -- SLA monitoring ----------------------------------------------------------
    async def create_sla_target(self, **fields: object) -> SlaTarget:
        target = SlaTarget(**_base_fields(**fields))
        self.sla_targets[target.id] = target
        return target

    async def get_sla_target(self, target_id: uuid.UUID) -> SlaTarget | None:
        return self.sla_targets.get(target_id)

    async def list_sla_targets(
        self, *, organization_id: uuid.UUID | None = None
    ) -> list[SlaTarget]:
        if organization_id is None:
            return list(self.sla_targets.values())
        return [
            t for t in self.sla_targets.values() if t.organization_id == organization_id
        ]

    async def create_sla_report(self, **fields: object) -> SlaReport:
        report = SlaReport(**_base_fields(**fields))
        self.sla_reports.append(report)
        return report

    async def list_sla_reports(self, **kwargs: object):
        raise NotImplementedError("not exercised by these unit tests")

    async def get_latest_sla_report(self, sla_target_id: uuid.UUID) -> SlaReport | None:
        matching = [r for r in self.sla_reports if r.sla_target_id == sla_target_id]
        if not matching:
            return None
        return max(matching, key=lambda r: r.generated_at)

    async def compute_health_check_stats(
        self, *, component: str | None, start: datetime, end: datetime
    ) -> tuple[int, int, float | None]:
        return self.health_check_stats

    async def get_average_provisioning_duration_seconds(
        self, *, organization_id: uuid.UUID | None, start: datetime, end: datetime
    ) -> float | None:
        return self.average_provisioning_duration_seconds


def _mock_http_client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _alert_rule_fields(
    *,
    trigger_type: AlertTriggerType,
    target_component: str | None,
    condition_config: dict[str, object],
    organization_id: uuid.UUID | None = None,
    severity: AlertSeverity = AlertSeverity.CRITICAL,
    is_active: bool = True,
) -> dict[str, object]:
    return dict(
        name="Test rule",
        description=None,
        organization_id=organization_id,
        trigger_type=trigger_type.value,
        target_component=target_component,
        condition_config=condition_config,
        severity=severity.value,
        is_active=is_active,
    )


# ============================================================================
# Alert rule condition-config validation
# ============================================================================


def test_validate_health_status_change_requires_target_component():
    with pytest.raises(InvalidAlertRuleConfigError):
        validate_alert_rule_condition_config(
            AlertTriggerType.HEALTH_STATUS_CHANGE,
            None,
            {"expected_status": "unhealthy"},
        )


def test_validate_health_status_change_requires_expected_status():
    with pytest.raises(InvalidAlertRuleConfigError):
        validate_alert_rule_condition_config(
            AlertTriggerType.HEALTH_STATUS_CHANGE, "database", {}
        )


def test_validate_threshold_rejects_target_component():
    with pytest.raises(InvalidAlertRuleConfigError):
        validate_alert_rule_condition_config(
            AlertTriggerType.THRESHOLD,
            "database",
            {"metric": "cpu_usage_percent", "operator": "gte", "value": 90},
        )


def test_validate_threshold_requires_valid_metric_operator_value():
    with pytest.raises(InvalidAlertRuleConfigError):
        validate_alert_rule_condition_config(
            AlertTriggerType.THRESHOLD,
            None,
            {"metric": "not_a_metric", "operator": "gte", "value": 90},
        )
    with pytest.raises(InvalidAlertRuleConfigError):
        validate_alert_rule_condition_config(
            AlertTriggerType.THRESHOLD,
            None,
            {"metric": "cpu_usage_percent", "operator": "nope", "value": 90},
        )
    with pytest.raises(InvalidAlertRuleConfigError):
        validate_alert_rule_condition_config(
            AlertTriggerType.THRESHOLD,
            None,
            {"metric": "cpu_usage_percent", "operator": "gte", "value": "high"},
        )


def test_validate_event_occurred_requires_event_type():
    with pytest.raises(InvalidAlertRuleConfigError):
        validate_alert_rule_condition_config(AlertTriggerType.EVENT_OCCURRED, None, {})


def test_validate_valid_configs_pass():
    validate_alert_rule_condition_config(
        AlertTriggerType.HEALTH_STATUS_CHANGE,
        "database",
        {"expected_status": "unhealthy"},
    )
    validate_alert_rule_condition_config(
        AlertTriggerType.THRESHOLD,
        None,
        {"metric": "cpu_usage_percent", "operator": "gte", "value": 90},
    )
    validate_alert_rule_condition_config(
        AlertTriggerType.EVENT_OCCURRED,
        None,
        {"event_type": "monitoring.component_unhealthy"},
    )


# ============================================================================
# Alert Engine: evaluation -- HEALTH_STATUS_CHANGE (platform component)
# ============================================================================


async def test_health_status_rule_triggers_on_platform_component():
    repo = FakeRepository()
    service = AlertService(repo)
    rule = await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.HEALTH_STATUS_CHANGE,
            target_component="database",
            condition_config={"expected_status": "unhealthy"},
        )
    )
    repo.service_health_rows["database"] = ServiceHealth(
        **_base_fields(
            component="database",
            status="unhealthy",
            last_checked_at=_now(),
            consecutive_failure_count=3,
        )
    )

    result = await service.evaluate_alert_rules()
    assert len(result.triggered) == 1
    assert result.triggered[0].rule_id == rule.id
    assert result.triggered[0].status == AlertStatus.TRIGGERED.value
    assert result.triggered[0].severity == rule.severity


async def test_health_status_rule_deduplicates_already_firing_alert():
    repo = FakeRepository()
    service = AlertService(repo)
    await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.HEALTH_STATUS_CHANGE,
            target_component="database",
            condition_config={"expected_status": "unhealthy"},
        )
    )
    repo.service_health_rows["database"] = ServiceHealth(
        **_base_fields(
            component="database",
            status="unhealthy",
            last_checked_at=_now(),
            consecutive_failure_count=1,
        )
    )

    first = await service.evaluate_alert_rules()
    second = await service.evaluate_alert_rules()
    assert len(first.triggered) == 1
    assert len(second.triggered) == 0
    assert len(repo.alerts) == 1


async def test_health_status_rule_auto_resolves_on_recovery():
    repo = FakeRepository()
    service = AlertService(repo)
    await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.HEALTH_STATUS_CHANGE,
            target_component="database",
            condition_config={"expected_status": "unhealthy"},
        )
    )
    repo.service_health_rows["database"] = ServiceHealth(
        **_base_fields(
            component="database",
            status="unhealthy",
            last_checked_at=_now(),
            consecutive_failure_count=1,
        )
    )
    await service.evaluate_alert_rules()

    repo.service_health_rows["database"].status = "healthy"
    result = await service.evaluate_alert_rules()

    assert len(result.triggered) == 0
    assert len(result.resolved) == 1
    resolved_alert = result.resolved[0]
    assert resolved_alert.status == AlertStatus.RESOLVED.value
    assert resolved_alert.resolved_at is not None

    # Recovering again is a no-op (nothing left open to resolve).
    again = await service.evaluate_alert_rules()
    assert again.triggered == []
    assert again.resolved == []


# ============================================================================
# Alert Engine: evaluation -- HEALTH_STATUS_CHANGE (per-router)
# ============================================================================


async def test_router_health_status_rule_triggers_and_resolves():
    repo = FakeRepository()
    service = AlertService(repo)
    org_id = uuid.uuid4()
    router = FakeRouter(
        id=uuid.uuid4(),
        organization_id=org_id,
        location_id=uuid.uuid4(),
        name="Router One",
        health_status="unhealthy",
    )
    repo.routers.append(router)
    await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.HEALTH_STATUS_CHANGE,
            target_component=ALERT_TARGET_ROUTER,
            condition_config={"expected_status": "unhealthy"},
            organization_id=org_id,
        )
    )

    triggered = (await service.evaluate_alert_rules()).triggered
    assert len(triggered) == 1
    assert triggered[0].router_id == router.id
    assert triggered[0].location_id == router.location_id

    router.health_status = "healthy"
    resolved = (await service.evaluate_alert_rules()).resolved
    assert len(resolved) == 1
    assert resolved[0].id == triggered[0].id


# ============================================================================
# Alert Engine: evaluation -- THRESHOLD
# ============================================================================


async def test_threshold_rule_triggers_and_resolves():
    repo = FakeRepository()
    service = AlertService(repo)
    org_id = uuid.uuid4()
    router = FakeRouter(
        id=uuid.uuid4(),
        organization_id=org_id,
        location_id=uuid.uuid4(),
        name="Router One",
        health_status="healthy",
    )
    repo.routers.append(router)
    repo.snapshots[router.id] = FakeSnapshot(cpu_usage_percent=95.0)
    await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.THRESHOLD,
            target_component=None,
            condition_config={
                "metric": "cpu_usage_percent",
                "operator": "gte",
                "value": 90,
            },
            organization_id=org_id,
        )
    )

    triggered = (await service.evaluate_alert_rules()).triggered
    assert len(triggered) == 1
    assert "cpu_usage_percent=95.0" in triggered[0].message

    repo.snapshots[router.id] = FakeSnapshot(cpu_usage_percent=10.0)
    resolved = (await service.evaluate_alert_rules()).resolved
    assert len(resolved) == 1


async def test_threshold_rule_no_snapshot_never_triggers():
    repo = FakeRepository()
    service = AlertService(repo)
    org_id = uuid.uuid4()
    router = FakeRouter(
        id=uuid.uuid4(),
        organization_id=org_id,
        location_id=uuid.uuid4(),
        name="Router One",
        health_status="healthy",
    )
    repo.routers.append(router)
    await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.THRESHOLD,
            target_component=None,
            condition_config={
                "metric": "cpu_usage_percent",
                "operator": "gte",
                "value": 90,
            },
            organization_id=org_id,
        )
    )
    result = await service.evaluate_alert_rules()
    assert result.triggered == []
    assert result.resolved == []


# ============================================================================
# Alert Engine: evaluation -- EVENT_OCCURRED
# ============================================================================


async def test_event_occurred_rule_creates_one_alert_per_event_no_duplicates():
    repo = FakeRepository()
    service = AlertService(repo)
    await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.EVENT_OCCURRED,
            target_component=None,
            condition_config={"event_type": "monitoring.component_unhealthy"},
        )
    )
    event = PlatformEvent(
        **_base_fields(
            category="system",
            event_type="monitoring.component_unhealthy",
            severity="critical",
            organization_id=None,
            location_id=None,
            router_id=None,
            source_domain="monitoring",
            message="database unhealthy",
            event_metadata={},
            occurred_at=_now(),
        )
    )
    repo.platform_events.append(event)

    first = await service.evaluate_alert_rules()
    second = await service.evaluate_alert_rules()
    assert len(first.triggered) == 1
    assert first.triggered[0].related_event_id == event.id
    assert len(second.triggered) == 0
    # Event-occurred alerts never auto-resolve themselves.
    assert second.resolved == []

    another_event = PlatformEvent(
        **_base_fields(
            category="system",
            event_type="monitoring.component_unhealthy",
            severity="critical",
            organization_id=None,
            location_id=None,
            router_id=None,
            source_domain="monitoring",
            message="redis unhealthy",
            event_metadata={},
            occurred_at=_now(),
        )
    )
    repo.platform_events.append(another_event)
    third = await service.evaluate_alert_rules()
    assert len(third.triggered) == 1
    assert len(repo.alerts) == 2


async def test_event_occurred_rule_ignores_events_outside_lookback_window():
    repo = FakeRepository()
    service = AlertService(repo)
    await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.EVENT_OCCURRED,
            target_component=None,
            condition_config={"event_type": "monitoring.component_unhealthy"},
        )
    )
    stale_event = PlatformEvent(
        **_base_fields(
            category="system",
            event_type="monitoring.component_unhealthy",
            severity="critical",
            organization_id=None,
            location_id=None,
            router_id=None,
            source_domain="monitoring",
            message="old",
            event_metadata={},
            occurred_at=_now() - timedelta(hours=2),
        )
    )
    repo.platform_events.append(stale_event)
    result = await service.evaluate_alert_rules()
    assert result.triggered == []


# ============================================================================
# Alert lifecycle
# ============================================================================


async def test_acknowledge_then_resolve_transitions():
    repo = FakeRepository()
    service = AlertService(repo)
    rule = await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.EVENT_OCCURRED,
            target_component=None,
            condition_config={"event_type": "x"},
        )
    )
    alert = await repo.create_alert(
        rule_id=rule.id,
        status=AlertStatus.TRIGGERED.value,
        triggered_at=_now(),
        acknowledged_at=None,
        acknowledged_by_user_id=None,
        resolved_at=None,
        organization_id=None,
        location_id=None,
        router_id=None,
        message="test",
        related_health_check_id=None,
        related_event_id=None,
        severity=rule.severity,
    )
    user_id = uuid.uuid4()

    acknowledged = await service.acknowledge_alert(alert.id, user_id=user_id)
    assert acknowledged.status == AlertStatus.ACKNOWLEDGED.value
    assert acknowledged.acknowledged_by_user_id == user_id

    resolved = await service.resolve_alert(alert.id)
    assert resolved.status == AlertStatus.RESOLVED.value
    assert resolved.resolved_at is not None


async def test_resolved_alert_cannot_be_reacknowledged():
    repo = FakeRepository()
    service = AlertService(repo)
    rule = await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.EVENT_OCCURRED,
            target_component=None,
            condition_config={"event_type": "x"},
        )
    )
    alert = await repo.create_alert(
        rule_id=rule.id,
        status=AlertStatus.RESOLVED.value,
        triggered_at=_now(),
        acknowledged_at=None,
        acknowledged_by_user_id=None,
        resolved_at=_now(),
        organization_id=None,
        location_id=None,
        router_id=None,
        message="test",
        related_health_check_id=None,
        related_event_id=None,
        severity=rule.severity,
    )
    with pytest.raises(InvalidAlertStatusTransitionError):
        await service.acknowledge_alert(alert.id, user_id=uuid.uuid4())


async def test_get_alert_not_found_raises():
    repo = FakeRepository()
    service = AlertService(repo)
    with pytest.raises(AlertNotFoundError):
        await service.get_alert(uuid.uuid4())


async def test_get_alert_rule_not_found_raises():
    repo = FakeRepository()
    service = AlertService(repo)
    with pytest.raises(AlertRuleNotFoundError):
        await service.get_alert_rule(uuid.uuid4())


# ============================================================================
# Notification Engine: dispatch per channel type
# ============================================================================


async def _channel(
    repo: FakeRepository, channel_type: NotificationChannelType, config: dict
):
    from app.domains.router.crypto import encrypt_secret

    return await repo.create_notification_channel(
        organization_id=None,
        channel_type=channel_type.value,
        name="test channel",
        config_encrypted=encrypt_secret(json.dumps(config)),
        is_active=True,
    )


def _sample_alert(
    rule_id: uuid.UUID | None = None, *, status: str = "triggered"
) -> Alert:
    return Alert(
        **_base_fields(
            rule_id=rule_id or uuid.uuid4(),
            status=status,
            triggered_at=_now(),
            acknowledged_at=None,
            acknowledged_by_user_id=None,
            resolved_at=None,
            organization_id=None,
            location_id=None,
            router_id=None,
            message="database is unhealthy",
            related_health_check_id=None,
            related_event_id=None,
            severity="critical",
        )
    )


async def test_email_notifier_dispatch_sends_and_logs():
    repo = FakeRepository()
    service = NotificationService(repo, httpx.AsyncClient())
    channel = await _channel(
        repo, NotificationChannelType.EMAIL, {"email": "ops@example.com"}
    )
    alert = _sample_alert()

    log = await service.dispatch_notification(alert=alert, channel=channel)
    assert log.status == NotificationStatus.SENT.value
    assert "EmailProviderProtocol" in (log.response_summary or "")


async def test_sms_notifier_dispatch_sends_and_logs():
    repo = FakeRepository()
    service = NotificationService(repo, httpx.AsyncClient())
    channel = await _channel(
        repo, NotificationChannelType.SMS, {"phone_number": "+15551234567"}
    )
    alert = _sample_alert()

    log = await service.dispatch_notification(alert=alert, channel=channel)
    assert log.status == NotificationStatus.SENT.value
    assert "SmsProviderProtocol" in (log.response_summary or "")


async def test_whatsapp_notifier_is_honest_logging_only_placeholder():
    repo = FakeRepository()
    service = NotificationService(repo, httpx.AsyncClient())
    channel = await _channel(
        repo, NotificationChannelType.WHATSAPP, {"phone_number": "+15551234567"}
    )
    alert = _sample_alert()

    log = await service.dispatch_notification(alert=alert, channel=channel)
    assert log.status == NotificationStatus.SENT.value
    assert "no real WhatsApp Business API integration exists" in (
        log.response_summary or ""
    )


async def test_slack_notifier_real_http_post_uses_text_payload():
    captured: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["json"] = json.loads(request.content)
        return httpx.Response(200)

    repo = FakeRepository()
    service = NotificationService(repo, _mock_http_client(handler))
    channel = await _channel(
        repo,
        NotificationChannelType.SLACK,
        {"webhook_url": "https://hooks.slack.com/services/T/B/X"},
    )
    alert = _sample_alert()

    log = await service.dispatch_notification(alert=alert, channel=channel)
    assert log.status == NotificationStatus.SENT.value
    assert log.response_summary == "HTTP 200"
    assert "text" in captured["json"]
    assert "database is unhealthy" in captured["json"]["text"]


async def test_teams_notifier_real_http_post_uses_message_card_payload():
    captured: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["json"] = json.loads(request.content)
        return httpx.Response(200)

    repo = FakeRepository()
    service = NotificationService(repo, _mock_http_client(handler))
    channel = await _channel(
        repo,
        NotificationChannelType.TEAMS,
        {"webhook_url": "https://outlook.office.com/webhook/x"},
    )
    alert = _sample_alert()

    log = await service.dispatch_notification(alert=alert, channel=channel)
    assert log.status == NotificationStatus.SENT.value
    assert captured["json"]["@type"] == "MessageCard"


async def test_discord_notifier_real_http_post_uses_content_payload():
    captured: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["json"] = json.loads(request.content)
        return httpx.Response(200)

    repo = FakeRepository()
    service = NotificationService(repo, _mock_http_client(handler))
    channel = await _channel(
        repo,
        NotificationChannelType.DISCORD,
        {"webhook_url": "https://discord.com/api/webhooks/x"},
    )
    alert = _sample_alert()

    log = await service.dispatch_notification(alert=alert, channel=channel)
    assert log.status == NotificationStatus.SENT.value
    assert "content" in captured["json"]


async def test_webhook_notifier_sends_structured_payload_and_auth_header():
    captured: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["json"] = json.loads(request.content)
        captured["headers"] = dict(request.headers)
        return httpx.Response(202)

    repo = FakeRepository()
    service = NotificationService(repo, _mock_http_client(handler))
    channel = await _channel(
        repo,
        NotificationChannelType.WEBHOOK,
        {
            "url": "https://example.com/hook",
            "auth_header_name": "X-Api-Key",
            "auth_header_value": "secret-token",
        },
    )
    alert = _sample_alert()

    log = await service.dispatch_notification(alert=alert, channel=channel)
    assert log.status == NotificationStatus.SENT.value
    assert log.response_summary == "HTTP 202"
    assert captured["json"]["alert_id"] == str(alert.id)
    assert captured["headers"]["x-api-key"] == "secret-token"


async def test_notification_dispatch_failure_never_raises_and_is_logged():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="internal error")

    repo = FakeRepository()
    service = NotificationService(repo, _mock_http_client(handler))
    channel = await _channel(
        repo,
        NotificationChannelType.WEBHOOK,
        {"url": "https://example.com/hook"},
    )
    alert = _sample_alert()

    log = await service.dispatch_notification(alert=alert, channel=channel)
    assert log.status == NotificationStatus.FAILED.value
    assert log.error_message is not None
    assert "500" in log.error_message


async def test_notification_dispatch_network_error_never_raises():
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    repo = FakeRepository()
    service = NotificationService(repo, _mock_http_client(handler))
    channel = await _channel(
        repo,
        NotificationChannelType.WEBHOOK,
        {"url": "https://example.com/hook"},
    )
    alert = _sample_alert()

    log = await service.dispatch_notification(alert=alert, channel=channel)
    assert log.status == NotificationStatus.FAILED.value
    assert log.error_message is not None


async def test_alert_evaluation_dispatches_to_configured_channels():
    """End-to-end: AlertService.evaluate_alert_rules -> _dispatch_for_alert
    -> NotificationService.dispatch_notification -> a real (faked) HTTP POST,
    recorded as a NotificationLog row."""
    captured: list[dict] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.append(json.loads(request.content))
        return httpx.Response(200)

    repo = FakeRepository()
    notification_service = NotificationService(repo, _mock_http_client(handler))
    alert_service = AlertService(repo, notification_service=notification_service)

    channel = await _channel(
        repo,
        NotificationChannelType.SLACK,
        {"webhook_url": "https://hooks.slack.com/services/T/B/X"},
    )
    rule = await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.HEALTH_STATUS_CHANGE,
            target_component="database",
            condition_config={"expected_status": "unhealthy"},
        )
    )
    await repo.replace_alert_rule_notification_channels(rule.id, [channel.id])
    repo.service_health_rows["database"] = ServiceHealth(
        **_base_fields(
            component="database",
            status="unhealthy",
            last_checked_at=_now(),
            consecutive_failure_count=1,
        )
    )

    await alert_service.evaluate_alert_rules()

    assert len(captured) == 1
    assert len(repo.notification_logs) == 1
    assert repo.notification_logs[0].status == NotificationStatus.SENT.value


# ============================================================================
# Notification channel config: encryption round-trip + validation
# ============================================================================


async def test_create_channel_encrypts_config_round_trip():
    repo = FakeRepository()
    service = NotificationService(repo, httpx.AsyncClient())
    config = {"email": "ops@example.com"}
    channel = await service.create_channel(
        organization_id=None,
        channel_type=NotificationChannelType.EMAIL,
        name="Ops email",
        config=config,
    )
    assert channel.config_encrypted != json.dumps(config)
    decrypted = json.loads(decrypt_secret(channel.config_encrypted))
    assert decrypted == config


async def test_get_channel_not_found_raises():
    repo = FakeRepository()
    service = NotificationService(repo, httpx.AsyncClient())
    with pytest.raises(NotificationChannelNotFoundError):
        await service.get_channel(uuid.uuid4())


def test_validate_email_channel_config():
    with pytest.raises(InvalidNotificationChannelConfigError):
        validate_notification_channel_config(NotificationChannelType.EMAIL, {})
    validate_notification_channel_config(
        NotificationChannelType.EMAIL, {"email": "a@b.com"}
    )


def test_validate_slack_requires_https_webhook_url():
    with pytest.raises(InvalidNotificationChannelConfigError):
        validate_notification_channel_config(
            NotificationChannelType.SLACK, {"webhook_url": "http://not-https.example"}
        )
    validate_notification_channel_config(
        NotificationChannelType.SLACK, {"webhook_url": "https://hooks.slack.com/x"}
    )


def test_validate_webhook_requires_paired_auth_headers():
    with pytest.raises(InvalidNotificationChannelConfigError):
        validate_notification_channel_config(
            NotificationChannelType.WEBHOOK,
            {"url": "https://example.com", "auth_header_name": "X-Api-Key"},
        )
    validate_notification_channel_config(
        NotificationChannelType.WEBHOOK, {"url": "https://example.com"}
    )


# ============================================================================
# Incident Engine
# ============================================================================


async def test_incident_lifecycle_transitions():
    repo = FakeRepository()
    service = IncidentService(repo)
    incident = await service.create_incident(
        title="Multiple routers offline",
        description=None,
        severity=AlertSeverity.CRITICAL.value,
        organization_id=None,
    )
    assert incident.status == IncidentStatus.OPEN.value

    investigating = await service.update_incident(
        incident.id, status=IncidentStatus.INVESTIGATING
    )
    assert investigating.status == IncidentStatus.INVESTIGATING.value

    resolved = await service.update_incident(
        incident.id, status=IncidentStatus.RESOLVED, resolution_notes="Fixed"
    )
    assert resolved.status == IncidentStatus.RESOLVED.value
    assert resolved.resolved_at is not None
    assert resolved.resolution_notes == "Fixed"

    closed = await service.update_incident(incident.id, status=IncidentStatus.CLOSED)
    assert closed.status == IncidentStatus.CLOSED.value
    assert closed.closed_at is not None


async def test_incident_invalid_transition_raises():
    repo = FakeRepository()
    service = IncidentService(repo)
    incident = await service.create_incident(
        title="X",
        description=None,
        severity=AlertSeverity.INFO.value,
        organization_id=None,
    )
    await service.update_incident(incident.id, status=IncidentStatus.CLOSED)
    with pytest.raises(InvalidIncidentStatusTransitionError):
        await service.update_incident(incident.id, status=IncidentStatus.OPEN)


async def test_incident_attach_alert_is_idempotent():
    repo = FakeRepository()
    service = IncidentService(repo)
    incident = await service.create_incident(
        title="X",
        description=None,
        severity=AlertSeverity.WARNING.value,
        organization_id=None,
    )
    alert = await repo.create_alert(
        rule_id=uuid.uuid4(),
        status=AlertStatus.TRIGGERED.value,
        triggered_at=_now(),
        acknowledged_at=None,
        acknowledged_by_user_id=None,
        resolved_at=None,
        organization_id=None,
        location_id=None,
        router_id=None,
        message="m",
        related_health_check_id=None,
        related_event_id=None,
        severity="warning",
    )

    await service.attach_alert(incident.id, alert.id)
    await service.attach_alert(incident.id, alert.id)

    alerts = await service.list_alerts_for_incident(incident.id)
    assert len(alerts) == 1
    assert alerts[0].id == alert.id


async def test_incident_not_found_raises():
    repo = FakeRepository()
    service = IncidentService(repo)
    with pytest.raises(IncidentNotFoundError):
        await service.get_incident(uuid.uuid4())


# ============================================================================
# SLA Monitoring
# ============================================================================


async def test_sla_target_config_validation():
    with pytest.raises(InvalidSlaTargetConfigError):
        validate_sla_target_config(target_percentage=0, measurement_window_days=30)
    with pytest.raises(InvalidSlaTargetConfigError):
        validate_sla_target_config(target_percentage=101, measurement_window_days=30)
    with pytest.raises(InvalidSlaTargetConfigError):
        validate_sla_target_config(target_percentage=99.9, measurement_window_days=0)
    validate_sla_target_config(target_percentage=99.9, measurement_window_days=30)


async def test_generate_report_computes_simple_ratio():
    repo = FakeRepository()
    repo.health_check_stats = (100, 80, 42.5)
    service = SlaService(repo)
    target = await service.create_target(
        organization_id=None,
        component="database",
        target_percentage=99.9,
        measurement_window_days=30,
    )

    report = await service.generate_report(target.id)
    assert report.total_checks == 100
    assert report.healthy_checks == 80
    assert report.achieved_percentage == 80.0
    assert report.average_response_time_ms == 42.5


async def test_generate_report_raises_when_no_health_check_data():
    repo = FakeRepository()
    repo.health_check_stats = (0, 0, None)
    service = SlaService(repo)
    target = await service.create_target(
        organization_id=None,
        component="database",
        target_percentage=99.9,
        measurement_window_days=30,
    )
    with pytest.raises(InsufficientSlaDataError):
        await service.generate_report(target.id)


async def test_sla_target_not_found_raises():
    repo = FakeRepository()
    service = SlaService(repo)
    with pytest.raises(SlaTargetNotFoundError):
        await service.get_target(uuid.uuid4())


async def test_list_targets_with_latest_report_pairs_correctly():
    repo = FakeRepository()
    repo.health_check_stats = (10, 10, 5.0)
    service = SlaService(repo)
    target = await service.create_target(
        organization_id=None,
        component="redis",
        target_percentage=99.0,
        measurement_window_days=7,
    )
    pairs_before = await service.list_targets_with_latest_report()
    assert pairs_before == [(target, None)]

    report = await service.generate_report(target.id)
    pairs_after = await service.list_targets_with_latest_report()
    assert pairs_after == [(target, report)]


async def test_average_provisioning_duration_delegates_to_repository():
    repo = FakeRepository()
    repo.average_provisioning_duration_seconds = 123.4
    service = SlaService(repo)
    result = await service.get_average_provisioning_duration_seconds(
        organization_id=None, start=_now() - timedelta(days=1), end=_now()
    )
    assert result == 123.4


# ============================================================================
# RBAC permission-key reuse -- verified directly off the registered routes
# ============================================================================


def _permission_key_for_route(route) -> str | None:
    """Introspects a ``Depends(RequirePermission(key))`` route dependency's
    closure to recover ``key`` -- ``RequirePermission`` is a factory that
    returns a closure capturing ``permission_key`` (see
    ``app.domains.rbac.dependencies.RequirePermission``); this reads it
    back without needing RBAC's own code to expose it as a public
    attribute. This codebase has no established route-level ``TestClient``
    pattern (see this module's own docstring) -- introspecting the actual
    registered dependency is the most direct way to verify the RBAC-key-
    reuse decisions documented in ``docs/monitoring/FLOW.md`` without
    inventing a new HTTP testing pattern only for this domain."""
    for dependency in route.dependant.dependencies:
        call = dependency.call
        freevars = getattr(call.__code__, "co_freevars", ())
        if "permission_key" in freevars:
            index = freevars.index("permission_key")
            return call.__closure__[index].cell_contents
    return None


@pytest.fixture(scope="module")
def monitoring_routes_by_path_method():
    from app.main import create_app

    app = create_app()
    routes: dict[tuple[str, str], object] = {}
    for route in app.routes:
        methods = getattr(route, "methods", None)
        path = getattr(route, "path", None)
        if not methods or not path or not path.startswith("/api/v1/"):
            continue
        for method in methods:
            routes[(path, method)] = route
    return routes


@pytest.mark.parametrize(
    ("path", "method", "expected_key"),
    [
        ("/api/v1/alerts/rules", "POST", "alerts.manage"),
        ("/api/v1/alerts/rules", "GET", "alerts.read"),
        ("/api/v1/alerts/rules/{rule_id}", "GET", "alerts.read"),
        ("/api/v1/alerts/rules/{rule_id}", "PUT", "alerts.update"),
        ("/api/v1/alerts/rules/{rule_id}", "DELETE", "alerts.delete"),
        ("/api/v1/alerts", "GET", "alerts.read"),
        ("/api/v1/alerts/{alert_id}", "GET", "alerts.read"),
        ("/api/v1/alerts/{alert_id}/acknowledge", "POST", "alerts.update"),
        ("/api/v1/alerts/{alert_id}/resolve", "POST", "alerts.update"),
        ("/api/v1/notifications/channels", "POST", "notifications.manage"),
        ("/api/v1/notifications/channels", "GET", "notifications.read"),
        ("/api/v1/notifications/channels/{channel_id}", "PUT", "notifications.update"),
        (
            "/api/v1/notifications/channels/{channel_id}",
            "DELETE",
            "notifications.delete",
        ),
        ("/api/v1/notifications/logs", "GET", "notifications.read"),
        ("/api/v1/incidents", "POST", "alerts.manage"),
        ("/api/v1/incidents", "GET", "alerts.read"),
        ("/api/v1/incidents/{incident_id}", "PUT", "alerts.update"),
        ("/api/v1/incidents/{incident_id}/alerts", "POST", "alerts.update"),
        ("/api/v1/sla", "GET", "reports.read"),
        ("/api/v1/sla/targets", "POST", "reports.manage"),
        ("/api/v1/sla/{target_id}/reports", "GET", "reports.read"),
        ("/api/v1/sla/{target_id}/generate-report", "POST", "reports.manage"),
    ],
)
def test_endpoint_requires_expected_permission_key(
    monitoring_routes_by_path_method, path, method, expected_key
):
    route = monitoring_routes_by_path_method[(path, method)]
    assert _permission_key_for_route(route) == expected_key
