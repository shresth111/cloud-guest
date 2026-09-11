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

from app.domains.dhcp.constants import RogueDhcpAlertState
from app.domains.isp.constants import HealthStatus as IspHealthStatus
from app.domains.isp.constants import IspLinkRole, IspLinkType
from app.domains.isp.device_adapters import PingResult
from app.domains.monitoring.constants import (
    ALERT_TARGET_ISP_LINK,
    ALERT_TARGET_MONITORED_HARDWARE,
    ALERT_TARGET_NETWORK_CONTROLLER,
    ALERT_TARGET_NETWORK_CONTROLLER_AUTHORIZE,
    ALERT_TARGET_NETWORK_CONTROLLER_SETUP,
    ALERT_TARGET_ROGUE_DHCP_GUARD,
    ALERT_TARGET_ROUTER,
    ALERT_TARGET_ROUTER_REACHABILITY,
    ROGUE_DHCP_STATE_GUARDED,
    ROGUE_DHCP_STATE_UNGUARDED,
    ROGUE_DHCP_STATE_UNKNOWN,
    AlertSeverity,
    AlertStatus,
    AlertTriggerType,
    IncidentStatus,
    NotificationChannelType,
    NotificationStatus,
)
from app.domains.monitoring.default_alerting import (
    DEFAULT_ALERT_RULES,
    ensure_default_alerting,
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
    UnscopedOrganizationListError,
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
from app.domains.monitoring.repository import MonitoringRepository
from app.domains.monitoring.service import (
    AlertService,
    IncidentService,
    NotificationDeliveryError,
    NotificationService,
    SlaService,
)
from app.domains.monitoring.validators import (
    validate_alert_rule_condition_config,
    validate_notification_channel_config,
    validate_sla_target_config,
)
from app.domains.router.crypto import decrypt_secret
from tests.unit.test_isp import FakeIspHealthAdapter, _make_router, make_harness

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
    the attributes ``AlertService`` actually reads.

    ``reachability_state`` is declared here rather than being stuck on
    instances ad hoc, so that a test can never assert against a field the
    real ``Router`` does not have. Defaults to ``None`` -- "the reachability
    sweep has never judged this router" -- which is what every pre-existing
    test in this file means, and which the evaluator must never alert on."""

    id: uuid.UUID
    organization_id: uuid.UUID
    location_id: uuid.UUID
    name: str
    health_status: str | None
    reachability_state: str | None = None
    # Contract 11.5. Defaulted to the column's own default so every
    # pre-existing construction in this file means exactly what it always
    # meant -- a MikroTik running this platform's agent -- and the vendor
    # gate this field feeds is only visible to the tests that set it.
    vendor: str = "mikrotik"


@dataclass
class FakeSnapshot:
    """Duck-typed stand-in for
    ``app.domains.router_provisioning.models.RouterHealthSnapshot``."""

    cpu_usage_percent: float | None = None
    memory_usage_percent: float | None = None
    uptime_seconds: int | None = None
    connected_clients_count: int | None = None


@dataclass
class FakeIspLink:
    """Duck-typed stand-in for ``app.domains.isp.models.IspLink`` -- only
    the attributes ``AlertService._evaluate_health_status_rule``'s
    ``ALERT_TARGET_ISP_LINK`` branch actually reads."""

    id: uuid.UUID
    organization_id: uuid.UUID
    location_id: uuid.UUID
    router_id: uuid.UUID
    provider_name: str
    health_status: str | None


@dataclass
class FakeRogueDhcpStatus:
    """Duck-typed stand-in for
    ``app.domains.dhcp.models.RouterRogueDhcpStatus`` -- only the two
    attributes ``AlertService._evaluate_rogue_dhcp_guard_rule`` actually
    reads. The real row carries ``alert_present``/``enabled``/
    ``serves_dhcp``/``checked_at``/``detail`` beside these; the alert
    engine reads none of them, because the detector has already rolled them
    up into ``alert_state`` and re-deriving that here would be a second
    opinion about a device this process never spoke to."""

    interface: str
    alert_state: str


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
    isp_links: list[FakeIspLink] = field(default_factory=list)
    rogue_dhcp_rows: list[tuple[FakeRouter, FakeRogueDhcpStatus]] = field(
        default_factory=list
    )
    # Duck-typed ``NetworkIntegration`` rows and per-integration
    # ``AuthorizationOutcomeCounts`` -- see
    # ``tests/unit/test_monitoring_network_controller_alerts.py``.
    network_integrations: list[object] = field(default_factory=list)
    authorization_counts: list[object] = field(default_factory=list)
    organization_names: dict[uuid.UUID, str] = field(default_factory=dict)
    location_names: dict[uuid.UUID, str] = field(default_factory=dict)
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

    async def list_alert_rules(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        include_all_organizations: bool = False,
        is_active: bool | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[AlertRule], object]:
        """Taught to this fake because ``ensure_default_alerting`` calls it
        to decide what is already there. Kept faithful on the one axis that
        decides that answer -- the organization filter -- because a fake
        that returned every organization's rules would make the idempotency
        assertions below pass for the wrong reason."""
        rules = [
            rule
            for rule in self.alert_rules.values()
            if not rule.is_deleted
            and (organization_id is None or rule.organization_id == organization_id)
            and (is_active is None or rule.is_active == is_active)
        ]
        return rules, None

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

    async def list_isp_links(
        self, *, organization_id: uuid.UUID | None = None
    ) -> list[FakeIspLink]:
        if organization_id is None:
            return list(self.isp_links)
        return [
            link for link in self.isp_links if link.organization_id == organization_id
        ]

    async def list_rogue_dhcp_statuses_with_routers(
        self, *, organization_id: uuid.UUID | None = None
    ) -> list[tuple[FakeRouter, FakeRogueDhcpStatus]]:
        """Taught to this fake *before* any assertion below relies on it.

        That ordering is not ceremony. cloud-guest#131 landed wiring in this
        same domain that no test actually exercised, because a fake was
        missing the new method and a broad ``except Exception`` upstream
        swallowed the resulting ``AttributeError`` -- the suite went green
        over code that had never run. A fake that answers every method the
        service calls is what keeps that from happening twice.
        """
        if organization_id is None:
            return list(self.rogue_dhcp_rows)
        return [
            (router, status)
            for router, status in self.rogue_dhcp_rows
            if router.organization_id == organization_id
        ]

    async def list_network_integrations(
        self, *, organization_id: uuid.UUID | None = None
    ) -> list[object]:
        """Taught to this fake for the same reason as the rogue-DHCP read
        above: every organization's defaults now include the three
        network-controller rules, so every test here that evaluates default
        rules calls this. A missing method would be swallowed by the
        per-rule isolation and counted into ``skipped_rules``."""
        return [
            row
            for row in self.network_integrations
            if not getattr(row, "is_deleted", False)
            and (organization_id is None or row.organization_id == organization_id)
        ]

    async def count_authorization_outcomes_since(
        self, *, since: datetime, organization_id: uuid.UUID | None = None
    ) -> list[object]:
        """Counts are handed in pre-aggregated, the way the real grouped
        query returns them; the window itself is the SQL's job and is
        checked against the compiled statement in the network-controller
        test file."""
        wanted = {
            row.id
            for row in await self.list_network_integrations(
                organization_id=organization_id
            )
        }
        return [c for c in self.authorization_counts if c.integration_id in wanted]

    async def get_organization_and_location_names(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
    ) -> tuple[str | None, str | None]:
        return (
            self.organization_names.get(organization_id) if organization_id else None,
            self.location_names.get(location_id) if location_id else None,
        )

    async def list_open_alerts_for_rule(self, *, rule_id: uuid.UUID) -> list[Alert]:
        """The bulk de-duplication read. Same predicate and same
        newest-first ordering as ``find_active_alert`` above, because the
        real repository's two methods are deliberately the same query
        asked for one target vs. all of them."""
        return sorted(
            (
                alert
                for alert in self.alerts.values()
                if alert.rule_id == rule_id
                and not alert.is_deleted
                and alert.status != AlertStatus.RESOLVED.value
            ),
            key=lambda alert: alert.triggered_at,
            reverse=True,
        )

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

    async def list_notification_channels(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        include_all_organizations: bool = False,
        channel_type: str | None = None,
        is_active: bool | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[NotificationChannel], object]:
        channels = [
            channel
            for channel in self.notification_channels.values()
            if not channel.is_deleted
            and (
                organization_id is None
                or channel.organization_id == organization_id
            )
            and (channel_type is None or channel.channel_type == channel_type)
            and (is_active is None or channel.is_active == is_active)
        ]
        return channels, None

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
        self,
        *,
        organization_id: uuid.UUID | None = None,
        include_all_organizations: bool = False,
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


# ============================================================================
# Contract 11.5: a controller-managed fleet row is never judged as a device
# ============================================================================


def _controller_row(org_id: uuid.UUID, **overrides) -> FakeRouter:
    """A TP-Link Omada controller as `create_integration_with_fleet_device`
    actually writes it: a real `Router` row (because
    `guest_sessions.router_id` is NOT NULL and an Omada-only venue has no
    MikroTik in the path at all) whose agent-written columns are NULL
    forever, not temporarily."""
    fields = dict(
        id=uuid.uuid4(),
        organization_id=org_id,
        location_id=uuid.uuid4(),
        name="Lobby Controller",
        health_status=None,
        reachability_state=None,
        vendor="tplink_omada",
    )
    fields.update(overrides)
    return FakeRouter(**fields)


async def test_a_controller_is_not_alerted_on_by_a_router_health_rule():
    """The rule reads `Router.health_status`, which only an agent health
    snapshot ever writes. A rule written for the NULL-ish state -- and
    `unknown` is a state an operator would plausibly want to watch -- would
    otherwise fire on every Omada venue, forever, with no action anyone
    could take: the device will never run an agent."""
    repo = FakeRepository()
    service = AlertService(repo)
    org_id = uuid.uuid4()
    repo.routers.append(_controller_row(org_id, health_status="unhealthy"))
    await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.HEALTH_STATUS_CHANGE,
            target_component=ALERT_TARGET_ROUTER,
            condition_config={"expected_status": "unhealthy"},
            organization_id=org_id,
        )
    )

    result = await service.evaluate_alert_rules()

    assert result.triggered == []


async def test_a_controller_is_not_alerted_on_by_a_reachability_rule():
    """`reachability_state` is written solely by
    `RouterService.sweep_router_reachability`, whose candidate query is
    inner-joined to `router_agent_credentials`. A controller has none, so
    the column is permanently NULL -- and a rule watching for a state the
    sweep can never write is a rule that can never resolve either."""
    repo = FakeRepository()
    service = AlertService(repo)
    org_id = uuid.uuid4()
    repo.routers.append(_controller_row(org_id, reachability_state="unreachable"))
    await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.HEALTH_STATUS_CHANGE,
            target_component=ALERT_TARGET_ROUTER_REACHABILITY,
            condition_config={"expected_status": "unreachable"},
            organization_id=org_id,
        )
    )

    result = await service.evaluate_alert_rules()

    assert result.triggered == []


async def test_a_controller_is_not_alerted_on_by_a_threshold_rule():
    """Threshold rules read `RouterHealthSnapshot` metrics, which the agent
    poll writes. Today a controller simply has no snapshot, so the rule
    falls through -- this pins the gate rather than the accident, because
    a snapshot arriving from some other writer would otherwise start
    paging on a device with no CPU of ours to measure."""
    repo = FakeRepository()
    service = AlertService(repo)
    org_id = uuid.uuid4()
    controller = _controller_row(org_id)
    repo.routers.append(controller)
    repo.snapshots[controller.id] = FakeSnapshot(cpu_usage_percent=99.0)
    await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.THRESHOLD,
            target_component=None,
            condition_config={
                "metric": "cpu_usage_percent",
                "operator": "gte",
                "value": 75,
            },
            organization_id=org_id,
        )
    )

    result = await service.evaluate_alert_rules()

    assert result.triggered == []


async def test_a_mikrotik_beside_a_controller_is_still_alerted_on():
    """The gate has to be narrow. An Omada controller at one venue must not
    make the MikroTik at the next one invisible to the same rule."""
    repo = FakeRepository()
    service = AlertService(repo)
    org_id = uuid.uuid4()
    mikrotik = FakeRouter(
        id=uuid.uuid4(),
        organization_id=org_id,
        location_id=uuid.uuid4(),
        name="Router One",
        health_status="unhealthy",
    )
    repo.routers.append(_controller_row(org_id, health_status="unhealthy"))
    repo.routers.append(mikrotik)
    await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.HEALTH_STATUS_CHANGE,
            target_component=ALERT_TARGET_ROUTER,
            condition_config={"expected_status": "unhealthy"},
            organization_id=org_id,
        )
    )

    result = await service.evaluate_alert_rules()

    assert [a.router_id for a in result.triggered] == [mikrotik.id]


async def test_a_controller_still_resolves_to_its_name_on_the_alerts_page():
    """The other half, and the reason `MonitoringRepository.list_routers`
    is deliberately NOT filtered in SQL. An alert can legitimately carry a
    controller's `router_id` -- the network integration links one -- and a
    name lookup that hid the row would put a bare UUID back on the
    customer's Alerts page, the exact defect
    `get_router_names_for_alerts` was written to fix."""
    repo = FakeRepository()
    service = AlertService(repo)
    org_id = uuid.uuid4()
    controller = _controller_row(org_id)
    repo.routers.append(controller)
    alert = await repo.create_alert(
        rule_id=uuid.uuid4(),
        organization_id=org_id,
        location_id=controller.location_id,
        router_id=controller.id,
        message="something",
        severity=AlertSeverity.CRITICAL.value,
        status=AlertStatus.TRIGGERED.value,
    )

    names = await service.get_router_names_for_alerts(
        [alert], organization_id=org_id
    )

    assert names == {controller.id: controller.name}


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


async def test_isp_link_health_status_rule_triggers_and_resolves():
    repo = FakeRepository()
    service = AlertService(repo)
    org_id = uuid.uuid4()
    router_id = uuid.uuid4()
    link = FakeIspLink(
        id=uuid.uuid4(),
        organization_id=org_id,
        location_id=uuid.uuid4(),
        router_id=router_id,
        provider_name="Acme Fiber",
        health_status="unhealthy",
    )
    repo.isp_links.append(link)
    await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.HEALTH_STATUS_CHANGE,
            target_component=ALERT_TARGET_ISP_LINK,
            condition_config={"expected_status": "unhealthy"},
            organization_id=org_id,
        )
    )

    triggered = (await service.evaluate_alert_rules()).triggered
    assert len(triggered) == 1
    assert triggered[0].router_id == router_id
    assert triggered[0].location_id == link.location_id
    assert "Acme Fiber" in triggered[0].message

    link.health_status = "healthy"
    resolved = (await service.evaluate_alert_rules()).resolved
    assert len(resolved) == 1
    assert resolved[0].id == triggered[0].id


async def test_isp_link_and_router_rules_on_same_router_do_not_collide():
    """Both an ``ALERT_TARGET_ROUTER`` rule and an ``ALERT_TARGET_ISP_LINK``
    rule can watch the same underlying router (the link's own ``router_id``)
    without one rule's open alert masking the other's -- ``rule_id`` is
    always part of the de-duplication key (see ``AlertService``'s own
    docstring)."""
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
    repo.isp_links.append(
        FakeIspLink(
            id=uuid.uuid4(),
            organization_id=org_id,
            location_id=router.location_id,
            router_id=router.id,
            provider_name="Acme Fiber",
            health_status="unhealthy",
        )
    )
    await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.HEALTH_STATUS_CHANGE,
            target_component=ALERT_TARGET_ROUTER,
            condition_config={"expected_status": "unhealthy"},
            organization_id=org_id,
        )
    )
    await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.HEALTH_STATUS_CHANGE,
            target_component=ALERT_TARGET_ISP_LINK,
            condition_config={"expected_status": "unhealthy"},
            organization_id=org_id,
        )
    )

    triggered = (await service.evaluate_alert_rules()).triggered
    assert len(triggered) == 2
    assert {a.router_id for a in triggered} == {router.id}
    assert {a.rule_id for a in triggered} == set(repo.alert_rules.keys())

    # A second evaluation pass must not spam a third/fourth alert -- both
    # conditions are still true, both already have an open alert.
    triggered_again = (await service.evaluate_alert_rules()).triggered
    assert triggered_again == []


async def test_isp_link_alert_fires_end_to_end_from_a_real_health_check():
    """Bandwidth-monitoring rollout spec, BE track #4: the two tests above
    (and every other ``ALERT_TARGET_ISP_LINK`` test in this file) drive the
    rule off a hand-built ``FakeIspLink`` with ``health_status`` set
    directly -- real, but never proof the branch survives contact with a
    *real* ``app.domains.isp.service.IspService`` health check, and never
    proof a notification actually gets dispatched for this target type
    specifically (``test_alert_evaluation_dispatches_to_configured_channels``
    covers dispatch, but only for a platform ``ServiceHealth`` component).
    This test closes both gaps in one pass: a real ``IspLink`` row, pushed
    to ``unhealthy`` by a real ``IspService.check_link_health`` call (real
    ping -> real ``classify_health_status`` -> real
    ``record_health_check_result``, exactly the automated sweep's own
    path -- see ``app.domains.isp.service``), is then handed to a real
    ``AlertService.evaluate_alert_rules()`` and asserted to both create an
    ``Alert`` row and actually POST a (faked-transport) notification."""
    isp = make_harness(
        health_adapter=FakeIspHealthAdapter(
            next_result=PingResult(
                sent=5, received=0, packet_loss_percentage=100.0, avg_rtt_ms=None
            )
        )
    )
    router = isp.router_lookup.add(_make_router())
    link = await isp.service.create_link(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=router.organization_id,
        router_id=router.id,
        provider_name="Acme Fiber",
        link_type=IspLinkType.FIBER.value,
        role=IspLinkRole.PRIMARY,
        gateway_ip_address="203.0.113.1",
    )
    # Sanity: not pre-faked into "unhealthy" -- a brand new link starts
    # UNKNOWN until its first real check.
    assert link.health_status == IspHealthStatus.UNKNOWN.value

    link = await isp.service.check_link_health(
        link.id, requesting_organization_id=router.organization_id
    )
    assert link.health_status == IspHealthStatus.UNHEALTHY.value

    captured: list[dict] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.append(json.loads(request.content))
        return httpx.Response(200)

    repo = FakeRepository()
    notification_service = NotificationService(repo, _mock_http_client(handler))
    alert_service = AlertService(repo, notification_service=notification_service)
    # The real IspLink from the isp domain above, handed directly to the
    # monitoring domain's own repository fake -- exactly the read-only
    # cross-domain composition IspRepository.list_isp_links documents in
    # the real (non-test) code.
    repo.isp_links.append(link)

    channel = await _channel(
        repo,
        NotificationChannelType.SLACK,
        {"webhook_url": "https://hooks.slack.com/services/T/B/X"},
    )
    rule = await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.HEALTH_STATUS_CHANGE,
            target_component=ALERT_TARGET_ISP_LINK,
            condition_config={"expected_status": "unhealthy"},
            organization_id=router.organization_id,
        )
    )
    await repo.replace_alert_rule_notification_channels(rule.id, [channel.id])

    result = await alert_service.evaluate_alert_rules()

    assert len(result.triggered) == 1
    assert result.triggered[0].router_id == router.id
    assert result.triggered[0].location_id == link.location_id
    assert "Acme Fiber" in result.triggered[0].message
    assert len(repo.alerts) == 1
    # The real proof this end-to-end path works: a notification was
    # actually dispatched, not just an Alert row silently created.
    assert len(captured) == 1
    assert len(repo.notification_logs) == 1
    assert repo.notification_logs[0].status == NotificationStatus.SENT.value

    # And the recovery half of the same real path: a subsequent healthy
    # real ping auto-resolves the same alert.
    isp.health_adapter.next_result = PingResult(
        sent=5, received=5, packet_loss_percentage=0.0, avg_rtt_ms=15.0
    )
    link = await isp.service.check_link_health(
        link.id, requesting_organization_id=router.organization_id
    )
    assert link.health_status == IspHealthStatus.HEALTHY.value
    repo.isp_links[0] = link

    resolved = (await alert_service.evaluate_alert_rules()).resolved
    assert len(resolved) == 1
    assert resolved[0].id == result.triggered[0].id
    assert resolved[0].status == AlertStatus.RESOLVED.value


def test_validate_health_status_change_accepts_isp_link_target():
    validate_alert_rule_condition_config(
        AlertTriggerType.HEALTH_STATUS_CHANGE,
        ALERT_TARGET_ISP_LINK,
        {"expected_status": "unhealthy"},
    )


# ============================================================================
# Alert Engine: evaluation -- ALERT_TARGET_ROGUE_DHCP_GUARD
# ============================================================================
#
# The push half of cloud-guest#139's rogue-DHCP detector. #139 persisted a
# ``RouterRogueDhcpStatus`` row per ``(router_id, interface)`` and put a
# readiness checklist item over it; an unguarded router therefore only ever
# appeared if somebody opened that router's checklist, which nobody does.
#
# Every test below builds its rows through ``_rogue_router``/``_rogue_rows``
# and drives the real ``AlertService.evaluate_alert_rules`` -- never the
# private branch directly -- so the wiring from ``evaluate_alert_rules``
# through the new repository surface is what is under test, not just the
# branch's arithmetic.


def _rogue_router(org_id: uuid.UUID, name: str = "Lobby Router") -> FakeRouter:
    return FakeRouter(
        id=uuid.uuid4(),
        organization_id=org_id,
        location_id=uuid.uuid4(),
        name=name,
        health_status="healthy",
    )


def _rogue_rows(
    router: FakeRouter, states: dict[str, str]
) -> list[tuple[FakeRouter, FakeRogueDhcpStatus]]:
    return [
        (router, FakeRogueDhcpStatus(interface=iface, alert_state=state))
        for iface, state in states.items()
    ]


async def _rogue_dhcp_harness(
    org_id: uuid.UUID,
) -> tuple[FakeRepository, AlertService]:
    repo = FakeRepository()
    service = AlertService(repo)
    await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.HEALTH_STATUS_CHANGE,
            target_component=ALERT_TARGET_ROGUE_DHCP_GUARD,
            condition_config={"expected_status": ROGUE_DHCP_STATE_UNGUARDED},
            organization_id=org_id,
            severity=AlertSeverity.WARNING,
        )
    )
    return repo, service


def test_rogue_dhcp_state_constants_match_the_detector_enum():
    """``app.domains.monitoring`` holds these as plain strings rather than
    importing ``dhcp``'s enum, keeping this module's zero-cross-domain-import
    shape. That is only safe if the two cannot drift apart silently, which
    is what this pins."""
    assert RogueDhcpAlertState.GUARDED.value == ROGUE_DHCP_STATE_GUARDED
    assert RogueDhcpAlertState.UNGUARDED.value == ROGUE_DHCP_STATE_UNGUARDED
    assert RogueDhcpAlertState.UNKNOWN.value == ROGUE_DHCP_STATE_UNKNOWN


def test_validate_health_status_change_accepts_rogue_dhcp_guard_target():
    validate_alert_rule_condition_config(
        AlertTriggerType.HEALTH_STATUS_CHANGE,
        ALERT_TARGET_ROGUE_DHCP_GUARD,
        {"expected_status": ROGUE_DHCP_STATE_UNGUARDED},
    )


def test_validate_rogue_dhcp_guard_rejects_guarded_and_unknown_expected_status():
    """A rule asking for ``guarded`` would fire when everything is fine, and
    one asking for ``unknown`` would page somebody for every router the
    detector could not reach. Both are rejected when the rule is saved, not
    silently evaluated to nothing six hours later."""
    for bad in (ROGUE_DHCP_STATE_GUARDED, ROGUE_DHCP_STATE_UNKNOWN):
        with pytest.raises(InvalidAlertRuleConfigError):
            validate_alert_rule_condition_config(
                AlertTriggerType.HEALTH_STATUS_CHANGE,
                ALERT_TARGET_ROGUE_DHCP_GUARD,
                {"expected_status": bad},
            )


async def test_rogue_dhcp_guard_rule_triggers_on_unguarded_interface():
    """A device that *answered*, and answered "nothing is watching this",
    is a real finding and raises a real alert."""
    org_id = uuid.uuid4()
    repo, service = await _rogue_dhcp_harness(org_id)
    router = _rogue_router(org_id)
    repo.rogue_dhcp_rows.extend(
        _rogue_rows(
            router,
            {
                "ether2": ROGUE_DHCP_STATE_UNGUARDED,
                "vlan10": ROGUE_DHCP_STATE_GUARDED,
            },
        )
    )

    result = await service.evaluate_alert_rules()

    assert len(result.triggered) == 1
    alert = result.triggered[0]
    assert alert.router_id == router.id
    assert alert.organization_id == org_id
    assert alert.location_id == router.location_id
    # The interface an operator has to go and fix is named, and the one
    # that is fine is not.
    assert "ether2" in alert.message
    assert "vlan10" not in alert.message

    # Second pass, same condition: de-duplicated, never a second alert.
    assert (await service.evaluate_alert_rules()).triggered == []


async def test_rogue_dhcp_guard_rule_never_triggers_on_unknown():
    """A router the detector could not reach is **not** a router we know is
    unwatched.

    The tri-state is carried end to end -- the gateway reader, the
    persisted ``alert_state``, the detector's per-router summary counts,
    and the readiness item's NOT_CHECKED-not-FAIL branch all keep
    ``unknown`` separate from ``unguarded``. This is the last step, and it
    does not collapse it either. Reporting every unreachable router as
    unguarded would page somebody for every offline router in the fleet
    while telling them nothing true about rogue DHCP -- the same conflation
    that once rendered a missing SMS provider as "delivery failed" and
    silently dropped locations from a fleet list.
    """
    org_id = uuid.uuid4()
    repo, service = await _rogue_dhcp_harness(org_id)
    router = _rogue_router(org_id, name="Unreachable Router")
    repo.rogue_dhcp_rows.extend(
        _rogue_rows(
            router,
            {
                "ether2": ROGUE_DHCP_STATE_UNKNOWN,
                "vlan10": ROGUE_DHCP_STATE_UNKNOWN,
            },
        )
    )

    result = await service.evaluate_alert_rules()

    assert result.triggered == []
    assert result.resolved == []
    assert repo.alerts == {}


async def test_rogue_dhcp_guard_unknown_beside_unguarded_still_triggers():
    """Ordering, and it matters: a known-unguarded interface outranks an
    unknown one beside it. The finding was established by a device that
    answered, and the unknown next to it does not soften it -- the same
    ordering ``ReadinessService._check_rogue_dhcp_detection`` uses on these
    same rows."""
    org_id = uuid.uuid4()
    repo, service = await _rogue_dhcp_harness(org_id)
    router = _rogue_router(org_id)
    repo.rogue_dhcp_rows.extend(
        _rogue_rows(
            router,
            {
                "ether2": ROGUE_DHCP_STATE_UNGUARDED,
                "vlan10": ROGUE_DHCP_STATE_UNKNOWN,
            },
        )
    )

    result = await service.evaluate_alert_rules()

    assert len(result.triggered) == 1
    assert "ether2" in result.triggered[0].message


async def test_rogue_dhcp_guard_unknown_never_resolves_an_open_alert():
    """The half that is easy to get wrong. An alert is open, then the
    detector loses contact with the router: that is not evidence anybody
    fixed anything, so the alert stays open. Auto-resolving on a timeout
    would tell an operator "the guard is back" on the strength of no answer
    at all."""
    org_id = uuid.uuid4()
    repo, service = await _rogue_dhcp_harness(org_id)
    router = _rogue_router(org_id)
    repo.rogue_dhcp_rows.extend(
        _rogue_rows(router, {"ether2": ROGUE_DHCP_STATE_UNGUARDED})
    )
    triggered = (await service.evaluate_alert_rules()).triggered
    assert len(triggered) == 1

    repo.rogue_dhcp_rows[:] = _rogue_rows(router, {"ether2": ROGUE_DHCP_STATE_UNKNOWN})
    result = await service.evaluate_alert_rules()

    assert result.resolved == []
    assert result.triggered == []
    assert repo.alerts[triggered[0].id].status == AlertStatus.TRIGGERED.value


async def test_rogue_dhcp_guard_rule_resolves_when_the_guard_is_restored():
    """An alert that fires when a router becomes unguarded and never clears
    when the guard comes back trains people to ignore alerts. Same
    no-separate-recovery-rule design every other target here uses: the
    condition is re-evaluated each pass and the open alert is transitioned
    straight to RESOLVED."""
    org_id = uuid.uuid4()
    repo, service = await _rogue_dhcp_harness(org_id)
    router = _rogue_router(org_id)
    repo.rogue_dhcp_rows.extend(
        _rogue_rows(router, {"ether2": ROGUE_DHCP_STATE_UNGUARDED})
    )
    triggered = (await service.evaluate_alert_rules()).triggered
    assert len(triggered) == 1

    repo.rogue_dhcp_rows[:] = _rogue_rows(router, {"ether2": ROGUE_DHCP_STATE_GUARDED})
    result = await service.evaluate_alert_rules()

    assert len(result.resolved) == 1
    assert result.resolved[0].id == triggered[0].id
    assert result.resolved[0].status == AlertStatus.RESOLVED.value
    assert result.resolved[0].resolved_at is not None
    # The text is replaced at resolution time, so the "[RESOLVED]" prefix
    # _format_alert_message adds cannot produce "[RESOLVED] ... detection
    # is off" -- the contradiction a real operator read in a real email
    # once already.
    assert "is off" not in result.resolved[0].message
    assert "active again" in result.resolved[0].message

    # And it stays resolved: a resolved alert is not re-resolved next pass.
    assert (await service.evaluate_alert_rules()).resolved == []


async def test_rogue_dhcp_guard_alert_text_never_claims_protection():
    """``/ip dhcp-server alert`` logs. It blocks nothing, drops nothing and
    rate-limits nothing. Copy that says otherwise describes a defence this
    platform has never had and leaves an operator believing the fix
    restores one -- so both the trigger and the resolution wording are
    pinned here, on the real ``Alert.message`` the notifiers send."""
    org_id = uuid.uuid4()
    repo, service = await _rogue_dhcp_harness(org_id)
    router = _rogue_router(org_id)
    repo.rogue_dhcp_rows.extend(
        _rogue_rows(router, {"ether2": ROGUE_DHCP_STATE_UNGUARDED})
    )
    triggered = (await service.evaluate_alert_rules()).triggered
    # Snapshotted *before* resolving, and this is load-bearing:
    # ``_auto_resolve`` replaces the message on the very same ``Alert``
    # object it resolves, so ``triggered[0]`` and ``resolved[0]`` are one
    # object and reading ``.message`` afterwards would silently check the
    # resolution copy twice and never look at the trigger copy at all.
    # Caught by mutation-testing this test -- putting "protection" into the
    # trigger wording left it green.
    trigger_message = triggered[0].message
    repo.rogue_dhcp_rows[:] = _rogue_rows(router, {"ether2": ROGUE_DHCP_STATE_GUARDED})
    resolved = (await service.evaluate_alert_rules()).resolved
    resolved_message = resolved[0].message

    forbidden = (
        "protect",
        "protection",
        "protected",
        "unprotected",
        "block",
        "blocked",
        "blocking",
        "prevent",
        "prevented",
        "defend",
        "defence",
        "defense",
        "secured",
        "guard",  # incl. "guarded"/"unguarded" -- internal vocabulary
        "shield",
        "stop",
    )
    assert trigger_message != resolved_message
    for message in (trigger_message, resolved_message):
        lowered = message.lower()
        for word in forbidden:
            # "it does not block" is the one permitted use, and it is a
            # denial of protection, not a claim of it.
            occurrences = lowered.count(word)
            allowed = 1 if word == "block" and "does not block" in lowered else 0
            assert occurrences == allowed, (
                f"alert copy claims protection via {word!r}: {message}"
            )
        assert "detection only -- it logs, it does not block" in lowered


async def test_rogue_dhcp_guard_two_unguarded_interfaces_are_one_alert():
    """The de-duplication key is ``(rule_id, organization_id, location_id,
    router_id)`` and has no interface dimension. Evaluating per interface
    would address two findings to one key -- one alert plus one silently
    swallowed duplicate, with whichever interface the query returned first
    in the message. So the rows are grouped per router and both interfaces
    are named."""
    org_id = uuid.uuid4()
    repo, service = await _rogue_dhcp_harness(org_id)
    router = _rogue_router(org_id)
    repo.rogue_dhcp_rows.extend(
        _rogue_rows(
            router,
            {
                "vlan10": ROGUE_DHCP_STATE_UNGUARDED,
                "ether2": ROGUE_DHCP_STATE_UNGUARDED,
            },
        )
    )

    result = await service.evaluate_alert_rules()

    assert len(result.triggered) == 1
    # Sorted, not insertion-ordered: the message must read the same however
    # the rows came back.
    assert "ether2, vlan10" in result.triggered[0].message


async def test_rogue_dhcp_guard_rule_is_scoped_to_its_organization():
    org_id = uuid.uuid4()
    other_org_id = uuid.uuid4()
    repo, service = await _rogue_dhcp_harness(org_id)
    mine = _rogue_router(org_id, name="Mine")
    theirs = _rogue_router(other_org_id, name="Theirs")
    repo.rogue_dhcp_rows.extend(
        _rogue_rows(mine, {"ether2": ROGUE_DHCP_STATE_UNGUARDED})
    )
    repo.rogue_dhcp_rows.extend(
        _rogue_rows(theirs, {"ether2": ROGUE_DHCP_STATE_UNGUARDED})
    )

    result = await service.evaluate_alert_rules()

    assert len(result.triggered) == 1
    assert result.triggered[0].router_id == mine.id


async def test_rogue_dhcp_guard_rule_reads_state_only_never_a_device():
    """The engine's standing promise, and the reason cloud-guest#139 split
    detector-writes from surface-reads in the first place: evaluation reads
    already-persisted rows and performs no per-device I/O. A fake with no
    device surface at all is the assertion -- if the branch ever tried to
    reach a router it would have nothing to reach it with.

    It is also O(1) queries in fleet size: one bulk status read and one
    bulk open-alert read per rule, not one of each per router. Counted
    here, because "don't make evaluation scale with router count" is the
    kind of promise that quietly stops being true.
    """
    org_id = uuid.uuid4()
    repo, service = await _rogue_dhcp_harness(org_id)
    calls: list[str] = []
    real_statuses = repo.list_rogue_dhcp_statuses_with_routers
    real_open = repo.list_open_alerts_for_rule
    real_find = repo.find_active_alert

    async def counted_statuses(**kwargs):
        calls.append("statuses")
        return await real_statuses(**kwargs)

    async def counted_open(**kwargs):
        calls.append("open_alerts")
        return await real_open(**kwargs)

    async def counted_find(**kwargs):
        calls.append("find_active_alert")
        return await real_find(**kwargs)

    repo.list_rogue_dhcp_statuses_with_routers = counted_statuses
    repo.list_open_alerts_for_rule = counted_open
    repo.find_active_alert = counted_find
    for index in range(12):
        repo.rogue_dhcp_rows.extend(
            _rogue_rows(
                _rogue_router(org_id, name=f"Router {index}"),
                {"ether2": ROGUE_DHCP_STATE_UNGUARDED},
            )
        )

    result = await service.evaluate_alert_rules()

    assert len(result.triggered) == 12
    assert calls == ["statuses", "open_alerts"]


async def test_new_organizations_get_a_working_rogue_dhcp_rule_from_day_one():
    """This is the answer to the foreign key that blocked this feature.

    ``Alert.rule_id`` is a non-nullable FK to ``alert_rules``, so the
    detector in ``app.domains.dhcp.tasks`` could not raise anything without
    a rule existing first -- which is exactly why cloud-guest#139 stopped at
    a persisted row and a checklist item. The fix is the mechanism this
    codebase already uses for ``ALERT_TARGET_MONITORED_HARDWARE``: a default
    rule created with the organization, at the router/orchestration layer,
    non-fatally. Not a nullable column, and not a new seeding path.

    Exercised through the real ``AlertService.create_alert_rule`` (which
    runs ``validate_alert_rule_condition_config``), so a default whose
    ``condition_config`` the validator would reject fails here rather than
    silently logging "default_alert_rule_creation_failed" in production and
    leaving a new customer with no rule -- the failure mode that
    ``except Exception`` is deliberately wide enough to hide.
    """
    repo = FakeRepository()
    transport = httpx.MockTransport(lambda request: httpx.Response(200))
    async with httpx.AsyncClient(transport=transport) as http_client:
        notification_service = NotificationService(repo, http_client)
        service = AlertService(repo, notification_service=notification_service)
        org_id = uuid.uuid4()

        await ensure_default_alerting(
            service,
            notification_service,
            organization_id=org_id,
            contact_email="owner@venue.example",
        )

    rules = {rule.target_component: rule for rule in repo.alert_rules.values()}
    assert set(rules) == {
        ALERT_TARGET_ROUTER_REACHABILITY,
        ALERT_TARGET_ISP_LINK,
        ALERT_TARGET_MONITORED_HARDWARE,
        ALERT_TARGET_ROGUE_DHCP_GUARD,
        ALERT_TARGET_NETWORK_CONTROLLER,
        ALERT_TARGET_NETWORK_CONTROLLER_AUTHORIZE,
        ALERT_TARGET_NETWORK_CONTROLLER_SETUP,
    }
    rogue_rule = rules[ALERT_TARGET_ROGUE_DHCP_GUARD]
    assert rogue_rule.organization_id == org_id
    assert rogue_rule.is_active
    assert rogue_rule.condition_config == {
        "expected_status": ROGUE_DHCP_STATE_UNGUARDED
    }
    assert rogue_rule.trigger_type == AlertTriggerType.HEALTH_STATUS_CHANGE.value
    # Detector-only naming, same rule as the alert copy itself: nothing an
    # operator reads about this may imply /ip dhcp-server alert protects
    # anything.
    for text in (rogue_rule.name.lower(), (rogue_rule.description or "").lower()):
        assert "protect" not in text
        assert text.count("block") == ("does not block" in text)


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
        incident.id,
        status=IncidentStatus.INVESTIGATING,
        requesting_organization_id=None,
    )
    assert investigating.status == IncidentStatus.INVESTIGATING.value

    resolved = await service.update_incident(
        incident.id,
        status=IncidentStatus.RESOLVED,
        resolution_notes="Fixed",
        requesting_organization_id=None,
    )
    assert resolved.status == IncidentStatus.RESOLVED.value
    assert resolved.resolved_at is not None
    assert resolved.resolution_notes == "Fixed"

    closed = await service.update_incident(
        incident.id,
        status=IncidentStatus.CLOSED,
        requesting_organization_id=None,
    )
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
    await service.update_incident(
        incident.id,
        status=IncidentStatus.CLOSED,
        requesting_organization_id=None,
    )
    with pytest.raises(InvalidIncidentStatusTransitionError):
        await service.update_incident(
            incident.id,
            status=IncidentStatus.OPEN,
            requesting_organization_id=None,
        )


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

    await service.attach_alert(
        incident.id,
        alert.id,
        requesting_organization_id=None,
    )
    await service.attach_alert(
        incident.id,
        alert.id,
        requesting_organization_id=None,
    )

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

    report = await service.generate_report(
        target.id,
        requesting_organization_id=None,
    )
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
        await service.generate_report(
            target.id,
            requesting_organization_id=None,
        )


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

    report = await service.generate_report(
        target.id,
        requesting_organization_id=None,
    )
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


# ============================================================================
# Tenant scoping of the alerts / alert-rules listings
# ----------------------------------------------------------------------------
# GET /alerts and GET /alerts/rules must derive the effective organization
# from the caller's auth scope, never from a client-supplied query param, and
# a missing org filter must never silently mean "every organization" for a
# scoped caller. See ``fix(monitoring): scope alerts/rules to caller org``.
# ============================================================================


@dataclass
class _FakeAlertRow:
    organization_id: uuid.UUID
    location_id: uuid.UUID | None = None


@dataclass
class _FakePaginateMeta:
    total_items: int


class _RecordingPaginator:
    """Stands in for a ``GenericRepository`` on ``MonitoringRepository`` --
    just enough of ``paginate`` to observe the org filter the repository builds
    and mimic ``apply_filters``' "``None`` org -> no WHERE clause -> every
    row" behaviour, so the test proves the repository's own guard, not
    ``apply_filters`` itself."""

    def __init__(self, rows: list[_FakeAlertRow]) -> None:
        self._rows = rows
        self.last_filters: dict[str, object] | None = None

    async def paginate(self, *, page, page_size, filters, sort_by, sort_order):
        self.last_filters = filters
        org = filters.get("organization_id")
        loc = filters.get("location_id")
        selected = [
            r
            for r in self._rows
            if (org is None or r.organization_id == org)
            # Mirrors apply_filters: a None filter contributes no WHERE clause.
            and (loc is None or r.location_id == loc)
        ]
        return selected, _FakePaginateMeta(total_items=len(selected))


def _repo_with_alert_rows(rows: list[_FakeAlertRow]) -> MonitoringRepository:
    repo = MonitoringRepository(session=None)  # type: ignore[arg-type]
    paginator = _RecordingPaginator(rows)
    # Both listings route through their respective GenericRepository; swap in a
    # recording double so no live session is touched.
    repo.alerts = paginator  # type: ignore[assignment]
    repo.alert_rules = paginator  # type: ignore[assignment]
    return repo


async def test_list_alerts_scoped_admin_sees_only_own_org():
    org_a, org_b = uuid.uuid4(), uuid.uuid4()
    rows = [_FakeAlertRow(org_a), _FakeAlertRow(org_a), _FakeAlertRow(org_b)]
    service = AlertService(_repo_with_alert_rows(rows))

    # An organization-scoped caller resolves to their own org (org_a) and sees
    # only org_a's alerts -- never org_b's.
    items, _meta = await service.list_alerts(organization_id=org_a)
    assert len(items) == 2
    assert all(row.organization_id == org_a for row in items)


async def test_list_alerts_missing_org_without_optin_is_refused():
    rows = [_FakeAlertRow(uuid.uuid4())]
    service = AlertService(_repo_with_alert_rows(rows))

    # Defense-in-depth: a missing org filter without an explicit cross-org
    # opt-in must never fall through to "every organization".
    with pytest.raises(UnscopedOrganizationListError):
        await service.list_alerts(organization_id=None)


async def test_list_alerts_platform_caller_may_read_across_orgs():
    org_a, org_b = uuid.uuid4(), uuid.uuid4()
    rows = [_FakeAlertRow(org_a), _FakeAlertRow(org_b)]
    service = AlertService(_repo_with_alert_rows(rows))

    # A platform/GLOBAL caller (org resolves to None) explicitly opts into the
    # cross-organization read and sees every org's alerts.
    items, _meta = await service.list_alerts(
        organization_id=None, include_all_organizations=True
    )
    assert len(items) == 2


async def test_list_alert_rules_scoped_admin_sees_only_own_org():
    org_a, org_b = uuid.uuid4(), uuid.uuid4()
    rows = [_FakeAlertRow(org_a), _FakeAlertRow(org_b)]
    service = AlertService(_repo_with_alert_rows(rows))

    items, _meta = await service.list_alert_rules(organization_id=org_a)
    assert len(items) == 1
    assert items[0].organization_id == org_a


async def test_list_alert_rules_missing_org_without_optin_is_refused():
    service = AlertService(_repo_with_alert_rows([_FakeAlertRow(uuid.uuid4())]))

    with pytest.raises(UnscopedOrganizationListError):
        await service.list_alert_rules(organization_id=None)


async def test_list_alert_rules_platform_caller_may_read_across_orgs():
    rows = [_FakeAlertRow(uuid.uuid4()), _FakeAlertRow(uuid.uuid4())]
    service = AlertService(_repo_with_alert_rows(rows))

    items, _meta = await service.list_alert_rules(
        organization_id=None, include_all_organizations=True
    )
    assert len(items) == 2


# ----------------------------------------------------------------------------
# Same tenant-scoping guard for the notification-channels / incidents / SLA
# listings (the endpoints fixed alongside alerts/alert-rules): an org-scoped
# caller omitting the param must see only their own org's rows, never every
# organization's. See ``fix(monitoring): scope channels/incidents/sla``.
# ----------------------------------------------------------------------------


class _RecordingLister:
    """``get_all`` counterpart to ``_RecordingPaginator`` -- stands in for a
    ``GenericRepository`` whose listing returns a plain ``list`` (SLA targets),
    mimicking ``apply_filters``' "``None`` org -> every row" so the test proves
    the repository's own guard, not ``apply_filters``."""

    def __init__(self, rows: list[_FakeAlertRow]) -> None:
        self._rows = rows

    async def get_all(self, *, filters, sort_by=None, sort_order=None, **kwargs):
        org = filters.get("organization_id")
        return [r for r in self._rows if org is None or r.organization_id == org]


def _repo_with_rows_on(attr: str, rows: list[_FakeAlertRow]) -> MonitoringRepository:
    repo = MonitoringRepository(session=None)  # type: ignore[arg-type]
    setattr(repo, attr, _RecordingPaginator(rows))
    return repo


async def test_list_channels_scoped_admin_sees_only_own_org():
    org_a, org_b = uuid.uuid4(), uuid.uuid4()
    rows = [_FakeAlertRow(org_a), _FakeAlertRow(org_a), _FakeAlertRow(org_b)]
    service = NotificationService(
        _repo_with_rows_on("notification_channels", rows), httpx.AsyncClient()
    )

    items, _meta = await service.list_channels(organization_id=org_a)
    assert len(items) == 2
    assert all(row.organization_id == org_a for row in items)


async def test_list_channels_missing_org_without_optin_is_refused():
    service = NotificationService(
        _repo_with_rows_on("notification_channels", [_FakeAlertRow(uuid.uuid4())]),
        httpx.AsyncClient(),
    )
    with pytest.raises(UnscopedOrganizationListError):
        await service.list_channels(organization_id=None)


async def test_list_channels_platform_caller_may_read_across_orgs():
    rows = [_FakeAlertRow(uuid.uuid4()), _FakeAlertRow(uuid.uuid4())]
    service = NotificationService(
        _repo_with_rows_on("notification_channels", rows), httpx.AsyncClient()
    )
    items, _meta = await service.list_channels(
        organization_id=None, include_all_organizations=True
    )
    assert len(items) == 2


async def test_list_incidents_scoped_admin_sees_only_own_org():
    org_a, org_b = uuid.uuid4(), uuid.uuid4()
    rows = [_FakeAlertRow(org_a), _FakeAlertRow(org_b)]
    service = IncidentService(_repo_with_rows_on("incidents", rows))

    items, _meta = await service.list_incidents(organization_id=org_a)
    assert len(items) == 1
    assert items[0].organization_id == org_a


async def test_list_incidents_missing_org_without_optin_is_refused():
    service = IncidentService(
        _repo_with_rows_on("incidents", [_FakeAlertRow(uuid.uuid4())])
    )
    with pytest.raises(UnscopedOrganizationListError):
        await service.list_incidents(organization_id=None)


async def test_list_incidents_platform_caller_may_read_across_orgs():
    rows = [_FakeAlertRow(uuid.uuid4()), _FakeAlertRow(uuid.uuid4())]
    service = IncidentService(_repo_with_rows_on("incidents", rows))
    items, _meta = await service.list_incidents(
        organization_id=None, include_all_organizations=True
    )
    assert len(items) == 2


async def test_list_sla_targets_scoped_admin_sees_only_own_org():
    org_a, org_b = uuid.uuid4(), uuid.uuid4()
    repo = MonitoringRepository(session=None)  # type: ignore[arg-type]
    repo.sla_targets = _RecordingLister(  # type: ignore[assignment]
        [_FakeAlertRow(org_a), _FakeAlertRow(org_a), _FakeAlertRow(org_b)]
    )
    targets = await repo.list_sla_targets(organization_id=org_a)
    assert len(targets) == 2
    assert all(t.organization_id == org_a for t in targets)


async def test_list_sla_targets_missing_org_without_optin_is_refused():
    repo = MonitoringRepository(session=None)  # type: ignore[arg-type]
    repo.sla_targets = _RecordingLister([_FakeAlertRow(uuid.uuid4())])  # type: ignore[assignment]
    with pytest.raises(UnscopedOrganizationListError):
        await repo.list_sla_targets(organization_id=None)


async def test_list_sla_targets_platform_caller_may_read_across_orgs():
    repo = MonitoringRepository(session=None)  # type: ignore[arg-type]
    repo.sla_targets = _RecordingLister(  # type: ignore[assignment]
        [_FakeAlertRow(uuid.uuid4()), _FakeAlertRow(uuid.uuid4())]
    )
    targets = await repo.list_sla_targets(
        organization_id=None, include_all_organizations=True
    )
    assert len(targets) == 2


@pytest.mark.parametrize(
    ("path", "method"),
    [
        ("/api/v1/alerts", "GET"),
        ("/api/v1/alerts/rules", "GET"),
        ("/api/v1/notifications/channels", "GET"),
        ("/api/v1/incidents", "GET"),
        ("/api/v1/sla", "GET"),
    ],
)
def test_alerts_listings_resolve_org_from_auth_scope_not_query_param(
    monitoring_routes_by_path_method, path, method
):
    """The two listings must take ``organization_id`` from
    ``CurrentOrganization`` (the caller's validated auth scope), not from a
    client-supplied query param -- otherwise an org-scoped admin omitting the
    param would read every organization's rows."""
    from app.domains.rbac.dependencies import CurrentOrganization

    route = monitoring_routes_by_path_method[(path, method)]
    dependant = route.dependant

    # organization_id is no longer a request query parameter ...
    query_names = {param.name for param in dependant.query_params}
    assert "organization_id" not in query_names

    # ... it is resolved via the CurrentOrganization dependency instead.
    dependency_calls = {dep.call for dep in dependant.dependencies}
    assert CurrentOrganization in dependency_calls


@pytest.mark.parametrize(
    ("path", "method"),
    [
        ("/api/v1/events", "GET"),
        ("/api/v1/monitoring/dashboard", "GET"),
        ("/api/v1/monitoring/devices", "GET"),
        ("/api/v1/ztp/dashboard", "GET"),
        ("/api/v1/ztp/analytics", "GET"),
    ],
)
def test_platform_dashboards_resolve_org_from_auth_scope_not_query_param(
    monitoring_routes_by_path_method, path, method
):
    """The platform monitoring/ZTP dashboards must take ``organization_id``
    from ``CurrentOrganization`` (the caller's validated auth scope), not from
    a client-supplied query param.

    ``monitoring.read``/``analytics.read`` are grantable at ORGANIZATION scope
    (see ``rbac.seed`` MODULE_NARROWEST_SCOPE), so an org-scoped admin who sent
    ``X-Organization-Id`` (passing the org-scoped permission check) but omitted
    ``?organization_id=`` previously had the org filter silently dropped and
    aggregated every organization's data cross-tenant. A caller with no org
    header resolves to ``None`` and, having passed the GLOBAL-scope permission
    gate, may still legitimately read across organizations.
    """
    from app.domains.rbac.dependencies import CurrentOrganization

    route = monitoring_routes_by_path_method[(path, method)]
    dependant = route.dependant

    query_names = {param.name for param in dependant.query_params}
    assert "organization_id" not in query_names

    dependency_calls = {dep.call for dep in dependant.dependencies}
    assert CurrentOrganization in dependency_calls


async def test_list_alerts_filters_by_location_server_side():
    """A venue's alerts must be selectable by location in the query, not by
    over-fetching the organization and narrowing client-side.

    The customer dashboard's Monitoring tab did the latter: it asked for the
    org's first 100 alerts and filtered on `a.locationId === locationId`, so a
    location whose alerts fell past that page reported "Open alerts 0", and
    browsing N locations issued N byte-identical org-wide requests.
    """
    org = uuid.uuid4()
    venue_a, venue_b = uuid.uuid4(), uuid.uuid4()
    rows = [
        _FakeAlertRow(org, venue_a),
        _FakeAlertRow(org, venue_b),
        _FakeAlertRow(org, venue_b),
        _FakeAlertRow(org, None),
    ]
    repo = _repo_with_alert_rows(rows)
    service = AlertService(repo)

    items, meta = await service.list_alerts(organization_id=org, location_id=venue_b)

    assert len(items) == 2
    assert all(row.location_id == venue_b for row in items)
    # total_items must reflect the filtered set, so the tile shows the venue's
    # real count rather than the organization's.
    assert meta.total_items == 2
    assert repo.alerts.last_filters["location_id"] == venue_b  # type: ignore[union-attr]


async def test_list_alerts_without_location_still_returns_the_whole_org():
    """The new filter is additive -- omitting it must not narrow anything."""
    org = uuid.uuid4()
    rows = [_FakeAlertRow(org, uuid.uuid4()), _FakeAlertRow(org, None)]
    repo = _repo_with_alert_rows(rows)
    service = AlertService(repo)

    items, _meta = await service.list_alerts(organization_id=org)

    assert len(items) == 2
    assert repo.alerts.last_filters["location_id"] is None  # type: ignore[union-attr]


class TestHealthCheckSweepIsScheduled:
    """The Health Engine had no schedule at all.

    `GET /monitoring/health` only reads stored `service_health` rows, and
    the only writer was the Master console's own "Run health checks now"
    button. So the System Health page's component timestamps were exactly
    as old as the last time a human clicked it -- two days, when this was
    found on 2026-09-04, while the page described itself as live and
    FreeRADIUS sat on "Degraded, 5 consecutive failures" from a check
    nobody had re-run.

    A scheduled sweep that is registered but not in `beat_schedule`, or in
    `beat_schedule` under a task name nothing registered, fails exactly the
    same way and just as silently -- so both halves are asserted, and that
    they name the same task.
    """

    def test_the_task_is_registered_and_scheduled_under_the_same_name(
        self,
    ) -> None:
        import app.domains.monitoring.tasks  # noqa: F401 -- registers the task
        from app.core.celery_app import celery_app
        from app.domains.monitoring.constants import (
            HEALTH_CHECK_SWEEP_INTERVAL_SECONDS,
            TASK_RUN_HEALTH_CHECK_SWEEP,
        )

        entry = celery_app.conf.beat_schedule.get("monitoring-health-check-sweep")
        assert entry is not None, "the Health Engine has no Beat entry again"
        assert entry["task"] == TASK_RUN_HEALTH_CHECK_SWEEP
        assert entry["schedule"] == HEALTH_CHECK_SWEEP_INTERVAL_SECONDS
        assert TASK_RUN_HEALTH_CHECK_SWEEP in celery_app.tasks, (
            "scheduled under a task name nothing registered"
        )

    def test_the_cadence_is_not_silently_widened(self) -> None:
        """Five minutes is a deliberate choice, not a default: these checks
        touch the database, Redis, disk and the hub's own agents, so they
        are far more expensive than the 30-second alert sweep that only
        reads persisted state. Widening this to hours would restore the
        stale-data problem without removing the entry, which is the change
        that would not look like a regression in review."""
        from app.domains.monitoring.constants import (
            HEALTH_CHECK_SWEEP_INTERVAL_SECONDS,
        )

        assert 60.0 <= HEALTH_CHECK_SWEEP_INTERVAL_SECONDS <= 900.0


# ============================================================================
# Alert Engine: per-rule failure isolation, and the malformed rows that
# proved it was needed
# ============================================================================


async def test_a_malformed_rule_does_not_blind_every_other_rule():
    """THE REGRESSION. This is the defect, reproduced exactly.

    Production carried two demo rules whose ``condition_config`` read
    ``{"metric": ..., "operator": ..., "threshold": 75}``. The canonical key
    is ``value`` -- ``validators.validate_alert_rule_condition_config``
    requires it, the frontend's ``conditionConfigFromAlertRuleForm`` emits
    it, and ``_evaluate_threshold_rule`` reads it -- and nothing in either
    repository has ever written ``threshold``, so those rows were inserted
    around the validator.

    ``_evaluate_threshold_rule``'s bare ``rule.condition_config["value"]``
    then raised ``KeyError('value')`` out of the middle of the evaluation
    loop, aborting the whole pass. In the six hours before this was found:
    276 tracebacks, zero completed runs, and therefore no rule belonging to
    any real customer evaluated even once. Two malformed demo rows blinded
    alerting for the entire platform.

    So the assertion that matters is not that the bad rule is skipped. It is
    that the GOOD rule -- ordered after it, exactly as the malformed demo
    rules were -- still fires.
    """
    repo = FakeRepository()
    service = AlertService(repo)
    await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.THRESHOLD,
            target_component=None,
            # The literal production shape.
            condition_config={
                "metric": "cpu_usage_percent",
                "operator": "gte",
                "threshold": 75,
            },
        )
    )
    healthy_rule = await repo.create_alert_rule(
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
    assert result.triggered[0].rule_id == healthy_rule.id
    assert result.skipped_rules == 1, (
        "the bad rule must be counted, not silently swallowed -- isolation "
        "is only an improvement if the skipping is loud"
    )


async def test_the_canonical_threshold_key_is_value_and_still_evaluates():
    """The other half of the same decision: ``value`` is canonical and the
    reader was right. This pins that down so nobody later 'fixes' the
    KeyError by teaching the evaluator to accept ``threshold`` as well,
    which would leave two spellings of one field in the database forever."""
    repo = FakeRepository()
    service = AlertService(repo)
    router = FakeRouter(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        location_id=uuid.uuid4(),
        name="Office Guest",
        health_status="healthy",
    )
    repo.routers.append(router)
    repo.snapshots[router.id] = FakeSnapshot(cpu_usage_percent=91.0)
    await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.THRESHOLD,
            target_component=None,
            condition_config={
                "metric": "cpu_usage_percent",
                "operator": "gte",
                "value": 75,
            },
        )
    )

    result = await service.evaluate_alert_rules()

    assert len(result.triggered) == 1
    assert result.skipped_rules == 0


async def test_one_rule_raising_never_costs_the_others():
    """Isolation is not specific to malformed config. Anything a single
    rule's evaluation can raise -- a repository hiccup, a collaborator
    returning something unexpected -- must cost that rule and nothing
    else. Same discipline ``RouterService.sweep_stale_heartbeats``
    documents for its own per-router loop."""
    repo = FakeRepository()
    service = AlertService(repo)
    exploding = await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.HEALTH_STATUS_CHANGE,
            target_component="database",
            condition_config={"expected_status": "unhealthy"},
        )
    )
    healthy_rule = await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.HEALTH_STATUS_CHANGE,
            target_component="redis",
            condition_config={"expected_status": "unhealthy"},
        )
    )
    for component in ("database", "redis"):
        repo.service_health_rows[component] = ServiceHealth(
            **_base_fields(
                component=component,
                status="unhealthy",
                last_checked_at=_now(),
                consecutive_failure_count=1,
            )
        )

    original = repo.get_service_health

    async def exploding_lookup(component: str):
        if component == "database":
            raise RuntimeError("connection reset")
        return await original(component)

    repo.get_service_health = exploding_lookup

    result = await service.evaluate_alert_rules()

    assert result.skipped_rules == 1
    assert [alert.rule_id for alert in result.triggered] == [healthy_rule.id]
    assert exploding.id not in {alert.rule_id for alert in result.triggered}


async def test_one_broken_channel_does_not_stop_the_others():
    """A rule fanning out to several channels must reach the rest even if
    one of them blows up outside ``dispatch_notification``'s own
    never-raises guarantee -- an unknown ``channel_type``, say. Otherwise
    the exception climbs into the per-rule isolation above and takes the
    whole rule with it."""
    repo = FakeRepository()
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(200))
    ) as http_client:
        notification_service = NotificationService(repo, http_client)
        service = AlertService(repo, notification_service=notification_service)
        good = await notification_service.create_channel(
            organization_id=None,
            channel_type=NotificationChannelType.SLACK,
            name="Ops",
            config={"webhook_url": "https://hooks.example/abc"},
        )
        broken = await repo.create_notification_channel(
            organization_id=None,
            channel_type="carrier_pigeon",
            name="Nope",
            config_encrypted="{}",
            is_active=True,
        )
        rule = await repo.create_alert_rule(
            **_alert_rule_fields(
                trigger_type=AlertTriggerType.HEALTH_STATUS_CHANGE,
                target_component="database",
                condition_config={"expected_status": "unhealthy"},
            )
        )
        repo.rule_channels[rule.id] = [broken.id, good.id]
        repo.service_health_rows["database"] = ServiceHealth(
            **_base_fields(
                component="database",
                status="unhealthy",
                last_checked_at=_now(),
                consecutive_failure_count=1,
            )
        )

        result = await service.evaluate_alert_rules()

    assert len(result.triggered) == 1
    assert result.skipped_rules == 0
    assert [log.channel_id for log in repo.notification_logs] == [good.id]


# ============================================================================
# Alert Engine: the two-minute outage rule
# ============================================================================


def _unreachable_rule_fields(**overrides: object) -> dict[str, object]:
    return _alert_rule_fields(
        trigger_type=AlertTriggerType.HEALTH_STATUS_CHANGE,
        target_component=ALERT_TARGET_ROUTER_REACHABILITY,
        condition_config={"expected_status": "unreachable"},
        **overrides,
    )


async def test_a_router_going_down_raises_an_alert():
    """THE OTHER REGRESSION. Nothing on this platform raised an alert when
    a router went down.

    ``sweep_stale_heartbeats`` was the only writer of ONLINE -> OFFLINE and
    its own docstring called alerting "a future alert rule". On 2026-09-07
    it correctly marked a real router offline and notified nobody. This is
    that alert.
    """
    repo = FakeRepository()
    service = AlertService(repo)
    org_id = uuid.uuid4()
    router = FakeRouter(
        id=uuid.uuid4(),
        organization_id=org_id,
        location_id=uuid.uuid4(),
        name="Office Guest",
        health_status="healthy",
        reachability_state="unreachable",
    )
    repo.routers.append(router)
    rule = await repo.create_alert_rule(
        **_unreachable_rule_fields(organization_id=org_id)
    )

    result = await service.evaluate_alert_rules()

    assert len(result.triggered) == 1
    alert = result.triggered[0]
    assert alert.rule_id == rule.id
    assert alert.router_id == router.id
    assert alert.organization_id == org_id


async def test_the_outage_email_never_claims_the_isp_is_down():
    """THE COPY CONSTRAINT, as an assertion.

    Outage #1 on 2026-09-07 was a router reboot -- the device's own log
    shows a cold boot with NTP correcting the clock -- while the ISP was
    perfectly healthy. From the cloud it looked identical to an uplink
    failure. An email saying "your ISP is down" would have been
    checkably wrong and would have sent the owner to argue with their
    provider about an outage the provider did not cause.

    So the trigger copy may say what was observed and must not name a
    cause it cannot know.
    """
    repo = FakeRepository()
    service = AlertService(repo)
    org_id = uuid.uuid4()
    router = FakeRouter(
        id=uuid.uuid4(),
        organization_id=org_id,
        location_id=uuid.uuid4(),
        name="Office Guest",
        health_status="healthy",
        reachability_state="unreachable",
    )
    repo.routers.append(router)
    await repo.create_alert_rule(**_unreachable_rule_fields(organization_id=org_id))

    result = await service.evaluate_alert_rules()
    message = result.triggered[0].message.lower()

    assert "office guest" in message
    assert "stopped responding" in message
    assert "isp" not in message, (
        "the platform only knows it stopped hearing from the site"
    )
    assert "can't tell" in message, "the uncertainty has to be stated, not implied"


async def test_the_alert_resolves_and_says_it_stayed_up():
    repo = FakeRepository()
    service = AlertService(repo)
    org_id = uuid.uuid4()
    router = FakeRouter(
        id=uuid.uuid4(),
        organization_id=org_id,
        location_id=uuid.uuid4(),
        name="Office Guest",
        health_status="healthy",
        reachability_state="unreachable",
    )
    repo.routers.append(router)
    await repo.create_alert_rule(**_unreachable_rule_fields(organization_id=org_id))

    await service.evaluate_alert_rules()
    router.reachability_state = "reachable"
    result = await service.evaluate_alert_rules()

    assert len(result.resolved) == 1
    assert result.resolved[0].status == AlertStatus.RESOLVED.value
    assert "back online" in result.resolved[0].message.lower()


async def test_a_router_the_sweep_cannot_judge_never_alerts():
    """NULL and "unknown" both mean "we have never been able to tell" -- a
    freshly enrolled device, one mid-provisioning, one whose agent
    credential expired. Alerting on an unanswered question is exactly what
    the rogue-DHCP guard already refuses to do."""
    repo = FakeRepository()
    service = AlertService(repo)
    org_id = uuid.uuid4()
    for state in (None, "unknown"):
        router = FakeRouter(
            id=uuid.uuid4(),
            organization_id=org_id,
            location_id=uuid.uuid4(),
            name="Never seen",
            health_status=None,
            reachability_state=state,
        )
        repo.routers.append(router)
    await repo.create_alert_rule(**_unreachable_rule_fields(organization_id=org_id))

    result = await service.evaluate_alert_rules()

    assert result.triggered == []


async def test_a_reachability_rule_may_only_watch_for_unreachable():
    with pytest.raises(InvalidAlertRuleConfigError):
        validate_alert_rule_condition_config(
            AlertTriggerType.HEALTH_STATUS_CHANGE,
            ALERT_TARGET_ROUTER_REACHABILITY,
            {"expected_status": "reachable"},
        )
    with pytest.raises(InvalidAlertRuleConfigError):
        validate_alert_rule_condition_config(
            AlertTriggerType.HEALTH_STATUS_CHANGE,
            ALERT_TARGET_ROUTER_REACHABILITY,
            {"expected_status": "unknown"},
        )


# ============================================================================
# Default alerting: a venue that never opened the alerts screen
# ============================================================================


async def _ensure_defaults(repo: FakeRepository, org_id, contact_email):
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(200))
    ) as http_client:
        notification_service = NotificationService(repo, http_client)
        alert_service = AlertService(repo, notification_service=notification_service)
        return await ensure_default_alerting(
            alert_service,
            notification_service,
            organization_id=org_id,
            contact_email=contact_email,
        )


async def test_a_new_organization_can_actually_be_emailed():
    """THE THIRD REGRESSION.

    Default rules already existed. What did not exist was anywhere for them
    to send. A rule with no row in ``alert_rule_notification_channels``
    reaches ``_dispatch_for_alert`` and returns -- the ``Alert`` appears on
    the dashboard and no mail is sent. On 2026-09-07 the platform's one real
    organization had zero rules AND no channel of its own, so even a working
    evaluator would have emailed nobody.

    ``notifiable`` is the whole assertion: rules AND a channel AND the link.
    """
    repo = FakeRepository()
    org_id = uuid.uuid4()

    report = await _ensure_defaults(repo, org_id, "owner@venue.example")

    assert report.notifiable
    assert report.channel_created
    reachability_rules = [
        rule
        for rule in repo.alert_rules.values()
        if rule.target_component == ALERT_TARGET_ROUTER_REACHABILITY
    ]
    assert len(reachability_rules) == 1
    linked = repo.rule_channels[reachability_rules[0].id]
    assert len(linked) == 1
    channel = repo.notification_channels[linked[0]]
    assert channel.channel_type == NotificationChannelType.EMAIL.value
    assert json.loads(decrypt_secret(channel.config_encrypted)) == {
        "email": "owner@venue.example"
    }


async def test_running_the_backfill_twice_changes_nothing():
    """The backfill script runs against live customer data, so a second run
    -- or a re-run after an interruption -- must be a no-op rather than a
    duplicate set of rules and a second channel."""
    repo = FakeRepository()
    org_id = uuid.uuid4()

    first = await _ensure_defaults(repo, org_id, "owner@venue.example")
    rules_after_first = dict(repo.alert_rules)
    channels_after_first = dict(repo.notification_channels)

    second = await _ensure_defaults(repo, org_id, "owner@venue.example")

    assert first.rules_created and not second.rules_created
    assert second.channel_already_present
    assert set(repo.alert_rules) == set(rules_after_first)
    assert set(repo.notification_channels) == set(channels_after_first)


async def test_an_organization_with_no_contact_email_is_reported_not_silent():
    """It still gets its rules, but "this venue cannot be emailed" has to be
    a visible outcome rather than a half-configured organization nobody
    notices until the night it matters."""
    repo = FakeRepository()

    report = await _ensure_defaults(repo, uuid.uuid4(), None)

    assert report.rules_created
    assert not report.notifiable
    assert report.channel_skipped_reason


async def test_the_backfill_never_argues_with_a_rule_somebody_changed():
    """An operator who retuned, renamed or switched off a default meant to.
    Idempotency here means "fill in what is missing", never "restore what I
    think it should be"."""
    repo = FakeRepository()
    org_id = uuid.uuid4()
    await _ensure_defaults(repo, org_id, "owner@venue.example")
    existing = next(
        rule
        for rule in repo.alert_rules.values()
        if rule.target_component == ALERT_TARGET_ROUTER_REACHABILITY
    )
    existing.is_active = False
    existing.severity = AlertSeverity.INFO.value

    await _ensure_defaults(repo, org_id, "owner@venue.example")

    assert existing.is_active is False
    assert existing.severity == AlertSeverity.INFO.value


async def test_every_default_rule_survives_the_real_validator():
    """Each default goes through ``AlertService.create_alert_rule``, which
    runs ``validate_alert_rule_condition_config`` -- so a default whose
    config the validator would reject fails here, loudly, rather than
    logging ``default_alert_rule_creation_failed`` in production and
    leaving a new customer with one fewer rule than they think they have.
    """
    repo = FakeRepository()

    report = await _ensure_defaults(repo, uuid.uuid4(), "owner@venue.example")

    assert report.rules_failed == []
    assert len(report.rules_created) == len(DEFAULT_ALERT_RULES)


# ============================================================================
# A bad mail setting must not take down alerting for every other channel
# ============================================================================


def test_a_broken_smtp_setting_no_longer_kills_the_whole_sweep():
    """``get_configured_email_provider`` raises at SERVICE-CONSTRUCTION
    time when ``email_delivery_provider`` is ``smtp``/``ses`` and the
    matching settings are incomplete -- most easily by leaving
    ``smtp_from_address`` at its ``noreply@cloudguest.local`` default while
    authenticating as a real mailbox, which ``SmtpIdentity`` refuses.

    It was called eagerly in two places. In
    ``_run_alert_rule_evaluation_sweep_async`` it built the service graph
    before a single rule was evaluated, so ONE wrong mail setting took down
    alert evaluation for every channel type on the platform -- Slack,
    webhooks and SMS included, none of which involve email at all. In
    ``dependencies.get_notification_service`` it is a FastAPI dependency, so
    the same setting 500'd every monitoring endpoint that touches it,
    including the alerts screen an operator would open to find out why they
    were not being alerted. Both now go through the same resolver.
    """
    from app.core.config import Settings
    from app.domains.monitoring.email_provider import resolve_email_provider

    settings = Settings(
        email_delivery_provider="smtp",
        smtp_host="smtp.zoho.in",
        smtp_username="alerts@example.com",
        smtp_password="hunter2",
        # The default, and a different mailbox from the username -- the
        # exact misconfiguration SmtpIdentity refuses.
        smtp_from_address="noreply@cloudguest.local",
    )

    provider = resolve_email_provider(settings)

    assert provider is not None, "constructing the service must still succeed"


async def test_an_unconfigured_mailbox_fails_loudly_rather_than_reporting_success():
    """And it must NOT degrade to ``LoggingEmailProvider``.

    That provider returns success, so ``dispatch_notification`` writes
    ``notification_logs.status = 'sent'`` with ``response_summary`` reading
    "queued to ... via EmailProviderProtocol" for a mail that was never
    sent -- indistinguishable from a real delivery in both the database and
    the API, and the single most dangerous failure mode on this path.

    The misconfiguration is carried to the point of use instead, so the
    operator finds the original config error in a FAILED row, which is
    exactly where they will look for it.
    """
    from app.domains.monitoring.email_provider import UnconfiguredEmailProvider

    provider = UnconfiguredEmailProvider("smtp_from_address does not match")
    with pytest.raises(NotificationDeliveryError) as exc_info:
        await provider.send("owner@venue.example", "subject", "body")

    assert "smtp_from_address does not match" in str(exc_info.value)
