"""Pure, side-effect-free validation for the Monitoring domain.

Mirrors ``app.domains.guest.validators``/``app.domains.wireguard
.validators``'s identical discipline: no I/O, just "is this a legal input"
checks (or, for ``classify_storage_health``, a pure classification
function) the service layer calls before/around touching the database or
filesystem.
"""

from __future__ import annotations

from datetime import datetime

from .constants import (
    ALERT_STATUS_TRANSITIONS,
    ALERT_TARGET_ROUTER,
    INCIDENT_STATUS_TRANSITIONS,
    STORAGE_DEGRADED_USED_PERCENT,
    STORAGE_UNHEALTHY_USED_PERCENT,
    AlertStatus,
    AlertTriggerType,
    HealthComponent,
    HealthStatus,
    IncidentStatus,
    NotificationChannelType,
    ThresholdMetric,
    ThresholdOperator,
)
from .exceptions import (
    InvalidAlertRuleConfigError,
    InvalidAlertStatusTransitionError,
    InvalidEventDateRangeError,
    InvalidIncidentStatusTransitionError,
    InvalidNotificationChannelConfigError,
    InvalidSlaTargetConfigError,
)


def validate_date_range(start: datetime | None, end: datetime | None) -> None:
    """Raises ``InvalidEventDateRangeError`` if both bounds are supplied and
    ``start`` is after ``end`` -- a no-op (no error) if either bound is
    absent, since an open-ended range is always legal."""
    if start is not None and end is not None and start > end:
        raise InvalidEventDateRangeError()


def classify_storage_health(*, percent_used: float, writable: bool) -> HealthStatus:
    """Pure percent-used/writability -> ``HealthStatus`` classification for
    ``service.MonitoringService.check_storage_health`` -- kept separate from
    the ``shutil.disk_usage``/``os.access`` I/O itself so the threshold
    logic can be tested deterministically without depending on the actual
    disk the test happens to run on (see ``tests/unit/test_monitoring.py``).

    An unwritable log directory is always ``UNHEALTHY`` regardless of free
    space -- a full disk and a permissions problem both mean the same thing
    in practice (structured logging can no longer be written), so there is
    no useful ``DEGRADED`` distinction to draw for the not-writable case."""
    if not writable:
        return HealthStatus.UNHEALTHY
    if percent_used >= STORAGE_UNHEALTHY_USED_PERCENT:
        return HealthStatus.UNHEALTHY
    if percent_used >= STORAGE_DEGRADED_USED_PERCENT:
        return HealthStatus.DEGRADED
    return HealthStatus.HEALTHY


# ============================================================================
# Alert Engine
# ============================================================================


def validate_alert_rule_condition_config(
    trigger_type: AlertTriggerType,
    target_component: str | None,
    condition_config: dict[str, object],
) -> None:
    """Raises ``InvalidAlertRuleConfigError`` unless ``target_component``/
    ``condition_config`` match the shape documented on
    ``constants.AlertTriggerType`` for ``trigger_type``."""
    if trigger_type == AlertTriggerType.HEALTH_STATUS_CHANGE:
        if not target_component:
            raise InvalidAlertRuleConfigError(
                "health_status_change rules require target_component "
                "(a HealthComponent value or 'router')"
            )
        valid_components = {c.value for c in HealthComponent} | {ALERT_TARGET_ROUTER}
        if target_component not in valid_components:
            raise InvalidAlertRuleConfigError(
                f"target_component '{target_component}' is not a known "
                "HealthComponent value or 'router'"
            )
        expected_status = condition_config.get("expected_status")
        if not isinstance(expected_status, str) or not expected_status:
            raise InvalidAlertRuleConfigError(
                "condition_config.expected_status is required for "
                "health_status_change rules"
            )
    elif trigger_type == AlertTriggerType.THRESHOLD:
        if target_component:
            raise InvalidAlertRuleConfigError(
                "threshold rules must not set target_component -- they "
                "evaluate every router in the rule's organization scope"
            )
        metric = condition_config.get("metric")
        if metric not in {m.value for m in ThresholdMetric}:
            raise InvalidAlertRuleConfigError(
                f"condition_config.metric '{metric}' is not one of "
                f"{[m.value for m in ThresholdMetric]}"
            )
        operator = condition_config.get("operator")
        if operator not in {o.value for o in ThresholdOperator}:
            raise InvalidAlertRuleConfigError(
                f"condition_config.operator '{operator}' is not one of "
                f"{[o.value for o in ThresholdOperator]}"
            )
        value = condition_config.get("value")
        if not isinstance(value, int | float) or isinstance(value, bool):
            raise InvalidAlertRuleConfigError(
                "condition_config.value must be a number for threshold rules"
            )
    elif trigger_type == AlertTriggerType.EVENT_OCCURRED:
        event_type = condition_config.get("event_type")
        if not isinstance(event_type, str) or not event_type:
            raise InvalidAlertRuleConfigError(
                "condition_config.event_type is required for " "event_occurred rules"
            )
    else:  # pragma: no cover -- unreachable, trigger_type is a closed enum
        raise InvalidAlertRuleConfigError(f"Unknown trigger_type '{trigger_type}'")


def validate_alert_status_transition(current: AlertStatus, new: AlertStatus) -> None:
    if new not in ALERT_STATUS_TRANSITIONS.get(current, frozenset()):
        raise InvalidAlertStatusTransitionError(current.value, new.value)


def compare_threshold(
    value: float, operator: ThresholdOperator, threshold: float
) -> bool:
    """Pure metric-vs-threshold comparison used by
    ``service.AlertService._evaluate_threshold_rule``."""
    if operator == ThresholdOperator.GT:
        return value > threshold
    if operator == ThresholdOperator.GTE:
        return value >= threshold
    if operator == ThresholdOperator.LT:
        return value < threshold
    if operator == ThresholdOperator.LTE:
        return value <= threshold
    return value == threshold  # ThresholdOperator.EQ


# ============================================================================
# Notification Engine
# ============================================================================


def validate_notification_channel_config(
    channel_type: NotificationChannelType, config: dict[str, object]
) -> None:
    """Raises ``InvalidNotificationChannelConfigError`` unless ``config``
    matches the required schema for ``channel_type`` -- see
    ``docs/monitoring/FLOW.md`` for the full per-type schema table."""
    if channel_type == NotificationChannelType.EMAIL:
        email = config.get("email")
        if not isinstance(email, str) or "@" not in email:
            raise InvalidNotificationChannelConfigError(
                "email channel config requires a valid 'email' address"
            )
    elif channel_type in (
        NotificationChannelType.SMS,
        NotificationChannelType.WHATSAPP,
    ):
        phone_number = config.get("phone_number")
        if not isinstance(phone_number, str) or not phone_number:
            raise InvalidNotificationChannelConfigError(
                f"{channel_type.value} channel config requires a " "'phone_number'"
            )
    elif channel_type in (
        NotificationChannelType.SLACK,
        NotificationChannelType.TEAMS,
        NotificationChannelType.DISCORD,
    ):
        webhook_url = config.get("webhook_url")
        if not isinstance(webhook_url, str) or not webhook_url.startswith("https://"):
            raise InvalidNotificationChannelConfigError(
                f"{channel_type.value} channel config requires a "
                "'webhook_url' starting with https://"
            )
    elif channel_type == NotificationChannelType.WEBHOOK:
        url = config.get("url")
        if not isinstance(url, str) or not url.startswith(("https://", "http://")):
            raise InvalidNotificationChannelConfigError(
                "webhook channel config requires a 'url' starting with "
                "http:// or https://"
            )
        auth_header_name = config.get("auth_header_name")
        auth_header_value = config.get("auth_header_value")
        if (auth_header_name is None) != (auth_header_value is None):
            raise InvalidNotificationChannelConfigError(
                "webhook channel config's auth_header_name/auth_header_value "
                "must both be set or both be absent"
            )
    else:  # pragma: no cover -- unreachable, channel_type is a closed enum
        raise InvalidNotificationChannelConfigError(
            f"Unknown channel_type '{channel_type}'"
        )


# ============================================================================
# Incident Engine
# ============================================================================


def validate_incident_status_transition(
    current: IncidentStatus, new: IncidentStatus
) -> None:
    if new not in INCIDENT_STATUS_TRANSITIONS.get(current, frozenset()):
        raise InvalidIncidentStatusTransitionError(current.value, new.value)


# ============================================================================
# SLA Monitoring
# ============================================================================


def validate_sla_target_config(
    *, target_percentage: float, measurement_window_days: int
) -> None:
    if not (0 < target_percentage <= 100):
        raise InvalidSlaTargetConfigError(
            "target_percentage must be greater than 0 and at most 100"
        )
    if measurement_window_days <= 0:
        raise InvalidSlaTargetConfigError(
            "measurement_window_days must be a positive integer"
        )


__all__ = [
    "validate_date_range",
    "classify_storage_health",
    "validate_alert_rule_condition_config",
    "validate_alert_status_transition",
    "compare_threshold",
    "validate_notification_channel_config",
    "validate_incident_status_transition",
    "validate_sla_target_config",
]
