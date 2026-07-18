"""Monitoring domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like every
other domain's exception hierarchy -- no route needs its own try/except
translation.

Deliberately small: this module's health checks are designed to *catch*
their own failures and report them as an honest ``HealthStatus.UNHEALTHY``/
``UNKNOWN`` result (see ``service.py``), not raise -- a failing dependency
(Postgres down, Redis down) is exactly the condition this module exists to
observe and record, not to crash on. The only real exception surface is
input validation (an invalid event-timeline date range).
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

__all__ = [
    "MonitoringError",
    "InvalidEventDateRangeError",
    "AlertRuleNotFoundError",
    "InvalidAlertRuleConfigError",
    "AlertNotFoundError",
    "InvalidAlertStatusTransitionError",
    "NotificationChannelNotFoundError",
    "InvalidNotificationChannelConfigError",
    "IncidentNotFoundError",
    "InvalidIncidentStatusTransitionError",
    "SlaTargetNotFoundError",
    "InvalidSlaTargetConfigError",
    "InsufficientSlaDataError",
]


class MonitoringError(CloudGuestError):
    """Base exception for Monitoring domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class InvalidEventDateRangeError(MonitoringError):
    """Raised by ``MonitoringService.get_event_timeline`` when both
    ``start``/``end`` are supplied and ``start`` is after ``end`` -- mirrors
    ``app.domains.guest.exceptions.InvalidAnalyticsDateRangeError``'s
    identical validation."""

    def __init__(self) -> None:
        super().__init__(
            "start_date must be before or equal to end_date",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


# ============================================================================
# Alert Engine (BE-011 Part 2)
# ============================================================================


class AlertRuleNotFoundError(MonitoringError):
    def __init__(self, rule_id: uuid.UUID) -> None:
        super().__init__(
            f"Alert rule not found: {rule_id}", status_code=status.HTTP_404_NOT_FOUND
        )


class InvalidAlertRuleConfigError(MonitoringError):
    """Raised by ``validators.validate_alert_rule_condition_config`` when a
    rule's ``trigger_type``/``target_component``/``condition_config``
    combination does not match one of the three documented shapes (see
    ``constants.AlertTriggerType``'s docstring)."""

    def __init__(self, reason: str) -> None:
        super().__init__(
            f"Invalid alert rule configuration: {reason}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class AlertNotFoundError(MonitoringError):
    def __init__(self, alert_id: uuid.UUID) -> None:
        super().__init__(
            f"Alert not found: {alert_id}", status_code=status.HTTP_404_NOT_FOUND
        )


class InvalidAlertStatusTransitionError(MonitoringError):
    def __init__(self, current: str, new: str) -> None:
        super().__init__(
            f"Cannot transition alert from '{current}' to '{new}'",
            status_code=status.HTTP_409_CONFLICT,
        )


# ============================================================================
# Notification Engine (BE-011 Part 2)
# ============================================================================


class NotificationChannelNotFoundError(MonitoringError):
    def __init__(self, channel_id: uuid.UUID) -> None:
        super().__init__(
            f"Notification channel not found: {channel_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class InvalidNotificationChannelConfigError(MonitoringError):
    """Raised by ``validators.validate_notification_channel_config`` when a
    channel's ``config`` does not match the required per-``channel_type``
    schema (see ``docs/monitoring/FLOW.md`` for the exact schema table)."""

    def __init__(self, reason: str) -> None:
        super().__init__(
            f"Invalid notification channel configuration: {reason}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


# ============================================================================
# Incident Engine (BE-011 Part 2)
# ============================================================================


class IncidentNotFoundError(MonitoringError):
    def __init__(self, incident_id: uuid.UUID) -> None:
        super().__init__(
            f"Incident not found: {incident_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class InvalidIncidentStatusTransitionError(MonitoringError):
    def __init__(self, current: str, new: str) -> None:
        super().__init__(
            f"Cannot transition incident from '{current}' to '{new}'",
            status_code=status.HTTP_409_CONFLICT,
        )


# ============================================================================
# SLA Monitoring (BE-011 Part 2)
# ============================================================================


class SlaTargetNotFoundError(MonitoringError):
    def __init__(self, target_id: uuid.UUID) -> None:
        super().__init__(
            f"SLA target not found: {target_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class InvalidSlaTargetConfigError(MonitoringError):
    def __init__(self, reason: str) -> None:
        super().__init__(
            f"Invalid SLA target configuration: {reason}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class InsufficientSlaDataError(MonitoringError):
    """Raised by ``SlaService.generate_report`` when zero ``HealthCheck``
    rows exist for the target's component/window. Deliberately **not**
    silently reported as a fabricated 0% or 100% -- see
    ``SlaService.generate_report``'s docstring for the full "no fabricated
    data" reasoning this mirrors from Part 1's honest Celery/WebSocket
    ``UNKNOWN`` treatment."""

    def __init__(self, component: str | None) -> None:
        super().__init__(
            "No health check data is available for "
            f"component={component or 'overall'} in the requested window "
            "yet -- run health checks first",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
