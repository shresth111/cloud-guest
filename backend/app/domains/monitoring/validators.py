"""Pure, side-effect-free validation for the Monitoring domain.

Mirrors ``app.domains.guest.validators``/``app.domains.wireguard
.validators``'s identical discipline: no I/O, just "is this a legal input"
checks (or, for ``classify_storage_health``, a pure classification
function) the service layer calls before/around touching the database or
filesystem.
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.domains.router.enums import RouterStatus
from app.domains.router.models import Router
from app.domains.router_provisioning.constants import (
    EnrollmentStatus,
    ProvisioningJobStatus,
)
from app.domains.router_provisioning.models import (
    ProvisioningJob,
    RouterEnrollmentRequest,
)

from .constants import (
    ALERT_STATUS_TRANSITIONS,
    ALERT_TARGET_ROUTER,
    INCIDENT_STATUS_TRANSITIONS,
    ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES,
    ROUTER_HEARTBEAT_WARNING_STALE_MINUTES,
    STORAGE_DEGRADED_USED_PERCENT,
    STORAGE_UNHEALTHY_USED_PERCENT,
    AlertStatus,
    AlertTriggerType,
    HealthComponent,
    HealthStatus,
    IncidentStatus,
    NotificationChannelType,
    RouterLifecycleStage,
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


# ============================================================================
# ZTP Monitoring Dashboard -- router lifecycle stage (BE-011 Part 3)
# ============================================================================


def _heartbeat_staleness_minutes(
    last_seen_at: datetime | None, moment: datetime
) -> float | None:
    """Minutes since ``last_seen_at``, or ``None`` if a router has never
    once checked in (``last_seen_at IS NULL``) -- callers treat ``None`` the
    same as "maximally stale"."""
    if last_seen_at is None:
        return None
    return (moment - last_seen_at).total_seconds() / 60.0


def compute_lifecycle_stage(
    *,
    router: Router | None,
    enrollment: RouterEnrollmentRequest | None,
    latest_job: ProvisioningJob | None,
    now: datetime | None = None,
) -> RouterLifecycleStage:
    """Derives one of the module brief's 9 idealized ZTP lifecycle labels
    (:class:`~.constants.RouterLifecycleStage`) from three other domains'
    already-authoritative signals -- a pure, side-effect-free
    classification (mirrors ``classify_storage_health``'s identical
    "pure function the service layer calls" shape), never persisted (see
    ``RouterLifecycleStage``'s own docstring for why).

    ## Full mapping table

    Evaluated top-to-bottom; the first matching rule wins.

    1. No ``Router`` row yet, no ``RouterEnrollmentRequest`` either
       -> ``PENDING``.
    2. No ``Router`` row yet, enrollment ``status=PENDING`` -> ``PENDING``.
    3. No ``Router`` row yet, enrollment ``status=REJECTED`` -> ``FAILED``.
    4. No ``Router`` row yet, enrollment ``status=APPROVED`` (data anomaly:
       approved but the linked router is unresolvable) -> ``WARNING``.
    5. ``Router.status=SUSPENDED`` -> ``WARNING``.
    6. ``Router.status=PENDING_PROVISIONING``, no ``ProvisioningJob`` yet
       -> ``APPROVED``.
    7. ``Router.status=PENDING_PROVISIONING``, latest job
       ``QUEUED``/``RUNNING``/``SUCCEEDED`` -> ``CLAIMED``.
    8. ``Router.status=PENDING_PROVISIONING``, latest job ``FAILED``,
       ``attempts < max_attempts`` -> ``WARNING``.
    9. ``Router.status=PENDING_PROVISIONING``, latest job ``FAILED``,
       ``attempts >= max_attempts`` -> ``FAILED``.
    10. ``Router.status=PROVISIONING``, no job or latest job
        ``QUEUED``/``RUNNING`` -> ``PROVISIONING``.
    11. ``Router.status=PROVISIONING``, latest job ``SUCCEEDED``
        -> ``PROVISIONED``.
    12. ``Router.status=PROVISIONING``, latest job ``FAILED``,
        ``attempts < max_attempts`` -> ``WARNING``.
    13. ``Router.status=PROVISIONING``, latest job ``FAILED``,
        ``attempts >= max_attempts`` -> ``FAILED``.
    14. ``Router.status=OFFLINE`` -> ``OFFLINE``.
    15. ``Router.status=ONLINE``, heartbeat fresh (below
        ``ROUTER_HEARTBEAT_WARNING_STALE_MINUTES``) -> ``ONLINE``.
    16. ``Router.status=ONLINE``, heartbeat stale (at/above the warning
        threshold, below the offline threshold) -> ``WARNING``.
    17. ``Router.status=ONLINE``, heartbeat very stale (at/above
        ``ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES``) or ``last_seen_at IS
        NULL`` -> ``OFFLINE``.
    18. ``Router.status=DECOMMISSIONED`` (excluded from the active
        dashboard listing by the caller -- see
        ``service.ZtpMonitoringService.get_dashboard``; reachable here only
        defensively) -> ``WARNING``.

    ``CLAIMED`` (row 7) sits between ``APPROVED`` (nothing dispatched yet)
    and ``PROVISIONING`` (``Router.status`` itself has flipped, meaning the
    device already presented its provisioning token) -- it represents "an
    initial-config job has been queued/picked up for this router, but the
    device has not yet checked in with its provisioning token," the one
    genuinely distinct sub-phase this system's data can actually
    distinguish within the ``PENDING_PROVISIONING`` window.
    """
    moment = now or datetime.now(UTC)

    if router is None:
        if enrollment is None:
            return RouterLifecycleStage.PENDING
        if enrollment.status == EnrollmentStatus.REJECTED.value:
            return RouterLifecycleStage.FAILED
        if enrollment.status == EnrollmentStatus.APPROVED.value:
            # Data anomaly: approved but the linked router record could not
            # be resolved by the caller. Surfaced as WARNING (needs human
            # attention), never silently reported as a healthy stage.
            return RouterLifecycleStage.WARNING
        return RouterLifecycleStage.PENDING

    status = RouterStatus(router.status)

    if status == RouterStatus.SUSPENDED:
        return RouterLifecycleStage.WARNING

    if status == RouterStatus.PENDING_PROVISIONING:
        if latest_job is None:
            return RouterLifecycleStage.APPROVED
        job_status = ProvisioningJobStatus(latest_job.status)
        if job_status == ProvisioningJobStatus.FAILED:
            if latest_job.attempts >= latest_job.max_attempts:
                return RouterLifecycleStage.FAILED
            return RouterLifecycleStage.WARNING
        return RouterLifecycleStage.CLAIMED

    if status == RouterStatus.PROVISIONING:
        if latest_job is None:
            return RouterLifecycleStage.PROVISIONING
        job_status = ProvisioningJobStatus(latest_job.status)
        if job_status == ProvisioningJobStatus.SUCCEEDED:
            return RouterLifecycleStage.PROVISIONED
        if job_status == ProvisioningJobStatus.FAILED:
            if latest_job.attempts >= latest_job.max_attempts:
                return RouterLifecycleStage.FAILED
            return RouterLifecycleStage.WARNING
        return RouterLifecycleStage.PROVISIONING

    if status == RouterStatus.OFFLINE:
        return RouterLifecycleStage.OFFLINE

    if status == RouterStatus.ONLINE:
        staleness = _heartbeat_staleness_minutes(router.last_seen_at, moment)
        if staleness is None or staleness >= ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES:
            return RouterLifecycleStage.OFFLINE
        if staleness >= ROUTER_HEARTBEAT_WARNING_STALE_MINUTES:
            return RouterLifecycleStage.WARNING
        return RouterLifecycleStage.ONLINE

    # DECOMMISSIONED -- excluded from the active ZTP dashboard listing by the
    # caller (see service.ZtpMonitoringService.get_dashboard); reachable
    # only if a caller passes a decommissioned router directly.
    return RouterLifecycleStage.WARNING  # pragma: no cover -- defensive only


__all__ = [
    "validate_date_range",
    "classify_storage_health",
    "validate_alert_rule_condition_config",
    "validate_alert_status_transition",
    "compare_threshold",
    "validate_notification_channel_config",
    "validate_incident_status_transition",
    "validate_sla_target_config",
    "compute_lifecycle_stage",
]
