"""Alerting for network-controller (TP-Link Omada) integrations.

Before these targets existed, an Omada venue whose controller the platform
could no longer reach -- which means no new guest there can get online --
surfaced only as a badge on an integration page. ``app.domains.monitoring``
had no reference to ``network_integration`` at all, and the router rules
deliberately skip the controller's synthetic fleet row.

Same conventions as ``test_monitoring_alerts.py``, whose ``FakeRepository``
this reuses: in-memory fakes, no Postgres. The one piece of SQL that matters
-- the grouped authorization count -- is checked by compiling the statement
the real repository builds.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy.dialects import postgresql

from app.domains.monitoring.constants import (
    ALERT_TARGET_NETWORK_CONTROLLER,
    ALERT_TARGET_NETWORK_CONTROLLER_AUTHORIZE,
    ALERT_TARGET_NETWORK_CONTROLLER_SETUP,
    NETWORK_CONTROLLER_FAILING_MIN_CONSECUTIVE_FAILURES,
    NETWORK_CONTROLLER_SETUP_GRACE_HOURS,
    NETWORK_CONTROLLER_STATE_FAILING,
    NETWORK_CONTROLLER_STATE_REFUSING_GUESTS,
    NETWORK_CONTROLLER_STATE_SETUP_INCOMPLETE,
    NETWORK_CONTROLLER_TARGET_STATES,
    AlertSeverity,
    AlertStatus,
    AlertTriggerType,
)
from app.domains.monitoring.default_alerting import DEFAULT_ALERT_RULES
from app.domains.monitoring.exceptions import InvalidAlertRuleConfigError
from app.domains.monitoring.repository import (
    AuthorizationOutcomeCounts,
    MonitoringRepository,
)
from app.domains.monitoring.service import AlertService, network_controller_verdict
from app.domains.monitoring.validators import validate_alert_rule_condition_config
from app.domains.network_integration.constants import ErrorCode, IntegrationStatus
from tests.unit.test_monitoring_alerts import (
    FakeRepository,
    _alert_rule_fields,
    _ensure_defaults,
)


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass
class FakeIntegration:
    """Duck-typed ``NetworkIntegration`` -- only what the evaluator reads."""

    organization_id: uuid.UUID
    name: str = "Lobby Omada"
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    location_id: uuid.UUID | None = field(default_factory=uuid.uuid4)
    router_id: uuid.UUID | None = field(default_factory=uuid.uuid4)
    status: str = IntegrationStatus.CONNECTED.value
    is_enabled: bool = True
    is_deleted: bool = False
    provider_metadata: dict[str, Any] = field(default_factory=dict)
    last_error_code: str | None = None
    last_error_message: str | None = None
    created_at: datetime = field(default_factory=lambda: _now() - timedelta(days=7))

    def failing(self, status: IntegrationStatus, failures: int) -> None:
        self.status = status.value
        self.provider_metadata = {"consecutive_failure_count": failures}

    def recovered(self) -> None:
        self.status = IntegrationStatus.CONNECTED.value
        self.provider_metadata = {"consecutive_failure_count": 0}


async def _harness(
    target: str, org_id: uuid.UUID
) -> tuple[FakeRepository, AlertService]:
    repo = FakeRepository()
    await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.HEALTH_STATUS_CHANGE,
            target_component=target,
            condition_config={
                "expected_status": NETWORK_CONTROLLER_TARGET_STATES[target]
            },
            organization_id=org_id,
        )
    )
    return repo, AlertService(repo)


def _counts(
    integration: FakeIntegration, *, attempts: int, failed: int, guests: int
) -> AuthorizationOutcomeCounts:
    return AuthorizationOutcomeCounts(
        integration_id=integration.id,
        attempts=attempts,
        failed_attempts=failed,
        failed_guests=guests,
    )


# ============================================================================
# Validator
# ============================================================================


@pytest.mark.parametrize(
    ("target", "state"),
    [
        (ALERT_TARGET_NETWORK_CONTROLLER, NETWORK_CONTROLLER_STATE_FAILING),
        (
            ALERT_TARGET_NETWORK_CONTROLLER_AUTHORIZE,
            NETWORK_CONTROLLER_STATE_REFUSING_GUESTS,
        ),
        (
            ALERT_TARGET_NETWORK_CONTROLLER_SETUP,
            NETWORK_CONTROLLER_STATE_SETUP_INCOMPLETE,
        ),
    ],
)
def test_each_target_accepts_only_its_own_state(target: str, state: str) -> None:
    validate_alert_rule_condition_config(
        AlertTriggerType.HEALTH_STATUS_CHANGE, target, {"expected_status": state}
    )
    for other in ("healthy", "unknown", "connected"):
        with pytest.raises(InvalidAlertRuleConfigError):
            validate_alert_rule_condition_config(
                AlertTriggerType.HEALTH_STATUS_CHANGE,
                target,
                {"expected_status": other},
            )


# ============================================================================
# Controller failing
# ============================================================================


async def test_a_blip_does_not_page_anybody() -> None:
    """One or two failed syncs is a controller reboot or an upgrade. The
    alert waits for the third -- about half an hour at the default interval
    once the backoff is counted."""
    org_id = uuid.uuid4()
    repo, service = await _harness(ALERT_TARGET_NETWORK_CONTROLLER, org_id)
    integration = FakeIntegration(organization_id=org_id)
    integration.failing(
        IntegrationStatus.CONNECTION_FAILED,
        NETWORK_CONTROLLER_FAILING_MIN_CONSECUTIVE_FAILURES - 1,
    )
    repo.network_integrations.append(integration)

    assert (await service.evaluate_alert_rules()).triggered == []


async def test_an_unreachable_controller_alerts_once_and_resolves_on_recovery() -> None:
    org_id = uuid.uuid4()
    repo, service = await _harness(ALERT_TARGET_NETWORK_CONTROLLER, org_id)
    integration = FakeIntegration(organization_id=org_id)
    integration.failing(
        IntegrationStatus.CONNECTION_FAILED,
        NETWORK_CONTROLLER_FAILING_MIN_CONSECUTIVE_FAILURES,
    )
    repo.network_integrations.append(integration)

    first = await service.evaluate_alert_rules()

    assert len(first.triggered) == 1
    alert = first.triggered[0]
    assert alert.router_id == integration.router_id
    assert alert.location_id == integration.location_id
    assert alert.severity == AlertSeverity.CRITICAL.value
    assert "Lobby Omada" in alert.message
    assert "cannot reach" in alert.message
    assert "cannot get online" in alert.message

    # Still down, still one alert.
    assert (await service.evaluate_alert_rules()).triggered == []

    integration.recovered()
    second = await service.evaluate_alert_rules()

    assert [a.id for a in second.resolved] == [alert.id]
    assert alert.status == AlertStatus.RESOLVED.value
    assert "answering normally again" in alert.message


async def test_rejected_credentials_say_so() -> None:
    """An auth failure needs someone with the controller's password; a
    connection failure needs someone to look at the network. The email has
    to send them to the right one."""
    org_id = uuid.uuid4()
    repo, service = await _harness(ALERT_TARGET_NETWORK_CONTROLLER, org_id)
    integration = FakeIntegration(organization_id=org_id)
    integration.failing(IntegrationStatus.AUTH_FAILED, 5)
    repo.network_integrations.append(integration)

    (alert,) = (await service.evaluate_alert_rules()).triggered

    assert "rejecting the saved login" in alert.message
    assert "5 checks in a row" in alert.message


async def test_failing_below_the_bar_neither_opens_nor_closes() -> None:
    """The counter is only reset by a successful sync, so "failing, but
    under three" after an alert fired means a manual attempt reset nothing
    -- it is not a recovery, and must not send one."""
    org_id = uuid.uuid4()
    repo, service = await _harness(ALERT_TARGET_NETWORK_CONTROLLER, org_id)
    integration = FakeIntegration(organization_id=org_id)
    integration.failing(IntegrationStatus.CONNECTION_FAILED, 4)
    repo.network_integrations.append(integration)
    (alert,) = (await service.evaluate_alert_rules()).triggered

    integration.failing(IntegrationStatus.CONNECTION_FAILED, 1)
    result = await service.evaluate_alert_rules()

    assert result.resolved == []
    assert alert.status == AlertStatus.TRIGGERED.value


async def test_switching_an_integration_off_closes_its_alert_and_says_why() -> None:
    org_id = uuid.uuid4()
    repo, service = await _harness(ALERT_TARGET_NETWORK_CONTROLLER, org_id)
    integration = FakeIntegration(organization_id=org_id)
    integration.failing(IntegrationStatus.AUTH_FAILED, 3)
    repo.network_integrations.append(integration)
    (alert,) = (await service.evaluate_alert_rules()).triggered

    integration.is_enabled = False
    integration.status = IntegrationStatus.DISABLED.value
    result = await service.evaluate_alert_rules()

    assert [a.id for a in result.resolved] == [alert.id]
    assert "switched off" in alert.message


async def test_a_deleted_integration_does_not_leave_an_alert_open_forever() -> None:
    org_id = uuid.uuid4()
    repo, service = await _harness(ALERT_TARGET_NETWORK_CONTROLLER, org_id)
    integration = FakeIntegration(organization_id=org_id)
    integration.failing(IntegrationStatus.CONNECTION_FAILED, 3)
    repo.network_integrations.append(integration)
    (alert,) = (await service.evaluate_alert_rules()).triggered

    integration.is_deleted = True
    result = await service.evaluate_alert_rules()

    assert [a.id for a in result.resolved] == [alert.id]
    assert "removed" in alert.message


async def test_two_integrations_sharing_a_key_are_one_alert_naming_both() -> None:
    """``alerts`` has no integration column. Two self-service rows with no
    fleet device in one venue share a key, so they share an alert -- and it
    stays open until both have recovered."""
    org_id = uuid.uuid4()
    location_id = uuid.uuid4()
    repo, service = await _harness(ALERT_TARGET_NETWORK_CONTROLLER, org_id)
    first = FakeIntegration(
        organization_id=org_id, name="East wing", location_id=location_id,
        router_id=None,
    )
    second = FakeIntegration(
        organization_id=org_id, name="West wing", location_id=location_id,
        router_id=None,
    )
    first.failing(IntegrationStatus.CONNECTION_FAILED, 3)
    second.failing(IntegrationStatus.CONNECTION_FAILED, 3)
    repo.network_integrations.extend([first, second])

    (alert,) = (await service.evaluate_alert_rules()).triggered
    assert "East wing" in alert.message and "West wing" in alert.message

    first.recovered()
    assert (await service.evaluate_alert_rules()).resolved == []

    second.recovered()
    assert [a.id for a in (await service.evaluate_alert_rules()).resolved] == [
        alert.id
    ]


async def test_another_organizations_controller_is_not_this_rules_business() -> None:
    org_id = uuid.uuid4()
    repo, service = await _harness(ALERT_TARGET_NETWORK_CONTROLLER, org_id)
    stranger = FakeIntegration(organization_id=uuid.uuid4())
    stranger.failing(IntegrationStatus.CONNECTION_FAILED, 9)
    repo.network_integrations.append(stranger)

    assert (await service.evaluate_alert_rules()).triggered == []


# ============================================================================
# Setup never finished
# ============================================================================


async def test_setup_gets_a_day_before_anybody_is_told() -> None:
    org_id = uuid.uuid4()
    repo, service = await _harness(ALERT_TARGET_NETWORK_CONTROLLER_SETUP, org_id)
    integration = FakeIntegration(
        organization_id=org_id,
        status=IntegrationStatus.UNCONFIGURED.value,
        created_at=_now() - timedelta(hours=NETWORK_CONTROLLER_SETUP_GRACE_HOURS - 1),
    )
    repo.network_integrations.append(integration)

    assert (await service.evaluate_alert_rules()).triggered == []


async def test_abandoned_setup_alerts_with_the_readiness_reason() -> None:
    org_id = uuid.uuid4()
    repo, service = await _harness(ALERT_TARGET_NETWORK_CONTROLLER_SETUP, org_id)
    integration = FakeIntegration(
        organization_id=org_id,
        status=IntegrationStatus.UNCONFIGURED.value,
        created_at=_now() - timedelta(hours=NETWORK_CONTROLLER_SETUP_GRACE_HOURS + 1),
        last_error_code=ErrorCode.SETUP_INCOMPLETE.value,
        last_error_message="no controller site has been selected",
    )
    repo.network_integrations.append(integration)

    (alert,) = (await service.evaluate_alert_rules()).triggered
    assert "no controller site has been selected" in alert.message

    integration.status = IntegrationStatus.CONNECTED.value
    result = await service.evaluate_alert_rules()
    assert [a.id for a in result.resolved] == [alert.id]
    assert "setup is complete" in alert.message


async def test_setup_never_started_does_not_invent_a_reason() -> None:
    """With no credentials the sync never runs and writes nothing, so
    ``last_error_message`` is not a readiness sentence -- the copy must not
    borrow whatever is there."""
    org_id = uuid.uuid4()
    repo, service = await _harness(ALERT_TARGET_NETWORK_CONTROLLER_SETUP, org_id)
    integration = FakeIntegration(
        organization_id=org_id,
        status=IntegrationStatus.UNCONFIGURED.value,
        created_at=_now() - timedelta(days=3),
        last_error_code="SOMETHING_ELSE",
        last_error_message="stale text from another code path",
    )
    repo.network_integrations.append(integration)

    (alert,) = (await service.evaluate_alert_rules()).triggered
    assert "stale text" not in alert.message
    assert "has not completed a connection" in alert.message


# ============================================================================
# Refusing guests
# ============================================================================


async def test_one_unlucky_phone_is_not_a_venue_problem() -> None:
    """Retries leave several failed rows for one device; the threshold
    counts guests, not rows."""
    org_id = uuid.uuid4()
    repo, service = await _harness(ALERT_TARGET_NETWORK_CONTROLLER_AUTHORIZE, org_id)
    integration = FakeIntegration(organization_id=org_id)
    repo.network_integrations.append(integration)
    repo.authorization_counts.append(
        _counts(integration, attempts=8, failed=8, guests=1)
    )

    assert (await service.evaluate_alert_rules()).triggered == []


async def test_a_few_odd_devices_at_a_busy_venue_are_not_a_venue_problem() -> None:
    org_id = uuid.uuid4()
    repo, service = await _harness(ALERT_TARGET_NETWORK_CONTROLLER_AUTHORIZE, org_id)
    integration = FakeIntegration(organization_id=org_id)
    repo.network_integrations.append(integration)
    repo.authorization_counts.append(
        _counts(integration, attempts=40, failed=4, guests=4)
    )

    assert (await service.evaluate_alert_rules()).triggered == []


async def test_refusals_alert_and_only_a_clean_window_resolves() -> None:
    """Hysteresis: dropping back under the trigger is not a recovery, or a
    sustained problem hovering at the line would mail the venue every few
    minutes."""
    org_id = uuid.uuid4()
    repo, service = await _harness(ALERT_TARGET_NETWORK_CONTROLLER_AUTHORIZE, org_id)
    integration = FakeIntegration(organization_id=org_id)
    repo.network_integrations.append(integration)
    repo.authorization_counts.append(
        _counts(integration, attempts=6, failed=5, guests=4)
    )

    (alert,) = (await service.evaluate_alert_rules()).triggered
    assert "refused 4 guests" in alert.message
    assert "5 of 6 attempts" in alert.message

    repo.authorization_counts[:] = [
        _counts(integration, attempts=10, failed=1, guests=1)
    ]
    assert (await service.evaluate_alert_rules()).resolved == []

    repo.authorization_counts.clear()
    result = await service.evaluate_alert_rules()
    assert [a.id for a in result.resolved] == [alert.id]
    assert "no guest has been refused" in alert.message


def test_the_verdict_is_three_valued() -> None:
    """``None`` is load-bearing: it is how "not yet" and "not sure" stay
    distinct from "fine"."""
    now = _now()
    integration = FakeIntegration(organization_id=uuid.uuid4())
    integration.status = IntegrationStatus.CONNECTING.value
    assert network_controller_verdict(
        ALERT_TARGET_NETWORK_CONTROLLER, integration, now=now
    ) is None
    integration.status = IntegrationStatus.CONNECTED.value
    assert network_controller_verdict(
        ALERT_TARGET_NETWORK_CONTROLLER, integration, now=now
    ) is False


# ============================================================================
# Defaults, and a venue with no controller at all
# ============================================================================


def test_every_organization_gets_the_three_controller_defaults() -> None:
    by_target = {rule["target_component"]: rule for rule in DEFAULT_ALERT_RULES}
    assert by_target[ALERT_TARGET_NETWORK_CONTROLLER]["severity"] == (
        AlertSeverity.CRITICAL.value
    )
    assert by_target[ALERT_TARGET_NETWORK_CONTROLLER_AUTHORIZE]["severity"] == (
        AlertSeverity.WARNING.value
    )
    assert by_target[ALERT_TARGET_NETWORK_CONTROLLER_SETUP]["severity"] == (
        AlertSeverity.WARNING.value
    )


async def test_a_mikrotik_only_organization_evaluates_its_defaults_cleanly() -> None:
    """Every organization now carries these rules. With no integrations
    they must evaluate to nothing -- not to a skipped rule, which is how a
    broken read would show up behind the per-rule isolation."""
    repo = FakeRepository()
    await _ensure_defaults(repo, uuid.uuid4(), "owner@venue.example")

    result = await AlertService(repo).evaluate_alert_rules()

    assert result.skipped_rules == 0
    assert result.triggered == []


# ============================================================================
# The grouped count, as the database will receive it
# ============================================================================


class _CapturingSession:
    def __init__(self) -> None:
        self.statements: list[object] = []

    async def execute(self, statement: object) -> object:
        self.statements.append(statement)

        class _Result:
            def all(self) -> list[object]:
                return []

        return _Result()


async def test_the_authorization_count_is_one_grouped_filtered_query() -> None:
    session = _CapturingSession()
    repo = MonitoringRepository(session)  # type: ignore[arg-type]
    org_id = uuid.uuid4()

    assert (
        await repo.count_authorization_outcomes_since(
            since=_now() - timedelta(minutes=15), organization_id=org_id
        )
        == []
    )

    (statement,) = session.statements
    sql = str(statement.compile(dialect=postgresql.dialect()))
    assert "GROUP BY network_integration_authorizations.integration_id" in sql
    assert "count(DISTINCT network_integration_authorizations.guest_session_id)" in sql
    assert "FILTER (WHERE network_integration_authorizations.status" in sql
    assert "network_integration_authorizations.created_at >=" in sql
    assert "network_integration_authorizations.organization_id =" in sql
