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

import httpx
import pytest
from pydantic import ValidationError
from sqlalchemy.dialects import postgresql

from app.core.config import Settings
from app.domains.monitoring.constants import (
    ALERT_TARGET_NETWORK_CONTROLLER,
    ALERT_TARGET_NETWORK_CONTROLLER_AUTHORIZE,
    ALERT_TARGET_NETWORK_CONTROLLER_SETUP,
    ALERT_TARGET_ROUTER_REACHABILITY,
    NETWORK_CONTROLLER_FAILING_MIN_CONSECUTIVE_FAILURES,
    NETWORK_CONTROLLER_SETUP_GRACE_HOURS,
    NETWORK_CONTROLLER_STATE_FAILING,
    NETWORK_CONTROLLER_STATE_REFUSING_GUESTS,
    NETWORK_CONTROLLER_STATE_SETUP_INCOMPLETE,
    NETWORK_CONTROLLER_TARGET_STATES,
    AlertSeverity,
    AlertStatus,
    AlertTriggerType,
    NotificationChannelType,
)
from app.domains.monitoring.default_alerting import DEFAULT_ALERT_RULES
from app.domains.monitoring.exceptions import InvalidAlertRuleConfigError
from app.domains.monitoring.repository import (
    AuthorizationOutcomeCounts,
    MonitoringRepository,
)
from app.domains.monitoring.service import (
    AlertService,
    NotificationService,
    network_controller_verdict,
)
from app.domains.monitoring.validators import validate_alert_rule_condition_config
from app.domains.network_integration.constants import (
    ControllerAuthMode,
    ErrorCode,
    IntegrationStatus,
)
from tests.unit.test_monitoring_alerts import (
    FakeRepository,
    FakeRouter,
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
    # Read by the capability-boundary predicate. Defaults to the mode that
    # CAN read inventory, so every pre-existing test here keeps meaning
    # exactly what it meant.
    auth_mode: str = ControllerAuthMode.OPENAPI.value
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


async def test_a_hotspot_operator_venue_never_pages_anybody() -> None:
    """The defect this exists to stop. A `legacy` integration cannot read
    the controller's inventory -- that is CR-002, it is documented, it is
    chosen deliberately at onboarding, and below controller v5.13 it is the
    only mode there is. The sweep used to ask anyway, so the row sat in
    `sync_error` with a counter that only climbed, and this CRITICAL rule
    fired on the third failure and could never resolve: the venue and the
    platform inbox were paged for ever about a correctly-configured venue
    whose captive portal was working."""
    org_id = uuid.uuid4()
    repo, service = await _harness(ALERT_TARGET_NETWORK_CONTROLLER, org_id)
    integration = FakeIntegration(
        organization_id=org_id, auth_mode=ControllerAuthMode.LEGACY.value
    )
    integration.failing(IntegrationStatus.SYNC_ERROR, 6)
    integration.last_error_code = ErrorCode.API_UNSUPPORTED.value
    repo.network_integrations.append(integration)

    assert (await service.evaluate_alert_rules()).triggered == []


async def test_an_alert_already_open_on_one_resolves() -> None:
    """Rows are already carrying this state in production. They must be
    able to close on the next evaluation rather than wait for a sync --
    which is why the verdict is `False` and not `None`."""
    org_id = uuid.uuid4()
    repo, service = await _harness(ALERT_TARGET_NETWORK_CONTROLLER, org_id)
    integration = FakeIntegration(organization_id=org_id)
    integration.failing(IntegrationStatus.SYNC_ERROR, 6)
    repo.network_integrations.append(integration)
    (alert,) = (await service.evaluate_alert_rules()).triggered

    integration.auth_mode = ControllerAuthMode.LEGACY.value
    integration.last_error_code = ErrorCode.API_UNSUPPORTED.value
    result = await service.evaluate_alert_rules()

    assert [a.id for a in result.resolved] == [alert.id]


async def test_an_openapi_row_refused_the_same_way_still_pages() -> None:
    """On an Open API row the identical code means something is genuinely
    wrong -- the controller is below 5.13, or the app was revoked -- and
    somebody has to go and look."""
    org_id = uuid.uuid4()
    repo, service = await _harness(ALERT_TARGET_NETWORK_CONTROLLER, org_id)
    integration = FakeIntegration(organization_id=org_id)
    integration.failing(IntegrationStatus.SYNC_ERROR, 6)
    integration.last_error_code = ErrorCode.API_UNSUPPORTED.value
    repo.network_integrations.append(integration)

    assert len((await service.evaluate_alert_rules()).triggered) == 1


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


async def test_abandoned_setup_does_not_leak_controller_detail_to_the_venue() -> None:
    """The reason is deliberately NOT in the message, and that is the test.

    This asserted the opposite until the branch in
    ``monitoring/service.py`` stopped interpolating
    ``last_error_message``. Its own comment gives the reason: every other
    branch of that function is vendor-neutral and never quotes provider
    text, because the alert is delivered to a **venue owner** and the
    product decision is that a venue owner is not shown the controller.
    This branch pasted in ``describe_portal_readiness_gaps``, which names
    controller configuration field by field ("no controller site has been
    selected"), on the alert most likely to fire -- ``SETUP_INCOMPLETE`` is
    where a freshly onboarded integration sits.

    Rewritten rather than relaxed, and now stronger: it fails if that
    string ever comes back. The detail is not lost -- ``last_error_message``,
    ``last_error_code`` and ``portal_readiness_gaps`` are all on
    ``GET /platform/integrations/{id}``, and the alert names the
    integration, so an operator is one click from the specific reason.
    """
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
    assert "no controller site has been selected" not in alert.message
    assert "setup has not been completed" in alert.message

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
    # The copy this branch settled on. The load-bearing half of this test is
    # the line above -- that nothing from another code path is borrowed --
    # and it is unchanged.
    assert "setup has not been completed" in alert.message


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


# ============================================================================
# The platform team's copy (Settings.platform_alert_emails)
# ============================================================================


def test_the_setting_is_normalized_deduplicated_and_empty_by_default() -> None:
    assert Settings(platform_alert_emails="").platform_alert_email_list == ()
    settings = Settings(
        platform_alert_emails=(
            " Ops@WyFy.example , oncall@wyfy.example,,ops@wyfy.example "
        )
    )
    assert settings.platform_alert_email_list == (
        "ops@wyfy.example",
        "oncall@wyfy.example",
    )


def test_a_malformed_address_is_refused_by_name() -> None:
    with pytest.raises(ValidationError) as exc_info:
        Settings(platform_alert_emails="ops@wyfy.example,not-an-address")
    assert "not-an-address" in str(exc_info.value)


@dataclass
class CapturingEmailProvider:
    sent: list[tuple[str, str, str]] = field(default_factory=list)

    async def send(
        self, email: str, subject: str, body: str, *, attachment: object = None
    ) -> None:
        self.sent.append((email, subject, body))


async def _platform_harness(
    *,
    platform_emails: tuple[str, ...],
    org_email: str | None = "owner@venue.example",
    org_channel_active: bool = True,
    target: str = ALERT_TARGET_NETWORK_CONTROLLER,
) -> tuple[FakeRepository, AlertService, CapturingEmailProvider, FakeIntegration]:
    org_id = uuid.uuid4()
    repo = FakeRepository()
    provider = CapturingEmailProvider()
    http_client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(200))
    )
    notification_service = NotificationService(
        repo, http_client, email_provider=provider
    )
    channel_ids = []
    if org_email is not None:
        channel = await notification_service.create_channel(
            organization_id=org_id,
            channel_type=NotificationChannelType.EMAIL,
            name="Account email",
            config={"email": org_email},
            is_active=org_channel_active,
        )
        channel_ids.append(channel.id)
    rule = await repo.create_alert_rule(
        **_alert_rule_fields(
            trigger_type=AlertTriggerType.HEALTH_STATUS_CHANGE,
            target_component=target,
            condition_config={
                "expected_status": (
                    NETWORK_CONTROLLER_TARGET_STATES.get(target, "unreachable")
                )
            },
            organization_id=org_id,
        )
    )
    repo.rule_channels[rule.id] = channel_ids
    integration = FakeIntegration(organization_id=org_id, name="Lobby Omada")
    integration.failing(IntegrationStatus.CONNECTION_FAILED, 3)
    repo.network_integrations.append(integration)
    repo.organization_names[org_id] = "Seaview Hotels"
    repo.location_names[integration.location_id] = "Seaview Goa"
    service = AlertService(
        repo,
        notification_service=notification_service,
        platform_alert_emails=platform_emails,
    )
    return repo, service, provider, integration


async def test_the_platform_team_gets_a_copy_naming_the_tenant_and_venue() -> None:
    _, service, provider, integration = await _platform_harness(
        platform_emails=("ops@wyfy.example",)
    )

    await service.evaluate_alert_rules()

    recipients = [email for email, _, _ in provider.sent]
    assert sorted(recipients) == ["ops@wyfy.example", "owner@venue.example"]
    _, subject, body = next(m for m in provider.sent if m[0] == "ops@wyfy.example")
    assert "Seaview Hotels" in subject
    assert "Organization: Seaview Hotels. Venue: Seaview Goa." in body
    assert "Lobby Omada" in body
    # The organization's own copy is unchanged: no tenant line, no suffix.
    _, org_subject, org_body = next(
        m for m in provider.sent if m[0] == "owner@venue.example"
    )
    assert org_subject == "Wyfy Guest alert: CRITICAL"
    assert "Organization:" not in org_body

    # Recovery reaches the team too.
    integration.recovered()
    provider.sent.clear()
    await service.evaluate_alert_rules()
    team = [m for m in provider.sent if m[0] == "ops@wyfy.example"]
    assert len(team) == 1 and "RESOLVED" in team[0][1]


async def test_an_empty_setting_changes_nothing() -> None:
    _, service, provider, _ = await _platform_harness(platform_emails=())

    await service.evaluate_alert_rules()

    assert [email for email, _, _ in provider.sent] == ["owner@venue.example"]


async def test_a_platform_address_equal_to_the_orgs_is_sent_once() -> None:
    _, service, provider, _ = await _platform_harness(
        platform_emails=("OWNER@venue.example", "ops@wyfy.example"),
    )

    await service.evaluate_alert_rules()

    recipients = sorted(email for email, _, _ in provider.sent)
    assert recipients == ["ops@wyfy.example", "owner@venue.example"]


async def test_a_venue_nobody_is_told_about_still_reaches_the_team() -> None:
    """An organization with its channel switched off is the case the team
    most needs, and the one where de-duplicating against the
    contact_email column would have dropped the only copy."""
    _, service, provider, _ = await _platform_harness(
        platform_emails=("owner@venue.example",), org_channel_active=False
    )

    await service.evaluate_alert_rules()

    assert [email for email, _, _ in provider.sent] == ["owner@venue.example"]
    assert "Organization: Seaview Hotels" in provider.sent[0][2]


async def test_other_alerts_stay_the_organizations_own_business() -> None:
    repo, service, provider, integration = await _platform_harness(
        platform_emails=("ops@wyfy.example",),
        target=ALERT_TARGET_ROUTER_REACHABILITY,
    )
    repo.network_integrations.clear()
    repo.routers.append(
        FakeRouter(
            id=uuid.uuid4(),
            organization_id=integration.organization_id,
            location_id=integration.location_id,
            name="hEX lite",
            health_status="healthy",
            reachability_state="unreachable",
        )
    )

    result = await service.evaluate_alert_rules()

    assert len(result.triggered) == 1
    assert [email for email, _, _ in provider.sent] == ["owner@venue.example"]
