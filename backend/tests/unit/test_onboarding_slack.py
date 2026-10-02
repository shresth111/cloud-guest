"""Unit tests for Master-console onboarding status posted to Slack.

Three things are actually being proven here, and everything else is
supporting detail:

1. **A missing webhook is inert.** No row, no POST, no exception, and an
   onboarding that behaves exactly as it did before the feature existed.
2. **A Slack outage does not fail an onboarding.** Every layer -- the
   enqueue, the broker publish, and the dispatch sweep -- absorbs its own
   failure.
3. **No secret and no personal data reaches the payload.** Asserted both
   by content (a realistic provisioning result full of credentials, none
   of which appears in the message) and structurally (the builders do not
   have parameters for them, so a future edit cannot add one by accident).

Style follows ``tests/unit/test_notification.py``: plain ``assert``,
native ``async def``, hand-rolled fakes at the narrow Protocol boundary,
and no real Postgres, broker or network anywhere. The Slack transport is
exercised against ``httpx.MockTransport`` -- nothing in this file can
reach a real workspace.
"""

from __future__ import annotations

import inspect
import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx
import pytest

from app.core.config import Settings
from app.domains.notification.constants import (
    SLACK_ONBOARDING_RECIPIENT,
    NotificationChannelType,
    NotificationDeliveryStatus,
    NotificationEventType,
)
from app.domains.notification.exceptions import InvalidNotificationRecipientError
from app.domains.notification.models import NotificationDelivery
from app.domains.notification.onboarding_slack import (
    MAX_MESSAGE_LENGTH,
    OnboardingSlackNotifier,
    build_context,
    build_slack_text,
    controller_onboarded_notice,
    customer_created_notice,
    location_provisioned_notice,
    notice_from_context,
    onboarding_failed_notice,
    resolve_master_console_base_url,
)
from app.domains.notification.service import NotificationService
from app.domains.notification.slack import (
    HttpxSlackWebhookSender,
    SlackDeliveryError,
    SlackWebhookNotConfiguredError,
    UnconfiguredSlackSender,
    _redact,
    get_configured_slack_sender,
)
from app.domains.notification.validators import validate_recipient

# ============================================================================
# Fixtures / fakes
# ============================================================================

# A webhook-shaped string. Not a real webhook: `hooks.slack.invalid` is
# under the reserved `.invalid` TLD (RFC 2606), so even a bug that got
# past MockTransport could not resolve it.
FAKE_WEBHOOK = "https://hooks.slack.invalid/services/T00000000/B00000000/xoxbSECRET"

# Everything a real provisioning run has on hand and must not publish.
OWNER_EMAIL = "priya.menon@grandhotel.example"
OWNER_PHONE = "+919812345678"
TEMPORARY_PASSWORD = "Tq7!vZm2Lp9x"
ROUTER_API_SECRET = "mikrotik-api-secret-9f2b"
WIFI_PASSWORD = "GuestWiFi2026!"
TUNNEL_IP = "10.77.0.14"
GUEST_MSISDN = "+919900112233"

SECRETS_AND_PII = (
    FAKE_WEBHOOK,
    "xoxbSECRET",
    OWNER_EMAIL,
    OWNER_PHONE,
    TEMPORARY_PASSWORD,
    ROUTER_API_SECRET,
    WIFI_PASSWORD,
    TUNNEL_IP,
    GUEST_MSISDN,
)


def _settings(**overrides: object) -> Settings:
    base: dict[str, object] = {"environment": "test"}
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


@dataclass
class FakeEnqueuer:
    """Stands in for ``NotificationService`` at the one method
    ``OnboardingSlackNotifier`` uses."""

    calls: list[dict[str, object]] = field(default_factory=list)
    raises: Exception | None = None

    async def enqueue(self, **kwargs: object) -> object:
        if self.raises is not None:
            raise self.raises
        self.calls.append(kwargs)
        return object()


@dataclass
class RecordingSlackSender:
    sent: list[str] = field(default_factory=list)

    async def send(self, text: str) -> None:
        self.sent.append(text)


@dataclass
class ExplodingSlackSender:
    async def send(self, text: str) -> None:
        raise SlackDeliveryError("HTTP 503: service_unavailable")


def _base_fields(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": uuid.uuid4(),
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
        "deleted_at": None,
        "is_deleted": False,
        "created_by": None,
        "updated_by": None,
        "version": 1,
    }
    base.update(overrides)
    return base


def _slack_delivery(**overrides: object) -> NotificationDelivery:
    fields: dict[str, object] = {
        "organization_id": None,
        "template_id": None,
        "event_type": (
            NotificationEventType.ONBOARDING_LOCATION_PROVISIONED.value
        ),
        "channel": NotificationChannelType.SLACK.value,
        "recipient": SLACK_ONBOARDING_RECIPIENT,
        "subject": None,
        "body": "Onboarding succeeded",
        "status": NotificationDeliveryStatus.PENDING.value,
        "attempt_count": 0,
        "max_attempts": 3,
        "next_attempt_at": None,
        "sent_at": None,
        "error_message": None,
        "attachment_storage_key": None,
        "attachment_filename": None,
        "context": None,
    }
    fields.update(overrides)
    return NotificationDelivery(**_base_fields(**fields))


@dataclass
class OneRowRepository:
    """Just enough repository for ``dispatch_pending`` on a single row."""

    delivery: NotificationDelivery

    async def list_due_deliveries(self, **_: object) -> list[NotificationDelivery]:
        return [self.delivery]

    async def update_delivery(
        self, delivery: NotificationDelivery, data: dict[str, object]
    ) -> NotificationDelivery:
        for key, value in data.items():
            setattr(delivery, key, value)
        return delivery


def _provisioned_notice():
    """The notice a real successful ``POST /locations/provision`` produces.

    Built through the public builder, so it goes through exactly the path
    the router uses.
    """
    return location_provisioned_notice(
        organization_id=uuid.uuid4(),
        organization_name="Grand Hotel Andheri",
        location_name="Grand Hotel Andheri - Lobby",
        location_code="GHA-001",
        property_type="hotel",
        plan_name="Business",
        router_name="gha-lobby-rb5009",
        tunnel_allocated=True,
        actor_user_id=uuid.uuid4(),
    )


# ============================================================================
# 1. A missing webhook is inert
# ============================================================================


def test_no_webhook_means_no_sender() -> None:
    assert get_configured_slack_sender(_settings()) is None


def test_webhook_configured_yields_a_real_sender() -> None:
    sender = get_configured_slack_sender(
        _settings(slack_onboarding_webhook_url=FAKE_WEBHOOK)
    )
    assert isinstance(sender, HttpxSlackWebhookSender)
    assert sender.webhook_url == FAKE_WEBHOOK


def test_blank_webhook_is_treated_as_unset() -> None:
    assert get_configured_slack_sender(
        _settings(slack_onboarding_webhook_url="   ")
    ) is None


async def test_disabled_notifier_writes_no_outbox_row() -> None:
    """The headline guarantee: with no webhook, onboarding does not even
    touch the outbox."""
    enqueuer = FakeEnqueuer()
    notifier = OnboardingSlackNotifier(notification_service=enqueuer, enabled=False)

    await notifier.notify(_provisioned_notice())

    assert enqueuer.calls == []


async def test_enabled_notifier_writes_exactly_one_row() -> None:
    enqueuer = FakeEnqueuer()
    notifier = OnboardingSlackNotifier(
        notification_service=enqueuer,
        enabled=True,
        master_base_url="https://master.wyfyguest.example",
    )

    await notifier.notify(_provisioned_notice())

    assert len(enqueuer.calls) == 1
    call = enqueuer.calls[0]
    assert call["channel"] is NotificationChannelType.SLACK
    assert call["recipient"] == SLACK_ONBOARDING_RECIPIENT
    # NULL organization: invisible to every tenant's own delivery listing,
    # which filters org-scoped callers by strict equality. See
    # `onboarding_slack`'s Scope section.
    assert call["organization_id"] is None


async def test_disabled_notifier_is_inert_for_every_event_type() -> None:
    enqueuer = FakeEnqueuer()
    notifier = OnboardingSlackNotifier(notification_service=enqueuer, enabled=False)

    await notifier.notify(
        customer_created_notice(
            organization_id=uuid.uuid4(),
            organization_name="Cafe Koramangala",
            organization_slug="cafe-koramangala",
            location_created=True,
            actor_user_id=uuid.uuid4(),
        )
    )
    await notifier.notify(_provisioned_notice())
    await notifier.notify(
        controller_onboarded_notice(
            organization_id=uuid.uuid4(),
            organization_name="Cafe Koramangala",
            controller_name="OC200 Koramangala",
            provider="omada",
            site_name="Koramangala",
            synthetic_identity=True,
            actor_user_id=uuid.uuid4(),
        )
    )
    await notifier.notify(
        onboarding_failed_notice(
            stage="Location provisioning",
            organization_name="Cafe Koramangala",
            organization_id=None,
            error_type="RouterTunnelProvisioningFailedError",
            status_code=502,
            actor_user_id=uuid.uuid4(),
            request_id="req-1",
        )
    )

    assert enqueuer.calls == []


# ============================================================================
# 2. A Slack outage does not fail an onboarding
# ============================================================================


async def test_notifier_swallows_an_enqueue_failure() -> None:
    """If writing the outbox row itself blows up, the onboarding request
    still returns. ``notify`` is called from a route handler that must
    succeed regardless."""
    enqueuer = FakeEnqueuer(raises=RuntimeError("outbox exploded"))
    notifier = OnboardingSlackNotifier(notification_service=enqueuer, enabled=True)

    await notifier.notify(_provisioned_notice())  # must not raise


async def test_dispatch_sweep_survives_a_slack_outage() -> None:
    """A dead Slack does not crash the sweep and does not lose the row --
    it retries, exactly as an SMTP failure already does."""
    delivery = _slack_delivery(max_attempts=3)
    service = NotificationService(
        OneRowRepository(delivery),
        slack_sender=ExplodingSlackSender(),
        max_attempts=3,
        retry_backoff_seconds=60,
    )

    summary = await service.dispatch_pending(batch_size=10)

    assert summary.attempted == 1
    assert summary.retrying == 1
    assert delivery.status == NotificationDeliveryStatus.RETRYING.value
    assert delivery.attempt_count == 1
    assert delivery.next_attempt_at is not None


async def test_slack_row_fails_terminally_once_attempts_are_exhausted() -> None:
    delivery = _slack_delivery(attempt_count=2, max_attempts=3)
    service = NotificationService(
        OneRowRepository(delivery),
        slack_sender=ExplodingSlackSender(),
        max_attempts=3,
    )

    summary = await service.dispatch_pending(batch_size=10)

    assert summary.failed == 1
    assert delivery.status == NotificationDeliveryStatus.FAILED.value


async def test_slack_row_is_sent_through_the_slack_sender() -> None:
    """The positive control for the tests above: the SLACK branch really
    does route to the Slack sender and not to email or SMS."""
    delivery = _slack_delivery(body="Onboarding succeeded - Grand Hotel")
    sender = RecordingSlackSender()
    service = NotificationService(OneRowRepository(delivery), slack_sender=sender)

    summary = await service.dispatch_pending(batch_size=10)

    assert summary.sent == 1
    assert sender.sent == ["Onboarding succeeded - Grand Hotel"]
    assert delivery.status == NotificationDeliveryStatus.SENT.value


async def test_a_removed_webhook_fails_the_row_rather_than_faking_a_send() -> None:
    """A row enqueued while a webhook existed, drained after it was
    removed. It must not be marked SENT -- nothing was sent."""
    delivery = _slack_delivery(max_attempts=2)
    service = NotificationService(
        OneRowRepository(delivery),
        slack_sender=UnconfiguredSlackSender(),
        max_attempts=2,
    )

    summary = await service.dispatch_pending(batch_size=10)

    assert summary.sent == 0
    assert delivery.status != NotificationDeliveryStatus.SENT.value
    assert delivery.error_message is not None


async def test_unconfigured_sender_raises() -> None:
    with pytest.raises(SlackWebhookNotConfiguredError):
        await UnconfiguredSlackSender().send("anything")


async def test_transport_error_becomes_a_domain_error_not_an_httpx_error() -> None:
    """A network failure must surface as ``SlackDeliveryError`` so the
    sweep's own handling stays uniform -- and the raised message must not
    carry the URL."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    sender = HttpxSlackWebhookSender(
        FAKE_WEBHOOK,
        timeout_seconds=1.0,
        client_factory=lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ),
    )

    with pytest.raises(SlackDeliveryError) as excinfo:
        await sender.send("hello")

    assert "xoxbSECRET" not in str(excinfo.value)
    assert FAKE_WEBHOOK not in str(excinfo.value)


async def test_non_2xx_response_becomes_a_domain_error() -> None:
    sender = HttpxSlackWebhookSender(
        FAKE_WEBHOOK,
        timeout_seconds=1.0,
        client_factory=lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(403, text="invalid_token")
            )
        ),
    )

    with pytest.raises(SlackDeliveryError) as excinfo:
        await sender.send("hello")

    assert "invalid_token" in str(excinfo.value)


async def test_real_sender_posts_slacks_documented_payload() -> None:
    """Recorded transport, never a real workspace."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, text="ok")

    sender = HttpxSlackWebhookSender(
        FAKE_WEBHOOK,
        timeout_seconds=1.0,
        client_factory=lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ),
    )

    await sender.send("Onboarding succeeded")

    assert len(seen) == 1
    assert str(seen[0].url) == FAKE_WEBHOOK
    assert json.loads(seen[0].read()) == {"text": "Onboarding succeeded"}


# ============================================================================
# 3. No secret and no personal data in the payload
# ============================================================================


def test_provisioned_message_carries_no_secret_or_pii() -> None:
    notice = _provisioned_notice()
    text = build_slack_text(notice, master_base_url="https://master.wyfyguest.example")
    serialized = repr(build_context(notice))

    for forbidden in SECRETS_AND_PII:
        assert forbidden not in text, forbidden
        assert forbidden not in serialized, forbidden

    # ...while still saying the things it exists to say.
    assert "Grand Hotel Andheri" in text
    assert "GHA-001" in text
    assert "Business" in text


def test_tunnel_is_reported_as_a_boolean_not_an_address() -> None:
    text = build_slack_text(_provisioned_notice())
    assert "allocated" in text
    assert TUNNEL_IP not in text


def test_controller_message_carries_no_credentials_or_wifi_password() -> None:
    """The Omada SSID list endpoint returns ``securityKey`` in plaintext,
    so the controller builder must have no way to reach an SSID object."""
    notice = controller_onboarded_notice(
        organization_id=uuid.uuid4(),
        organization_name="Cafe Koramangala",
        controller_name="OC200 Koramangala",
        provider="omada",
        site_name="Koramangala",
        synthetic_identity=True,
        actor_user_id=uuid.uuid4(),
    )
    text = build_slack_text(notice)
    serialized = repr(build_context(notice))

    for forbidden in SECRETS_AND_PII:
        assert forbidden not in text, forbidden
        assert forbidden not in serialized, forbidden
    assert "OC200 Koramangala" in text


@pytest.mark.parametrize(
    "builder",
    [
        customer_created_notice,
        location_provisioned_notice,
        controller_onboarded_notice,
        onboarding_failed_notice,
    ],
)
def test_no_builder_accepts_a_secret_or_pii_parameter(builder) -> None:
    """Structural, not content-based. The content assertions above prove
    today's payload is clean; this one is what stops somebody adding
    ``owner_email=`` or ``temporary_password=`` to a builder six months
    from now and quietly publishing it."""
    forbidden_fragments = (
        "password",
        "secret",
        "credential",
        "token",
        "email",
        "phone",
        "msisdn",
        "webhook",
        "ssid",
        "security_key",
        "api_key",
        "owner_name",
        "tunnel_ip",
        "base_url",
    )
    for name in inspect.signature(builder).parameters:
        lowered = name.lower()
        for fragment in forbidden_fragments:
            assert fragment not in lowered, f"{builder.__name__} exposes {name}"


def test_failure_message_reports_the_exception_type_never_its_text() -> None:
    """``str(exc)`` is built by arbitrary layers below and can echo an
    address, a row or a query. Only the class name is published."""
    notice = onboarding_failed_notice(
        stage="Location provisioning",
        organization_name="Grand Hotel Andheri",
        organization_id=uuid.uuid4(),
        error_type="DuplicateUserError",
        status_code=409,
        actor_user_id=uuid.uuid4(),
        request_id="req-9f2b41",
        details=[("Location", "Grand Hotel Andheri - Lobby")],
    )
    text = build_slack_text(notice)

    assert "DuplicateUserError" in text
    assert "HTTP 409" in text
    assert "req-9f2b41" in text
    assert notice.outcome == "failed"
    for forbidden in SECRETS_AND_PII:
        assert forbidden not in text, forbidden


def test_redact_never_reveals_the_webhook_path() -> None:
    redacted = _redact(FAKE_WEBHOOK)
    assert "hooks.slack.invalid" in redacted
    assert "xoxbSECRET" not in redacted
    assert "/services/" not in redacted


def test_slack_recipient_must_be_the_channel_label() -> None:
    """Belt and braces on the column that a Master ops screen renders: a
    caller cannot smuggle a webhook URL or an address into it."""
    validate_recipient(SLACK_ONBOARDING_RECIPIENT, NotificationChannelType.SLACK)

    for bad in (FAKE_WEBHOOK, OWNER_EMAIL, OWNER_PHONE, ""):
        with pytest.raises(InvalidNotificationRecipientError):
            validate_recipient(bad, NotificationChannelType.SLACK)


# ============================================================================
# Rendering details
# ============================================================================


def test_markup_and_control_characters_are_stripped_from_values() -> None:
    notice = customer_created_notice(
        organization_id=uuid.uuid4(),
        organization_name="Acme *Hotels*\n<@channel>",
        organization_slug="acme-hotels",
        location_created=False,
        actor_user_id=None,
    )
    text = build_slack_text(notice)

    assert "<@channel>" not in text
    assert "Acme Hotels@channel" in text
    # The headline's own markup survives; only values are stripped.
    assert text.startswith("✅ *Onboarding succeeded*")


def test_message_is_length_bounded() -> None:
    notice = customer_created_notice(
        organization_id=uuid.uuid4(),
        organization_name="A" * 5000,
        organization_slug="B" * 5000,
        location_created=True,
        actor_user_id=uuid.uuid4(),
    )
    assert len(build_slack_text(notice)) <= MAX_MESSAGE_LENGTH


def test_link_is_omitted_without_a_real_master_origin() -> None:
    notice = _provisioned_notice()
    assert "Open in Master" not in build_slack_text(notice, master_base_url="")
    assert "Open in Master" in build_slack_text(
        notice, master_base_url="https://master.wyfyguest.example/"
    )


def test_link_uses_the_routes_the_master_console_actually_registers() -> None:
    base = "https://master.wyfyguest.example"
    org_id = uuid.uuid4()

    customer_text = build_slack_text(
        customer_created_notice(
            organization_id=org_id,
            organization_name="Grand Hotel Andheri",
            organization_slug="grand-hotel-andheri",
            location_created=True,
            actor_user_id=None,
        ),
        master_base_url=base,
    )
    # `/master/customers?open=<orgId>` -- the page has no id route; `open`
    # is what makes it show that customer's drawer.
    assert f"{base}/master/customers?open={org_id}" in customer_text

    location_text = build_slack_text(_provisioned_notice(), master_base_url=base)
    assert f"{base}/master/locations?q=GHA-001" in location_text


def test_placeholder_frontend_base_url_yields_no_link() -> None:
    """``frontend_base_url``'s committed default is documented as a
    placeholder host. A link to it would 404."""
    assert resolve_master_console_base_url(_settings()) == ""
    assert (
        resolve_master_console_base_url(
            _settings(frontend_base_url="https://app.wyfyguest.example")
        )
        == "https://app.wyfyguest.example"
    )
    assert (
        resolve_master_console_base_url(
            _settings(
                frontend_base_url="https://app.wyfyguest.example",
                master_console_base_url="https://master.wyfyguest.example",
            )
        )
        == "https://master.wyfyguest.example"
    )


def test_context_round_trips_across_the_celery_boundary() -> None:
    """``record_onboarding_failure`` receives JSON, not an object. The
    rebuild must read fields by name and ignore anything else, so the
    allowlist still holds on the far side of the broker."""
    original = onboarding_failed_notice(
        stage="Controller onboarding",
        organization_name="Cafe Koramangala",
        organization_id=uuid.uuid4(),
        error_type="OmadaLoginFailedError",
        status_code=502,
        actor_user_id=uuid.uuid4(),
        request_id="req-77",
        details=[("Controller", "OC200 Koramangala")],
    )
    payload = build_context(original)
    payload["smuggled_password"] = TEMPORARY_PASSWORD

    rebuilt = notice_from_context(payload)
    text = build_slack_text(rebuilt)

    assert rebuilt.event_type is NotificationEventType.ONBOARDING_FAILED
    assert rebuilt.organization_id == original.organization_id
    assert "OmadaLoginFailedError" in text
    assert "OC200 Koramangala" in text
    assert TEMPORARY_PASSWORD not in text
    assert TEMPORARY_PASSWORD not in repr(build_context(rebuilt))


# ============================================================================
# The failure path's broker hand-off
# ============================================================================


def test_failure_dispatch_is_inert_without_a_webhook(monkeypatch) -> None:
    """Nothing is even published to the broker when Slack is unconfigured
    -- the common case, and the one that must cost an already-failing
    onboarding nothing at all."""
    from app.domains.notification import tasks

    published: list[object] = []
    monkeypatch.setattr(
        tasks.record_onboarding_failure,
        "delay",
        lambda payload: published.append(payload),
    )

    tasks.dispatch_onboarding_failure(
        settings=_settings(),
        stage="Location provisioning",
        organization_name="Grand Hotel Andheri",
        organization_id=None,
        error=RuntimeError("boom"),
        actor_user_id=uuid.uuid4(),
        request_id="req-1",
    )

    assert published == []


def test_failure_dispatch_publishes_a_clean_payload(monkeypatch) -> None:
    from app.domains.notification import tasks

    published: list[dict] = []
    monkeypatch.setattr(
        tasks.record_onboarding_failure,
        "delay",
        lambda payload: published.append(payload),
    )

    class DuplicateUserError(Exception):
        status_code = 409

    tasks.dispatch_onboarding_failure(
        settings=_settings(slack_onboarding_webhook_url=FAKE_WEBHOOK),
        stage="Location provisioning",
        organization_name="Grand Hotel Andheri",
        organization_id=None,
        error=DuplicateUserError(f"user {OWNER_EMAIL} already exists"),
        actor_user_id=uuid.uuid4(),
        request_id="req-42",
        details=[("Location", "Grand Hotel Andheri - Lobby")],
    )

    assert len(published) == 1
    payload = published[0]
    assert payload["error_type"] == "DuplicateUserError"
    assert payload["status_code"] == 409
    # The exception's own message named the owner. The payload does not.
    for forbidden in SECRETS_AND_PII:
        assert forbidden not in repr(payload), forbidden


def test_failure_dispatch_survives_an_unreachable_broker(monkeypatch) -> None:
    """A down Celery broker must not replace the caller's real exception
    with a different one on the way out of the request handler."""
    from app.domains.notification import tasks

    def explode(payload: object) -> None:
        raise OSError("broker unreachable")

    monkeypatch.setattr(tasks.record_onboarding_failure, "delay", explode)

    tasks.dispatch_onboarding_failure(  # must not raise
        settings=_settings(slack_onboarding_webhook_url=FAKE_WEBHOOK),
        stage="Controller onboarding",
        organization_name="Cafe Koramangala",
        organization_id=uuid.uuid4(),
        error=RuntimeError("boom"),
        actor_user_id=None,
        request_id=None,
    )


# ============================================================================
# Wiring
# ============================================================================


def test_the_dependency_is_disabled_unless_a_webhook_is_configured() -> None:
    """The routers never test for configuration themselves -- this
    dependency decides it once. If this were wired wrong, every assertion
    above about "inert" would be testing a class nothing builds."""
    from app.domains.notification.dependencies import get_onboarding_slack_notifier

    off = get_onboarding_slack_notifier(
        notification_service=FakeEnqueuer(),  # type: ignore[arg-type]
        settings=_settings(),
    )
    assert off.enabled is False
    assert off.master_base_url == ""

    on = get_onboarding_slack_notifier(
        notification_service=FakeEnqueuer(),  # type: ignore[arg-type]
        settings=_settings(
            slack_onboarding_webhook_url=FAKE_WEBHOOK,
            master_console_base_url="https://master.wyfyguest.example",
        ),
    )
    assert on.enabled is True
    assert on.master_base_url == "https://master.wyfyguest.example"


def test_the_failure_task_is_registered_on_the_celery_app() -> None:
    """A task the routes call by name must actually exist on the worker,
    or every failure notice is a silently unrouted message."""
    from app.core.celery_app import celery_app
    from app.domains.notification.constants import TASK_RECORD_ONBOARDING_FAILURE

    assert TASK_RECORD_ONBOARDING_FAILURE in celery_app.tasks


def test_slack_values_fit_the_columns_they_are_written_to() -> None:
    """No migration ships with this change, which is only true while the
    new values fit the existing widths."""
    for event in (
        NotificationEventType.ONBOARDING_CUSTOMER_CREATED,
        NotificationEventType.ONBOARDING_LOCATION_PROVISIONED,
        NotificationEventType.ONBOARDING_CONTROLLER_ONBOARDED,
        NotificationEventType.ONBOARDING_FAILED,
    ):
        assert len(event.value) <= 50, event

    assert len(NotificationChannelType.SLACK.value) <= 20
    assert len(SLACK_ONBOARDING_RECIPIENT) <= 255


def test_identifiers_survive_cleaning_intact() -> None:
    """Regression. `_` and `~` used to be stripped along with Slack's
    markup, which silently mangled any identifier containing one --
    organization slugs are normalised by nothing but `strip().lower()`, so
    `grand_hotel_andheri` is a legal slug and was rendering as
    `grandhotelandheri`. An operator copying that out of Slack would not
    find it."""
    text = build_slack_text(
        customer_created_notice(
            organization_id=uuid.uuid4(),
            organization_name="Grand Hotel Andheri",
            organization_slug="grand_hotel_andheri",
            location_created=True,
            actor_user_id=None,
        )
    )
    assert "grand_hotel_andheri" in text


def test_mention_injection_is_still_impossible() -> None:
    """The other half of the narrowing above: dropping `_`/`~`/`|` from the
    strip set must not reopen the thing the strip set exists for. Every
    Slack construct that *acts* needs `<` and `>`, and those still go."""
    for hostile in (
        "<!channel>",
        "<!here>",
        "<@U024BE7LH>",
        "<#C024BE7LV>",
        "<https://evil.invalid|Open in Master>",
    ):
        text = build_slack_text(
            customer_created_notice(
                organization_id=uuid.uuid4(),
                organization_name=f"Acme {hostile}",
                organization_slug="acme",
                location_created=False,
                actor_user_id=None,
            )
        )
        assert "<" not in text
        assert ">" not in text
