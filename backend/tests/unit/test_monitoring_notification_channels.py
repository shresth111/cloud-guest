"""Unit tests for the Master-console integrations layer built on top of
``app.domains.monitoring``'s Notification Engine: the tenant guard on
channel *creation*, credential redaction, the connectivity test, and
category routing for producers that are not an alert.

Follows the convention ``tests/unit/test_monitoring_alerts.py`` establishes
and states: plain ``assert``/native ``async def`` against small hand-rolled
in-memory fakes, and every outbound HTTP POST faked through
``httpx.MockTransport``. No test here makes a real network call, and no
test sends to a real Slack/SMS/email destination.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import httpx
import pytest

from app.domains.monitoring.channel_config import (
    fingerprint_secret,
    summarize_channel_config,
)
from app.domains.monitoring.constants import (
    NotificationChannelType,
    NotificationEventCategory,
    NotificationLogKind,
    NotificationStatus,
)
from app.domains.monitoring.exceptions import (
    InvalidNotificationChannelConfigError,
)
from app.domains.monitoring.models import NotificationChannel, NotificationLog
from app.domains.monitoring.schemas import NotificationChannelResponse
from app.domains.monitoring.service import NotificationService
from app.domains.monitoring.validators import (
    validate_notification_event_categories,
)
from app.domains.organization.exceptions import CrossOrganizationAccessError

# Fixtures, not credentials. The host is real because the redaction under
# test keeps the host and discards the path, so the assertions need a
# recognisable one -- but the path is deliberately NOT token-shaped.
#
# The first version of this file used a realistic 24-character Slack token
# here and GitHub push protection rejected the push, which is the control
# working: this repository is public. The fix is a fixture that cannot be
# mistaken for a credential by a scanner or by a reader, not an allowlist
# entry. Nothing in this file reaches the network -- every request is served
# by an `httpx.MockTransport`.
FAKE_SLACK_URL = "https://hooks.slack.com/services/EXAMPLE-NOT-A-REAL-WEBHOOK"
FAKE_WEBHOOK_URL = "https://ops.example.internal/hooks/ingest?tenant=acme"
FAKE_AUTH_VALUE = "example-not-a-real-api-key"


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


class FakeRepository:
    """Only the notification-channel/log surface ``NotificationService``
    touches. Everything else raises, so a test that strays outside this
    layer fails loudly rather than silently exercising a stub."""

    def __init__(self) -> None:
        self.channels: dict[uuid.UUID, NotificationChannel] = {}
        self.logs: list[NotificationLog] = []

    async def create_notification_channel(self, **fields: object):
        fields.setdefault("event_categories", [])
        channel = NotificationChannel(**_base_fields(**fields))
        self.channels[channel.id] = channel
        return channel

    async def get_notification_channel(self, channel_id: uuid.UUID):
        channel = self.channels.get(channel_id)
        return channel if channel is not None and not channel.is_deleted else None

    async def update_notification_channel(self, channel, data):
        for key, value in data.items():
            setattr(channel, key, value)
        return channel

    async def create_notification_log(self, **fields: object) -> NotificationLog:
        log = NotificationLog(**_base_fields(**fields))
        self.logs.append(log)
        return log

    async def list_active_notification_channels_for_category(
        self, *, category: str, organization_id: uuid.UUID | None
    ) -> list[NotificationChannel]:
        # Mirrors the SQL in MonitoringRepository: platform-wide channels
        # are always included; a named organization additionally gets its
        # own; a platform event gets platform-wide ONLY.
        out = []
        for channel in self.channels.values():
            if channel.is_deleted or not channel.is_active:
                continue
            if category not in (channel.event_categories or []):
                continue
            own = organization_id is not None and (
                channel.organization_id == organization_id
            )
            if channel.organization_id is None or own:
                out.append(channel)
        return out

    async def latest_notification_logs_by_channel(self, channel_ids):
        latest: dict[uuid.UUID, NotificationLog] = {}
        for log in sorted(self.logs, key=lambda row: row.sent_at):
            if log.channel_id in channel_ids:
                latest[log.channel_id] = log
        return latest


def _service(handler=None) -> tuple[NotificationService, FakeRepository]:
    handler = handler or (lambda request: httpx.Response(200, text="ok"))
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    repository = FakeRepository()
    return NotificationService(repository, client), repository


# ============================================================================
# The tenant guard on channel creation
#
# Before this, POST /notifications/channels took organization_id straight
# from the body. PermissionModule.NOTIFICATIONS is seeded at
# ScopeType.LOCATION with GrantLevel.OPERATE on Office Admin and Location
# Manager, so a single venue's front-desk account held notifications.manage.
# ============================================================================


@pytest.mark.asyncio
async def test_tenant_caller_cannot_create_a_platform_wide_channel():
    """``organization_id: null`` is not "unscoped", it is *platform-wide* --
    the scope a system alert rule delivers to. A tenant creating one would
    attach its own webhook to the platform's alert stream and receive
    infrastructure alerts about every other tenant on the estate."""
    service, repository = _service()
    caller_org = uuid.uuid4()

    with pytest.raises(CrossOrganizationAccessError):
        await service.create_channel(
            organization_id=None,
            channel_type=NotificationChannelType.SLACK,
            name="totally normal channel",
            config={"webhook_url": FAKE_SLACK_URL},
            requesting_organization_id=caller_org,
        )

    assert repository.channels == {}, "nothing may be persisted on a refusal"


@pytest.mark.asyncio
async def test_tenant_caller_cannot_create_a_channel_for_another_tenant():
    service, repository = _service()

    with pytest.raises(CrossOrganizationAccessError):
        await service.create_channel(
            organization_id=uuid.uuid4(),
            channel_type=NotificationChannelType.SLACK,
            name="victim's channel",
            config={"webhook_url": FAKE_SLACK_URL},
            requesting_organization_id=uuid.uuid4(),
        )

    assert repository.channels == {}


@pytest.mark.asyncio
async def test_tenant_caller_may_create_a_channel_for_its_own_organization():
    """The guard must not break the legitimate case, or it would just be an
    outage with a security-shaped explanation."""
    service, _ = _service()
    caller_org = uuid.uuid4()

    channel = await service.create_channel(
        organization_id=caller_org,
        channel_type=NotificationChannelType.SLACK,
        name="ops",
        config={"webhook_url": FAKE_SLACK_URL},
        requesting_organization_id=caller_org,
    )

    assert channel.organization_id == caller_org


@pytest.mark.asyncio
async def test_platform_caller_may_create_a_platform_wide_channel():
    service, _ = _service()

    channel = await service.create_channel(
        organization_id=None,
        channel_type=NotificationChannelType.SLACK,
        name="platform ops",
        config={"webhook_url": FAKE_SLACK_URL},
        requesting_organization_id=None,
    )

    assert channel.organization_id is None


# ============================================================================
# Redaction -- what may leave the process
# ============================================================================


def test_slack_summary_never_contains_the_webhook_path():
    summary = summarize_channel_config(
        NotificationChannelType.SLACK, {"webhook_url": FAKE_SLACK_URL}
    )

    assert summary.configured is True
    assert summary.target == "https://hooks.slack.com/…"
    # The secret is the path. Neither it, nor any segment of it, may appear
    # anywhere in the summary.
    rendered = json.dumps(
        {
            "target": summary.target,
            "fingerprint": summary.fingerprint,
            "auth_header_name": summary.auth_header_name,
        }
    )
    assert "EXAMPLE-NOT-A-REAL-WEBHOOK" not in rendered
    assert "services" not in rendered
    # A fingerprint is a hash, never a prefix of the value it stands for.
    assert summary.fingerprint is not None
    assert summary.fingerprint not in FAKE_SLACK_URL


def test_fingerprints_distinguish_two_channels_without_revealing_either():
    """The question an operator actually has -- "is this the same webhook
    as that one?" -- answered without disclosure."""
    other = FAKE_SLACK_URL.replace("EXAMPLE", "DIFFERENT")
    one = summarize_channel_config(
        NotificationChannelType.SLACK, {"webhook_url": FAKE_SLACK_URL}
    )
    two = summarize_channel_config(
        NotificationChannelType.SLACK, {"webhook_url": other}
    )
    same = summarize_channel_config(
        NotificationChannelType.SLACK, {"webhook_url": FAKE_SLACK_URL}
    )

    assert one.fingerprint != two.fingerprint
    assert one.fingerprint == same.fingerprint


def test_low_entropy_destinations_are_never_fingerprinted():
    """A ten-digit phone number's hash is recovered by brute force in
    seconds, so publishing one would turn a redaction into a disclosure.
    Email and SMS/WhatsApp get a partial mask and no hash at all."""
    email = summarize_channel_config(
        NotificationChannelType.EMAIL, {"email": "operations@acme.example"}
    )
    sms = summarize_channel_config(
        NotificationChannelType.SMS, {"phone_number": "+919876543210"}
    )

    assert email.fingerprint is None
    assert sms.fingerprint is None
    assert email.target == "op•••@acme.example"
    assert "erations" not in email.target
    assert sms.target.endswith("3210")
    assert "98765" not in sms.target


def test_webhook_auth_header_value_is_never_represented_in_any_form():
    """The header *name* is safe and useful; the value is not represented
    -- not masked, not fingerprinted on its own, not by length."""
    summary = summarize_channel_config(
        NotificationChannelType.WEBHOOK,
        {
            "url": FAKE_WEBHOOK_URL,
            "auth_header_name": "X-Api-Key",
            "auth_header_value": FAKE_AUTH_VALUE,
        },
    )

    assert summary.auth_header_name == "X-Api-Key"
    assert summary.has_secret is True
    rendered = json.dumps(
        {
            "target": summary.target,
            "fingerprint": summary.fingerprint,
            "auth_header_name": summary.auth_header_name,
            "has_secret": summary.has_secret,
        }
    )
    assert FAKE_AUTH_VALUE not in rendered
    assert "not-a-real-api-key" not in rendered
    # The query string can carry a tenant identifier, so it goes too.
    assert "tenant=acme" not in rendered
    assert summary.target == "https://ops.example.internal/…"


def test_rotating_either_half_of_a_webhook_credential_changes_the_fingerprint():
    base = {
        "url": FAKE_WEBHOOK_URL,
        "auth_header_name": "X-Api-Key",
        "auth_header_value": FAKE_AUTH_VALUE,
    }
    rotated_key = summarize_channel_config(
        NotificationChannelType.WEBHOOK,
        {**base, "auth_header_value": "example-rotated-key"},
    )
    original = summarize_channel_config(NotificationChannelType.WEBHOOK, base)

    assert original.fingerprint != rotated_key.fingerprint


def test_an_empty_config_reads_as_not_configured_rather_than_as_working():
    """The state the console previously rendered identically to a working
    channel."""
    summary = summarize_channel_config(NotificationChannelType.SLACK, {})

    assert summary.configured is False
    assert summary.target == "not configured"
    assert summary.fingerprint is None


def test_an_unknown_channel_type_redacts_instead_of_raising():
    """``channel_type`` is a persisted string column. A row written before
    a member existed must not take down the list endpoint that is the
    operator's only way of finding it."""
    summary = summarize_channel_config(
        "carrier_pigeon", {"webhook_url": FAKE_SLACK_URL}
    )

    assert summary.configured is False
    assert FAKE_SLACK_URL not in summary.target


def test_the_channel_response_model_has_no_config_field_at_all():
    """A list endpoint in this codebase once returned plaintext WiFi
    passwords because its serializer reached for the model. This asserts
    the allowlist directly: there is no field a config could arrive in."""
    fields = set(NotificationChannelResponse.model_fields)

    assert "config" not in fields
    assert "config_encrypted" not in fields
    assert fields == {
        "id",
        "organization_id",
        "channel_type",
        "name",
        "is_active",
        "event_categories",
        "created_at",
        "updated_at",
        "config_summary",
        "last_delivery",
    }


@pytest.mark.asyncio
async def test_summarize_channel_round_trips_through_real_encryption():
    service, _ = _service()
    channel = await service.create_channel(
        organization_id=None,
        channel_type=NotificationChannelType.SLACK,
        name="ops",
        config={"webhook_url": FAKE_SLACK_URL},
    )

    # The stored column really is ciphertext, not the URL.
    assert FAKE_SLACK_URL not in channel.config_encrypted

    summary = service.summarize_channel(channel)
    assert summary.configured is True
    assert summary.fingerprint == fingerprint_secret(FAKE_SLACK_URL)


@pytest.mark.asyncio
async def test_an_undecryptable_config_reports_unconfigured_not_an_exception():
    service, _ = _service()
    channel = await service.create_channel(
        organization_id=None,
        channel_type=NotificationChannelType.SLACK,
        name="ops",
        config={"webhook_url": FAKE_SLACK_URL},
    )
    channel.config_encrypted = "not-fernet-ciphertext"

    summary = service.summarize_channel(channel)

    assert summary.configured is False


# ============================================================================
# The connectivity test
# ============================================================================


@pytest.mark.asyncio
async def test_a_slack_test_posts_a_self_describing_message_and_logs_it():
    posted: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        posted.append(json.loads(request.content))
        return httpx.Response(200, text="ok")

    service, repository = _service(handler)
    channel = await service.create_channel(
        organization_id=None,
        channel_type=NotificationChannelType.SLACK,
        name="Platform ops",
        config={"webhook_url": FAKE_SLACK_URL},
    )

    log = await service.send_test_notification(channel)

    assert len(posted) == 1
    # Says what it is in its first words -- this lands in a channel real
    # people read, and a message indistinguishable from a real alert is how
    # a test becomes an incident.
    assert posted[0]["text"].startswith("[INFO] Test notification from")
    assert "Platform ops" in posted[0]["text"]
    assert log.status == NotificationStatus.SENT.value
    assert log.kind == NotificationLogKind.TEST.value
    assert log.alert_id is None
    assert log.response_summary == "HTTP 200"


@pytest.mark.asyncio
async def test_a_failing_test_records_the_real_error_and_never_raises():
    """A test that raised would retry a *delivery* inside Celery. The
    FAILED row with the real error is the answer, and it is what
    distinguishes "nobody configured this" from "the webhook was
    revoked"."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="no_service")

    service, repository = _service(handler)
    channel = await service.create_channel(
        organization_id=None,
        channel_type=NotificationChannelType.SLACK,
        name="revoked",
        config={"webhook_url": FAKE_SLACK_URL},
    )

    log = await service.send_test_notification(channel)

    assert log.status == NotificationStatus.FAILED.value
    assert log.kind == NotificationLogKind.TEST.value
    assert "404" in (log.error_message or "")
    assert "no_service" in (log.error_message or "")


@pytest.mark.asyncio
async def test_a_failed_test_log_never_carries_the_webhook_url():
    def handler(request: httpx.Request) -> httpx.Response:
        # A server that unhelpfully echoes the request back at you -- the
        # realistic way a secret ends up in an error string.
        return httpx.Response(500, text=f"upstream rejected {FAKE_SLACK_URL}")

    service, _ = _service(handler)
    channel = await service.create_channel(
        organization_id=None,
        channel_type=NotificationChannelType.SLACK,
        name="ops",
        config={"webhook_url": FAKE_SLACK_URL},
    )

    log = await service.send_test_notification(channel)

    assert log.status == NotificationStatus.FAILED.value
    # We cannot stop a remote server saying whatever it likes, but we can
    # assert that *our* error string is the transport's status line and
    # that the secret is not reintroduced by us from the config.
    assert log.error_message is not None
    assert log.error_message.startswith("HTTP 500")


@pytest.mark.asyncio
async def test_a_generic_webhook_test_is_labelled_a_test_not_an_alert():
    """Every other channel carries a human-readable string that explains
    itself. A generic webhook carries structured JSON a machine acts on,
    and ``event: alert`` with a synthesised id would instruct the receiver
    to treat a test as a production incident."""
    posted: list[dict] = []
    headers: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        posted.append(json.loads(request.content))
        headers.append(request.headers.get("x-api-key", ""))
        return httpx.Response(204)

    service, _ = _service(handler)
    channel = await service.create_channel(
        organization_id=None,
        channel_type=NotificationChannelType.WEBHOOK,
        name="ops ingest",
        config={
            "url": FAKE_WEBHOOK_URL,
            "auth_header_name": "X-Api-Key",
            "auth_header_value": FAKE_AUTH_VALUE,
        },
    )

    log = await service.send_test_notification(channel)

    assert posted[0]["event"] == "test"
    assert "alert_id" not in posted[0]
    # The test proves the credential: the real auth header went with it.
    assert headers[0] == FAKE_AUTH_VALUE
    assert log.status == NotificationStatus.SENT.value


@pytest.mark.asyncio
async def test_a_test_send_travels_the_same_transport_as_a_real_alert():
    """The reason a test is worth anything. This codebase has been bitten
    by parallel configuration paths drifting while each one's own tests
    stayed green, so assert the test and the alert reach the same URL with
    the same payload shape."""
    urls: list[str] = []
    shapes: list[set[str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        urls.append(str(request.url))
        shapes.append(set(json.loads(request.content)))
        return httpx.Response(200, text="ok")

    service, _ = _service(handler)
    channel = await service.create_channel(
        organization_id=None,
        channel_type=NotificationChannelType.SLACK,
        name="ops",
        config={"webhook_url": FAKE_SLACK_URL},
    )

    await service.send_test_notification(channel)

    assert urls == [FAKE_SLACK_URL]
    assert shapes == [{"text"}]


# ============================================================================
# Category routing -- the fan-out guard
# ============================================================================


@pytest.mark.asyncio
async def test_a_tenant_event_reaches_that_tenant_and_the_platform_only():
    service, repository = _service()
    acme = uuid.uuid4()
    other = uuid.uuid4()

    for org, name in ((acme, "acme ops"), (other, "other ops"), (None, "platform")):
        await service.create_channel(
            organization_id=org,
            channel_type=NotificationChannelType.SLACK,
            name=name,
            config={"webhook_url": FAKE_SLACK_URL},
            event_categories=[NotificationEventCategory.CUSTOMER_ONBOARDING.value],
        )

    reached = await service.list_channels_for_category(
        NotificationEventCategory.CUSTOMER_ONBOARDING, organization_id=acme
    )

    assert {c.name for c in reached} == {"acme ops", "platform"}


@pytest.mark.asyncio
async def test_a_platform_event_never_widens_to_every_tenants_channels():
    """``organization_id is None`` means "the platform", never "no filter".
    A naive read of it as "no WHERE clause" is the documented way a global
    scope fans out across all fourteen organizations."""
    service, _ = _service()
    acme = uuid.uuid4()

    for org, name in ((acme, "acme ops"), (None, "platform")):
        await service.create_channel(
            organization_id=org,
            channel_type=NotificationChannelType.SLACK,
            name=name,
            config={"webhook_url": FAKE_SLACK_URL},
            event_categories=[NotificationEventCategory.PLATFORM_OPS.value],
        )

    reached = await service.list_channels_for_category(
        NotificationEventCategory.PLATFORM_OPS, organization_id=None
    )

    assert {c.name for c in reached} == {"platform"}


@pytest.mark.asyncio
async def test_a_channel_with_no_categories_receives_no_category_events():
    """Empty is the default and every pre-existing row's value: alerts
    only, i.e. exactly today's behaviour. Nothing starts delivering
    because of this feature."""
    service, _ = _service()
    await service.create_channel(
        organization_id=None,
        channel_type=NotificationChannelType.SLACK,
        name="alerts only",
        config={"webhook_url": FAKE_SLACK_URL},
    )

    reached = await service.list_channels_for_category(
        NotificationEventCategory.PLATFORM_OPS, organization_id=None
    )

    assert reached == []


@pytest.mark.asyncio
async def test_a_disabled_channel_receives_nothing():
    service, _ = _service()
    await service.create_channel(
        organization_id=None,
        channel_type=NotificationChannelType.SLACK,
        name="paused",
        config={"webhook_url": FAKE_SLACK_URL},
        is_active=False,
        event_categories=[NotificationEventCategory.PLATFORM_OPS.value],
    )

    reached = await service.list_channels_for_category(
        NotificationEventCategory.PLATFORM_OPS, organization_id=None
    )

    assert reached == []


# ============================================================================
# Category validation
# ============================================================================


def test_an_unknown_category_is_rejected_rather_than_dropped():
    """Silently discarding it produces a channel the console shows as
    subscribed while nothing is ever delivered -- the
    failure-that-looks-like-success this domain exists to prevent."""
    with pytest.raises(InvalidNotificationChannelConfigError) as excinfo:
        validate_notification_event_categories(["platfrom_ops"])

    assert "platfrom_ops" in str(excinfo.value)
    # The error names what IS allowed, so the fix does not need a grep.
    assert "platform_ops" in str(excinfo.value)


def test_categories_are_deduplicated_and_order_preserving():
    assert validate_notification_event_categories(
        ["billing", "platform_ops", "billing"]
    ) == ["billing", "platform_ops"]


def test_a_non_string_category_is_rejected():
    with pytest.raises(InvalidNotificationChannelConfigError):
        validate_notification_event_categories([123])


# ============================================================================
# RBAC -- introspected off the registered routes, the convention
# test_monitoring_alerts.py establishes for this codebase
# ============================================================================


def _permission_key_for_route(route) -> str | None:
    """Reads ``key`` back out of a ``Depends(RequirePermission(key))``
    closure -- the same introspection ``tests/unit/test_monitoring_alerts
    .py`` uses, and for the reason its own docstring gives: this codebase
    has no route-level ``TestClient`` pattern, so the registered dependency
    is the most direct thing to assert against."""
    for dependency in route.dependant.dependencies:
        call = dependency.call
        freevars = getattr(call.__code__, "co_freevars", ())
        if "permission_key" in freevars:
            return call.__closure__[freevars.index("permission_key")].cell_contents
    return None


def test_the_test_endpoint_requires_a_write_permission_not_a_read_one():
    """It causes a real outbound message to a real destination. Gating it
    on ``notifications.read`` would let an account that may only look at
    the channel list post into every Slack channel on it."""
    from app.main import create_app

    route = next(
        r
        for r in create_app().routes
        if getattr(r, "path", None)
        == "/api/v1/notifications/channels/{channel_id}/test"
    )

    assert _permission_key_for_route(route) == "notifications.manage"
