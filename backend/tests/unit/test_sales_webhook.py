"""Tests for the sales-automation webhook (``app.domains.notification
.sales_webhook``) and its two callers, ``DemoRequestService`` and
``DemoBookingService``.

The guarantees under test:

1. Off by default: with no configuration nothing is enqueued and the demo
   flows are unchanged.
2. When on, each lifecycle event becomes exactly one WEBHOOK outbox row,
   addressed to the constant label (never the URL), whose body is the JSON
   that will be POSTed.
3. Delivery sends that body verbatim with the shared-secret header, and a
   failure becomes RETRYING/FAILED through the existing outbox, never SENT.
4. Nothing secret leaks: no manage token in a payload, no URL or secret in
   an error.

No network: the transport is ``httpx.MockTransport`` and the URL is under
the reserved ``.invalid`` TLD.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx
import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.domains.demo_request.service import DemoRequestService
from app.domains.notification.constants import (
    SALES_WEBHOOK_RECIPIENT,
    NotificationChannelType,
    NotificationDeliveryStatus,
    NotificationEventType,
)
from app.domains.notification.exceptions import InvalidNotificationRecipientError
from app.domains.notification.models import NotificationDelivery
from app.domains.notification.sales_webhook import (
    EVENT_HEADER,
    EVENT_ID_HEADER,
    SECRET_HEADER,
    HttpxSalesWebhookSender,
    SalesWebhookDeliveryError,
    SalesWebhookEvent,
    SalesWebhookPublisher,
    UnconfiguredSalesWebhookSender,
    get_configured_sales_webhook_sender,
    is_sales_webhook_configured,
)
from app.domains.notification.service import NotificationService
from app.domains.notification.validators import validate_recipient
from tests.unit.test_demo_booking import book, make_service
from tests.unit.test_demo_request import FakeDemoRequestRepository

FAKE_URL = "https://automation.example.invalid/webhook/wyfy-demo-request"
FAKE_SECRET = "unit-test-shared-secret-not-real"
FIXED_NOW = datetime(2026, 9, 1, 6, 0, tzinfo=UTC)


def _settings(**overrides: object) -> Settings:
    base: dict[str, object] = {"environment": "test"}
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


@dataclass
class FakeEnqueuer:
    calls: list[dict[str, object]] = field(default_factory=list)
    raises: Exception | None = None

    async def enqueue(self, **fields: object) -> object:
        if self.raises is not None:
            raise self.raises
        self.calls.append(dict(fields))
        return type("Delivery", (), {"id": uuid.uuid4()})()


@dataclass
class RecordingPublisher:
    events: list[tuple[str, dict[str, object]]] = field(default_factory=list)

    async def publish(self, event: str, data: dict[str, object]) -> None:
        self.events.append((event, data))


def _enabled_publisher(enqueuer: FakeEnqueuer) -> SalesWebhookPublisher:
    return SalesWebhookPublisher(enqueuer, enabled=True, clock=lambda: FIXED_NOW)


# ============================================================================
# 1. Configuration: off by default, all three settings required
# ============================================================================


def test_default_settings_leave_the_webhook_off() -> None:
    settings = _settings()
    assert settings.sales_webhook_enabled is False
    assert is_sales_webhook_configured(settings) is False
    assert get_configured_sales_webhook_sender(settings) is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"sales_webhook_url": FAKE_URL, "sales_webhook_secret": FAKE_SECRET},
        {"sales_webhook_enabled": True, "sales_webhook_secret": FAKE_SECRET},
        {"sales_webhook_enabled": True, "sales_webhook_url": FAKE_URL},
        {
            "sales_webhook_enabled": True,
            "sales_webhook_url": FAKE_URL,
            "sales_webhook_secret": "   ",
        },
    ],
)
def test_any_missing_piece_keeps_it_off(overrides: dict[str, object]) -> None:
    assert is_sales_webhook_configured(_settings(**overrides)) is False


def test_fully_configured_yields_a_real_sender() -> None:
    sender = get_configured_sales_webhook_sender(
        _settings(
            sales_webhook_enabled=True,
            sales_webhook_url=FAKE_URL,
            sales_webhook_secret=FAKE_SECRET,
        )
    )
    assert isinstance(sender, HttpxSalesWebhookSender)
    assert sender.url == FAKE_URL


def test_plain_http_is_refused_except_on_localhost() -> None:
    with pytest.raises(ValidationError):
        _settings(sales_webhook_url="http://automation.example.invalid/webhook/x")
    assert _settings(sales_webhook_url="http://localhost:5678/webhook/x")


# ============================================================================
# 2. Publisher: one WEBHOOK row per event, or nothing at all
# ============================================================================


async def test_disabled_publisher_writes_no_row() -> None:
    enqueuer = FakeEnqueuer()
    publisher = SalesWebhookPublisher(enqueuer, enabled=False)

    await publisher.publish(SalesWebhookEvent.DEMO_REQUEST_CREATED, {"lead": {}})

    assert enqueuer.calls == []


async def test_enabled_publisher_enqueues_one_labelled_webhook_row() -> None:
    enqueuer = FakeEnqueuer()

    await _enabled_publisher(enqueuer).publish(
        SalesWebhookEvent.DEMO_REQUEST_CREATED, {"lead": {"email": "a@b.example"}}
    )

    assert len(enqueuer.calls) == 1
    call = enqueuer.calls[0]
    assert call["channel"] is NotificationChannelType.WEBHOOK
    assert call["recipient"] == SALES_WEBHOOK_RECIPIENT
    assert call["event_type"] is NotificationEventType.SALES_AUTOMATION_EVENT
    assert call["organization_id"] is None
    body = json.loads(str(call["body"]))
    assert body["event"] == "demo_request.created"
    assert body["occurred_at"] == "2026-09-01T06:00:00Z"
    assert body["data"] == {"lead": {"email": "a@b.example"}}
    uuid.UUID(body["event_id"])
    assert FAKE_URL not in str(call) and FAKE_SECRET not in str(call)


async def test_publisher_never_raises() -> None:
    enqueuer = FakeEnqueuer(raises=RuntimeError("outbox write failed"))

    await _enabled_publisher(enqueuer).publish(
        SalesWebhookEvent.DEMO_BOOKING_CREATED, {}
    )


def test_webhook_recipient_must_be_the_constant_label() -> None:
    validate_recipient(SALES_WEBHOOK_RECIPIENT, NotificationChannelType.WEBHOOK)
    with pytest.raises(InvalidNotificationRecipientError):
        validate_recipient(FAKE_URL, NotificationChannelType.WEBHOOK)


# ============================================================================
# 3. Delivery: verbatim body + secret header; failures go through the outbox
# ============================================================================


def _sender(handler) -> HttpxSalesWebhookSender:
    return HttpxSalesWebhookSender(
        FAKE_URL,
        FAKE_SECRET,
        timeout_seconds=1.0,
        client_factory=lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ),
    )


async def test_sender_posts_body_verbatim_with_secret_and_event_headers() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"ok": True})

    body = SalesWebhookPublisher(None, enabled=False).build_body(
        "demo_booking.created", {"booking": {"id": "b1"}}
    )
    await _sender(handler).send(body)

    assert len(seen) == 1
    request = seen[0]
    assert request.method == "POST"
    assert str(request.url) == FAKE_URL
    assert request.content.decode() == body
    assert request.headers[SECRET_HEADER] == FAKE_SECRET
    assert request.headers[EVENT_HEADER] == "demo_booking.created"
    assert request.headers[EVENT_ID_HEADER] == json.loads(body)["event_id"]
    assert request.headers["content-type"] == "application/json"


async def test_http_error_status_raises() -> None:
    sender = _sender(lambda request: httpx.Response(500, text="boom"))
    with pytest.raises(SalesWebhookDeliveryError):
        await sender.send("{}")


async def test_transport_error_never_echoes_the_url_or_secret() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connect failed", request=request)

    with pytest.raises(SalesWebhookDeliveryError) as excinfo:
        await _sender(handler).send("{}")
    assert FAKE_URL not in str(excinfo.value)
    assert FAKE_SECRET not in str(excinfo.value)
    assert excinfo.value.__cause__ is None


@dataclass
class OneRowRepository:
    delivery: NotificationDelivery

    async def list_due_deliveries(self, **_: object) -> list[NotificationDelivery]:
        return [self.delivery]

    async def update_delivery(
        self, delivery: NotificationDelivery, data: dict[str, object]
    ) -> NotificationDelivery:
        for key, value in data.items():
            setattr(delivery, key, value)
        return delivery


def _webhook_row(**overrides: object) -> NotificationDelivery:
    now = datetime.now(UTC)
    fields: dict[str, object] = {
        "id": uuid.uuid4(),
        "created_at": now,
        "updated_at": now,
        "deleted_at": None,
        "is_deleted": False,
        "created_by": None,
        "updated_by": None,
        "version": 1,
        "organization_id": None,
        "template_id": None,
        "event_type": NotificationEventType.SALES_AUTOMATION_EVENT.value,
        "channel": NotificationChannelType.WEBHOOK.value,
        "recipient": SALES_WEBHOOK_RECIPIENT,
        "subject": "demo_request.created",
        "body": '{"event":"demo_request.created"}',
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
    return NotificationDelivery(**fields)


@dataclass
class RecordingSender:
    sent: list[str] = field(default_factory=list)

    async def send(self, body: str) -> None:
        self.sent.append(body)


async def test_webhook_row_is_sent_through_the_webhook_sender() -> None:
    row = _webhook_row()
    sender = RecordingSender()
    service = NotificationService(OneRowRepository(row), sales_webhook_sender=sender)

    summary = await service.dispatch_pending(batch_size=10)

    assert summary.sent == 1
    assert sender.sent == ['{"event":"demo_request.created"}']
    assert row.status == NotificationDeliveryStatus.SENT.value


async def test_unconfigured_sender_retries_rather_than_faking_a_send() -> None:
    row = _webhook_row()
    service = NotificationService(
        OneRowRepository(row), sales_webhook_sender=UnconfiguredSalesWebhookSender()
    )

    summary = await service.dispatch_pending(batch_size=10)

    assert summary.retrying == 1
    assert row.status == NotificationDeliveryStatus.RETRYING.value
    assert row.next_attempt_at is not None


# ============================================================================
# 4. The callers
# ============================================================================


async def test_demo_request_without_publisher_is_unchanged() -> None:
    service = DemoRequestService(FakeDemoRequestRepository())
    created = await service.submit_demo_request(
        full_name="Alice Anderson",
        email="alice@example.com",
        phone=None,
        company_name="Lakeside Hotel",
        message=None,
    )
    assert created.email == "alice@example.com"


async def test_demo_request_publishes_created_with_the_lead() -> None:
    publisher = RecordingPublisher()
    service = DemoRequestService(FakeDemoRequestRepository(), sales_webhook=publisher)

    created = await service.submit_demo_request(
        full_name="  Alice Anderson ",
        email="Alice@Example.com",
        phone="+919800000000",
        company_name="Lakeside Hotel",
        message="Two cafes",
        property_type="cafe_restaurant",
        location_count=2,
    )

    assert [event for event, _ in publisher.events] == ["demo_request.created"]
    lead = publisher.events[0][1]["lead"]
    assert lead["id"] == str(created.id)
    assert lead["email"] == "alice@example.com"
    assert lead["full_name"] == "Alice Anderson"
    assert lead["property_type"] == "cafe_restaurant"
    assert lead["lead_priority"] == "multi_location"
    assert "internal_notes" not in lead


async def test_booking_publishes_created_and_cancelled_without_the_token() -> None:
    publisher = RecordingPublisher()
    service, _, _ = make_service(sales_webhook=publisher)

    result = await book(service)
    await service.cancel_booking(
        booking_id=result.booking.id,
        manage_token=result.manage_token,
        reason="Changed plans",
    )

    events = [event for event, _ in publisher.events]
    assert events == ["demo_booking.created", "demo_booking.cancelled"]
    created = publisher.events[0][1]
    assert created["booking"]["id"] == str(result.booking.id)
    assert created["booking"]["status"] == "confirmed"
    assert created["booking"]["starts_at"].startswith("2026-09-01T05:30:00")
    assert created["lead"]["status"] == "scheduled"
    assert created["lead"]["email"] == "asha@hotelblue.in"
    cancelled = publisher.events[1][1]
    assert cancelled["booking"]["status"] == "cancelled"
    assert cancelled["booking"]["cancellation_reason"] == "Changed plans"
    serialized = json.dumps(publisher.events)
    assert result.manage_token not in serialized
    assert result.booking.manage_token_hash not in serialized


async def test_event_names_match_the_documented_constants() -> None:
    assert {
        SalesWebhookEvent.DEMO_REQUEST_CREATED,
        SalesWebhookEvent.DEMO_BOOKING_CREATED,
        SalesWebhookEvent.DEMO_BOOKING_RESCHEDULED,
        SalesWebhookEvent.DEMO_BOOKING_CANCELLED,
        SalesWebhookEvent.DEMO_BOOKING_UPDATED,
    } == {
        "demo_request.created",
        "demo_booking.created",
        "demo_booking.rescheduled",
        "demo_booking.cancelled",
        "demo_booking.updated",
    }
