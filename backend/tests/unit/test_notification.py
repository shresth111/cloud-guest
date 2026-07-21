"""Unit tests for the notification domain: template CRUD, ``enqueue``/
``render_and_enqueue`` (the outbox write), and ``dispatch_pending`` (the
sweep's real send + PENDING -> SENT/RETRYING/FAILED status transitions).

Follows this project's plain-``assert``/native-``async def`` style and its
"fake the narrow Protocol boundary" precedent (see
``tests/unit/test_isp_routing.py``). ``NotificationService`` is exercised
against small, hand-rolled in-memory fakes for its own repository and
every composed provider (email/SMS) -- mirrors ``test_auth.py``'s/
``test_isp_routing.py``'s identical "fake, not a real Postgres" boundary.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.notification.constants import (
    NotificationChannelType,
    NotificationDeliveryStatus,
    NotificationEventType,
)
from app.domains.notification.exceptions import (
    CrossOrganizationNotificationAccessError,
    InvalidNotificationRecipientError,
    NotificationDeliveryNotFoundError,
    NotificationDeliveryNotRetryableError,
    NotificationTemplateNotFoundError,
    NotificationTemplateNotFoundForEventError,
)
from app.domains.notification.models import NotificationDelivery, NotificationTemplate
from app.domains.notification.service import NotificationService


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


def _make_template(**overrides: object) -> NotificationTemplate:
    fields: dict[str, object] = {
        "organization_id": None,
        "event_type": NotificationEventType.PASSWORD_RESET.value,
        "channel": NotificationChannelType.EMAIL.value,
        "subject_template": "Reset your password",
        "body_template": "Hello {{first_name}}, reset here: {{reset_link}}",
        "is_active": True,
    }
    fields.update(overrides)
    return NotificationTemplate(**_base_fields(**fields))


def _make_delivery(**overrides: object) -> NotificationDelivery:
    fields: dict[str, object] = {
        "organization_id": None,
        "template_id": None,
        "event_type": NotificationEventType.PASSWORD_RESET.value,
        "channel": NotificationChannelType.EMAIL.value,
        "recipient": "guest@example.com",
        "subject": "Reset your password",
        "body": "reset link here",
        "status": NotificationDeliveryStatus.PENDING.value,
        "attempt_count": 0,
        "max_attempts": 5,
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
class FakeNotificationRepository:
    templates_by_id: dict[uuid.UUID, NotificationTemplate] = field(default_factory=dict)
    deliveries_by_id: dict[uuid.UUID, NotificationDelivery] = field(
        default_factory=dict
    )

    async def create_template(self, **fields: object) -> NotificationTemplate:
        template = _make_template(**fields)
        self.templates_by_id[template.id] = template
        return template

    async def get_template_by_id(
        self, template_id: uuid.UUID
    ) -> NotificationTemplate | None:
        return self.templates_by_id.get(template_id)

    async def find_active_template(
        self,
        *,
        organization_id: uuid.UUID | None,
        event_type: str,
        channel: str,
    ) -> NotificationTemplate | None:
        candidates = [
            t
            for t in self.templates_by_id.values()
            if t.event_type == event_type and t.channel == channel and t.is_active
        ]
        if organization_id is not None:
            org_matches = [
                t for t in candidates if t.organization_id == organization_id
            ]
            if org_matches:
                return org_matches[0]
        platform_defaults = [t for t in candidates if t.organization_id is None]
        return platform_defaults[0] if platform_defaults else None

    async def update_template(
        self, template: NotificationTemplate, data: dict[str, object]
    ) -> NotificationTemplate:
        for key, value in data.items():
            setattr(template, key, value)
        return template

    async def list_templates(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        page: int,
        page_size: int,
    ) -> tuple[list[NotificationTemplate], PaginationMeta]:
        values = list(self.templates_by_id.values())
        if requesting_organization_id is not None:
            values = [
                v for v in values if v.organization_id == requesting_organization_id
            ]
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    async def create_delivery(self, **fields: object) -> NotificationDelivery:
        delivery = _make_delivery(**fields)
        self.deliveries_by_id[delivery.id] = delivery
        return delivery

    async def get_delivery_by_id(
        self, delivery_id: uuid.UUID
    ) -> NotificationDelivery | None:
        return self.deliveries_by_id.get(delivery_id)

    async def update_delivery(
        self, delivery: NotificationDelivery, data: dict[str, object]
    ) -> NotificationDelivery:
        for key, value in data.items():
            setattr(delivery, key, value)
        return delivery

    async def list_deliveries(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        status: str | None,
        event_type: str | None,
        page: int,
        page_size: int,
    ) -> tuple[list[NotificationDelivery], PaginationMeta]:
        values = list(self.deliveries_by_id.values())
        if requesting_organization_id is not None:
            values = [
                v for v in values if v.organization_id == requesting_organization_id
            ]
        if status is not None:
            values = [v for v in values if v.status == status]
        if event_type is not None:
            values = [v for v in values if v.event_type == event_type]
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    async def list_due_deliveries(
        self, *, statuses: list[str], now: datetime, limit: int
    ) -> list[NotificationDelivery]:
        values = [
            v
            for v in self.deliveries_by_id.values()
            if v.status in statuses
            and (v.next_attempt_at is None or v.next_attempt_at <= now)
        ]
        return values[:limit]


@dataclass
class FakeEmailProvider:
    sent: list[tuple[str, str, str]] = field(default_factory=list)
    should_fail: bool = False

    async def send(self, email: str, subject: str, body: str) -> None:
        if self.should_fail:
            raise RuntimeError("simulated email provider outage")
        self.sent.append((email, subject, body))


@dataclass
class FakeSmsProvider:
    sent: list[tuple[str, str]] = field(default_factory=list)
    should_fail: bool = False

    async def send(self, phone_number: str, message: str) -> None:
        if self.should_fail:
            raise RuntimeError("simulated sms provider outage")
        self.sent.append((phone_number, message))


def _make_service(
    *, email_provider: FakeEmailProvider | None = None, sms_provider=None, **kwargs
) -> tuple[NotificationService, FakeNotificationRepository]:
    repository = FakeNotificationRepository()
    service = NotificationService(
        repository,
        email_provider=email_provider or FakeEmailProvider(),
        sms_provider=sms_provider or FakeSmsProvider(),
        **kwargs,
    )
    return service, repository


# ============================================================================
# enqueue
# ============================================================================


async def test_enqueue_creates_pending_delivery() -> None:
    service, repository = _make_service()

    delivery = await service.enqueue(
        event_type=NotificationEventType.PASSWORD_RESET,
        channel=NotificationChannelType.EMAIL,
        recipient="guest@example.com",
        subject="Reset your password",
        body="reset link here",
        organization_id=None,
    )

    assert delivery.status == NotificationDeliveryStatus.PENDING.value
    assert delivery.attempt_count == 0
    assert repository.deliveries_by_id[delivery.id] is delivery


async def test_enqueue_rejects_invalid_recipient_for_channel() -> None:
    service, _repository = _make_service()

    with pytest.raises(InvalidNotificationRecipientError):
        await service.enqueue(
            event_type=NotificationEventType.PASSWORD_RESET,
            channel=NotificationChannelType.EMAIL,
            recipient="not-an-email",
            body="reset link here",
            organization_id=None,
        )


# ============================================================================
# render_and_enqueue
# ============================================================================


async def test_render_and_enqueue_renders_active_template() -> None:
    service, repository = _make_service()
    template = await repository.create_template(
        organization_id=None,
        event_type=NotificationEventType.PASSWORD_RESET.value,
        channel=NotificationChannelType.EMAIL.value,
        subject_template="Reset for {{first_name}}",
        body_template="Hello {{first_name}}, reset here: {{reset_link}}",
        is_active=True,
    )

    delivery = await service.render_and_enqueue(
        event_type=NotificationEventType.PASSWORD_RESET,
        channel=NotificationChannelType.EMAIL,
        recipient="guest@example.com",
        organization_id=None,
        variables={"first_name": "Alex", "reset_link": "https://example.com/reset"},
    )

    assert delivery.subject == "Reset for Alex"
    assert delivery.body == "Hello Alex, reset here: https://example.com/reset"
    assert delivery.template_id == template.id


async def test_render_and_enqueue_raises_when_no_template_exists() -> None:
    service, _repository = _make_service()

    with pytest.raises(NotificationTemplateNotFoundForEventError):
        await service.render_and_enqueue(
            event_type=NotificationEventType.SCHEDULED_REPORT,
            channel=NotificationChannelType.EMAIL,
            recipient="guest@example.com",
            organization_id=None,
            variables={},
        )


# ============================================================================
# dispatch_pending
# ============================================================================


async def test_dispatch_pending_sends_email_and_marks_sent() -> None:
    email_provider = FakeEmailProvider()
    service, repository = _make_service(email_provider=email_provider)
    delivery = await repository.create_delivery(
        organization_id=None,
        template_id=None,
        event_type=NotificationEventType.PASSWORD_RESET.value,
        channel=NotificationChannelType.EMAIL.value,
        recipient="guest@example.com",
        subject="Reset your password",
        body="reset link here",
        status=NotificationDeliveryStatus.PENDING.value,
        attempt_count=0,
        max_attempts=5,
        next_attempt_at=None,
        sent_at=None,
        error_message=None,
        attachment_storage_key=None,
        attachment_filename=None,
        context=None,
    )

    summary = await service.dispatch_pending()

    assert summary.attempted == 1
    assert summary.sent == 1
    assert email_provider.sent == [
        ("guest@example.com", "Reset your password", "reset link here")
    ]
    assert delivery.status == NotificationDeliveryStatus.SENT.value
    assert delivery.attempt_count == 1
    assert delivery.sent_at is not None


async def test_dispatch_pending_sends_sms_for_sms_channel() -> None:
    sms_provider = FakeSmsProvider()
    service, repository = _make_service(sms_provider=sms_provider)
    await repository.create_delivery(
        organization_id=None,
        template_id=None,
        event_type=NotificationEventType.PASSWORD_RESET.value,
        channel=NotificationChannelType.SMS.value,
        recipient="+15551234567",
        subject=None,
        body="your code is 123456",
        status=NotificationDeliveryStatus.PENDING.value,
        attempt_count=0,
        max_attempts=5,
        next_attempt_at=None,
        sent_at=None,
        error_message=None,
        attachment_storage_key=None,
        attachment_filename=None,
        context=None,
    )

    summary = await service.dispatch_pending()

    assert summary.sent == 1
    assert sms_provider.sent == [("+15551234567", "your code is 123456")]


async def test_dispatch_pending_retries_on_transient_failure() -> None:
    email_provider = FakeEmailProvider(should_fail=True)
    service, repository = _make_service(
        email_provider=email_provider, retry_backoff_seconds=300
    )
    delivery = await repository.create_delivery(
        organization_id=None,
        template_id=None,
        event_type=NotificationEventType.PASSWORD_RESET.value,
        channel=NotificationChannelType.EMAIL.value,
        recipient="guest@example.com",
        subject="Reset your password",
        body="reset link here",
        status=NotificationDeliveryStatus.PENDING.value,
        attempt_count=0,
        max_attempts=5,
        next_attempt_at=None,
        sent_at=None,
        error_message=None,
        attachment_storage_key=None,
        attachment_filename=None,
        context=None,
    )

    summary = await service.dispatch_pending()

    assert summary.retrying == 1
    assert delivery.status == NotificationDeliveryStatus.RETRYING.value
    assert delivery.attempt_count == 1
    assert delivery.error_message == "simulated email provider outage"
    assert delivery.next_attempt_at is not None
    assert delivery.next_attempt_at > _now()


async def test_dispatch_pending_marks_terminal_failed_after_max_attempts() -> None:
    email_provider = FakeEmailProvider(should_fail=True)
    service, repository = _make_service(email_provider=email_provider)
    delivery = await repository.create_delivery(
        organization_id=None,
        template_id=None,
        event_type=NotificationEventType.PASSWORD_RESET.value,
        channel=NotificationChannelType.EMAIL.value,
        recipient="guest@example.com",
        subject="Reset your password",
        body="reset link here",
        status=NotificationDeliveryStatus.RETRYING.value,
        attempt_count=4,
        max_attempts=5,
        next_attempt_at=_now() - timedelta(seconds=1),
        sent_at=None,
        error_message="previous failure",
        attachment_storage_key=None,
        attachment_filename=None,
        context=None,
    )

    summary = await service.dispatch_pending()

    assert summary.failed == 1
    assert delivery.status == NotificationDeliveryStatus.FAILED.value
    assert delivery.attempt_count == 5
    assert delivery.next_attempt_at is None


async def test_dispatch_pending_ignores_deliveries_not_yet_due() -> None:
    email_provider = FakeEmailProvider()
    service, repository = _make_service(email_provider=email_provider)
    await repository.create_delivery(
        organization_id=None,
        template_id=None,
        event_type=NotificationEventType.PASSWORD_RESET.value,
        channel=NotificationChannelType.EMAIL.value,
        recipient="guest@example.com",
        subject="Reset your password",
        body="reset link here",
        status=NotificationDeliveryStatus.RETRYING.value,
        attempt_count=1,
        max_attempts=5,
        next_attempt_at=_now() + timedelta(hours=1),
        sent_at=None,
        error_message="previous failure",
        attachment_storage_key=None,
        attachment_filename=None,
        context=None,
    )

    summary = await service.dispatch_pending()

    assert summary.attempted == 0
    assert email_provider.sent == []


# ============================================================================
# retry_delivery
# ============================================================================


async def test_retry_delivery_resets_failed_delivery_to_pending() -> None:
    service, repository = _make_service()
    delivery = await repository.create_delivery(
        organization_id=None,
        template_id=None,
        event_type=NotificationEventType.PASSWORD_RESET.value,
        channel=NotificationChannelType.EMAIL.value,
        recipient="guest@example.com",
        subject="Reset your password",
        body="reset link here",
        status=NotificationDeliveryStatus.FAILED.value,
        attempt_count=5,
        max_attempts=5,
        next_attempt_at=None,
        sent_at=None,
        error_message="gave up",
        attachment_storage_key=None,
        attachment_filename=None,
        context=None,
    )

    retried = await service.retry_delivery(
        delivery.id, requesting_organization_id=None
    )

    assert retried.status == NotificationDeliveryStatus.PENDING.value
    assert retried.error_message is None
    assert delivery is retried


async def test_retry_delivery_rejects_non_failed_delivery() -> None:
    service, repository = _make_service()
    delivery = await repository.create_delivery(
        organization_id=None,
        template_id=None,
        event_type=NotificationEventType.PASSWORD_RESET.value,
        channel=NotificationChannelType.EMAIL.value,
        recipient="guest@example.com",
        subject="Reset your password",
        body="reset link here",
        status=NotificationDeliveryStatus.SENT.value,
        attempt_count=1,
        max_attempts=5,
        next_attempt_at=None,
        sent_at=_now(),
        error_message=None,
        attachment_storage_key=None,
        attachment_filename=None,
        context=None,
    )

    with pytest.raises(NotificationDeliveryNotRetryableError):
        await service.retry_delivery(delivery.id, requesting_organization_id=None)


async def test_retry_delivery_raises_when_not_found() -> None:
    service, _repository = _make_service()

    with pytest.raises(NotificationDeliveryNotFoundError):
        await service.retry_delivery(uuid.uuid4(), requesting_organization_id=None)


# ============================================================================
# Tenant isolation
# ============================================================================


async def test_get_delivery_rejects_cross_organization_access() -> None:
    service, repository = _make_service()
    other_org_id = uuid.uuid4()
    delivery = await repository.create_delivery(
        organization_id=other_org_id,
        template_id=None,
        event_type=NotificationEventType.PASSWORD_RESET.value,
        channel=NotificationChannelType.EMAIL.value,
        recipient="guest@example.com",
        subject="Reset your password",
        body="reset link here",
        status=NotificationDeliveryStatus.SENT.value,
        attempt_count=1,
        max_attempts=5,
        next_attempt_at=None,
        sent_at=_now(),
        error_message=None,
        attachment_storage_key=None,
        attachment_filename=None,
        context=None,
    )

    with pytest.raises(CrossOrganizationNotificationAccessError):
        await service.get_delivery(
            delivery.id, requesting_organization_id=uuid.uuid4()
        )


# ============================================================================
# Template CRUD
# ============================================================================


async def test_create_and_get_template() -> None:
    service, _repository = _make_service()

    created = await service.create_template(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=None,
        event_type=NotificationEventType.EMAIL_VERIFICATION.value,
        channel=NotificationChannelType.EMAIL.value,
        body_template="Verify: {{verification_link}}",
    )
    fetched = await service.get_template(created.id, requesting_organization_id=None)

    assert fetched is created
    assert fetched.event_type == NotificationEventType.EMAIL_VERIFICATION.value


async def test_get_template_raises_when_not_found() -> None:
    service, _repository = _make_service()

    with pytest.raises(NotificationTemplateNotFoundError):
        await service.get_template(uuid.uuid4(), requesting_organization_id=None)


async def test_update_template_applies_partial_fields() -> None:
    service, _repository = _make_service()
    created = await service.create_template(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=None,
        event_type=NotificationEventType.EMAIL_VERIFICATION.value,
        channel=NotificationChannelType.EMAIL.value,
        body_template="Verify: {{verification_link}}",
    )

    updated = await service.update_template(
        created.id,
        requesting_organization_id=None,
        data={"is_active": False},
    )

    assert updated.is_active is False
    assert updated.body_template == "Verify: {{verification_link}}"
