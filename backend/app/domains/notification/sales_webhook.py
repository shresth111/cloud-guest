"""Outbound sales-automation webhook: demo-request and demo-booking
lifecycle events, POSTed as JSON to one internal endpoint (the sales team's
workflow automation), riding the notification outbox.

## Off by default

Nothing happens unless ``Settings.sales_webhook_enabled`` is true AND both
``sales_webhook_url`` and ``sales_webhook_secret`` are set. In every other
state ``SalesWebhookPublisher.enabled`` is false, ``publish`` returns
without writing a row, and the demo-request/demo-booking flows behave
exactly as they did before this module existed.

## Why the outbox and not a direct POST

``publish`` only writes a ``NotificationDelivery`` row
(``channel=WEBHOOK``), in the same session as the lead/booking it
describes, so the event commits or rolls back with the write it reports.
The existing dispatch sweep then POSTs it and retries a failure with the
outbox's own backoff (``notification_max_delivery_attempts`` /
``notification_retry_backoff_seconds``). A slow or down automation
endpoint therefore never slows a prospect's form submission and never
loses an event.

## Payload and authentication

The row's ``body`` is the JSON document that is POSTed verbatim::

    {"event_id": "<uuid4>", "event": "demo_request.created",
     "occurred_at": "<ISO-8601 UTC>", "data": {...}}

``event_id`` is stable across retries (it is in the stored body), so the
receiver can de-duplicate a redelivery. The shared secret travels in the
``X-Wyfy-Webhook-Secret`` header, added at dispatch time from ``Settings``:
like the URL, it is never written to the database and never logged.

The secret is a static shared header rather than an HMAC signature on
purpose: the receiver's stock webhook trigger can verify a header with no
custom code. The endpoint must be HTTPS in production for that to be
sound (``Settings._validate_sales_webhook_url`` refuses anything but
``https://`` outside loopback).
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import urlsplit

import httpx
from fastapi import status

from app.common.exceptions import CloudGuestError
from app.core.config import Settings
from app.core.logging import get_logger

from .constants import (
    SALES_WEBHOOK_RECIPIENT,
    NotificationChannelType,
    NotificationEventType,
)

logger = get_logger(__name__)

SECRET_HEADER = "X-Wyfy-Webhook-Secret"
EVENT_HEADER = "X-Wyfy-Event"
EVENT_ID_HEADER = "X-Wyfy-Event-Id"


class SalesWebhookEvent:
    """The event names this module emits -- plain strings in the JSON body,
    so the receiver can route on them."""

    DEMO_REQUEST_CREATED = "demo_request.created"
    DEMO_BOOKING_CREATED = "demo_booking.created"
    DEMO_BOOKING_RESCHEDULED = "demo_booking.rescheduled"
    DEMO_BOOKING_CANCELLED = "demo_booking.cancelled"
    DEMO_BOOKING_UPDATED = "demo_booking.updated"


class SalesWebhookDeliveryError(CloudGuestError):
    """A real POST failed. Caught by
    ``NotificationService._attempt_delivery``'s blanket handler and turned
    into ``RETRYING``/``FAILED`` like any other provider failure."""

    def __init__(self, message: str) -> None:
        super().__init__(
            f"Sales webhook delivery failed: {message}",
            status_code=status.HTTP_502_BAD_GATEWAY,
        )


class SalesWebhookNotConfiguredError(CloudGuestError):
    def __init__(self) -> None:
        super().__init__(
            "The sales webhook is not configured (disabled, or URL/secret empty)",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )


class SalesWebhookSenderProtocol(Protocol):
    async def send(self, body: str) -> None: ...


def is_sales_webhook_configured(settings: Settings) -> bool:
    return bool(
        settings.sales_webhook_enabled
        and settings.sales_webhook_url.strip()
        and settings.sales_webhook_secret.strip()
    )


def _redact(url: str) -> str:
    """Host only -- the path of an automation webhook is often itself a
    guessable-or-secret identifier, so it is never logged."""
    try:
        return urlsplit(url).hostname or "<no host>"
    except ValueError:
        return "<unparseable url>"


def _event_headers(body: str) -> dict[str, str]:
    """``X-Wyfy-Event``/``X-Wyfy-Event-Id`` copied out of the stored body,
    so the receiver can route/de-duplicate before parsing. A body that is
    not the expected JSON still gets sent (the row was written by this
    module); it just carries no routing headers."""
    try:
        parsed = json.loads(body)
    except ValueError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    headers: dict[str, str] = {}
    if isinstance(parsed.get("event"), str):
        headers[EVENT_HEADER] = parsed["event"]
    if isinstance(parsed.get("event_id"), str):
        headers[EVENT_ID_HEADER] = parsed["event_id"]
    return headers


class HttpxSalesWebhookSender:
    """One POST, one bounded timeout, no retry of its own -- retrying is the
    outbox's job (same reasoning as ``slack.HttpxSlackWebhookSender``)."""

    def __init__(
        self,
        url: str,
        secret: str,
        *,
        timeout_seconds: float,
        client_factory: Callable[[], httpx.AsyncClient] = httpx.AsyncClient,
    ) -> None:
        self.url = url
        self.secret = secret
        self.timeout_seconds = timeout_seconds
        self.client_factory = client_factory

    async def send(self, body: str) -> None:
        headers = {
            "Content-Type": "application/json",
            SECRET_HEADER: self.secret,
            **_event_headers(body),
        }
        try:
            async with self.client_factory() as client:
                response = await client.post(
                    self.url,
                    content=body.encode("utf-8"),
                    headers=headers,
                    timeout=self.timeout_seconds,
                )
        except httpx.HTTPError as exc:
            logger.warning(
                "sales_webhook_post_failed",
                extra={"error_type": type(exc).__name__, "host": _redact(self.url)},
            )
            # `from None`: an httpx error's repr can carry the full URL.
            raise SalesWebhookDeliveryError(
                f"HTTP request failed ({type(exc).__name__})"
            ) from None
        if response.status_code >= 400:
            raise SalesWebhookDeliveryError(
                f"HTTP {response.status_code}: {response.text[:200]}"
            )


class UnconfiguredSalesWebhookSender:
    """Raises rather than marking a row SENT. Only reachable by a row that
    was enqueued while the webhook was configured and then drained after
    it was switched off."""

    async def send(self, body: str) -> None:
        raise SalesWebhookNotConfiguredError()


def get_configured_sales_webhook_sender(
    settings: Settings,
) -> SalesWebhookSenderProtocol | None:
    if not is_sales_webhook_configured(settings):
        return None
    return HttpxSalesWebhookSender(
        settings.sales_webhook_url.strip(),
        settings.sales_webhook_secret.strip(),
        timeout_seconds=settings.sales_webhook_timeout_seconds,
    )


class _Enqueuer(Protocol):
    async def enqueue(self, **fields: object) -> object: ...


class SalesWebhookPublisher:
    """What the demo domains call. ``publish`` never raises: a webhook is a
    side channel and must never fail the lead/booking write it reports
    (the same posture ``DemoRequestService._notify_team`` takes)."""

    def __init__(
        self,
        notification_service: _Enqueuer | None,
        *,
        enabled: bool,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.notification_service = notification_service
        self.enabled = bool(enabled and notification_service is not None)
        self._clock = clock or (lambda: datetime.now(UTC))

    def build_body(self, event: str, data: Mapping[str, object]) -> str:
        return json.dumps(
            {
                "event_id": str(uuid.uuid4()),
                "event": event,
                "occurred_at": self._clock().isoformat().replace("+00:00", "Z"),
                "data": dict(data),
            },
            default=str,
            separators=(",", ":"),
        )

    async def publish(self, event: str, data: Mapping[str, object]) -> None:
        if not self.enabled:
            return
        try:
            await self.notification_service.enqueue(  # type: ignore[union-attr]
                event_type=NotificationEventType.SALES_AUTOMATION_EVENT,
                channel=NotificationChannelType.WEBHOOK,
                recipient=SALES_WEBHOOK_RECIPIENT,
                subject=event,
                body=self.build_body(event, data),
                organization_id=None,
            )
        except Exception as exc:  # noqa: BLE001 -- see class docstring
            logger.warning(
                "sales_webhook_enqueue_failed",
                extra={"event": event, "error": str(exc)},
            )


__all__ = [
    "EVENT_HEADER",
    "EVENT_ID_HEADER",
    "SECRET_HEADER",
    "HttpxSalesWebhookSender",
    "SalesWebhookDeliveryError",
    "SalesWebhookEvent",
    "SalesWebhookNotConfiguredError",
    "SalesWebhookPublisher",
    "SalesWebhookSenderProtocol",
    "UnconfiguredSalesWebhookSender",
    "get_configured_sales_webhook_sender",
    "is_sales_webhook_configured",
]
