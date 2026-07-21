"""Domain exceptions for the notification domain."""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError


class NotificationTemplateNotFoundError(CloudGuestError):
    def __init__(self, template_id: uuid.UUID) -> None:
        super().__init__(
            f"Notification template {template_id} not found",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class NotificationDeliveryNotFoundError(CloudGuestError):
    def __init__(self, delivery_id: uuid.UUID) -> None:
        super().__init__(
            f"Notification delivery {delivery_id} not found",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class CrossOrganizationNotificationAccessError(CloudGuestError):
    def __init__(self) -> None:
        super().__init__(
            "Cannot access a notification resource outside your organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class NotificationDeliveryNotRetryableError(CloudGuestError):
    """Raised when ``NotificationService.retry_delivery`` is called against
    a delivery that isn't in a terminal ``FAILED`` state -- only a
    genuinely stuck delivery should ever be manually retried."""

    def __init__(self, delivery_id: uuid.UUID) -> None:
        super().__init__(
            f"Notification delivery {delivery_id} is not in a retryable state",
            status_code=status.HTTP_409_CONFLICT,
        )


class InvalidNotificationRecipientError(CloudGuestError):
    def __init__(self, recipient: str, channel: str) -> None:
        super().__init__(
            f"'{recipient}' is not a valid recipient for channel '{channel}'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class NotificationTemplateNotFoundForEventError(CloudGuestError):
    """Raised by ``NotificationService.render_and_enqueue`` when no active
    template (org-specific or platform-default) exists for the requested
    ``(event_type, channel)`` pair -- distinct from
    ``NotificationTemplateNotFoundError``, which is a by-id CRUD lookup
    miss."""

    def __init__(self, event_type: str, channel: str) -> None:
        super().__init__(
            f"No active notification template for event_type='{event_type}', "
            f"channel='{channel}'",
            status_code=status.HTTP_404_NOT_FOUND,
        )
