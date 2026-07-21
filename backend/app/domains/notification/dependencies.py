"""FastAPI dependencies for the notification domain.

Wires the repository/service layer, composing with ``app.core.storage``
(object storage) and ``app.domains.otp.service``'s real-provider selectors
(see that module's own docstring) rather than duplicating either.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.storage import ObjectStorageProtocol, get_object_storage
from app.database.session import get_db_session
from app.domains.otp.service import (
    get_configured_email_provider,
    get_configured_sms_provider,
)

from .repository import NotificationRepository, NotificationRepositoryProtocol
from .service import NotificationService


def get_notification_repository(
    db: AsyncSession = Depends(get_db_session),
) -> NotificationRepositoryProtocol:
    return NotificationRepository(db)


def get_notification_service(
    repository: NotificationRepositoryProtocol = Depends(get_notification_repository),
    object_storage: ObjectStorageProtocol = Depends(get_object_storage),
    settings: Settings = Depends(get_settings),
) -> NotificationService:
    return NotificationService(
        repository,
        object_storage=object_storage,
        email_provider=get_configured_email_provider(settings),
        sms_provider=get_configured_sms_provider(settings),
        max_attempts=settings.notification_max_delivery_attempts,
        retry_backoff_seconds=settings.notification_retry_backoff_seconds,
    )


__all__ = ["get_notification_repository", "get_notification_service"]
