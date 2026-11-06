"""FastAPI dependencies for the Demo Request domain -- wires the
repository/service layer. No tenant/location cross-reference or
audit-writer dependency is needed (a demo request is a standalone
lead-capture row), but it does compose with
``app.domains.notification.service.NotificationService`` for the
"new submission -> notify the internal team" email -- see
``service.DemoRequestService._notify_team``."""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.database.session import get_db_session
from app.domains.notification.dependencies import (
    get_notification_service,
    get_sales_webhook_publisher,
)
from app.domains.notification.sales_webhook import SalesWebhookPublisher
from app.domains.notification.service import NotificationService

from .repository import DemoRequestRepository, DemoRequestRepositoryProtocol
from .service import DemoRequestService


def get_demo_request_repository(
    db: AsyncSession = Depends(get_db_session),
) -> DemoRequestRepositoryProtocol:
    return DemoRequestRepository(db)


def get_demo_request_service(
    repository: DemoRequestRepositoryProtocol = Depends(get_demo_request_repository),
    notification_service: NotificationService = Depends(get_notification_service),
    settings: Settings = Depends(get_settings),
    sales_webhook: SalesWebhookPublisher = Depends(get_sales_webhook_publisher),
) -> DemoRequestService:
    return DemoRequestService(
        repository,
        notification_service=notification_service,
        notify_email=settings.demo_request_notify_email,
        sales_webhook=sales_webhook,
    )


__all__ = ["get_demo_request_repository", "get_demo_request_service"]
