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
    get_configured_email_providers_by_identity,
    get_configured_sms_provider,
)

from .onboarding_slack import (
    OnboardingSlackNotifier,
    resolve_master_console_base_url,
)
from .repository import NotificationRepository, NotificationRepositoryProtocol
from .service import NotificationService
from .slack import get_configured_slack_sender


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
        # Per-mailbox providers: this domain's outbox carries both
        # admin@-identity mail (password reset, new-location welcome) and
        # sales@-identity mail (demo-request notifications), so the
        # identity is chosen per row at dispatch time from
        # `constants.MAIL_IDENTITY_BY_EVENT_TYPE`, not once here.
        email_providers_by_identity=get_configured_email_providers_by_identity(
            settings
        ),
        sms_provider=get_configured_sms_provider(settings),
        # None when no webhook is configured, which is the default. The
        # service then falls back to `UnconfiguredSlackSender`, and in
        # practice no Slack row is ever enqueued in that state anyway --
        # `get_onboarding_slack_notifier` below is disabled by the same
        # condition.
        slack_sender=get_configured_slack_sender(settings),
        max_attempts=settings.notification_max_delivery_attempts,
        retry_backoff_seconds=settings.notification_retry_backoff_seconds,
    )


def get_onboarding_slack_notifier(
    notification_service: NotificationService = Depends(get_notification_service),
    settings: Settings = Depends(get_settings),
) -> OnboardingSlackNotifier:
    """The Master-console onboarding notifier, wired to the same
    request-scoped ``NotificationService`` (and therefore the same
    ``AsyncSession``) as everything else in the request.

    That shared session is the point: a success notice enqueued through
    this notifier commits with the onboarding it describes, or is rolled
    back with it. See ``onboarding_slack.py``'s "Why success rides the
    transaction and failure rides Celery".

    ``enabled`` is decided here, once, from configuration -- the routers
    that call ``notify`` never test for it and never need to know whether
    Slack is set up.
    """
    return OnboardingSlackNotifier(
        notification_service=notification_service,
        enabled=bool(settings.slack_onboarding_webhook_url.strip()),
        master_base_url=resolve_master_console_base_url(settings),
    )


__all__ = [
    "get_notification_repository",
    "get_notification_service",
    "get_onboarding_slack_notifier",
]
