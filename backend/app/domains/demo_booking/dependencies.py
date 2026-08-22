"""FastAPI dependencies for the Demo Booking domain.

Wires the repository/service layer and composes three things that already
exist rather than growing local copies of any of them:

* ``app.domains.demo_request.repository.DemoRequestRepository`` -- because
  a booked demo is still a lead, and it must land in the same table, with
  the same shape, as the lead the plain form writes;
* ``app.domains.notification.service.NotificationService`` -- the existing
  outbox, which is what makes "recorded as failed, never as sent" true;
* the shared Redis client, for the per-email attempt limiter.

Every one of them is handed the *same* request-scoped ``AsyncSession``,
because FastAPI resolves ``Depends(get_db_session)`` once per request --
see ``app.domains.location.provisioning_service``'s module docstring for
the full write-up of that guarantee.
"""

from __future__ import annotations

from fastapi import Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.database.redis import get_redis_client
from app.database.session import get_db_session
from app.domains.demo_request.repository import (
    DemoRequestRepository,
)
from app.domains.notification.dependencies import get_notification_service
from app.domains.notification.service import NotificationService

from .availability import BookingWindow
from .repository import (
    DemoBookingRepository,
    DemoBookingRepositoryProtocol,
    LeadRepositoryProtocol,
)
from .service import DemoBookingService


def get_demo_booking_repository(
    db: AsyncSession = Depends(get_db_session),
) -> DemoBookingRepositoryProtocol:
    return DemoBookingRepository(db)


def get_lead_repository(
    db: AsyncSession = Depends(get_db_session),
) -> LeadRepositoryProtocol:
    return DemoRequestRepository(db)


def get_booking_window(settings: Settings = Depends(get_settings)) -> BookingWindow:
    """Resolves the availability rules once per request.

    Deliberately not cached across requests: ``blackout_dates`` and the
    working schedule are operational settings a deployment may change, and
    a cached window would keep publishing yesterday's calendar until a
    restart. Parsing is a handful of string splits.
    """
    return BookingWindow.from_settings(settings)


def get_demo_booking_service(
    repository: DemoBookingRepositoryProtocol = Depends(get_demo_booking_repository),
    lead_repository: LeadRepositoryProtocol = Depends(get_lead_repository),
    window: BookingWindow = Depends(get_booking_window),
    notification_service: NotificationService = Depends(get_notification_service),
    redis: Redis = Depends(get_redis_client),
    settings: Settings = Depends(get_settings),
) -> DemoBookingService:
    return DemoBookingService(
        repository,
        lead_repository,
        window,
        notification_service=notification_service,
        # Reuses the demo-request team inbox rather than adding a second
        # setting that could drift from it. Empty is a genuine no-op --
        # see Settings.demo_request_notify_email's own docstring.
        notify_email=settings.demo_request_notify_email,
        redis=redis,
        max_attempts_per_window=settings.demo_booking_max_attempts_per_window,
        attempt_window_minutes=settings.demo_booking_attempt_window_minutes,
        max_active_per_email=settings.demo_booking_max_active_per_email,
        lead_dedupe_minutes=settings.demo_booking_lead_dedupe_minutes,
        # Slot ids are signed with the app's existing secret rather than a
        # new setting nobody would remember to rotate. Rotating
        # jwt_secret_key invalidates in-flight slot ids, which is the
        # correct behaviour: they are short-lived UI state, and a client
        # holding a stale one gets a clean "reload the calendar" (422
        # INVALID_SLOT_ID) rather than a booking against an old schedule.
        slot_id_secret=settings.jwt_secret_key,
    )


__all__ = [
    "get_booking_window",
    "get_demo_booking_repository",
    "get_demo_booking_service",
    "get_lead_repository",
]
