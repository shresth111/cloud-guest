"""FastAPI dependencies for the Analytics domain.

Wires the repository/service layer, composing with
``app.domains.guest``'s existing ``GuestAnalyticsService`` (reused directly
for guest/session aggregate queries, never reimplemented) rather than
duplicating it -- the same narrow, duck-typed ``Protocol`` composition
pattern every prior domain in this codebase establishes (see
``app.domains.monitoring.dependencies.get_platform_dashboard_service`` for
the closest existing precedent of a service composing another domain's
analytics service this same way).
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.guest.dependencies import get_guest_analytics_service
from app.domains.guest.service import GuestAnalyticsService

from .repository import AnalyticsRepository, AnalyticsRepositoryProtocol
from .service import AnalyticsService


def get_analytics_repository(
    db: AsyncSession = Depends(get_db_session),
) -> AnalyticsRepositoryProtocol:
    return AnalyticsRepository(db)


def get_analytics_service(
    repository: AnalyticsRepositoryProtocol = Depends(get_analytics_repository),
    guest_analytics_service: GuestAnalyticsService = Depends(
        get_guest_analytics_service
    ),
) -> AnalyticsService:
    return AnalyticsService(repository, guest_analytics_service)


__all__ = ["get_analytics_repository", "get_analytics_service"]
