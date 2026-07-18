"""FastAPI dependencies for the Monitoring domain.

Wires the repository/service layer, composing with ``app.domains.auth``
(auth-repository wiring check) and ``app.domains.wireguard`` (reused
handshake-staleness computation) rather than duplicating either -- the same
narrow, duck-typed ``Protocol`` composition pattern every prior domain in
this codebase establishes.
"""

from __future__ import annotations

import httpx
from fastapi import Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.database.redis import get_redis_client
from app.database.session import get_db_session
from app.domains.auth.dependencies import get_auth_repository
from app.domains.auth.repository import AuthRepositoryProtocol
from app.domains.wireguard.dependencies import get_wireguard_service
from app.domains.wireguard.service import WireGuardService

from .repository import MonitoringRepository, MonitoringRepositoryProtocol
from .service import (
    AlertService,
    IncidentService,
    MonitoringService,
    NotificationService,
    SlaService,
)


def get_monitoring_repository(
    db: AsyncSession = Depends(get_db_session),
) -> MonitoringRepositoryProtocol:
    return MonitoringRepository(db)


def get_monitoring_service(
    repository: MonitoringRepositoryProtocol = Depends(get_monitoring_repository),
    redis_client: Redis = Depends(get_redis_client),
    settings: Settings = Depends(get_settings),
    auth_repository: AuthRepositoryProtocol = Depends(get_auth_repository),
    wireguard_service: WireGuardService = Depends(get_wireguard_service),
) -> MonitoringService:
    return MonitoringService(
        repository,
        redis_client,
        settings,
        auth_repository=auth_repository,
        wireguard_service=wireguard_service,
    )


# A single, process-wide ``httpx.AsyncClient`` for every real outbound
# Slack/Teams/Discord/generic-Webhook notifier POST -- mirrors
# ``app.database.redis``'s own module-level ``redis_client`` singleton
# (one pooled client reused across requests, not a fresh connection per
# notification).
_http_client = httpx.AsyncClient()


def get_notification_http_client() -> httpx.AsyncClient:
    return _http_client


def get_notification_service(
    repository: MonitoringRepositoryProtocol = Depends(get_monitoring_repository),
    http_client: httpx.AsyncClient = Depends(get_notification_http_client),
) -> NotificationService:
    return NotificationService(repository, http_client)


def get_alert_service(
    repository: MonitoringRepositoryProtocol = Depends(get_monitoring_repository),
    notification_service: NotificationService = Depends(get_notification_service),
) -> AlertService:
    return AlertService(repository, notification_service=notification_service)


def get_incident_service(
    repository: MonitoringRepositoryProtocol = Depends(get_monitoring_repository),
) -> IncidentService:
    return IncidentService(repository)


def get_sla_service(
    repository: MonitoringRepositoryProtocol = Depends(get_monitoring_repository),
) -> SlaService:
    return SlaService(repository)


__all__ = [
    "get_monitoring_repository",
    "get_monitoring_service",
    "get_notification_http_client",
    "get_notification_service",
    "get_alert_service",
    "get_incident_service",
    "get_sla_service",
]
