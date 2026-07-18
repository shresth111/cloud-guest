"""FastAPI dependencies for the Monitoring domain.

Wires the repository/service layer, composing with ``app.domains.auth``
(auth-repository wiring check) and ``app.domains.wireguard`` (reused
handshake-staleness computation) rather than duplicating either -- the same
narrow, duck-typed ``Protocol`` composition pattern every prior domain in
this codebase establishes.
"""

from __future__ import annotations

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
from .service import MonitoringService


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


__all__ = [
    "get_monitoring_repository",
    "get_monitoring_service",
]
