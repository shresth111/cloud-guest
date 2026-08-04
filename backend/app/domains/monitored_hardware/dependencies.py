"""FastAPI dependencies for the Monitored Hardware domain.

Composes ``app.domains.location``/``app.domains.router`` entirely through
their own existing, already-wired FastAPI dependency functions -- exactly
the same real service graph the live API already builds for each of those
domains, mirroring ``app.domains.network_device.dependencies``'s identical
pattern.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.location.dependencies import get_location_service
from app.domains.location.service import LocationService
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService

from .repository import MonitoredHardwareRepository, MonitoredHardwareRepositoryProtocol
from .service import MonitoredHardwareService


def get_monitored_hardware_repository(
    db: AsyncSession = Depends(get_db_session),
) -> MonitoredHardwareRepositoryProtocol:
    return MonitoredHardwareRepository(db)


def get_monitored_hardware_service(
    repository: MonitoredHardwareRepositoryProtocol = Depends(
        get_monitored_hardware_repository
    ),
    location_service: LocationService = Depends(get_location_service),
    router_service: RouterService = Depends(get_router_service),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> MonitoredHardwareService:
    return MonitoredHardwareService(
        repository,
        location_service,
        router_service,
        audit_writer=audit_repository,
    )


__all__ = ["get_monitored_hardware_repository", "get_monitored_hardware_service"]
