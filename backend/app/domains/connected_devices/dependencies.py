"""FastAPI dependencies for the Connected Device Management domain.

Composes ``app.domains.router``/``app.domains.guest_access``/
``app.domains.guest`` entirely through their own existing, already-wired
FastAPI dependency functions (``get_router_service``/
``get_guest_access_service``/``get_guest_repository``) -- exactly the
same real service graph the live API already builds for each of those
domains, never a second, parallel construction path. Reuses
``get_guest_repository`` directly (not the full, heavy-dependency-chain
``get_guest_service``) since this domain only needs a narrow, read-only
``GuestLookupProtocol`` -- see ``service.py``'s own module docstring.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.guest.dependencies import get_guest_repository
from app.domains.guest.repository import GuestRepositoryProtocol
from app.domains.guest_access.dependencies import get_guest_access_service
from app.domains.guest_access.service import GuestAccessService
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService

from .repository import ConnectedDeviceRepository, ConnectedDeviceRepositoryProtocol
from .service import ConnectedDeviceService


def get_connected_device_repository(
    db: AsyncSession = Depends(get_db_session),
) -> ConnectedDeviceRepositoryProtocol:
    return ConnectedDeviceRepository(db)


def get_connected_device_service(
    repository: ConnectedDeviceRepositoryProtocol = Depends(
        get_connected_device_repository
    ),
    router_service: RouterService = Depends(get_router_service),
    guest_access_service: GuestAccessService = Depends(get_guest_access_service),
    guest_repository: GuestRepositoryProtocol = Depends(get_guest_repository),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> ConnectedDeviceService:
    return ConnectedDeviceService(
        repository,
        router_service,
        guest_access_service,
        guest_repository,
        audit_writer=audit_repository,
    )


__all__ = ["get_connected_device_repository", "get_connected_device_service"]
