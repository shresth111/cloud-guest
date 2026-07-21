"""FastAPI dependencies for the Device Synchronization domain.

Composes ``app.domains.router``/``app.domains.connected_devices``/
``app.domains.queue_management``/``app.domains.provisioning_engine``
entirely through their own existing, already-wired FastAPI dependency
functions -- exactly the same real service graph the live API already
builds for each of those domains, never a second, parallel construction
path.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.connected_devices.dependencies import get_connected_device_service
from app.domains.connected_devices.service import ConnectedDeviceService
from app.domains.provisioning_engine.dependencies import get_provisioning_engine_service
from app.domains.provisioning_engine.service import ProvisioningEngineService
from app.domains.queue_management.dependencies import get_queue_management_service
from app.domains.queue_management.service import QueueManagementService
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService

from .repository import DeviceSyncRepository, DeviceSyncRepositoryProtocol
from .service import DeviceSyncService


def get_device_sync_repository(
    db: AsyncSession = Depends(get_db_session),
) -> DeviceSyncRepositoryProtocol:
    return DeviceSyncRepository(db)


def get_device_sync_service(
    repository: DeviceSyncRepositoryProtocol = Depends(get_device_sync_repository),
    router_service: RouterService = Depends(get_router_service),
    connected_device_service: ConnectedDeviceService = Depends(
        get_connected_device_service
    ),
    queue_management_service: QueueManagementService = Depends(
        get_queue_management_service
    ),
    provisioning_engine_service: ProvisioningEngineService = Depends(
        get_provisioning_engine_service
    ),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> DeviceSyncService:
    return DeviceSyncService(
        repository,
        router_service,
        connected_device_service,
        queue_management_service,
        provisioning_engine_service,
        audit_writer=audit_repository,
    )


__all__ = ["get_device_sync_repository", "get_device_sync_service"]
