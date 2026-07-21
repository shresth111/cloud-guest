"""FastAPI dependencies for the Controller Logs domain.

Composes ``app.domains.provisioning_engine``/``app.domains
.router_provisioning``/``app.domains.auth``/``app.domains.guest``/
``app.domains.monitoring`` entirely through their own existing,
already-wired FastAPI dependency functions -- exactly the same real
service graph the live API already builds for each of those domains,
never a second, parallel construction path. ``ProvisionLog`` reads
compose the repository directly (``get_provisioning_engine_repository``)
since no service-level wrapper exists for that one read; guest login
history likewise composes ``GuestRepositoryProtocol`` directly (the
identical "narrow read, no need for the full, heavy-dependency-chain
service" precedent ``app.domains.connected_devices`` already
establishes).
"""

from __future__ import annotations

from fastapi import Depends

from app.domains.auth.dependencies import get_auth_service
from app.domains.auth.service import AuthService
from app.domains.guest.dependencies import get_guest_repository
from app.domains.guest.repository import GuestRepositoryProtocol
from app.domains.monitoring.dependencies import get_monitoring_service
from app.domains.monitoring.service import MonitoringService
from app.domains.provisioning_engine.dependencies import (
    get_provisioning_engine_repository,
    get_provisioning_engine_service,
)
from app.domains.provisioning_engine.repository import (
    ProvisioningEngineRepositoryProtocol,
)
from app.domains.provisioning_engine.service import ProvisioningEngineService
from app.domains.router_provisioning.dependencies import get_router_provisioning_service
from app.domains.router_provisioning.service import RouterProvisioningService

from .service import ControllerLogsService


def get_controller_logs_service(
    provisioning_engine_service: ProvisioningEngineService = Depends(
        get_provisioning_engine_service
    ),
    provisioning_engine_repository: ProvisioningEngineRepositoryProtocol = Depends(
        get_provisioning_engine_repository
    ),
    router_provisioning_service: RouterProvisioningService = Depends(
        get_router_provisioning_service
    ),
    auth_service: AuthService = Depends(get_auth_service),
    guest_repository: GuestRepositoryProtocol = Depends(get_guest_repository),
    monitoring_service: MonitoringService = Depends(get_monitoring_service),
) -> ControllerLogsService:
    return ControllerLogsService(
        provisioning_engine_service,
        provisioning_engine_repository,
        router_provisioning_service,
        router_provisioning_service,
        auth_service,
        guest_repository,
        monitoring_service,
    )


__all__ = ["get_controller_logs_service"]
