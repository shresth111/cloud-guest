"""FastAPI dependencies for the Router Provisioning domain.

Authorization for every endpoint here is provided entirely by RBAC's
existing ``RequirePermission`` dependency (``app.domains.rbac.dependencies``)
against the already-seeded ``router_provisioning.*``/``templates.*``
permission keys -- nothing here re-implements authorization. This module
only wires the repository/service layer, composing with
``app.domains.router`` (device lookup/creation/update, the real
``RouterService``), ``app.domains.location`` (denormalizing a
``LOCATION``-scoped variable's ``organization_id``), and RBAC (audit
logging) rather than duplicating any of them -- plus the Redis-backed
provisioning-queue dispatcher (``repository.RedisProvisioningQueueDispatcher``).

The device-facing enrollment-submission endpoint
(``POST /router-enrollment``) is deliberately excluded from any
``RequirePermission``/``CurrentUser`` dependency -- see ``router.py``'s
module docstring.
"""

from __future__ import annotations

from fastapi import Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.redis import get_redis_client
from app.database.session import get_db_session
from app.domains.location.dependencies import get_location_service
from app.domains.location.service import LocationService
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService

from .repository import (
    QueueDispatcherProtocol,
    RedisProvisioningQueueDispatcher,
    RouterProvisioningRepository,
    RouterProvisioningRepositoryProtocol,
)
from .service import RouterProvisioningService


def get_router_provisioning_repository(
    db: AsyncSession = Depends(get_db_session),
) -> RouterProvisioningRepositoryProtocol:
    return RouterProvisioningRepository(db)


def get_provisioning_queue_dispatcher(
    redis: Redis = Depends(get_redis_client),
) -> QueueDispatcherProtocol:
    return RedisProvisioningQueueDispatcher(redis)


def get_router_provisioning_service(
    repository: RouterProvisioningRepositoryProtocol = Depends(
        get_router_provisioning_repository
    ),
    router_service: RouterService = Depends(get_router_service),
    location_service: LocationService = Depends(get_location_service),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    queue_dispatcher: QueueDispatcherProtocol = Depends(
        get_provisioning_queue_dispatcher
    ),
) -> RouterProvisioningService:
    return RouterProvisioningService(
        repository,
        router_service,
        location_service,
        queue_dispatcher=queue_dispatcher,
        audit_writer=audit_repository,
    )


__all__ = [
    "get_router_provisioning_repository",
    "get_provisioning_queue_dispatcher",
    "get_router_provisioning_service",
]
