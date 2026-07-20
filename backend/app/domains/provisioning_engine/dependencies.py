"""FastAPI dependencies for the Provisioning Engine domain.

Authorization is provided entirely by RBAC's existing ``RequirePermission``
dependency against the newly-seeded ``provisioning_engine.*`` permission
keys (see ``app.domains.rbac.seed``) -- this module defines no permission
logic of its own. Composes ``app.domains.router``/
``app.domains.router_provisioning``/``app.domains.policy``/
``app.domains.guest`` entirely through their own existing, already-wired
FastAPI dependency functions (``get_router_service``/
``get_router_provisioning_service``/``get_policy_service``/
``get_radius_service``) -- exactly the same real service graph the live API
already builds for each of those domains, never a second, parallel
construction path. This mirrors ``app.domains.provisioning_engine.tasks``'s
own module docstring on why the full, real graph is built rather than a
lighter stand-in (that module builds it by hand because a Celery worker has
no FastAPI ``Depends`` container; this module gets it for free through one).
"""

from __future__ import annotations

from fastapi import Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.redis import get_redis_client
from app.database.session import get_db_session
from app.domains.guest.dependencies import get_radius_service
from app.domains.guest.service import RadiusService
from app.domains.policy.dependencies import get_policy_service
from app.domains.policy.service import PolicyService
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService
from app.domains.router_provisioning.dependencies import get_router_provisioning_service
from app.domains.router_provisioning.service import RouterProvisioningService

from .repository import (
    ProvisioningEngineRepository,
    ProvisioningEngineRepositoryProtocol,
    QueueDispatcherProtocol,
    RedisProvisionEngineQueueDispatcher,
)
from .service import ProvisioningEngineService


def get_provisioning_engine_repository(
    db: AsyncSession = Depends(get_db_session),
) -> ProvisioningEngineRepositoryProtocol:
    return ProvisioningEngineRepository(db)


def get_provisioning_engine_queue_dispatcher(
    redis: Redis = Depends(get_redis_client),
) -> QueueDispatcherProtocol:
    return RedisProvisionEngineQueueDispatcher(redis)


def get_provisioning_engine_service(
    repository: ProvisioningEngineRepositoryProtocol = Depends(
        get_provisioning_engine_repository
    ),
    router_service: RouterService = Depends(get_router_service),
    router_provisioning_service: RouterProvisioningService = Depends(
        get_router_provisioning_service
    ),
    policy_service: PolicyService = Depends(get_policy_service),
    radius_service: RadiusService = Depends(get_radius_service),
    queue_dispatcher: QueueDispatcherProtocol = Depends(
        get_provisioning_engine_queue_dispatcher
    ),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> ProvisioningEngineService:
    return ProvisioningEngineService(
        repository,
        router_service,
        router_provisioning_service,
        policy_service,
        radius_service,
        queue_dispatcher=queue_dispatcher,
        audit_writer=audit_repository,
    )


__all__ = [
    "get_provisioning_engine_repository",
    "get_provisioning_engine_queue_dispatcher",
    "get_provisioning_engine_service",
]
