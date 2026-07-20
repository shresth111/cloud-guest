"""FastAPI dependencies for the Queue Management Engine domain.

Authorization is provided entirely by RBAC's existing ``RequirePermission``
dependency against the extended ``bandwidth.*`` permission keys (see
``app.domains.rbac.seed`` -- this domain reuses the pre-existing
``PermissionModule.BANDWIDTH`` key rather than minting a new one; it was
seeded specifically for this concern, just under-scoped for a full-CRUD+
execute domain until this module extended its action tuple). Composes
``app.domains.router``/``app.domains.policy`` entirely through their own
existing, already-wired FastAPI dependency functions (``get_router_service``/
``get_policy_service``) -- exactly the same real service graph the live API
already builds for each of those domains, never a second, parallel
construction path.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.policy.dependencies import get_policy_service
from app.domains.policy.service import PolicyService
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService

from .repository import QueueManagementRepository, QueueManagementRepositoryProtocol
from .service import QueueManagementService


def get_queue_management_repository(
    db: AsyncSession = Depends(get_db_session),
) -> QueueManagementRepositoryProtocol:
    return QueueManagementRepository(db)


def get_queue_management_service(
    repository: QueueManagementRepositoryProtocol = Depends(
        get_queue_management_repository
    ),
    router_service: RouterService = Depends(get_router_service),
    policy_service: PolicyService = Depends(get_policy_service),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> QueueManagementService:
    return QueueManagementService(
        repository,
        router_service,
        policy_service,
        audit_writer=audit_repository,
    )


__all__ = [
    "get_queue_management_repository",
    "get_queue_management_service",
]
