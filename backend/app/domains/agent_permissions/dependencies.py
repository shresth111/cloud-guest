from __future__ import annotations

from fastapi import Depends

from app.domains.rbac.dependencies import get_rbac_service
from app.domains.rbac.service import RBACService

from .service import AgentPermissionService


def get_agent_permission_service(
    rbac_service: RBACService = Depends(get_rbac_service),
) -> AgentPermissionService:
    return AgentPermissionService(rbac_service=rbac_service)
