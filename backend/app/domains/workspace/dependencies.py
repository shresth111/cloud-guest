from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.organization.dependencies import get_organization_service
from app.domains.organization.service import OrganizationService
from app.domains.rbac.dependencies import get_rbac_service
from app.domains.rbac.service import RBACService

from .service import WorkspaceService


def get_workspace_service(
    organization_service: OrganizationService = Depends(get_organization_service),
    rbac_service: RBACService = Depends(get_rbac_service),
) -> WorkspaceService:
    return WorkspaceService(
        organization_service=organization_service,
        rbac_service=rbac_service,
    )
