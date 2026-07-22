"""Workspace context management service.

Allows users to view and switch between organizations they belong to.
The active workspace context is maintained client-side (the API returns
available workspaces and validates switches).
"""

from __future__ import annotations

import uuid
import logging

from app.domains.organization.service import OrganizationService
from app.domains.organization.repository import OrganizationRepositoryProtocol
from app.domains.rbac.service import RBACService
from app.domains.rbac.enums import ScopeType

from .schemas import (
    WorkspaceSummary,
    WorkspaceListResponse,
    WorkspaceCurrentResponse,
    WorkspaceSwitchResponse,
)

logger = logging.getLogger(__name__)


class WorkspaceService:
    def __init__(
        self,
        organization_service: OrganizationService,
        rbac_service: RBACService,
    ) -> None:
        self.organization_service = organization_service
        self.rbac_service = rbac_service

    async def list_workspaces(
        self, user_id: uuid.UUID
    ) -> WorkspaceListResponse:
        """List all organizations the user belongs to."""
        try:
            orgs, meta = await self.organization_service.list_organizations(
                requesting_user_id=user_id, page=1, page_size=100
            )
        except Exception:
            orgs = []

        workspace_list = []
        for org in orgs:
            try:
                role_assignments = await self.rbac_service.get_user_permissions(user_id)
                primary_role = "member"
            except Exception:
                primary_role = "member"

            workspace_list.append(
                WorkspaceSummary(
                    id=str(org.id),
                    organization_id=str(org.id),
                    organization_name=org.name,
                    organization_slug=getattr(org, "slug", ""),
                    role=primary_role,
                    plan=getattr(org, "org_type", None),
                    is_active=org.status == "active" if hasattr(org, "status") else True,
                )
            )

        return WorkspaceListResponse(workspaces=workspace_list)

    async def get_current_workspace(
        self, user_id: uuid.UUID, organization_id: uuid.UUID | None
    ) -> WorkspaceCurrentResponse:
        if not organization_id:
            return WorkspaceCurrentResponse(workspace=None)

        workspaces = await self.list_workspaces(user_id)
        for ws in workspaces.workspaces:
            if ws.organization_id == str(organization_id):
                return WorkspaceCurrentResponse(workspace=ws)

        return WorkspaceCurrentResponse(workspace=None)

    async def switch_workspace(
        self, user_id: uuid.UUID, target_organization_id: uuid.UUID
    ) -> WorkspaceSwitchResponse:
        workspaces = await self.list_workspaces(user_id)
        for ws in workspaces.workspaces:
            if ws.organization_id == str(target_organization_id):
                return WorkspaceSwitchResponse(
                    workspace=ws,
                    message=f"Switched to {ws.organization_name}",
                )

        from app.common.exceptions import CloudGuestError
        raise CloudGuestError(
            message="Organization not found or access denied",
            code="workspace_access_denied",
            status_code=403,
        )
