from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class SuggestedRole(BaseModel):
    id: str
    name: str
    slug: str
    description: str | None = None
    permission_count: int = 0
    is_system_role: bool = False
    scope_type: str = "organization"


class SuggestedRoleListResponse(BaseModel):
    roles: list[SuggestedRole]


class PermissionTreeNode(BaseModel):
    id: str
    key: str
    name: str
    description: str | None = None
    children: list[PermissionTreeNode] | None = None


class PermissionTreeResponse(BaseModel):
    tree: list[PermissionTreeNode]


class AgentPermissionAssignRequest(BaseModel):
    permission_keys: list[str]
    role_ids: list[str] | None = None


class AgentPermissionAssignResponse(BaseModel):
    agent_id: str
    assigned_permissions: list[str]
    message: str = "Permissions assigned"
