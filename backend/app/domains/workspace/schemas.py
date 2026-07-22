from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel


class WorkspaceSummary(BaseModel):
    id: str
    organization_id: str
    organization_name: str
    organization_slug: str
    role: str
    plan: str | None = None
    location_count: int = 0
    router_count: int = 0
    is_active: bool = True


class WorkspaceListResponse(BaseModel):
    workspaces: list[WorkspaceSummary]


class WorkspaceCurrentResponse(BaseModel):
    workspace: WorkspaceSummary | None = None


class WorkspaceSwitchRequest(BaseModel):
    organization_id: str


class WorkspaceSwitchResponse(BaseModel):
    workspace: WorkspaceSummary
    message: str = "Workspace switched"
