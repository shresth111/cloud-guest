"""Pydantic request/response schemas for the RBAC API.

Follows the same pydantic v2 conventions as ``app.domains.auth.schemas``
(``ConfigDict``, ``from_attributes``, explicit ``Field`` descriptions).
``MessageResponse`` is re-exported from the auth domain rather than
duplicated -- a plain ``{message, success}`` envelope isn't RBAC-specific.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.domains.auth.schemas import MessageResponse

from .enums import OverrideEffect, PermissionAction, ScopeType

__all__ = [
    "MessageResponse",
    "PermissionGroupResponse",
    "PermissionResponse",
    "RoleResponse",
    "RoleCreateRequest",
    "RoleUpdateRequest",
    "RoleCloneRequest",
    "RolePermissionAttachRequest",
    "UserRoleAssignRequest",
    "UserRoleResponse",
    "UserRoleListResponse",
    "UserPermissionsResponse",
    "PermissionOverrideRequest",
    "PermissionOverrideResponse",
]


# ============================================================================
# Response schemas
# ============================================================================


class PermissionGroupResponse(BaseModel):
    id: str
    key: str
    name: str
    description: str | None = None
    sort_order: int

    model_config = ConfigDict(from_attributes=True)


class PermissionResponse(BaseModel):
    id: str
    permission_group_id: str
    key: str
    action: PermissionAction
    name: str
    description: str | None = None
    is_active: bool

    model_config = ConfigDict(from_attributes=True)


class RoleResponse(BaseModel):
    id: str
    name: str
    slug: str
    description: str | None = None
    is_system_role: bool
    is_template: bool
    is_active: bool
    scope_type: ScopeType
    organization_id: str | None = None
    parent_role_id: str | None = None
    permissions: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserRoleResponse(BaseModel):
    id: str
    user_id: str
    role_id: str
    scope_type: ScopeType
    organization_id: str | None = None
    location_id: str | None = None
    router_id: str | None = None
    granted_at: datetime
    granted_by: str | None = None
    expires_at: datetime | None = None
    is_active: bool

    model_config = ConfigDict(from_attributes=True)


class UserRoleListResponse(BaseModel):
    items: list[UserRoleResponse] = Field(default_factory=list)


class UserPermissionsResponse(BaseModel):
    user_id: str
    permissions: list[str] = Field(default_factory=list)


class PermissionOverrideResponse(BaseModel):
    id: str
    user_id: str
    permission_id: str
    effect: OverrideEffect
    scope_type: ScopeType
    organization_id: str | None = None
    location_id: str | None = None
    router_id: str | None = None
    reason: str | None = None
    expires_at: datetime | None = None
    is_active: bool

    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# Request schemas
# ============================================================================


class RoleCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=150)
    slug: str = Field(..., min_length=1, max_length=150)
    description: str | None = Field(default=None, max_length=2000)
    scope_type: ScopeType
    organization_id: uuid.UUID | None = Field(
        default=None,
        description="Set for an org-scoped custom role; omit for a global role.",
    )
    parent_role_id: uuid.UUID | None = Field(
        default=None, description="Optional cloning-source / inheritance parent."
    )
    is_template: bool = Field(
        default=False,
        description="Whether this custom role may itself be cloned later.",
    )
    permission_keys: list[str] = Field(default_factory=list)
    allowed_scope_types: list[ScopeType] = Field(default_factory=list)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Front Desk",
                "slug": "front-desk",
                "description": "Custom reception role for a single location.",
                "scope_type": "location",
                "permission_keys": ["guest_users.create", "guest_users.read"],
            }
        }
    )


class RoleUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=150)
    description: str | None = Field(default=None, max_length=2000)
    is_template: bool | None = None
    parent_role_id: uuid.UUID | None = None


class RoleCloneRequest(BaseModel):
    new_name: str = Field(..., min_length=1, max_length=150)
    new_slug: str = Field(..., min_length=1, max_length=150)
    target_organization_id: uuid.UUID | None = Field(
        default=None,
        description="Organization the clone belongs to; omit for a global role.",
    )


class UserRoleAssignRequest(BaseModel):
    role_id: uuid.UUID
    scope_type: ScopeType
    organization_id: uuid.UUID | None = None
    location_id: uuid.UUID | None = None
    router_id: uuid.UUID | None = None
    expires_at: datetime | None = None


class RolePermissionAttachRequest(BaseModel):
    permission_key: str = Field(..., min_length=1, max_length=150)


class PermissionOverrideRequest(BaseModel):
    permission_key: str = Field(..., min_length=1, max_length=150)
    effect: OverrideEffect
    scope_type: ScopeType = ScopeType.GLOBAL
    organization_id: uuid.UUID | None = None
    location_id: uuid.UUID | None = None
    router_id: uuid.UUID | None = None
    reason: str | None = Field(default=None, max_length=1000)
    expires_at: datetime | None = None
