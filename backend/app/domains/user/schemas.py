"""Pydantic request/response schemas for the User management API.

Follows the same pydantic v2 conventions as ``app.domains.organization
.schemas``/``app.domains.location.schemas`` (``ConfigDict``,
``from_attributes``, explicit ``Field`` descriptions). ``MessageResponse``
is re-exported from the auth domain rather than duplicated, matching every
other domain's own convention.

``UserCreateRequest``/``UserUpdateRequest`` (admin) and ``MeUpdateRequest``
(self) are deliberately three separate schemas, not one schema reused with
``exclude_unset``-based field filtering alone -- the *set* of fields each
one exposes is itself part of the security boundary (see
``app.domains.user.service.ADMIN_EDITABLE_FIELDS``/``SELF_EDITABLE_FIELDS``):
a user must not even be able to *submit* ``is_verified`` on their own
profile update, not merely have it silently ignored.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.domains.auth.schemas import MessageResponse
from app.domains.rbac.enums import ScopeType

__all__ = [
    "MessageResponse",
    "UserResponse",
    "UserListResponse",
    "OrganizationMembershipSummary",
    "RoleSummary",
    "UserDetailResponse",
    "UserCreateRequest",
    "UserUpdateRequest",
    "MeUpdateRequest",
]


def _validate_username(value: str) -> str:
    if not all(char.isalnum() or char in "_-" for char in value):
        raise ValueError(
            "Username can only contain letters, numbers, underscores, and hyphens"
        )
    return value.lower()


# ============================================================================
# Response schemas
# ============================================================================


class UserResponse(BaseModel):
    """Identity fields only -- the shape returned by list/create/update and
    embedded in ``UserDetailResponse``. Deliberately mirrors
    ``auth.schemas.UserResponse``'s field set rather than importing it, so
    this domain's response contract can evolve independently of auth's own
    login/register response shape."""

    id: str
    first_name: str
    last_name: str
    full_name: str
    email: EmailStr
    username: str
    phone: str | None = None
    profile_photo: str | None = None
    designation: str | None = None
    department: str | None = None
    employee_id: str | None = None
    timezone: str
    language: str
    status: str
    is_active: bool
    is_verified: bool
    data_masking_enabled: bool
    last_login_at: datetime | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserListResponse(BaseModel):
    items: list[UserResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class OrganizationMembershipSummary(BaseModel):
    organization_id: str
    organization_name: str
    status: str
    is_primary_contact: bool
    invited_at: datetime
    joined_at: datetime | None = None


class RoleSummary(BaseModel):
    id: str
    name: str
    slug: str
    scope_type: ScopeType
    organization_id: str | None = None


class UserDetailResponse(BaseModel):
    """Read-composition of identity (``auth.User``) + org memberships
    (``organization.OrganizationMember``) + active roles (``rbac.Role``) --
    see ``app.domains.user.service.UserAggregate``. Not a persisted model."""

    user: UserResponse
    organizations: list[OrganizationMembershipSummary]
    roles: list[RoleSummary]


# ============================================================================
# Request schemas
# ============================================================================


class UserCreateRequest(BaseModel):
    """Admin-driven account creation -- distinct from self-service
    ``POST /auth/register``: the target user is not already authenticated,
    an administrator sets a temporary password on their behalf, and the
    account may optionally be created directly into an organization (with an
    active membership) and assigned an initial role in the same call."""

    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    email: EmailStr = Field(..., description="Email address")
    username: str = Field(
        ..., min_length=3, max_length=100, description="Unique username"
    )
    temporary_password: str = Field(
        ...,
        min_length=12,
        description=(
            "Temporary password set by the administrator (min 12 chars incl. "
            "upper, lower, digit, special char); the user should change it on "
            "first login."
        ),
    )
    phone: str | None = Field(default=None, max_length=20)
    designation: str | None = Field(default=None, max_length=100)
    department: str | None = Field(default=None, max_length=100)
    employee_id: str | None = Field(default=None, max_length=50)
    timezone: str = Field(default="UTC", max_length=50)
    language: str = Field(default="en", max_length=10)
    organization_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "If set, the new user is added as an active member of this "
            "organization in the same call."
        ),
    )
    initial_role_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "Optional convenience: assign this role (at ORGANIZATION scope, "
            "against organization_id) to the new user in the same call. "
            "Requires organization_id to also be set. For any other scope, "
            "assign the role afterward via RBAC's own "
            "POST /api/v1/users/{id}/roles."
        ),
    )

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        return _validate_username(value)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "first_name": "Jamie",
                "last_name": "Rivera",
                "email": "jamie.rivera@example.com",
                "username": "jamie_rivera",
                "temporary_password": "TempPass123!@#",
                "timezone": "America/Chicago",
                "language": "en",
            }
        }
    )


class UserUpdateRequest(BaseModel):
    """Administrator profile update. Excludes ``email``/``username`` (a
    login-identifier change is a sensitive auth-domain operation out of
    scope here) and ``is_active``/``status`` (owned exclusively by the
    dedicated ``deactivate``/``activate`` endpoints). See
    ``app.domains.user.service.ADMIN_EDITABLE_FIELDS``."""

    first_name: str | None = Field(default=None, min_length=1, max_length=100)
    last_name: str | None = Field(default=None, min_length=1, max_length=100)
    phone: str | None = Field(default=None, max_length=20)
    profile_photo: str | None = Field(default=None, max_length=500)
    designation: str | None = Field(default=None, max_length=100)
    department: str | None = Field(default=None, max_length=100)
    employee_id: str | None = Field(default=None, max_length=50)
    timezone: str | None = Field(default=None, max_length=50)
    language: str | None = Field(default=None, max_length=10)
    is_verified: bool | None = Field(
        default=None,
        description="Administrators may manually mark an account as verified.",
    )
    data_masking_enabled: bool | None = Field(
        default=None,
        description=(
            "Whether app.common.masking's Masked* fields (guest mobile/"
            "email/name, device MAC addresses) render masked for this "
            "user. True (masked) is the default for every account -- "
            "administrators explicitly flip this to False for privileged "
            "users, never the other way around via self-service."
        ),
    )


class MeUpdateRequest(BaseModel):
    """Self-service profile update -- a narrower field set than
    ``UserUpdateRequest``: a user may edit their own personal-preference
    fields but not organization-/HR-managed attributes (``designation``,
    ``department``, ``employee_id``) or their own verification/account
    status. See ``app.domains.user.service.SELF_EDITABLE_FIELDS``."""

    first_name: str | None = Field(default=None, min_length=1, max_length=100)
    last_name: str | None = Field(default=None, min_length=1, max_length=100)
    phone: str | None = Field(default=None, max_length=20)
    profile_photo: str | None = Field(default=None, max_length=500)
    timezone: str | None = Field(default=None, max_length=50)
    language: str | None = Field(default=None, max_length=10)
