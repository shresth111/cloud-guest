"""Pydantic request/response schemas for the Organization API.

Follows the same pydantic v2 conventions as ``app.domains.auth.schemas`` /
``app.domains.rbac.schemas`` (``ConfigDict``, ``from_attributes``, explicit
``Field`` descriptions). ``MessageResponse`` is re-exported from the auth
domain rather than duplicated, matching RBAC's own convention.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.domains.auth.schemas import MessageResponse

from .enums import OrganizationStatus, OrganizationType

__all__ = [
    "MessageResponse",
    "OrganizationResponse",
    "OrganizationListResponse",
    "OrganizationCreateRequest",
    "OrganizationUpdateRequest",
    "OrganizationMemberResponse",
    "OrganizationMemberInviteRequest",
    "OrganizationBrandingRequest",
    "OrganizationBrandingResponse",
]

_SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def _validate_slug(value: str) -> str:
    normalized = value.strip().lower()
    if not _SLUG_PATTERN.match(normalized):
        raise ValueError(
            "Slug must be lowercase, URL-safe, and contain only letters, "
            "numbers, and hyphens (e.g. 'acme-corp')"
        )
    return normalized


# ============================================================================
# Response schemas
# ============================================================================


class OrganizationResponse(BaseModel):
    id: str
    name: str
    slug: str
    legal_name: str | None = None
    org_type: OrganizationType
    status: OrganizationStatus
    parent_organization_id: str | None = None
    contact_email: str
    contact_phone: str | None = None
    timezone: str
    default_locale: str
    settings: dict[str, Any] = Field(default_factory=dict)
    subscription_tier: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class OrganizationListResponse(BaseModel):
    items: list[OrganizationResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class OrganizationMemberResponse(BaseModel):
    id: str
    organization_id: str
    user_id: str
    status: str
    invited_by_user_id: str | None = None
    invited_at: datetime
    joined_at: datetime | None = None
    is_primary_contact: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# Request schemas
# ============================================================================


class OrganizationCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    slug: str = Field(..., min_length=1, max_length=150)
    legal_name: str | None = Field(default=None, max_length=255)
    org_type: OrganizationType = Field(default=OrganizationType.STANDARD)
    status: OrganizationStatus = Field(default=OrganizationStatus.ACTIVE)
    parent_organization_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "Set only when this organization is owned by an MSP-type "
            "organization; the parent must have org_type=msp."
        ),
    )
    contact_email: EmailStr = Field(..., description="Primary contact email")
    contact_phone: str | None = Field(default=None, max_length=20)
    timezone: str = Field(default="UTC", max_length=50)
    default_locale: str = Field(default="en", max_length=10)
    settings: dict[str, Any] = Field(default_factory=dict)
    subscription_tier: str | None = Field(default=None, max_length=50)

    @field_validator("slug")
    @classmethod
    def validate_slug(cls, value: str) -> str:
        return _validate_slug(value)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Acme Corp",
                "slug": "acme-corp",
                "org_type": "standard",
                "contact_email": "admin@acme.example.com",
                "timezone": "America/New_York",
            }
        }
    )


class OrganizationUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    slug: str | None = Field(default=None, min_length=1, max_length=150)
    legal_name: str | None = Field(default=None, max_length=255)
    org_type: OrganizationType | None = None
    parent_organization_id: uuid.UUID | None = None
    contact_email: EmailStr | None = None
    contact_phone: str | None = Field(default=None, max_length=20)
    timezone: str | None = Field(default=None, max_length=50)
    default_locale: str | None = Field(default=None, max_length=10)
    settings: dict[str, Any] | None = None
    subscription_tier: str | None = Field(default=None, max_length=50)

    @field_validator("slug")
    @classmethod
    def validate_slug(cls, value: str | None) -> str | None:
        return _validate_slug(value) if value is not None else value


class OrganizationMemberInviteRequest(BaseModel):
    user_id: uuid.UUID = Field(..., description="User to invite into the organization")
    is_primary_contact: bool = Field(default=False)


# ============================================================================
# Org-wide product branding (White Label) -- gated by
# ``PlanFeatureKey.WHITE_LABEL``, distinct from per-portal
# ``app.domains.captive_portal`` branding (see ``service.py``'s own
# ``get_branding``/``update_branding`` docstring).
# ============================================================================


class OrganizationBrandingRequest(BaseModel):
    app_name: str | None = Field(default=None, max_length=100)
    favicon_url: str | None = Field(default=None, max_length=500)
    support_email: EmailStr | None = None
    custom_domain: str | None = Field(default=None, max_length=255)
    primary_color: str | None = Field(default=None, max_length=20)


class OrganizationBrandingResponse(BaseModel):
    app_name: str | None = None
    favicon_url: str | None = None
    support_email: str | None = None
    custom_domain: str | None = None
    primary_color: str | None = None
