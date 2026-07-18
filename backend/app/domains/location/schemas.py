"""Pydantic request/response schemas for the Location API.

Follows the same pydantic v2 conventions as
``app.domains.organization.schemas`` (``ConfigDict``, ``from_attributes``,
explicit ``Field`` descriptions). ``MessageResponse`` is re-exported from the
auth domain rather than duplicated, matching organization's/RBAC's own
convention.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.domains.auth.schemas import MessageResponse

from .enums import LocationStatus

__all__ = [
    "MessageResponse",
    "LocationResponse",
    "LocationListResponse",
    "LocationCreateRequest",
    "LocationUpdateRequest",
]

_SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_COUNTRY_PATTERN = re.compile(r"^[A-Za-z]{2}$")


def _validate_slug(value: str) -> str:
    normalized = value.strip().lower()
    if not _SLUG_PATTERN.match(normalized):
        raise ValueError(
            "Slug must be lowercase, URL-safe, and contain only letters, "
            "numbers, and hyphens (e.g. 'downtown-branch')"
        )
    return normalized


def _validate_country(value: str) -> str:
    normalized = value.strip().upper()
    if not _COUNTRY_PATTERN.match(normalized):
        raise ValueError("Country must be a 2-letter ISO 3166-1 alpha-2 code")
    return normalized


# ============================================================================
# Response schemas
# ============================================================================


class LocationResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    slug: str
    status: LocationStatus
    address_line1: str
    address_line2: str | None = None
    city: str
    state_province: str
    postal_code: str
    country: str
    timezone: str
    latitude: float | None = None
    longitude: float | None = None
    contact_name: str | None = None
    contact_phone: str | None = None
    contact_email: str | None = None
    settings: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class LocationListResponse(BaseModel):
    items: list[LocationResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


# ============================================================================
# Request schemas
# ============================================================================


class LocationCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    slug: str = Field(..., min_length=1, max_length=150)
    status: LocationStatus = Field(default=LocationStatus.ACTIVE)
    address_line1: str = Field(..., min_length=1, max_length=255)
    address_line2: str | None = Field(default=None, max_length=255)
    city: str = Field(..., min_length=1, max_length=100)
    state_province: str = Field(..., min_length=1, max_length=100)
    postal_code: str = Field(..., min_length=1, max_length=20)
    country: str = Field(..., min_length=2, max_length=2)
    timezone: str = Field(default="UTC", max_length=50)
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)
    contact_name: str | None = Field(default=None, max_length=200)
    contact_phone: str | None = Field(default=None, max_length=20)
    contact_email: EmailStr | None = Field(default=None)
    settings: dict[str, Any] = Field(default_factory=dict)

    @field_validator("slug")
    @classmethod
    def validate_slug(cls, value: str) -> str:
        return _validate_slug(value)

    @field_validator("country")
    @classmethod
    def validate_country(cls, value: str) -> str:
        return _validate_country(value)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Downtown Branch",
                "slug": "downtown-branch",
                "address_line1": "123 Main St",
                "city": "Austin",
                "state_province": "TX",
                "postal_code": "78701",
                "country": "US",
                "timezone": "America/Chicago",
            }
        }
    )


class LocationUpdateRequest(BaseModel):
    """Note: ``organization_id`` is deliberately not a field on this schema --
    a location's organization is immutable after creation (see
    ``docs/location/LOCATION_ARCHITECTURE.md``). ``status`` is likewise not
    settable here -- use the dedicated ``suspend``/``activate``/archive
    (``DELETE``) endpoints instead, mirroring
    ``OrganizationUpdateRequest``'s own shape.
    """

    name: str | None = Field(default=None, min_length=1, max_length=200)
    slug: str | None = Field(default=None, min_length=1, max_length=150)
    address_line1: str | None = Field(default=None, min_length=1, max_length=255)
    address_line2: str | None = Field(default=None, max_length=255)
    city: str | None = Field(default=None, min_length=1, max_length=100)
    state_province: str | None = Field(default=None, min_length=1, max_length=100)
    postal_code: str | None = Field(default=None, min_length=1, max_length=20)
    country: str | None = Field(default=None, min_length=2, max_length=2)
    timezone: str | None = Field(default=None, max_length=50)
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)
    contact_name: str | None = Field(default=None, max_length=200)
    contact_phone: str | None = Field(default=None, max_length=20)
    contact_email: EmailStr | None = Field(default=None)
    settings: dict[str, Any] | None = None

    @field_validator("slug")
    @classmethod
    def validate_slug(cls, value: str | None) -> str | None:
        return _validate_slug(value) if value is not None else value

    @field_validator("country")
    @classmethod
    def validate_country(cls, value: str | None) -> str | None:
        return _validate_country(value) if value is not None else value
