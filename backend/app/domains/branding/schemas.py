from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class BrandingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    organization_id: str
    company_name: str | None = None
    # Either the stable GET /branding/logo/raw proxy path (an uploaded
    # logo exists -- see BrandingService._resolve_logo_url) or the plain
    # text URL column (no upload, an admin typed an already-hosted URL
    # instead). `logo_is_uploaded` tells the caller which one this is --
    # the proxy path needs an authenticated blob fetch, a plain URL can
    # be hotlinked directly.
    logo_url: str | None = None
    logo_is_uploaded: bool = False
    favicon_url: str | None = None
    primary_color: str | None = None
    secondary_color: str | None = None
    accent_color: str | None = None
    theme: str = "light"
    # Freshly-generated presigned URL for the stored background_image_key,
    # not a persisted column itself -- see
    # BrandingService._resolve_background_image_url.
    background_image_url: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class BrandingUpdateRequest(BaseModel):
    company_name: str | None = Field(default=None, max_length=255)
    logo_url: str | None = Field(default=None, max_length=1024)
    favicon_url: str | None = Field(default=None, max_length=1024)
    primary_color: str | None = Field(default=None, max_length=50)
    secondary_color: str | None = Field(default=None, max_length=50)
    accent_color: str | None = Field(default=None, max_length=50)
    theme: str | None = Field(default=None, max_length=20)


class DefaultBrandingResponse(BaseModel):
    company_name: str = "CloudGuest"
    logo_url: str = "https://cloudguest.io/logo.svg"
    logo_is_uploaded: bool = False
    favicon_url: str = "https://cloudguest.io/favicon.ico"
    primary_color: str = "#4361EE"
    secondary_color: str = "#3F37C9"
    accent_color: str = "#4CC9F0"
    theme: str = "light"
    is_default: bool = True
