from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, ConfigDict


class BrandingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    organization_id: str
    company_name: str | None = None
    logo_url: str | None = None
    favicon_url: str | None = None
    primary_color: str | None = None
    secondary_color: str | None = None
    accent_color: str | None = None
    theme: str = "light"
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
    favicon_url: str = "https://cloudguest.io/favicon.ico"
    primary_color: str = "#4361EE"
    secondary_color: str = "#3F37C9"
    accent_color: str = "#4CC9F0"
    theme: str = "light"
    is_default: bool = True
