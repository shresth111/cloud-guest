"""Pydantic schemas for the Branding domain."""

from __future__ import annotations

import uuid
from pydantic import BaseModel, ConfigDict, EmailStr, Field


class BrandingCreate(BaseModel):
    organization_id: uuid.UUID
    location_id: uuid.UUID | None = None
    company_name: str = Field(..., min_length=2, max_length=100)
    logo_url: str | None = None
    dark_logo_url: str | None = None
    light_logo_url: str | None = None
    favicon_url: str | None = None
    primary_color: str = Field("#4F46E5", pattern="^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$")
    secondary_color: str = Field("#0F172A", pattern="^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$")
    typography: str = "Inter"
    theme: str = "light"
    footer_text: str | None = None
    support_email: EmailStr | None = None
    support_phone: str | None = None
    privacy_url: str | None = None
    terms_url: str | None = None
    help_center_url: str | None = None


class BrandingUpdate(BaseModel):
    company_name: str | None = Field(None, min_length=2, max_length=100)
    logo_url: str | None = None
    dark_logo_url: str | None = None
    light_logo_url: str | None = None
    favicon_url: str | None = None
    primary_color: str | None = Field(None, pattern="^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$")
    secondary_color: str | None = Field(None, pattern="^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$")
    typography: str | None = None
    theme: str | None = None
    footer_text: str | None = None
    support_email: EmailStr | None = None
    support_phone: str | None = None
    privacy_url: str | None = None
    terms_url: str | None = None
    help_center_url: str | None = None


class BrandingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    location_id: uuid.UUID | None
    company_name: str
    logo_url: str | None
    dark_logo_url: str | None
    light_logo_url: str | None
    favicon_url: str | None
    primary_color: str
    secondary_color: str
    typography: str
    theme: str
    footer_text: str | None
    support_email: str | None
    support_phone: str | None
    privacy_url: str | None
    terms_url: str | None
    help_center_url: str | None
