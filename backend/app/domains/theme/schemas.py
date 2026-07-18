"""Pydantic schemas for the Theme domain."""

from __future__ import annotations

import uuid
from pydantic import BaseModel, ConfigDict


class ThemeCreate(BaseModel):
    branding_id: uuid.UUID
    organization_id: uuid.UUID
    landing_page_theme: str = "modern"
    bg_image_url: str | None = None
    ad_banner_url: str | None = None
    custom_css: str | None = None
    custom_js: str | None = None
    terms_text: str | None = None
    privacy_text: str | None = None


class ThemeUpdate(BaseModel):
    landing_page_theme: str | None = None
    bg_image_url: str | None = None
    ad_banner_url: str | None = None
    custom_css: str | None = None
    custom_js: str | None = None
    terms_text: str | None = None
    privacy_text: str | None = None


class ThemeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    branding_id: uuid.UUID
    organization_id: uuid.UUID
    landing_page_theme: str
    bg_image_url: str | None
    ad_banner_url: str | None
    custom_css: str | None
    custom_js: str | None
    terms_text: str | None
    privacy_text: str | None
