"""Pydantic request/response schemas for the Captive Portal API.

All response schemas follow the same pydantic v2 conventions as every other
domain (``ConfigDict``, ``from_attributes``, explicit ``Field``
descriptions) and are wrapped in the project's standard
``ApiResponse``/``build_response`` envelope by ``router.py`` -- including
the guest-facing ``GET /captive-portal/resolve`` endpoint, mirroring
OTP's/Voucher's own guest-facing-but-still-enveloped precedent (a real
captive-portal frontend needs to parse a structured response, not a bare
model dump).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from .constants import (
    DEFAULT_LANGUAGE,
    DEFAULT_PRIMARY_COLOR,
    DEFAULT_SECONDARY_COLOR,
    DEFAULT_SUPPORTED_LANGUAGES,
    DEFAULT_THEME,
)

__all__ = [
    "CaptivePortalConfigCreateRequest",
    "CaptivePortalConfigUpdateRequest",
    "CaptivePortalConfigResponse",
    "CaptivePortalConfigListResponse",
    "ResolvedCaptivePortalConfigResponse",
]


# ============================================================================
# Request schemas
# ============================================================================


class CaptivePortalConfigCreateRequest(BaseModel):
    organization_id: uuid.UUID
    location_id: uuid.UUID | None = Field(
        default=None,
        description=(
            "Null means this is the organization's default portal config, "
            "used by any location without its own override. Non-null means "
            "a location-specific override for this exact location."
        ),
    )
    name: str = Field(..., min_length=1, max_length=200)
    is_active: bool = Field(default=True)
    is_default: bool = Field(
        default=False,
        description=(
            "Only settable when location_id is null. Setting this un-"
            "defaults any prior default config for the same organization."
        ),
    )
    theme: str = Field(default=DEFAULT_THEME.value, max_length=20)
    logo_url: str | None = Field(default=None, max_length=500)
    background_image_url: str | None = Field(default=None, max_length=500)
    primary_color: str = Field(default=DEFAULT_PRIMARY_COLOR, max_length=7)
    secondary_color: str = Field(default=DEFAULT_SECONDARY_COLOR, max_length=7)
    default_language: str = Field(default=DEFAULT_LANGUAGE, max_length=10)
    supported_languages: list[str] = Field(
        default_factory=lambda: list(DEFAULT_SUPPORTED_LANGUAGES)
    )
    advertisement_banner_url: str | None = Field(default=None, max_length=500)
    advertisement_banner_link: str | None = Field(default=None, max_length=500)
    terms_and_conditions_text: str | None = Field(default=None)
    terms_and_conditions_url: str | None = Field(default=None, max_length=500)
    privacy_policy_text: str | None = Field(default=None)
    privacy_policy_url: str | None = Field(default=None, max_length=500)
    splash_headline: str | None = Field(default=None, max_length=200)
    splash_welcome_message: str | None = Field(default=None)
    redirect_url: str | None = Field(default=None, max_length=500)
    otp_sms_enabled: bool = Field(default=True)
    otp_email_enabled: bool = Field(default=False)
    voucher_enabled: bool = Field(default=True)
    username_password_enabled: bool = Field(
        default=False,
        description=(
            "Schema-only placeholder -- no Guest model exists yet to "
            "authenticate a username/password against."
        ),
    )
    social_login_enabled: bool = Field(
        default=False,
        description=(
            "Schema-only readiness flag -- no real OAuth/social-login "
            "integration exists anywhere in this codebase. Setting this "
            "only changes what the resolve response reports as enabled."
        ),
    )
    social_login_providers: list[str] = Field(
        default_factory=list,
        description=(
            "Forward-compatible extension point (e.g. ['google', "
            "'facebook']) -- stored and returned verbatim, never validated "
            "against a real provider registry since none exists."
        ),
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "organization_id": "00000000-0000-0000-0000-000000000000",
                "location_id": None,
                "name": "Default Portal",
                "is_active": True,
                "is_default": True,
                "theme": "light",
                "primary_color": "#1A73E8",
                "secondary_color": "#FFFFFF",
                "default_language": "en",
                "supported_languages": ["en"],
                "splash_headline": "Welcome!",
                "otp_sms_enabled": True,
                "voucher_enabled": True,
            }
        }
    )


class CaptivePortalConfigUpdateRequest(BaseModel):
    """Note: ``organization_id``/``location_id`` are deliberately not
    fields on this schema -- both are immutable after creation, mirroring
    ``LocationUpdateRequest``'s identical convention for
    ``organization_id``. Use the dedicated ``activate``/``deactivate``
    endpoints to toggle ``is_active`` if preferred, though it may also be
    set directly here."""

    name: str | None = Field(default=None, min_length=1, max_length=200)
    is_active: bool | None = Field(default=None)
    is_default: bool | None = Field(default=None)
    theme: str | None = Field(default=None, max_length=20)
    logo_url: str | None = Field(default=None, max_length=500)
    background_image_url: str | None = Field(default=None, max_length=500)
    primary_color: str | None = Field(default=None, max_length=7)
    secondary_color: str | None = Field(default=None, max_length=7)
    default_language: str | None = Field(default=None, max_length=10)
    supported_languages: list[str] | None = Field(default=None)
    advertisement_banner_url: str | None = Field(default=None, max_length=500)
    advertisement_banner_link: str | None = Field(default=None, max_length=500)
    terms_and_conditions_text: str | None = Field(default=None)
    terms_and_conditions_url: str | None = Field(default=None, max_length=500)
    privacy_policy_text: str | None = Field(default=None)
    privacy_policy_url: str | None = Field(default=None, max_length=500)
    splash_headline: str | None = Field(default=None, max_length=200)
    splash_welcome_message: str | None = Field(default=None)
    redirect_url: str | None = Field(default=None, max_length=500)
    otp_sms_enabled: bool | None = Field(default=None)
    otp_email_enabled: bool | None = Field(default=None)
    voucher_enabled: bool | None = Field(default=None)
    username_password_enabled: bool | None = Field(default=None)
    social_login_enabled: bool | None = Field(default=None)
    social_login_providers: list[str] | None = Field(default=None)


# ============================================================================
# Response schemas
# ============================================================================


class CaptivePortalConfigResponse(BaseModel):
    id: str
    organization_id: str
    location_id: str | None
    name: str
    is_active: bool
    is_default: bool
    theme: str
    logo_url: str | None
    background_image_url: str | None
    primary_color: str
    secondary_color: str
    default_language: str
    supported_languages: list[str]
    advertisement_banner_url: str | None
    advertisement_banner_link: str | None
    terms_and_conditions_text: str | None
    terms_and_conditions_url: str | None
    privacy_policy_text: str | None
    privacy_policy_url: str | None
    splash_headline: str | None
    splash_welcome_message: str | None
    redirect_url: str | None
    otp_sms_enabled: bool
    otp_email_enabled: bool
    voucher_enabled: bool
    username_password_enabled: bool
    social_login_enabled: bool
    social_login_providers: list[str]
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CaptivePortalConfigListResponse(BaseModel):
    items: list[CaptivePortalConfigResponse]
    page: int
    page_size: int
    total_items: int
    total_pages: int
    has_next: bool
    has_previous: bool


class ResolvedCaptivePortalConfigResponse(CaptivePortalConfigResponse):
    """Same shape as ``CaptivePortalConfigResponse`` plus one extra field
    telling the caller which resolution tier answered the lookup -- useful
    for a captive-portal frontend/integration test to confirm it received a
    location override rather than the organization default, without having
    to separately compare ``location_id`` against what it asked for."""

    resolved_via_location_override: bool
