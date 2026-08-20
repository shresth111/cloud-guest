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
    SPLASH_HEADLINE_MAX_LENGTH,
    SPLASH_WELCOME_MESSAGE_MAX_LENGTH,
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
    splash_headline: str | None = Field(
        default=None,
        description=(
            "Venue-authored portal headline. Capped at "
            f"{SPLASH_HEADLINE_MAX_LENGTH} characters (v7 design spec "
            "§Part 2 / W2) -- a 2-rendered-line budget measured on a "
            "360x640 device in the widest supported script. Over-limit "
            "values are rejected with a 400 carrying `max_length` and "
            "`actual_length`, never truncated. Counted over the stripped "
            "value in Unicode code points."
        ),
    )
    splash_welcome_message: str | None = Field(
        default=None,
        description=(
            "Venue-authored portal welcome message. Capped at "
            f"{SPLASH_WELCOME_MESSAGE_MAX_LENGTH} characters (v7 design "
            "spec §Part 2 / W2) -- a 3-rendered-line budget, beyond which "
            "the primary 'Connect' button is pushed below the fold. "
            "Over-limit values are rejected with a 400 carrying "
            "`max_length` and `actual_length`, never truncated. Counted "
            "over the stripped value in Unicode code points."
        ),
    )
    redirect_url: str | None = Field(default=None, max_length=500)
    otp_sms_enabled: bool = Field(default=True)
    otp_email_enabled: bool = Field(default=False)
    otp_whatsapp_enabled: bool = Field(
        default=False,
        description=(
            "Third real OTP delivery channel -- see "
            "app.domains.otp.constants.OtpChannel.WHATSAPP. Defaults off: "
            "a real send needs a Meta-approved WhatsApp Business template "
            "configured (Settings.whatsapp_twilio_content_sid), which most "
            "fresh deployments won't have set up yet."
        ),
    )
    voucher_enabled: bool = Field(default=True)
    # Real, functional login method (GuestService.login_via_password /
    # POST /guest/login/password) -- no longer the placeholder this field
    # started as. Defaults to True (the standard baseline: every guest can
    # verify once via OTP, set a password right after, and use phone/email
    # + password from then on) -- mirrors
    # app.domains.location.provisioning_service._resolve_login_methods's
    # identical "always-on baseline" default for a newly provisioned
    # location. An admin can still explicitly turn it off per location
    # (e.g. an SMS-OTP-only kiosk) via CaptivePortalConfigUpdateRequest.
    username_password_enabled: bool = Field(default=True)
    pin_login_enabled: bool = Field(
        default=False,
        description=(
            "Real, functional login method (GuestService.login_via_pin / "
            "POST /guest/login/pin) -- defaults off, unlike "
            "username_password_enabled: a PIN is a materially weaker "
            "secret, so an operator opts in per location deliberately."
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
    splash_headline: str | None = Field(
        default=None,
        description=(
            "Venue-authored portal headline. Capped at "
            f"{SPLASH_HEADLINE_MAX_LENGTH} characters (v7 design spec "
            "§Part 2 / W2) -- a 2-rendered-line budget measured on a "
            "360x640 device in the widest supported script. Over-limit "
            "values are rejected with a 400 carrying `max_length` and "
            "`actual_length`, never truncated. Counted over the stripped "
            "value in Unicode code points."
        ),
    )
    splash_welcome_message: str | None = Field(
        default=None,
        description=(
            "Venue-authored portal welcome message. Capped at "
            f"{SPLASH_WELCOME_MESSAGE_MAX_LENGTH} characters (v7 design "
            "spec §Part 2 / W2) -- a 3-rendered-line budget, beyond which "
            "the primary 'Connect' button is pushed below the fold. "
            "Over-limit values are rejected with a 400 carrying "
            "`max_length` and `actual_length`, never truncated. Counted "
            "over the stripped value in Unicode code points."
        ),
    )
    redirect_url: str | None = Field(default=None, max_length=500)
    otp_sms_enabled: bool | None = Field(default=None)
    otp_email_enabled: bool | None = Field(default=None)
    otp_whatsapp_enabled: bool | None = Field(default=None)
    voucher_enabled: bool | None = Field(default=None)
    username_password_enabled: bool | None = Field(default=None)
    pin_login_enabled: bool | None = Field(default=None)
    social_login_enabled: bool | None = Field(default=None)
    social_login_providers: list[str] | None = Field(default=None)
    business_hours_enabled: bool | None = Field(default=None)
    business_hours_timezone: str | None = Field(default=None, max_length=64)
    business_hours_schedule: dict | None = Field(default=None)
    business_hours_closed_message: str | None = Field(default=None)
    guest_font_choice: str | None = Field(
        default=None,
        max_length=20,
        description=(
            "Curated heading-font allowlist (v6 design spec §3.2): "
            "'system' | 'modern-sans' | 'editorial-serif' | 'bold-display'. "
            "Validated server-side against this exact allowlist -- never "
            "free text."
        ),
    )
    background_overlay_strength: int | None = Field(
        default=None,
        description=(
            "Guest-facing background scrim peak opacity, 0-100 (v6 design "
            "spec §4.2). Validated server-side to the full [0, 100] "
            "range; the frontend applies its own separate [15, 85] "
            "render-time guardrail on top of whatever is stored here."
        ),
    )
    background_focal_x: int | None = Field(
        default=None,
        description=(
            "Per-venue background focal point, horizontal, as a "
            "percentage of the image width, 0-100 (v7 design spec §1.4 "
            "C4). Defaults to 50, exactly today's `background-position: "
            "center`."
        ),
    )
    background_focal_y: int | None = Field(
        default=None,
        description=(
            "Per-venue background focal point, vertical, as a percentage "
            "of the image height, 0-100 (v7 design spec §1.4 C4). "
            "Defaults to 25, exactly today's `background-position: "
            "center 25%`."
        ),
    )


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
    otp_whatsapp_enabled: bool
    voucher_enabled: bool
    username_password_enabled: bool
    pin_login_enabled: bool
    social_login_enabled: bool
    social_login_providers: list[str]
    business_hours_enabled: bool
    business_hours_timezone: str
    business_hours_schedule: dict
    business_hours_closed_message: str | None
    guest_font_choice: str
    background_overlay_strength: int
    background_focal_x: int
    background_focal_y: int
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
    # Computed live at resolve time (validators.is_open_now), never a
    # stored column -- see that function's own docstring.
    is_open_now: bool
    location_country: str | None = Field(
        default=None,
        description=(
            "The resolved location's own ISO 3166-1 alpha-2 country "
            "(app.domains.location.models.Location.country), e.g. 'IN' or "
            "'US' -- NOT a phone dialing/calling code. None when this "
            "config was resolved by organization_id alone (no location "
            "context to source a country from). A real, admin-entered "
            "physical-address field, strictly more reliable than "
            "default_language for defaulting a guest-facing OTP phone "
            "field's country-calling-code prefix (e.g. 'IN' -> +91) -- "
            "see v4 captive-portal design spec §6.3. The frontend owns "
            "the alpha-2 -> dialing-code mapping; this field intentionally "
            "returns the raw ISO country, not a pre-computed '+91' string, "
            "so the mapping stays a presentation concern."
        ),
    )
    background_luminance: int | None = Field(
        default=None,
        description=(
            "Mean luma (0-100) of the resolved background image, "
            "computed once at upload by the v7 pipeline "
            "(app.domains.branding.service._process_background_image) "
            "-- v7 design spec §1.4 C3. Sourced from the organization's "
            "`brandings` row, so it is present only when the background "
            "actually came from that upload; None when this config "
            "carries its own typed-in background_image_url (nothing "
            "measured it), and None for any image uploaded before the "
            "v7 pipeline existed and not yet backfilled. **None means "
            "'not measured', never 'measured 0'** -- a black photo "
            "legitimately measures 0, and the two must not be "
            "conflated. With None the frontend uses the unconditional "
            "§1.3 scrim floor, which is AA-safe over literally any "
            "image; these values only ever let a *nice* photo use less "
            "scrim than that floor, or flip the scrim's polarity."
        ),
    )
    background_top_luminance: int | None = Field(
        default=None,
        description=(
            "Mean luma (0-100) of the top band of the resolved "
            "background image -- the zone the headline sits over "
            "(v7 §1.4 C3). Same source and same None semantics as "
            "background_luminance."
        ),
    )
    background_entropy: int | None = Field(
        default=None,
        description=(
            "Normalized histogram entropy (0-100) of the resolved "
            "background image: how *busy* it is. Feeds v7 §1.4 C5's "
            "refusal rule -- above threshold, and combined with "
            "background_top_luminance, the headline drops onto the "
            "opaque card instead of sitting on the photo, because a "
            "mathematically compliant contrast ratio still reads badly "
            "when glyph edges compete with image edges. Same source and "
            "same None semantics as background_luminance."
        ),
    )
