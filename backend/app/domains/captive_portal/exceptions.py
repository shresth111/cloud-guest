"""Captive Portal domain exceptions.

All subclass ``app.common.exceptions.CloudGuestError`` so they flow through
the app-wide exception handler / ``ApiResponse`` envelope exactly like
every other domain's exception hierarchy -- no route needs its own
try/except translation.
"""

from __future__ import annotations

import uuid

from fastapi import status

from app.common.exceptions import CloudGuestError

from .constants import (
    MAX_BACKGROUND_FOCAL,
    MAX_BACKGROUND_OVERLAY_STRENGTH,
    MIN_BACKGROUND_FOCAL,
    MIN_BACKGROUND_OVERLAY_STRENGTH,
    GuestFontChoice,
)

__all__ = [
    "CaptivePortalError",
    "CaptivePortalConfigNotFoundError",
    "CrossOrganizationCaptivePortalConfigAccessError",
    "InvalidHexColorError",
    "InvalidPortalContentSourceError",
    "InvalidDefaultConfigScopeError",
    "CaptivePortalConfigNotConfiguredError",
    "MissingPortalResolutionParamsError",
    "CaptivePortalConfigImmutableFieldError",
    "InvalidBusinessHoursScheduleError",
    "InvalidGuestFontChoiceError",
    "InvalidBackgroundOverlayStrengthError",
    "InvalidBackgroundFocalPointError",
    "SplashTextTooLongError",
    "PoweredByAttributionNotEntitledError",
]


class CaptivePortalError(CloudGuestError):
    """Base exception for Captive Portal domain errors."""

    def __init__(
        self, message: str, *, status_code: int, data: dict[str, object] | None = None
    ) -> None:
        super().__init__(message, status_code=status_code, data=data)


class CaptivePortalConfigNotFoundError(CaptivePortalError):
    def __init__(self, config_id: uuid.UUID | str) -> None:
        super().__init__(
            f"Captive portal config not found: {config_id}",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class CrossOrganizationCaptivePortalConfigAccessError(CaptivePortalError):
    """A caller acting within organization A attempted to read/mutate a
    captive portal config belonging to organization B -- mirrors
    ``app.domains.voucher.exceptions.CrossOrganizationVoucherBatchAccessError``."""

    def __init__(self) -> None:
        super().__init__(
            "Cannot access a captive portal config belonging to another "
            "organization",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class InvalidHexColorError(CaptivePortalError):
    def __init__(self, field_name: str, value: str) -> None:
        super().__init__(
            f"{field_name} must be a 6-digit hex color (e.g. '#1A73E8'), got "
            f"'{value}'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class InvalidPortalContentSourceError(CaptivePortalError):
    """Both the inline-text and external-URL variant of the same content
    field (terms and conditions / privacy policy) were supplied at once --
    see ``validators.validate_single_content_source``'s docstring for why
    "both set" (not "neither set") is the condition rejected here."""

    def __init__(self, field_label: str) -> None:
        super().__init__(
            f"Provide at most one of {field_label} text or {field_label} URL, "
            "not both",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class InvalidDefaultConfigScopeError(CaptivePortalError):
    """``is_default=True`` was requested alongside a non-null
    ``location_id`` -- ``is_default`` only has meaning for an
    organization's own default config (``location_id IS NULL``); see
    ``models.CaptivePortalConfig``'s module docstring."""

    def __init__(self) -> None:
        super().__init__(
            "is_default can only be set on an organization-level config "
            "(location_id must be null)",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class CaptivePortalConfigNotConfiguredError(CaptivePortalError):
    """Neither a location-specific active config nor an organization-level
    active default config could be found -- there is no sensible
    platform-wide fallback (see ``service.CaptivePortalService
    .resolve_portal_config``'s docstring): every organization must
    configure at least a default portal before going live."""

    def __init__(self, organization_id: uuid.UUID | str) -> None:
        super().__init__(
            f"No active captive portal config is configured for "
            f"organization {organization_id} (no location override and no "
            "active organization default)",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class MissingPortalResolutionParamsError(CaptivePortalError):
    def __init__(self) -> None:
        super().__init__(
            "Either location_id or organization_id must be supplied to "
            "resolve a captive portal config",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class InvalidBusinessHoursScheduleError(CaptivePortalError):
    def __init__(self, reason: str) -> None:
        super().__init__(
            f"Invalid business hours schedule: {reason}",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class CaptivePortalConfigImmutableFieldError(CaptivePortalError):
    """``organization_id``/``location_id`` cannot be changed after creation
    -- mirrors ``app.domains.location``'s own hierarchy-immutability
    convention (``LocationOrganizationImmutableError``)."""

    def __init__(self, field_name: str) -> None:
        super().__init__(
            f"{field_name} cannot be changed after a captive portal config "
            "is created",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class InvalidGuestFontChoiceError(CaptivePortalError):
    """``guest_font_choice`` was set to something outside the curated
    4-value allowlist (v6 design spec §3.2) -- see
    ``validators.validate_guest_font_choice``. Deliberately never accepts
    free text, per the spec's explicit "never let this become free text"
    guardrail (§6.2 item 9)."""

    def __init__(self, value: str) -> None:
        allowed = ", ".join(sorted(c.value for c in GuestFontChoice))
        super().__init__(
            f"guest_font_choice must be one of [{allowed}], got '{value}'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class InvalidBackgroundOverlayStrengthError(CaptivePortalError):
    """``background_overlay_strength`` was outside the valid [0, 100]
    integer range -- see ``validators.validate_background_overlay_
    strength``. This is the stored-value range (v6 design spec §4.2), not
    the frontend's separate [15, 85] render-time guardrail (spec §4.3)."""

    def __init__(self, value: object) -> None:
        super().__init__(
            "background_overlay_strength must be an integer between "
            f"{MIN_BACKGROUND_OVERLAY_STRENGTH} and "
            f"{MAX_BACKGROUND_OVERLAY_STRENGTH}, got '{value}'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class InvalidBackgroundFocalPointError(CaptivePortalError):
    """``background_focal_x`` or ``background_focal_y`` was outside the
    valid [0, 100] integer range -- see
    ``validators.validate_background_focal_point``. Both axes are
    percentages of the image's own width/height (v7 design spec §1.4
    C4), so the range is the full 0-100 on each; there is no separate
    render-time clamp on the frontend for these, unlike
    ``background_overlay_strength``."""

    def __init__(self, axis: str, value: object) -> None:
        super().__init__(
            f"background_focal_{axis} must be an integer between "
            f"{MIN_BACKGROUND_FOCAL} and {MAX_BACKGROUND_FOCAL}, got '{value}'",
            status_code=status.HTTP_400_BAD_REQUEST,
        )


class SplashTextTooLongError(CaptivePortalError):
    """A venue-authored splash string (``splash_headline`` /
    ``splash_welcome_message``) exceeds its authoring-time length ceiling
    -- v7 design spec §Part 2 (W2).

    The ceilings and their full derivation live in ``constants.py``; the
    short version is that they are rendered-line budgets, measured on a
    360x640 device against the widest supported script, converted to
    characters. Enforced here rather than truncated at render because
    truncating would silently hide copy the venue deliberately wrote.

    Carries ``max_length``/``actual_length`` in ``data`` on purpose. The
    dashboard has to be able to say "27 of 26 characters -- 1 over" next
    to a live counter; a bare "string too long" would be a worse
    experience than the render truncation this replaces, which is the
    entire argument for validating at authoring time. 400, not 422: this
    is the same domain-validation class as every other error in this
    module (``InvalidHexColorError`` and friends), reached through the
    service layer, not through Pydantic.
    """

    def __init__(self, field_name: str, actual_length: int, max_length: int) -> None:
        self.field_name = field_name
        self.actual_length = actual_length
        self.max_length = max_length
        super().__init__(
            f"{field_name} must be at most {max_length} characters, got "
            f"{actual_length}",
            status_code=status.HTTP_400_BAD_REQUEST,
            data={
                "field": field_name,
                "max_length": max_length,
                "actual_length": actual_length,
            },
        )


class PoweredByAttributionNotEntitledError(CaptivePortalError):
    """An organization without the ``white_label`` plan feature tried to
    turn ``powered_by_enabled`` **off** -- v7 design spec §Part 3 (P4).

    402, not 403, and the distinction is the whole point: the caller holds
    ``captive_portal.update`` and is perfectly allowed to make this
    request, their *plan* just does not include the feature. A 403 would
    tell an admin to go ask for a permission that would not help them.
    Semantically identical to ``app.domains.billing.exceptions
    .FeatureNotEntitledError``; raised as a captive-portal error so the
    response carries the offending field and the feature key the caller
    would need to buy, which the billing exception does not.

    Deliberately raised only on the *transition* to ``False``. Turning
    attribution back **on** is always free, and re-submitting an already-
    ``False`` value (what a dashboard that PUTs its whole form does) is
    not a new purchase -- otherwise a tenant who downgraded could no
    longer change their own logo.
    """

    def __init__(self, organization_id: uuid.UUID, feature_key: str) -> None:
        super().__init__(
            f"Organization {organization_id}'s plan does not include the "
            f"'{feature_key}' feature, which is required to turn off the "
            "'Powered by Wyfy Guest' attribution",
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            data={
                "field": "powered_by_enabled",
                "required_feature": feature_key,
            },
        )
