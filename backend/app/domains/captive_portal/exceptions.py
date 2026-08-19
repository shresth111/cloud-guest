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
        # Retained as an attribute so the negative resolve-cache entry can
        # record *which* organization resolved to "not configured" -- see
        # ``service._NOT_CONFIGURED_MARKER`` (design spec §5 S10). Without
        # it the cached negative could not reconstruct this same error, nor
        # be indexed for organization-scoped invalidation.
        self.organization_id = organization_id
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
