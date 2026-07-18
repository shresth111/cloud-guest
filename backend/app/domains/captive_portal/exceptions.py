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
