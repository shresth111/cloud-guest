"""Enumerations and small constants for the Captive Portal domain.

``theme`` is stored as a plain ``String`` column on
:class:`~.models.CaptivePortalConfig`, never a native PostgreSQL enum type
-- the same reason every other domain in this codebase documents
(``app.domains.otp.constants``, ``app.domains.voucher.constants``,
``app.domains.rbac.enums``): adding a new theme value never requires an
``ALTER TYPE`` migration, only a new additive ``StrEnum`` member.

**No new ``Settings`` fields.** Like ``app.domains.voucher``, this module
adds no fields to ``app.core.config.Settings`` -- every tunable default
(color defaults, supported-language defaults) lives here instead, as plain
module-level constants. Nothing in this module's own scope needs
per-environment tuning.
"""

from __future__ import annotations

import re
from enum import StrEnum


class PortalTheme(StrEnum):
    """The high-level visual theme a captive portal's frontend renders
    against. ``CUSTOM`` signals the frontend should ignore any built-in
    light/dark stylesheet and render purely from ``primary_color``/
    ``secondary_color``/``logo_url``/``background_image_url`` -- this
    module stores the *selection*, it does not itself render anything."""

    LIGHT = "light"
    DARK = "dark"
    CUSTOM = "custom"


# 6-digit hex color, leading '#' required (e.g. "#1A73E8") -- deliberately
# does not accept the 3-digit shorthand (e.g. "#FFF") or an alpha channel:
# a single, unambiguous, copy-paste-from-a-design-tool format keeps
# ``validators.validate_hex_color`` a single, simple regex rather than a
# small color-parsing library.
HEX_COLOR_PATTERN = re.compile(r"^#[0-9A-Fa-f]{6}$")

DEFAULT_THEME = PortalTheme.LIGHT
DEFAULT_PRIMARY_COLOR = "#1A73E8"
DEFAULT_SECONDARY_COLOR = "#FFFFFF"
DEFAULT_LANGUAGE = "en"
DEFAULT_SUPPORTED_LANGUAGES: tuple[str, ...] = ("en",)

# Field-label constants for the "at most one of text/url" validation --
# see validators.validate_single_content_source's docstring for why this is
# "at most one", not "exactly one".
TERMS_AND_CONDITIONS_LABEL = "terms and conditions"
PRIVACY_POLICY_LABEL = "privacy policy"

__all__ = [
    "PortalTheme",
    "HEX_COLOR_PATTERN",
    "DEFAULT_THEME",
    "DEFAULT_PRIMARY_COLOR",
    "DEFAULT_SECONDARY_COLOR",
    "DEFAULT_LANGUAGE",
    "DEFAULT_SUPPORTED_LANGUAGES",
    "TERMS_AND_CONDITIONS_LABEL",
    "PRIVACY_POLICY_LABEL",
]
