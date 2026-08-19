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


class GuestFontChoice(StrEnum):
    """The curated heading-font allowlist for the guest-facing captive
    portal -- v6 design spec §3.2 (``docs/captive-portal-v6-design-spec.md``
    in the ``cloudguest-foundation`` repo). Deliberately a small, curated
    enum, not a free-text/Google-Fonts-catalog picker: every option here is
    a real, self-hosted, perf-budgeted asset the frontend controls, not an
    unbounded promise (see the spec's §1.3 for the bug this replaces -- a
    previous admin UI had an 8-option free-text font ``<Select>`` that was
    never actually wired to any backend field at all, so a chosen font was
    silently discarded on save). Governs the heading layer only (``pg-
    display``/``pg-title``/``pg-subtitle`` on the frontend) -- body/UI text
    is unaffected by this field, always rendered in the frontend's own
    system font stack, for every venue including ones with a font chosen.

    Adding a 5th+ option later must ship its own individually-budgeted
    self-hosted asset, exactly like the first four -- see spec §6.2 item 9
    ("never let guestFontChoice become free text")."""

    SYSTEM = "system"
    MODERN_SANS = "modern-sans"
    EDITORIAL_SERIF = "editorial-serif"
    BOLD_DISPLAY = "bold-display"


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

DEFAULT_GUEST_FONT_CHOICE = GuestFontChoice.SYSTEM

# Integer 0-100, the guest-facing scrim's peak opacity as a percentage --
# v6 design spec §4.2. 55 is not arbitrary: it is defined to reproduce the
# frontend's current hardcoded 0.55 peak-opacity scrim exactly, so a venue
# migrated from v5 with no explicit value set renders pixel-identical to
# today's shipped output (see spec §4.2/§4.3 -- confirmed there to within a
# rounding hair). The [15, 85] guardrail the frontend actually renders
# within (spec §4.3's `buildGuestBackdropScrim`) is a *client-side* render
# clamp, not a stored-value constraint -- this backend stores and validates
# the admin's literal chosen number across the full [0, 100] range, so the
# UI slider's displayed value always matches what was actually saved.
DEFAULT_BACKGROUND_OVERLAY_STRENGTH = 55
MIN_BACKGROUND_OVERLAY_STRENGTH = 0
MAX_BACKGROUND_OVERLAY_STRENGTH = 100

# Per-venue background focal point, as integer percentages of the image's
# width and height -- v7 design spec §1.4 C4. 50/25 is not a taste
# judgement: it is exactly the frontend's current hardcoded
# ``background-position: center 25%``, so every existing venue renders
# byte-identically after the migration that adds these columns.
#
# Per-venue on ``captive_portal_configs`` rather than org-level on
# ``brandings`` deliberately (spec C4): the *same* shared organization
# photo should crop differently at different venues, because what is
# worth centring on is a property of the venue, not of the file. The
# measurements that genuinely describe the file
# (``background_luminance``/``_top_luminance``/``_entropy``) live on
# ``brandings`` for the mirror-image reason.
#
# Worth knowing while reading this: spec §1.1 L7 records that
# ``center 25%`` has only ever worked on desktop. A percentage
# background-position only acts along the axis where the image overflows
# its box, and with ``cover`` on a tall narrow phone box the overflow is
# horizontal -- so the vertical 25% has had nothing to act against on
# any portrait phone since it shipped. The frontend fix for that is C1
# (crop against the viewport, not the document); these columns are what
# C1 then has something useful to position *with*.
DEFAULT_BACKGROUND_FOCAL_X = 50
DEFAULT_BACKGROUND_FOCAL_Y = 25
MIN_BACKGROUND_FOCAL = 0
MAX_BACKGROUND_FOCAL = 100

# Field-label constants for the "at most one of text/url" validation --
# see validators.validate_single_content_source's docstring for why this is
# "at most one", not "exactly one".
TERMS_AND_CONDITIONS_LABEL = "terms and conditions"
PRIVACY_POLICY_LABEL = "privacy policy"

__all__ = [
    "PortalTheme",
    "GuestFontChoice",
    "HEX_COLOR_PATTERN",
    "DEFAULT_THEME",
    "DEFAULT_PRIMARY_COLOR",
    "DEFAULT_SECONDARY_COLOR",
    "DEFAULT_LANGUAGE",
    "DEFAULT_SUPPORTED_LANGUAGES",
    "DEFAULT_GUEST_FONT_CHOICE",
    "DEFAULT_BACKGROUND_OVERLAY_STRENGTH",
    "MIN_BACKGROUND_OVERLAY_STRENGTH",
    "MAX_BACKGROUND_OVERLAY_STRENGTH",
    "DEFAULT_BACKGROUND_FOCAL_X",
    "DEFAULT_BACKGROUND_FOCAL_Y",
    "MIN_BACKGROUND_FOCAL",
    "MAX_BACKGROUND_FOCAL",
    "TERMS_AND_CONDITIONS_LABEL",
    "PRIVACY_POLICY_LABEL",
]
