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

# Authoring-time length ceilings for the two venue-authored splash strings
# -- v7 design spec §Part 2 (W2). These are *not* round numbers and are not
# taste judgements; each is the measured worst case of a real constraint,
# and the derivation is reproducible.
#
# The constraint is not "characters", it is **rendered lines above the
# fold**. W2's measured failure: on a phone the welcome message starts
# around y~255px and every wrapped line pushes the tab pill, the field, the
# terms row and the 48px primary button further down, until "Connect" is
# below the fold and the guest never sees the primary action. The spec
# fixes this at the admin end deliberately -- truncating at render would
# hide copy the venue chose to write; refusing it at authoring time tells
# them why.
#
# ---- Reference viewport: 360x640 -------------------------------------
# The narrowest *and* shortest device still in support. India is 92.44%
# Android (spec §0.5) and 360px is the long-standing Android CSS floor.
# Both halves of that number bind, and they bind independently:
#   * 360px wide  -> the text column is 360 - 2*16 (PortalShell.tsx:545's
#     `pl/pr-[max(1rem,safe-area)]`) - 2*20 (PortalCard's `p-5`, the v5
#     sizing scale Part 0 item 3 settles) = **288px**.
#   * 640px tall  -> the vertical budget below.
#
# ---- Line budget: derived, not chosen --------------------------------
# Summing the shipped components between the welcome message and the
# bottom edge of the primary CTA (AuthTabSwitcher's `p-1` + `min-h-[46px]`
# + `mb-4`; the OTP channel-chip row; PG_INPUT's `min-h-[3rem]`; the terms
# checkbox at 13px/1.375; PG_PRIMARY_BTN's `min-h-[3rem]`; the `space-y-3`
# gaps) against 12vh of shell padding, a 48px logo, `mt-3`, the `pg-title`
# h1 and `mt-1.5`, the slack left on a 360x640 device with the full
# realistic chrome (channel chips present, a venue name that wraps the h1
# to two lines) is ~87px. At `pg-body`'s 15px x 1.5 = 22.5px per line that
# is **3 lines** for the welcome message -- which independently reproduces
# W2's own observation that "three or four lines reliably buries the
# primary action".
#
# The two fields share that budget: 29.9*(headline_lines - 1) +
# 22.5*welcome_lines <= 87px admits (2 headline, 3 welcome) and
# (3 headline, 2 welcome), and nothing larger. W2 is about the welcome
# message, so the welcome message keeps its 3 lines and the headline is
# held to **2**. This is why the headline needs its own limit at all: if
# the h1 were unbounded the welcome message's own budget would not hold.
#
# ---- Characters per line: measured, per script -----------------------
# Same character count, wildly different line counts per script -- a limit
# tuned to English lets a Tamil venue bury the button anyway. Measured by
# HarfBuzz-shaping three realistic venue welcome messages per script
# (Pillow + Raqm, real system faces) and greedy-wrapping them at 288px,
# then counting the characters actually consumed by the allowed lines:
#
#   welcome, pg-body 15px/1.5, 3 lines | headline, pg-title 26px/1.15, 2 lines
#     Latin (en)        119            |   Latin (en)        40
#     Devanagari (hi)   104            |   Devanagari (hi)   55
#     Malayalam (ml)     98            |   Malayalam (ml)    31
#     Arabic (ar)        96            |   Arabic (ar)       48
#     Tamil (ta)     ->  78 <- binding |   Tamil (ta)    ->  26 <- binding
#
# Tamil binds both. One global limit per field, set by the worst supported
# script, is deliberate: the cost is that an English venue gets fewer
# characters than it strictly could, and the alternative cost is a buried
# Connect button, which is a total conversion loss rather than a minor one.
#
# ---- Correction (2026-08-20): the Tamil welcome figure ----------------
# The first pass measured Tamil at 92 using a macOS Tamil face
# (Tamil MN-class metrics, ~0.57em average text advance) -- but the
# device this budget is derived on is Android, whose Tamil face is Noto
# Sans Tamil. Measured from the actual Noto Sans Tamil file this product
# ships (wyfy-guest-website/public/fonts/noto-sans-tamil.woff2,
# per-codepoint hmtx advances weighted over realistic venue copy), Tamil
# text averages ~0.745em -- ~1.47x a Latin UI face's ~0.5em, not the
# ~1.24x the narrower macOS face implied. At 15px that is 11.2px per code
# point, so the 288px column holds floor(288/11.2) = 25 code points per
# line and 3 lines hold **78**. Greedy wrap-waste on long Tamil words can
# still cost a line below that (measured realistic strings consume 69-81
# code points in 3 lines); a character limit cannot encode word lengths,
# so 78 charges the mean advance and accepts that residual. The headline
# needed no correction: 26 is already inside Noto Tamil's 2-line capacity
# at 26px (floor(288/19.4) = 14 per line, 29 over 2 lines). The other
# scripts' figures carry the same macOS-face caveat, but Tamil binds with
# enough margin (78 vs 96+) that re-measuring them cannot change which
# script sets the limit.
#
# Counted over the **stripped** value, in Unicode code points -- exactly
# what the frontend renders (`splashWelcomeMessage?.trim()`,
# useGuestSignIn.ts:100). A dashboard counter must therefore count code
# points too: `[...value].length` in JS, never `value.length`, which is
# UTF-16 code units and double-counts emoji.
#
# If these ever need to move, the lever is the reference viewport, not
# taste: dropping 640px-tall devices from support roughly doubles the
# welcome budget, and accepting a 3-line headline on 360px Tamil costs
# the welcome message roughly a third of its allowance.
SPLASH_HEADLINE_MAX_LENGTH = 26
SPLASH_WELCOME_MESSAGE_MAX_LENGTH = 78

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
    "SPLASH_HEADLINE_MAX_LENGTH",
    "SPLASH_WELCOME_MESSAGE_MAX_LENGTH",
    "TERMS_AND_CONDITIONS_LABEL",
    "PRIVACY_POLICY_LABEL",
]
