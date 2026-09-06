"""Pure, side-effect-free validation for the Captive Portal domain.

Mirrors ``app.domains.voucher.validators``/``app.domains.otp.validators``'s
identical discipline: no I/O, just "is this a legal input" checks the
service layer calls before touching the database.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, time
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

# Imported, never copied. This is the name the hotspot's own ``dns-name``
# and ``/ip dns static`` entry are rendered from (``_render_vlan_hotspot``),
# and the name ``render_hotspot_walled_garden`` permits a guest to reach
# before they log in. The set of names a guest may be *sent* to and the set
# they are *allowed* to reach have to be the same set; a second literal
# here is how they would come to differ, silently, on a day nobody was
# looking at both files.
from app.domains.network_config.renderers import HOTSPOT_DNS_NAME

from .constants import (
    HEX_COLOR_PATTERN,
    MAX_BACKGROUND_FOCAL,
    MAX_BACKGROUND_OVERLAY_STRENGTH,
    MIN_BACKGROUND_FOCAL,
    MIN_BACKGROUND_OVERLAY_STRENGTH,
    SPLASH_HEADLINE_MAX_LENGTH,
    SPLASH_WELCOME_MESSAGE_MAX_LENGTH,
    GuestFontChoice,
    PortalContentMode,
)
from .exceptions import (
    InvalidBackgroundFocalPointError,
    InvalidBackgroundOverlayStrengthError,
    InvalidBusinessHoursScheduleError,
    InvalidDefaultConfigScopeError,
    InvalidGuestFontChoiceError,
    InvalidHexColorError,
    InvalidPortalContentModeError,
    InvalidPortalContentSourceError,
    InvalidUserPortalUrlError,
    SplashTextTooLongError,
)

_WEEKDAYS = (
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
)
_HHMM_PATTERN = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")


def validate_hex_color(value: str, *, field_name: str) -> None:
    """Raises ``InvalidHexColorError`` unless ``value`` is a 6-digit hex
    color with a leading ``#`` (e.g. ``"#1A73E8"``)."""
    if not HEX_COLOR_PATTERN.match(value):
        raise InvalidHexColorError(field_name, value)


def validate_single_content_source(
    text_value: str | None, url_value: str | None, *, field_label: str
) -> None:
    """Raises ``InvalidPortalContentSourceError`` if **both**
    ``text_value``/``url_value`` are supplied (non-``None``, non-blank) at
    once for the same content field (terms and conditions / privacy
    policy).

    Deliberately does **not** require *exactly* one to be set -- a config
    may legitimately have neither populated yet (e.g. an admin iterating on
    branding before finalizing legal text, or a config created inactive as
    a draft). What must never happen is *both* being set at once: a
    captive portal frontend rendering this config would have no
    principled way to choose which one to show, and having both persisted
    invites them silently drifting out of sync with each other. See
    ``models.CaptivePortalConfig``'s module docstring for the full
    "content fields" write-up.
    """
    has_text = bool(text_value and text_value.strip())
    has_url = bool(url_value and url_value.strip())
    if has_text and has_url:
        raise InvalidPortalContentSourceError(field_label)


_GUEST_FONT_CHOICE_VALUES = frozenset(choice.value for choice in GuestFontChoice)


def validate_guest_font_choice(value: str) -> None:
    """Raises ``InvalidGuestFontChoiceError`` unless ``value`` is one of
    the curated 4-value allowlist (v6 design spec §3.2). Deliberately
    rejects everything else, including a syntactically-plausible font
    name -- this is a curated enum, never a free-text field, per the
    spec's own explicit guardrail (§6.2 item 9)."""
    if value not in _GUEST_FONT_CHOICE_VALUES:
        raise InvalidGuestFontChoiceError(value)


_PORTAL_CONTENT_MODE_VALUES = frozenset(mode.value for mode in PortalContentMode)


def validate_content_mode(value: str) -> None:
    """Raises ``InvalidPortalContentModeError`` unless ``value`` is one of
    ``constants.PortalContentMode``'s values. Same closed-enum-stored-as-
    string discipline as ``validate_guest_font_choice``: an unknown mode has
    no frontend renderer, so it is refused here rather than silently falling
    back to the sign-in card."""
    if value not in _PORTAL_CONTENT_MODE_VALUES:
        raise InvalidPortalContentModeError(value)


def validate_background_overlay_strength(value: object) -> None:
    """Raises ``InvalidBackgroundOverlayStrengthError`` unless ``value`` is
    a real ``int`` (``bool`` explicitly excluded -- Python's ``bool`` is a
    subclass of ``int``, and ``True``/``False`` are never a legal overlay
    strength) within ``[0, 100]`` inclusive. This is the stored-value
    range (v6 design spec §4.2) -- the frontend's own ``[15, 85]``
    guardrail (spec §4.3) is a separate, render-time-only clamp this
    module never applies, so the admin UI's slider always reflects exactly
    what was saved."""
    in_range = (
        isinstance(value, int)
        and not isinstance(value, bool)
        and MIN_BACKGROUND_OVERLAY_STRENGTH <= value <= MAX_BACKGROUND_OVERLAY_STRENGTH
    )
    if not in_range:
        raise InvalidBackgroundOverlayStrengthError(value)


def validate_background_focal_point(axis: str, value: object) -> None:
    """Raises ``InvalidBackgroundFocalPointError`` unless ``value`` is a
    real ``int`` (``bool`` excluded for the same reason
    ``validate_background_overlay_strength`` excludes it -- Python's
    ``bool`` subclasses ``int`` and ``True`` is never a legal focal
    percentage) within ``[0, 100]`` inclusive.

    ``axis`` is ``"x"`` or ``"y"``, used only to name the offending
    field in the error message. Both axes share one validator because
    they share one range: they are percentages of the image's own
    width/height (v7 design spec §1.4 C4), and CSS
    ``background-position`` accepts the full 0-100 on each."""
    in_range = (
        isinstance(value, int)
        and not isinstance(value, bool)
        and MIN_BACKGROUND_FOCAL <= value <= MAX_BACKGROUND_FOCAL
    )
    if not in_range:
        raise InvalidBackgroundFocalPointError(axis, value)


# The two venue-authored splash strings and their ceilings, so the service
# layer never has to remember which constant belongs to which field.
SPLASH_TEXT_MAX_LENGTHS: dict[str, int] = {
    "splash_headline": SPLASH_HEADLINE_MAX_LENGTH,
    "splash_welcome_message": SPLASH_WELCOME_MESSAGE_MAX_LENGTH,
}


def validate_splash_text_length(field_name: str, value: object) -> None:
    """Raises ``SplashTextTooLongError`` if ``value`` is longer than
    ``field_name``'s rendered-line budget -- v7 design spec §Part 2 (W2).
    See ``constants.py`` for how each ceiling was derived.

    ``None`` and blank pass: clearing a splash string is always legal, and
    v5 §3.2 requires a venue with no welcome message to render no line at
    all rather than filler.

    Length is counted over the **stripped** value in Unicode code points,
    because that is exactly the string the guest sees -- the frontend
    renders ``config.splashWelcomeMessage?.trim()``
    (``useGuestSignIn.ts:100``). Charging a venue for trailing whitespace
    that costs no rendered width would be a validator disagreeing with
    the renderer it exists to protect.

    A ``field_name`` with no ceiling is a no-op rather than an error, so
    this can be called unconditionally from the write path.
    """
    max_length = SPLASH_TEXT_MAX_LENGTHS.get(field_name)
    if max_length is None or not isinstance(value, str):
        return
    actual = len(value.strip())
    if actual > max_length:
        raise SplashTextTooLongError(field_name, actual, max_length)


def default_splash_headline(location_name: str) -> str:
    """The headline a venue gets before it has written one, guaranteed to
    satisfy ``SPLASH_HEADLINE_MAX_LENGTH``.

    This exists because it did not, and the omission blocked provisioning
    outright. Both provisioning paths seeded the headline as
    ``f"Welcome to {location.name}"`` and then handed it to
    ``validate_splash_text_length`` like any venue-authored string. With
    the ceiling at 26 and ``"Welcome to "`` costing 11, that left **15**
    code points for the venue's own name -- so creating a location called
    "Danda Cafe Haldwani" failed with a 400 naming ``splash_headline``, a
    field the operator had never seen, let alone filled in. Observed live
    on 2026-08-27: two `POST /api/v1/locations/provision` attempts, both
    400, the second having already drafted a config version.

    The ceiling itself is right and is deliberately not relaxed here --
    see ``constants.py`` for the derivation (2 rendered lines at 360px,
    bound by Noto Sans Tamil's ~0.745em advance). The bug was validating a
    string the machine composed against a budget written for a string a
    human composed. A generated default must fit by construction.

    Three rungs, in preference order:

    1. ``Welcome to <name>`` when it fits -- the friendly form, unchanged
       for every venue whose name is <= 15 code points, which is most.
    2. the bare ``<name>`` when the greeting is what overflowed -- a
       26-character venue name is a perfectly good headline, and losing
       the greeting is a smaller loss than losing the name.
    3. the name hard-truncated with an ellipsis, for names longer than the
       ceiling on their own.

    Counted in code points over the stripped value, matching
    ``validate_splash_text_length`` exactly, so rung 1 and rung 2 can
    never emit something that function would then reject.
    """
    name = location_name.strip()
    greeted = f"Welcome to {name}"
    if len(greeted) <= SPLASH_HEADLINE_MAX_LENGTH:
        return greeted
    if len(name) <= SPLASH_HEADLINE_MAX_LENGTH:
        return name
    # Reserve one code point for the ellipsis rather than appending past
    # the ceiling, and strip again so a truncation landing on a space does
    # not render as "Some Venue …".
    return name[: SPLASH_HEADLINE_MAX_LENGTH - 1].rstrip() + "…"


def validate_default_scope(*, is_default: bool, location_id: uuid.UUID | None) -> None:
    """Raises ``InvalidDefaultConfigScopeError`` if ``is_default=True`` is
    requested alongside a non-null ``location_id`` -- ``is_default`` only
    has meaning for an organization-level config. See
    ``models.CaptivePortalConfig``'s module docstring."""
    if is_default and location_id is not None:
        raise InvalidDefaultConfigScopeError()


def validate_business_hours_timezone(value: str) -> None:
    """Raises ``InvalidBusinessHoursScheduleError`` unless ``value`` is a
    real IANA zone name Python's own ``zoneinfo`` can load -- rejected at
    write time, not silently defaulted to UTC on first use days later."""
    try:
        ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise InvalidBusinessHoursScheduleError(
            f"'{value}' is not a real timezone name (e.g. 'Asia/Kolkata')"
        ) from exc


def validate_business_hours_schedule(schedule: dict) -> None:
    """Raises ``InvalidBusinessHoursScheduleError`` on the first malformed
    entry. A valid schedule is a dict whose keys are a subset of the
    seven lowercase weekday names; each value is either
    ``{"open": false}`` (or simply absent -- a missing day is closed all
    day, see model docstring) or ``{"open": true, "start": "HH:MM",
    "end": "HH:MM"}`` with ``start`` strictly before ``end`` (a schedule
    has no concept of a window spanning midnight -- an honest limitation,
    not silently wrapped)."""
    if not isinstance(schedule, dict):
        raise InvalidBusinessHoursScheduleError("must be an object")
    for day, entry in schedule.items():
        if day not in _WEEKDAYS:
            raise InvalidBusinessHoursScheduleError(
                f"'{day}' is not a real weekday name"
            )
        if not isinstance(entry, dict) or "open" not in entry:
            raise InvalidBusinessHoursScheduleError(
                f"{day}: must be an object with an 'open' boolean"
            )
        if entry["open"] is not True:
            continue
        start, end = entry.get("start"), entry.get("end")
        if not isinstance(start, str) or not _HHMM_PATTERN.match(start):
            raise InvalidBusinessHoursScheduleError(
                f"{day}: 'start' must be HH:MM (24-hour)"
            )
        if not isinstance(end, str) or not _HHMM_PATTERN.match(end):
            raise InvalidBusinessHoursScheduleError(
                f"{day}: 'end' must be HH:MM (24-hour)"
            )
        if start >= end:
            raise InvalidBusinessHoursScheduleError(
                f"{day}: 'start' must be before 'end' (no overnight windows)"
            )


def is_open_now(
    *, enabled: bool, timezone: str, schedule: dict, now: datetime | None = None
) -> bool:
    """Whether the venue is open right now, per ``schedule`` evaluated in
    ``timezone`` -- ``enabled=False`` always returns ``True`` (business
    hours off means always open, the previous/default behavior). A
    malformed stored timezone falls back to UTC rather than raising --
    this runs on every guest-facing portal resolve, so a bad row must
    degrade to "always open," never 500 a guest trying to connect."""
    if not enabled:
        return True
    try:
        zone = ZoneInfo(timezone)
    except (ZoneInfoNotFoundError, ValueError):
        zone = ZoneInfo("UTC")
    moment = (now or datetime.now(zone)).astimezone(zone)
    day_name = _WEEKDAYS[moment.weekday()]
    entry = schedule.get(day_name)
    if not isinstance(entry, dict) or entry.get("open") is not True:
        return False
    start, end = entry.get("start"), entry.get("end")
    if not isinstance(start, str) or not isinstance(end, str):
        return False
    try:
        start_t = time.fromisoformat(start)
        end_t = time.fromisoformat(end)
    except ValueError:
        return False
    return start_t <= moment.time() <= end_t


__all__ = [
    "validate_hex_color",
    "validate_single_content_source",
    "validate_splash_text_length",
    "default_splash_headline",
    "SPLASH_TEXT_MAX_LENGTHS",
    "validate_default_scope",
    "validate_business_hours_timezone",
    "validate_business_hours_schedule",
    "validate_guest_font_choice",
    "validate_content_mode",
    "validate_background_overlay_strength",
    "validate_background_focal_point",
    "is_open_now",
]


#: One DNS label, as RouterOS's own per-VLAN hotspot names are built:
#: ``_render_vlan_hotspot`` renders ``f"vlan{vlan.vlan_id}.{HOTSPOT_DNS_NAME}"``
#: and nothing on this platform renders anything deeper. Deliberately not a
#: general subdomain pattern -- ``a.b.wifi.wyfyguest.com`` is not a name this
#: platform can produce, so accepting it would only widen the allowlist past
#: anything it has to cover.
_HOTSPOT_SUBDOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

#: Characters that URL parsers famously disagree about, rejected before
#: ``urlsplit`` ever sees the string. A backslash is the important one:
#: WHATWG-conformant browsers (and the URL parsers inside operating-system
#: captive-portal clients) treat ``\`` as a path separator, Python's
#: ``urlsplit`` does not, and that single disagreement is enough to make
#: ``http://wifi.wyfyguest.com\@evil.example/`` validate here and resolve to
#: ``evil.example`` there.
_URL_PARSER_HAZARDS = ("\\",)


def validate_user_portal_url(portal_url: str) -> str:
    """Validate the RFC 8908 endpoint's ``portal_url`` parameter and return
    a URL **this function built**, not the caller's string.

    ## Why this is not an ordinary open-redirect check

    The return value is reflected into the ``user-portal-url`` member of an
    ``application/captive+json`` document. A conforming operating system --
    Windows 11, macOS 13+, iOS 14+ -- fetches that document on its own,
    from the URI its DHCP lease handed it in RFC 8910 option 114, and then
    **opens ``user-portal-url`` by itself**, in a captive-portal browser
    surface the user did not choose to open and cannot inspect the address
    bar of. There is no link to hover over and no click to withhold. So the
    threat model is not "a user might be tricked into following this"; it
    is "an unauthenticated caller can nominate a page the OS will open".

    ## Validate, then rebuild -- the reflection is the vulnerability

    Every accepted URL is **reconstructed** from the one component that was
    actually checked (the hostname), rather than the caller's bytes being
    passed through. That is the whole point: a check-then-reflect design
    stays only as strong as the agreement between Python's ``urlsplit`` and
    whichever URL parser the guest's OS ships, and those two do not have to
    agree -- see ``_URL_PARSER_HAZARDS``. Rebuilding removes the question.
    Anything the caller sent that is not the hostname (path, query,
    fragment, and any encoding trick inside them) is discarded rather than
    sanitised.

    ## What is allowed, and why each bound is where it is

    - **``http`` only.** Not an oversight and not a downgrade. The hotspot
      login page is served by RouterOS itself, which has no certificate any
      guest device trusts; ``HOTSPOT_LOGIN_BY`` is pinned to ``http-pap``
      for exactly that reason, and an ``https`` redirect there is a
      confirmed live cause of "no sign-in popup on Windows or macOS at
      all" (the probe dies in the TLS handshake, below the HTTP layer the
      OS is inspecting). An ``https`` value here would be wrong even if it
      were safe.
    - **``HOTSPOT_DNS_NAME``, or one label under it.** The two shapes this
      platform actually renders: the bare name on the default ``hsprof1``
      hotspot, and ``vlan{id}.`` + the bare name per VLAN.
    - **No userinfo, no port other than 80.** ``http://a@b/`` and
      ``http://host:8080/`` are both parseable and neither is anything this
      platform emits.

    Returns the canonical ``http://<host>/`` form. Raises
    :class:`InvalidUserPortalUrlError` (400) otherwise.
    """
    if any(hazard in portal_url for hazard in _URL_PARSER_HAZARDS):
        raise InvalidUserPortalUrlError(portal_url)
    # Whitespace and C0/C1 controls: stripped by some parsers, significant
    # to others, emitted by none of ours.
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in portal_url):
        raise InvalidUserPortalUrlError(portal_url)

    try:
        parts = urlsplit(portal_url)
        # `.username`/`.password`/`.port` parse the netloc lazily and raise
        # ValueError on a malformed one (a non-numeric or out-of-range
        # port), so they belong inside the same guard as urlsplit itself.
        has_userinfo = bool(parts.username or parts.password)
        port = parts.port
        hostname = parts.hostname
    except ValueError:
        raise InvalidUserPortalUrlError(portal_url) from None

    if parts.scheme != "http" or has_userinfo or port not in (None, 80):
        raise InvalidUserPortalUrlError(portal_url)

    # A trailing dot is a legal, fully-qualified spelling of the same name
    # and resolves identically; it is normalised away rather than refused
    # so that the rebuilt URL has exactly one spelling.
    host = (hostname or "").rstrip(".").lower()
    if host != HOTSPOT_DNS_NAME:
        suffix = f".{HOTSPOT_DNS_NAME}"
        if not host.endswith(suffix):
            raise InvalidUserPortalUrlError(portal_url)
        label = host[: -len(suffix)]
        if not _HOTSPOT_SUBDOMAIN_LABEL.match(label):
            raise InvalidUserPortalUrlError(portal_url)

    return f"http://{host}/"
