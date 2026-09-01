"""Captive Portal business logic: config CRUD, single-default-per-organization
enforcement, activate/deactivate/delete lifecycle, and the guest-facing
most-specific-wins resolution lookup.

Design notes worth calling out up front (see
``docs/captive_portal/FLOW.md`` for the full write-up):

## Composition, not duplication, with Organization/Location

This service never queries ``organizations``/``locations`` directly -- it
composes with the real ``OrganizationService``/``LocationService`` through
narrow, duck-typed ``OrganizationLookupProtocol``/``LocationLookupProtocol``
protocols, the identical shape ``app.domains.voucher.service.VoucherService``
and ``app.domains.router_provisioning.service.RouterProvisioningService``
already establish. A config's ``location_id`` (when supplied) is validated
for real against the location's own ``organization_id`` via
``LocationService.get_location(location_id, requesting_organization_id=...)``
-- this module never re-implements that cross-tenant check.

## Single-default enforcement

See ``models.CaptivePortalConfig``'s module docstring for the full
two-layered write-up (service-layer ``_clear_existing_default`` plus a
database partial unique index backstop). In short: whenever a config is
created or updated with ``is_default=True``, any other org-level config
already holding ``is_default=True`` for that organization is flipped to
``False`` in the same call, before the new default is persisted.

## Resolution fallback: no hardcoded platform-wide default

``resolve_portal_config`` implements the most-specific-wins lookup a
guest's captive-portal frontend calls before the guest has authenticated:
a location-specific active config, else the organization's active default,
else ``CaptivePortalConfigNotConfiguredError``. There is deliberately **no**
third, hardcoded platform-wide fallback branding -- unlike
``app.domains.router_provisioning``'s variable resolution (which has a
genuine ``GLOBAL`` tier below ``ORGANIZATION``, because a config *variable*
can sensibly have a platform-wide default value), a captive portal's
branding is inherently tenant-specific content (a business's own logo,
colors, legal text) that CloudGuest cannot invent on a tenant's behalf.
Every organization must configure at least one active default portal
before its guest WiFi can be presented to a real guest.

## Audit-volume judgment call: full coverage, unlike OTP/Voucher's tiering

**Every create/update/activate/deactivate/delete is written to
``audit_log_entries``.** OTP and Voucher both carefully tier their audit
coverage because their own primary actions are high-volume, guest-facing,
unauthenticated traffic (an OTP request, a voucher redemption) where
auditing every single occurrence would flood a moderate-volume,
admin-reviewable table for limited benefit. This module's mutating actions
are the opposite profile: low-volume, always-authenticated, always
admin-initiated configuration changes to how a tenant's guest WiFi login
page looks and behaves -- the kind of change a compliance/support review
would specifically want a complete trail of ("who changed the terms and
conditions URL, and when"). There is no tiering question to make here the
way there is for a guest hammering "request OTP" a hundred times a
minute -- this module's write path simply never sees that volume profile,
so full coverage is the correct call, not merely the default one.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from app.domains.billing.constants import PlanFeatureKey
from app.domains.location.models import Location
from app.domains.organization.models import Organization
from app.domains.rbac.enums import AuditAction

from .constants import (
    DEFAULT_PORTAL_CONTENT_MODE,
    PRIVACY_POLICY_LABEL,
    TERMS_AND_CONDITIONS_LABEL,
)
from .events import (
    CaptivePortalConfigActivated,
    CaptivePortalConfigCreated,
    CaptivePortalConfigDeactivated,
    CaptivePortalConfigDeleted,
    CaptivePortalConfigUpdated,
    CaptivePortalPoweredByRestored,
)
from .exceptions import (
    CaptivePortalConfigNotConfiguredError,
    CaptivePortalConfigNotFoundError,
    CrossOrganizationCaptivePortalConfigAccessError,
    MissingPortalResolutionParamsError,
    PoweredByAttributionNotEntitledError,
)
from .html_sanitizer import sanitize_post_login_html
from .models import CaptivePortalConfig
from .repository import CaptivePortalRepositoryProtocol
from .validators import (
    SPLASH_TEXT_MAX_LENGTHS,
    validate_background_focal_point,
    validate_background_overlay_strength,
    validate_business_hours_schedule,
    validate_business_hours_timezone,
    validate_content_mode,
    validate_default_scope,
    validate_guest_font_choice,
    validate_hex_color,
    validate_single_content_source,
    validate_splash_text_length,
)

logger = logging.getLogger(__name__)


def _event_extra(event: object) -> dict[str, object]:
    """Flattens a frozen, ``slots=True`` ``events.py`` dataclass into
    ``logger.info(extra=)``-friendly, JSON-serializable keys -- identical
    reflection trick to ``app.domains.voucher.service._event_extra``/
    ``app.domains.otp.service._event_extra``."""
    return {
        f"event_{f.name}": value
        if isinstance(value := getattr(event, f.name), str | int | float | bool)
        else str(value)
        for f in dataclasses.fields(event)
    }


# ============================================================================
# Narrow cross-domain protocols (composition, not duplication)
# ============================================================================


class OrganizationLookupProtocol(Protocol):
    async def get_organization(
        self, organization_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Organization: ...


class LocationLookupProtocol(Protocol):
    async def get_location(
        self,
        location_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Location: ...


class BrandingRowProtocol(Protocol):
    """The exact columns ``resolve_portal_config`` reads off an
    ``app.domains.branding.models.Branding`` row -- structural, so this
    module never imports that model."""

    logo_key: str | None
    logo_url: str | None
    background_image_key: str | None
    background_luminance: int | None
    background_top_luminance: int | None
    background_entropy: int | None


class BrandingLookupProtocol(Protocol):
    """The single method ``resolve_portal_config`` needs from the real
    ``app.domains.branding.repository.BrandingRepository`` -- reused
    directly, never reimplemented, the identical composition
    ``OrganizationLookupProtocol``/``LocationLookupProtocol`` above
    already establish for their own real collaborators.

    ``None``-by-default on the service (see ``__init__``): a caller that
    wires no branding lookup simply resolves with ``branding=None``,
    exactly the shape a config carrying both its own ``logo_url`` and
    ``background_image_url`` already produces -- never a crash.
    """

    async def get_by_organization(
        self, organization_id: uuid.UUID
    ) -> BrandingRowProtocol | None: ...


class AuditLogWriter(Protocol):
    """The minimal surface this service needs to write into RBAC's shared
    ``audit_log_entries`` table -- the same narrow, duck-typed protocol
    shape every other domain's service already defines for itself."""

    async def create_audit_log_entry(self, **fields: object) -> object: ...


class EntitlementSnapshotProtocol(Protocol):
    """The one question this service asks of billing."""

    def has_feature(self, feature_key: object) -> bool: ...


class EntitlementCheckerProtocol(Protocol):
    """The minimal surface the ``powered_by_enabled`` white-label gate
    needs from ``app.domains.billing.service.EntitlementChecker`` -- kept
    structural for the same reason ``CaptivePortalResolveCacheProtocol``
    below is, so this module never imports billing's concrete class.

    Optional on the service (``None`` disables the gate). The dependency
    wiring in ``dependencies.py`` always supplies the real checker for
    every request that reaches the router; ``None`` is for the one
    pre-existing non-HTTP caller,
    ``app.domains.location.provisioning_service``, which creates configs
    during smart-location provisioning and never sets this field, and for
    unit tests that are not exercising the gate.
    """

    async def get_snapshot(
        self, organization_id: uuid.UUID
    ) -> EntitlementSnapshotProtocol: ...


class CaptivePortalResolveCacheProtocol(Protocol):
    """The minimal surface ``resolve_portal_config`` needs from
    ``cache.CaptivePortalResolveCache`` -- kept structural so this module
    never imports the concrete Redis-backed class, mirroring
    ``app.domains.billing.service.EntitlementCacheProtocol``'s identical
    narrow-Protocol convention."""

    async def get(
        self,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
    ) -> dict[str, Any] | None: ...

    async def set(
        self,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        payload: dict[str, Any],
        *,
        index_organization_id: uuid.UUID | None = None,
        negative: bool = False,
    ) -> None: ...

    async def invalidate(
        self,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
    ) -> None: ...

    async def invalidate_organization(self, organization_id: uuid.UUID) -> None: ...


# ============================================================================
# Read model
# ============================================================================


@dataclass(frozen=True, slots=True)
class ResolvedBranding:
    """The organization's own ``brandings`` row, reduced to exactly the
    six columns ``router.resolve_captive_portal_config`` reads when it
    falls back to org branding for a logo/background the config row
    itself left unset.

    **Why a reduced copy rather than the ORM row:** this object is
    JSON-round-tripped through the resolve cache (design spec §5 S7), and
    the router turns ``logo_key``/``background_image_key`` into absolute
    URLs using ``request.base_url`` -- which is *per-request* and must
    never be baked into a shared cache entry. Caching the raw facts and
    letting the router build the URL keeps the cached payload
    host-agnostic, so one entry stays correct for every origin the API is
    reachable on.

    Only the *presence* of a key matters to the router, but the real
    values are carried anyway: they are small, and a boolean would make
    the payload lossy for no saving.
    """

    logo_key: str | None
    logo_url: str | None
    background_image_key: str | None
    background_luminance: int | None
    background_top_luminance: int | None
    background_entropy: int | None

    @classmethod
    def from_row(cls, row: BrandingRowProtocol) -> ResolvedBranding:
        return cls(
            logo_key=row.logo_key,
            logo_url=row.logo_url,
            background_image_key=row.background_image_key,
            background_luminance=row.background_luminance,
            background_top_luminance=row.background_top_luminance,
            background_entropy=row.background_entropy,
        )

    def to_cache_payload(self) -> dict[str, Any]:
        return {
            "logo_key": self.logo_key,
            "logo_url": self.logo_url,
            "background_image_key": self.background_image_key,
            "background_luminance": self.background_luminance,
            "background_top_luminance": self.background_top_luminance,
            "background_entropy": self.background_entropy,
        }

    @classmethod
    def from_cache_payload(cls, payload: dict[str, Any]) -> ResolvedBranding:
        # Indexed unguarded, exactly like ``_config_from_cache_payload``
        # -- see ``cache._CACHE_KEY_TEMPLATE``'s own comment for why a
        # missing field must fail loudly in tests rather than degrade
        # silently in production, and why the key version is what keeps
        # that failure from ever reaching a real guest.
        return cls(
            logo_key=payload["logo_key"],
            logo_url=payload["logo_url"],
            background_image_key=payload["background_image_key"],
            background_luminance=payload["background_luminance"],
            background_top_luminance=payload["background_top_luminance"],
            background_entropy=payload["background_entropy"],
        )


@dataclass(frozen=True, slots=True)
class ResolvedPortalConfig:
    """Wraps the resolved config together with which tier answered the
    lookup -- useful for the guest-facing response/tests to assert
    resolution actually preferred the location override when both exist,
    without re-deriving it from the raw row.

    ``location_country`` is the resolved location's own ``Location.country``
    (ISO 3166-1 alpha-2, e.g. ``"IN"``/``"US"``) -- **not** a phone dialing
    code -- piggybacked off the exact same ``location_lookup.get_location``
    call ``resolve_portal_config`` already makes to derive
    ``organization_id`` from a location, so this costs no extra query.
    ``None`` whenever the caller resolved by ``organization_id`` alone (no
    location context exists to source a country from) -- see v4 captive-
    portal design spec §6.3: this is the real signal a guest-facing OTP
    phone field should derive its default calling code from, a materially
    better source than the config's own ``default_language`` (a language,
    not a country -- ambiguous for e.g. English-speaking deployments
    outside the US)."""

    config: CaptivePortalConfig
    resolved_via_location_override: bool
    location_country: str | None = None
    location_name: str | None = None
    """The resolved location's own ``Location.name`` -- piggybacked off the
    same ``location_lookup.get_location`` call ``location_country`` is
    sourced from, so ``router.resolve_captive_portal_config`` no longer
    needs its own second ``LocationRepository.get_by_id`` query just to
    render "courtesy of {location name}" instead of the config's internal
    admin label. ``None`` whenever the caller resolved by ``organization_id``
    alone (no location context exists)."""

    branding: ResolvedBranding | None = None
    """The resolved organization's own ``brandings`` row, fetched by
    ``_resolve_portal_config_uncached`` **only** when this config row
    left ``logo_url`` or ``background_image_url`` unset -- i.e. only when
    ``router.resolve_captive_portal_config`` would actually consult it.

    Design spec §5 S7: that router previously ran its own
    ``BrandingRepository.get_by_organization`` on every single resolve
    that needed a fallback, *outside* the resolve cache -- so a "cache
    hit" still cost a SELECT, a connection checkout, and (because
    ``app.database.session.get_db_session`` commits unconditionally) a
    COMMIT on a read-only guest request. Folding the row in here puts it
    behind the same cache as everything else.

    ``None`` means "not consulted", which the router treats identically
    to "no branding row exists" -- both leave the config's own values
    untouched, which is the correct outcome for a config that already
    supplies both URLs itself."""

    def to_cache_payload(self) -> dict[str, Any]:
        """Serializes for ``CaptivePortalResolveCacheProtocol.set`` --
        mirrors ``app.domains.billing.service.EntitlementSnapshot
        .to_cache_payload``'s identical shape. Every field
        ``router._config_response``/``resolve_captive_portal_config``
        reads off ``resolved.config`` is included, so a cache hit never
        needs to fall back to a real query."""
        return {
            "config": _config_to_cache_payload(self.config),
            "resolved_via_location_override": self.resolved_via_location_override,
            "location_country": self.location_country,
            "location_name": self.location_name,
            "branding": (
                self.branding.to_cache_payload() if self.branding is not None else None
            ),
        }

    @classmethod
    def from_cache_payload(cls, payload: dict[str, Any]) -> ResolvedPortalConfig:
        return cls(
            config=_config_from_cache_payload(dict(payload["config"])),
            resolved_via_location_override=bool(
                payload["resolved_via_location_override"]
            ),
            location_country=(
                str(payload["location_country"])
                if payload.get("location_country") is not None
                else None
            ),
            location_name=(
                str(payload["location_name"])
                if payload.get("location_name") is not None
                else None
            ),
            branding=(
                ResolvedBranding.from_cache_payload(dict(branding_payload))
                if (branding_payload := payload["branding"]) is not None
                else None
            ),
        )


# The exact subset of ``CaptivePortalConfig`` columns
# ``router._config_response``/``resolve_captive_portal_config`` read off a
# resolved config -- kept as one explicit tuple so ``_config_to_cache_payload``/
# ``_CachedCaptivePortalConfig`` can't silently drift apart from each other.
_CACHED_CONFIG_SCALAR_FIELDS = (
    "name",
    "is_active",
    "is_default",
    "theme",
    "logo_url",
    "background_image_url",
    "primary_color",
    "secondary_color",
    "default_language",
    "supported_languages",
    "advertisement_banner_url",
    "advertisement_banner_link",
    "terms_and_conditions_text",
    "terms_and_conditions_url",
    "privacy_policy_text",
    "privacy_policy_url",
    "splash_headline",
    "splash_welcome_message",
    "redirect_url",
    "post_login_html",
    "content_mode",
    "content_heading",
    "content_body",
    "content_image_url",
    "content_survey",
    "otp_sms_enabled",
    "otp_email_enabled",
    "otp_whatsapp_enabled",
    "voucher_enabled",
    "username_password_enabled",
    "pin_login_enabled",
    "social_login_enabled",
    "social_login_providers",
    "business_hours_enabled",
    "business_hours_timezone",
    "business_hours_schedule",
    "business_hours_closed_message",
    "guest_font_choice",
    "background_overlay_strength",
    "background_focal_x",
    "background_focal_y",
    "powered_by_enabled",
)


@dataclass(frozen=True, slots=True)
class _CachedCaptivePortalConfig:
    """A plain, JSON-round-trippable stand-in for ``CaptivePortalConfig``,
    exposing the identical attribute names ``router._config_response``
    reads -- so a cache hit can be handed to that function (and to
    ``resolve_captive_portal_config``'s own business-hours/branding-
    fallback logic) exactly as if it were the real ORM row, without a
    second query to reconstruct one. Never persisted, never passed to
    ``self.repository`` -- read-only, guest-facing-response shape only."""

    id: uuid.UUID
    organization_id: uuid.UUID
    location_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
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
    post_login_html: str | None
    content_mode: str
    content_heading: str | None
    content_body: str | None
    content_image_url: str | None
    content_survey: dict[str, Any] | None
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
    business_hours_schedule: dict[str, Any]
    business_hours_closed_message: str | None
    guest_font_choice: str
    background_overlay_strength: int
    background_focal_x: int
    background_focal_y: int
    powered_by_enabled: bool


def _splash_text_changed(incoming: object, stored: object) -> bool:
    """Whether an incoming splash value is a real change to what the guest
    already sees.

    Compares the **stripped** forms because that is what the frontend
    renders (``useGuestSignIn.ts:100``): a value that differs only in
    surrounding whitespace changes nothing on the portal and must not
    trip the length validator. ``None`` and ``""`` are both "no splash
    string" and are equivalent here for the same reason.
    """
    def _norm(value: object) -> str:
        return value.strip() if isinstance(value, str) else ""

    return _norm(incoming) != _norm(stored)


def _config_to_cache_payload(config: CaptivePortalConfig) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": str(config.id),
        "organization_id": str(config.organization_id),
        "location_id": str(config.location_id) if config.location_id else None,
        "created_at": config.created_at.isoformat(),
        "updated_at": config.updated_at.isoformat(),
    }
    for field_name in _CACHED_CONFIG_SCALAR_FIELDS:
        payload[field_name] = getattr(config, field_name)
    return payload


def _config_from_cache_payload(
    payload: dict[str, Any],
) -> _CachedCaptivePortalConfig:
    fields: dict[str, Any] = {
        "id": uuid.UUID(str(payload["id"])),
        "organization_id": uuid.UUID(str(payload["organization_id"])),
        "location_id": (
            uuid.UUID(str(payload["location_id"]))
            if payload.get("location_id") is not None
            else None
        ),
        "created_at": datetime.fromisoformat(str(payload["created_at"])),
        "updated_at": datetime.fromisoformat(str(payload["updated_at"])),
    }
    for field_name in _CACHED_CONFIG_SCALAR_FIELDS:
        fields[field_name] = payload[field_name]
    return _CachedCaptivePortalConfig(**fields)


# The marker distinguishing a cached *negative* result (this
# organization/location genuinely has no active portal config) from a
# cached real one. Design spec §5 S10: without negative caching, a single
# misconfigured location replays the entire resolution walk -- a location
# lookup, a location-config query, an org-default query -- on every guest
# device that joins, forever, and the walk ends in an exception so nothing
# ever warms.
_NOT_CONFIGURED_MARKER = "__not_configured__"


# In-flight resolution registry, keyed identically to the cache itself.
#
# Design spec §5 S10's third problem: with a 60-second TTL and a venue's
# worth of devices joining at once, every expiry is a small stampede --
# every concurrent miss runs the same full walk against the same rows to
# compute the same answer. Collapsing them means the first miss does the
# work and the rest await its result.
#
# **Module-level, not per-service, deliberately.** ``CaptivePortalService``
# is constructed per request by FastAPI's ``Depends`` chain, so an
# instance attribute would be a fresh empty dict on every request and
# would collapse exactly nothing.
#
# **In-process, not a Redis lock, deliberately.** A distributed lock would
# also collapse across worker processes, but it puts a network round trip
# -- and a lock that can be orphaned by a crashed holder -- directly on the
# unauthenticated path a guest hits first, standing in a lobby with no
# internet. That trades a bounded, cheap problem for an unbounded one. An
# in-process collapse reduces the stampede by the worker's own concurrency
# factor, cannot deadlock across processes, and adds no network hop; the
# residual is one walk per worker process per expiry, which the negative
# and positive caches then absorb.
_INFLIGHT_RESOLUTIONS: dict[
    tuple[uuid.UUID | None, uuid.UUID | None], asyncio.Future[ResolvedPortalConfig]
] = {}


# ============================================================================
# Service
# ============================================================================


class CaptivePortalService:
    """Core Captive Portal business logic."""

    def __init__(
        self,
        repository: CaptivePortalRepositoryProtocol,
        organization_lookup: OrganizationLookupProtocol,
        location_lookup: LocationLookupProtocol,
        *,
        audit_writer: AuditLogWriter | None = None,
        resolve_cache: CaptivePortalResolveCacheProtocol | None = None,
        entitlement_checker: EntitlementCheckerProtocol | None = None,
        branding_lookup: BrandingLookupProtocol | None = None,
    ) -> None:
        self.repository = repository
        self.organization_lookup = organization_lookup
        self.location_lookup = location_lookup
        self.audit_writer = audit_writer
        self.resolve_cache = resolve_cache
        self.entitlement_checker = entitlement_checker
        self.branding_lookup = branding_lookup

    # ========================================================================
    # Create / read / update / delete
    # ========================================================================

    async def create_config(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
        name: str,
        is_active: bool,
        is_default: bool,
        theme: str,
        logo_url: str | None,
        background_image_url: str | None,
        primary_color: str,
        secondary_color: str,
        default_language: str,
        supported_languages: list[str],
        advertisement_banner_url: str | None,
        advertisement_banner_link: str | None,
        terms_and_conditions_text: str | None,
        terms_and_conditions_url: str | None,
        privacy_policy_text: str | None,
        privacy_policy_url: str | None,
        splash_headline: str | None,
        splash_welcome_message: str | None,
        redirect_url: str | None,
        otp_sms_enabled: bool,
        otp_email_enabled: bool,
        otp_whatsapp_enabled: bool,
        voucher_enabled: bool,
        username_password_enabled: bool,
        social_login_enabled: bool,
        social_login_providers: list[str],
        # Defaults False (unlike every other keyword-only parameter above,
        # which the schema layer always supplies explicitly) so this
        # method's other pre-existing caller --
        # app.domains.location.provisioning_service
        # .LocationProvisioningService's smart-location provisioning flow
        # -- and this domain's own test suite keep working unchanged,
        # getting the same "off by default" behavior
        # CaptivePortalConfig.pin_login_enabled's own DB column default
        # already establishes, without either needing to know this
        # parameter exists at all.
        pin_login_enabled: bool = False,
        # Defaults True for the same reason pin_login_enabled defaults
        # above: the smart-location provisioning flow in
        # app.domains.location.provisioning_service, and this domain's
        # own tests, never pass it. True is also the only default that
        # cannot leak revenue -- see the column's own docstring.
        powered_by_enabled: bool = True,
        # Content mode + its per-mode source columns. All default to the
        # existing sign-in-only behaviour / empty content for the same reason
        # pin_login_enabled/powered_by_enabled default above: the smart-
        # location provisioning flow and this domain's tests never pass them,
        # and "login" is the only value that leaves a brand-new config
        # rendering exactly as every config does today.
        content_mode: str = DEFAULT_PORTAL_CONTENT_MODE.value,
        content_heading: str | None = None,
        content_body: str | None = None,
        content_image_url: str | None = None,
        content_survey: dict | None = None,
        # The venue's own post-sign-in page. Defaults None for the same
        # reason the content_* parameters above do -- the smart-location
        # provisioning flow and this domain's tests never pass it -- and
        # None is also the value that means "unchanged": a config created
        # without one behaves exactly as every config does today.
        post_login_html: str | None = None,
    ) -> CaptivePortalConfig:
        validate_hex_color(primary_color, field_name="primary_color")
        validate_hex_color(secondary_color, field_name="secondary_color")
        validate_single_content_source(
            terms_and_conditions_text,
            terms_and_conditions_url,
            field_label=TERMS_AND_CONDITIONS_LABEL,
        )
        validate_single_content_source(
            privacy_policy_text, privacy_policy_url, field_label=PRIVACY_POLICY_LABEL
        )
        validate_default_scope(is_default=is_default, location_id=location_id)
        # v7 §Part 2 (W2). Unconditional on create -- there is no existing
        # value to grandfather, so a brand-new config never gets to start
        # life over the limit. See update_config for why the same check is
        # conditional there.
        validate_splash_text_length("splash_headline", splash_headline)
        validate_splash_text_length("splash_welcome_message", splash_welcome_message)
        validate_content_mode(content_mode)
        # Sanitize here, not at the schema layer and not on read. The value
        # bound to `post_login_html` from this point on is the *stored*
        # value, which is what makes the response the caller gets back the
        # sanitized bytes rather than what they submitted -- a dashboard
        # editor that re-renders from the response therefore shows the
        # venue exactly what was kept. Raises PostLoginHtmlTooLargeError
        # (400) before any DB work if the submitted payload is over the
        # byte ceiling.
        post_login_html = sanitize_post_login_html(post_login_html)

        organization = await self.organization_lookup.get_organization(organization_id)
        if (
            requesting_organization_id is not None
            and organization.id != requesting_organization_id
        ):
            raise CrossOrganizationCaptivePortalConfigAccessError()
        if location_id is not None:
            await self.location_lookup.get_location(
                location_id, requesting_organization_id=organization.id
            )

        await self._enforce_powered_by_entitlement(
            organization_id=organization.id,
            current=None,
            requested=powered_by_enabled,
        )

        if is_default:
            await self._clear_existing_default(organization.id)

        config = await self.repository.create_config(
            organization_id=organization.id,
            location_id=location_id,
            name=name,
            is_active=is_active,
            is_default=is_default,
            theme=theme,
            logo_url=logo_url,
            background_image_url=background_image_url,
            primary_color=primary_color,
            secondary_color=secondary_color,
            default_language=default_language,
            supported_languages=list(supported_languages),
            advertisement_banner_url=advertisement_banner_url,
            advertisement_banner_link=advertisement_banner_link,
            terms_and_conditions_text=terms_and_conditions_text,
            terms_and_conditions_url=terms_and_conditions_url,
            privacy_policy_text=privacy_policy_text,
            privacy_policy_url=privacy_policy_url,
            splash_headline=splash_headline,
            splash_welcome_message=splash_welcome_message,
            redirect_url=redirect_url,
            post_login_html=post_login_html,
            content_mode=content_mode,
            content_heading=content_heading,
            content_body=content_body,
            content_image_url=content_image_url,
            content_survey=content_survey,
            otp_sms_enabled=otp_sms_enabled,
            otp_email_enabled=otp_email_enabled,
            otp_whatsapp_enabled=otp_whatsapp_enabled,
            voucher_enabled=voucher_enabled,
            username_password_enabled=username_password_enabled,
            pin_login_enabled=pin_login_enabled,
            social_login_enabled=social_login_enabled,
            social_login_providers=list(social_login_providers),
            powered_by_enabled=powered_by_enabled,
            created_by=actor_user_id,
        )
        event = CaptivePortalConfigCreated(
            config_id=config.id,
            organization_id=organization.id,
            location_id=location_id,
        )
        logger.info("captive_portal_config_created", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.CAPTIVE_PORTAL_CONFIG_CREATED,
            config,
            f"Captive portal config '{config.name}' created",
        )
        await self._invalidate_resolve_cache(config.organization_id, config.location_id)
        return config

    async def get_config(
        self,
        config_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
    ) -> CaptivePortalConfig:
        config = await self.repository.get_config(config_id)
        if config is None:
            raise CaptivePortalConfigNotFoundError(config_id)
        self._enforce_tenant_scope(config, requesting_organization_id)
        return config

    async def list_configs(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 25,
    ) -> tuple[list[CaptivePortalConfig], object]:
        filters: dict[str, object] = {}
        if requesting_organization_id is not None:
            filters["organization_id"] = requesting_organization_id
        if location_id is not None:
            filters["location_id"] = location_id
        return await self.repository.list_configs(
            page=page, page_size=page_size, filters=filters or None
        )

    async def update_config(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        config_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        data: dict[str, object],
    ) -> CaptivePortalConfig:
        config = await self.get_config(
            config_id, requesting_organization_id=requesting_organization_id
        )
        update_data = dict(data)
        # organization_id/location_id are immutable after creation -- the
        # schema layer never exposes them on the update request, so this is
        # a defensive strip, mirroring app.domains.location.service
        # .LocationService.update_location's identical convention.
        update_data.pop("organization_id", None)
        update_data.pop("location_id", None)

        merged_primary = str(update_data.get("primary_color", config.primary_color))
        merged_secondary = str(
            update_data.get("secondary_color", config.secondary_color)
        )
        validate_hex_color(merged_primary, field_name="primary_color")
        validate_hex_color(merged_secondary, field_name="secondary_color")

        merged_tc_text = update_data.get(
            "terms_and_conditions_text", config.terms_and_conditions_text
        )
        merged_tc_url = update_data.get(
            "terms_and_conditions_url", config.terms_and_conditions_url
        )
        validate_single_content_source(
            merged_tc_text, merged_tc_url, field_label=TERMS_AND_CONDITIONS_LABEL
        )

        merged_pp_text = update_data.get(
            "privacy_policy_text", config.privacy_policy_text
        )
        merged_pp_url = update_data.get("privacy_policy_url", config.privacy_policy_url)
        validate_single_content_source(
            merged_pp_text, merged_pp_url, field_label=PRIVACY_POLICY_LABEL
        )

        merged_is_default = bool(update_data.get("is_default", config.is_default))
        validate_default_scope(
            is_default=merged_is_default, location_id=config.location_id
        )

        if "business_hours_timezone" in update_data:
            validate_business_hours_timezone(
                str(update_data["business_hours_timezone"])
            )
        if "business_hours_schedule" in update_data:
            validate_business_hours_schedule(
                dict(update_data["business_hours_schedule"] or {})
            )
        if "guest_font_choice" in update_data:
            validate_guest_font_choice(str(update_data["guest_font_choice"]))
        if "content_mode" in update_data:
            validate_content_mode(str(update_data["content_mode"]))
        if "background_overlay_strength" in update_data:
            validate_background_overlay_strength(
                update_data["background_overlay_strength"]
            )
        for axis in ("x", "y"):
            field_name = f"background_focal_{axis}"
            if field_name in update_data:
                validate_background_focal_point(axis, update_data[field_name])

        # v7 §Part 2 (W2). Deliberately fires only when the value is
        # actually *changing*, not merely present in the payload.
        #
        # There are live rows over these ceilings -- the fields shipped
        # with no validation anywhere in the chain, `splash_welcome_message`
        # as an unbounded `Text` column. Rejecting on any write that
        # mentions the field would mean a venue with a long existing
        # message could not change their logo without first rewriting
        # their copy, and the dashboard PUTs its whole form, so it mentions
        # the field on every save. Rejecting on *change* grandfathers those
        # rows: the venue keeps rendering exactly what they wrote, and the
        # limit binds the moment they next edit that string -- which is
        # also the only moment a live character counter is in front of
        # them to explain it.
        #
        # The trade-off, stated rather than hidden: an over-limit legacy
        # value survives indefinitely if never edited. Surfacing those rows
        # is a dashboard warning and a backfill report, not a write-path
        # rejection.
        for splash_field in SPLASH_TEXT_MAX_LENGTHS:
            if splash_field not in update_data:
                continue
            incoming = update_data[splash_field]
            if not _splash_text_changed(incoming, getattr(config, splash_field)):
                continue
            validate_splash_text_length(splash_field, incoming)

        # Sanitized only when the key is actually present, so a PUT that
        # never mentions the field cannot rewrite a stored page -- and
        # `update_data` itself is mutated rather than a local, because what
        # goes to the repository has to be the sanitized bytes and the
        # response is built from the row that comes back. Unlike the splash
        # ceilings above there is no grandfathering clause: no row can
        # predate this column, so there is no legacy value to protect, and
        # unsanitized HTML is not something to grandfather in any case.
        if "post_login_html" in update_data:
            submitted = update_data["post_login_html"]
            update_data["post_login_html"] = sanitize_post_login_html(
                submitted if submitted is None else str(submitted)
            )

        if "powered_by_enabled" in update_data:
            await self._enforce_powered_by_entitlement(
                organization_id=config.organization_id,
                current=config.powered_by_enabled,
                requested=update_data["powered_by_enabled"],
            )

        if merged_is_default and not config.is_default:
            await self._clear_existing_default(
                config.organization_id, exclude_config_id=config.id
            )

        updated = await self.repository.update_config(
            config, {**update_data, "updated_by": actor_user_id}
        )
        event = CaptivePortalConfigUpdated(config_id=updated.id)
        logger.info("captive_portal_config_updated", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.CAPTIVE_PORTAL_CONFIG_UPDATED,
            updated,
            f"Captive portal config '{updated.name}' updated",
        )
        await self._invalidate_resolve_cache(
            updated.organization_id, updated.location_id
        )
        return updated

    async def _enforce_powered_by_entitlement(
        self,
        *,
        organization_id: uuid.UUID,
        current: bool | None,
        requested: object,
    ) -> None:
        """v7 design spec Part 3 (P4). Turning off "Powered by Wyfy Guest"
        is ``PlanFeatureKey.WHITE_LABEL`` behaviour, but
        ``captive_portal.update`` is granted to roles holding no
        ``white_label.*`` permission at all -- so without this any admin
        could switch the founder's attribution off across every guest at
        their venue for free.

        ``current`` is the value the row already carries, or ``None`` on
        create (where there is no prior value and any ``False`` is
        therefore a real turn-off). Gating create as well as update is not
        in the spec's literal wording, which names ``update_config`` only,
        but leaving it out would be a one-request bypass: POST a fresh
        config with ``powered_by_enabled=false`` and the update gate is
        never consulted.

        Three deliberate narrownesses, each with a failure mode behind it:

        * **Service layer, not a ``RequireFeature`` router dependency.**
          That dependency gates the whole ``PUT``, which would stop a
          non-entitled tenant changing their logo or their colours too.
        * **Only on the transition to ``False``.** Turning attribution
          back *on* must always be free, or a tenant who downgrades is
          stuck with a setting they cannot revert. And re-submitting an
          already-``False`` value is not a new purchase: the dashboard
          PUTs its whole form, so a downgraded tenant would otherwise be
          locked out of every other field on the page -- the same trap the
          splash-length check above avoids the same way.
        * **Write path only.** ``resolve`` is unauthenticated; a 402 there
          would break the portal outright for every non-entitled tenant.

        Known, accepted consequence, stated rather than left to the code:
        a tenant who turns the mark off while entitled and then downgrades
        keeps it off, because resolve honours the stored value and this
        check never fires again for them. Closing that needs a reset on
        the licence-downgrade path (``LicenseService.downgrade_license``),
        not a check on the guest hot path -- putting an entitlement lookup
        on the most critical unauthenticated request in the product buys a
        new failure mode there to recover revenue that is better recovered
        at the moment the plan actually changes.
        """
        if requested is not False:
            return
        if current is False:
            return
        if self.entitlement_checker is None:
            return
        snapshot = await self.entitlement_checker.get_snapshot(organization_id)
        if not snapshot.has_feature(PlanFeatureKey.WHITE_LABEL):
            raise PoweredByAttributionNotEntitledError(
                organization_id, PlanFeatureKey.WHITE_LABEL.value
            )

    async def activate_config(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        config_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> CaptivePortalConfig:
        config = await self.get_config(
            config_id, requesting_organization_id=requesting_organization_id
        )
        updated = await self.repository.update_config(
            config, {"is_active": True, "updated_by": actor_user_id}
        )
        event = CaptivePortalConfigActivated(config_id=updated.id)
        logger.info("captive_portal_config_activated", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.CAPTIVE_PORTAL_CONFIG_ACTIVATED,
            updated,
            f"Captive portal config '{updated.name}' activated",
        )
        await self._invalidate_resolve_cache(
            updated.organization_id, updated.location_id
        )
        return updated

    async def deactivate_config(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        config_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> CaptivePortalConfig:
        config = await self.get_config(
            config_id, requesting_organization_id=requesting_organization_id
        )
        updated = await self.repository.update_config(
            config, {"is_active": False, "updated_by": actor_user_id}
        )
        event = CaptivePortalConfigDeactivated(config_id=updated.id)
        logger.info("captive_portal_config_deactivated", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.CAPTIVE_PORTAL_CONFIG_DEACTIVATED,
            updated,
            f"Captive portal config '{updated.name}' deactivated",
        )
        await self._invalidate_resolve_cache(
            updated.organization_id, updated.location_id
        )
        return updated

    async def delete_config(
        self,
        *,
        actor_user_id: uuid.UUID | None,
        config_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> CaptivePortalConfig:
        config = await self.get_config(
            config_id, requesting_organization_id=requesting_organization_id
        )
        deactivated = await self.repository.update_config(
            config, {"is_active": False, "updated_by": actor_user_id}
        )
        deleted = await self.repository.soft_delete_config(deactivated)
        event = CaptivePortalConfigDeleted(config_id=deleted.id)
        logger.info("captive_portal_config_deleted", extra=_event_extra(event))
        await self._audit(
            actor_user_id,
            AuditAction.CAPTIVE_PORTAL_CONFIG_DELETED,
            deleted,
            f"Captive portal config '{deleted.name}' deleted",
        )
        await self._invalidate_resolve_cache(
            deleted.organization_id, deleted.location_id
        )
        return deleted

    # ========================================================================
    # Guest-facing resolution
    # ========================================================================

    async def resolve_portal_config(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
    ) -> ResolvedPortalConfig:
        """Most-specific-wins lookup: a location-specific active config,
        else the organization's active default, else
        ``CaptivePortalConfigNotConfiguredError``. See module docstring for
        why there is no third, hardcoded fallback tier.

        ``organization_id`` may be omitted when ``location_id`` is
        supplied -- it is derived from the location's own row (composing
        with ``LocationLookupProtocol``, never a direct query). When both
        are supplied, the location is confirmed to actually belong to that
        organization (``CrossOrganizationLocationAccessError`` otherwise --
        reused from ``app.domains.location``, not duplicated).
        """
        if organization_id is None and location_id is None:
            raise MissingPortalResolutionParamsError()

        cached = await self._cache_get(organization_id, location_id)
        if cached is not None:
            if _NOT_CONFIGURED_MARKER in cached:
                raise CaptivePortalConfigNotConfiguredError(
                    uuid.UUID(str(cached[_NOT_CONFIGURED_MARKER]))
                )
            return ResolvedPortalConfig.from_cache_payload(cached)

        return await self._resolve_single_flight(
            organization_id=organization_id, location_id=location_id
        )

    async def _cache_get(
        self,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
    ) -> dict[str, Any] | None:
        """Reads the resolve cache, treating any failure as a miss.

        Design spec §5 S10. This ``await`` was unguarded, so a Redis blip
        raised straight out of the unauthenticated ``GET
        /captive-portal/resolve`` -- the first request a guest's device
        makes on a WiFi join. A cache is an optimization; losing it must
        cost latency, not availability. Failing open here means a Redis
        outage degrades every venue to the pre-cache query path rather
        than taking guest WiFi down platform-wide.
        """
        if self.resolve_cache is None:
            return None
        try:
            return await self.resolve_cache.get(organization_id, location_id)
        except Exception as exc:  # noqa: BLE001 -- see docstring: fail open
            logger.warning(
                "captive_portal_resolve_cache_read_failed",
                extra={
                    "organization_id": str(organization_id),
                    "location_id": str(location_id),
                    "error": str(exc),
                },
            )
            return None

    async def _cache_set(
        self,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        payload: dict[str, Any],
        *,
        index_organization_id: uuid.UUID,
        negative: bool = False,
    ) -> None:
        """Writes the resolve cache, swallowing any failure -- the same
        fail-open posture as ``_cache_get``. A write that does not land
        costs the next request a cache miss, which is exactly what would
        have happened anyway."""
        if self.resolve_cache is None:
            return
        try:
            await self.resolve_cache.set(
                organization_id,
                location_id,
                payload,
                # The *resolved* organization, so an organization-scoped
                # edit can fan out to this key even when the caller only
                # supplied a location_id -- see the cache's own
                # ``set``/``invalidate_organization`` docstrings.
                index_organization_id=index_organization_id,
                negative=negative,
            )
        except Exception as exc:  # noqa: BLE001 -- see docstring: fail open
            logger.warning(
                "captive_portal_resolve_cache_write_failed",
                extra={
                    "organization_id": str(organization_id),
                    "location_id": str(location_id),
                    "error": str(exc),
                },
            )

    async def _resolve_single_flight(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
    ) -> ResolvedPortalConfig:
        """Runs the uncached resolution, collapsing concurrent misses for
        the same key onto one walk -- see ``_INFLIGHT_RESOLUTIONS``.

        Both outcomes are shared with waiters, the exception included: a
        venue with no config configured would otherwise have every
        concurrent miss run the full walk only to raise the same error.
        """
        key = (organization_id, location_id)
        loop = asyncio.get_running_loop()

        existing = _INFLIGHT_RESOLUTIONS.get(key)
        # ``get_loop()`` guards the case where a stale future outlived the
        # loop that created it (test suites routinely run one loop per
        # test). Awaiting such a future would hang forever, which on this
        # path means a guest's first request never returning -- so an
        # orphan is ignored and this caller simply does the work itself.
        if existing is not None and existing.get_loop() is loop:
            return await existing

        future: asyncio.Future[ResolvedPortalConfig] = loop.create_future()
        _INFLIGHT_RESOLUTIONS[key] = future
        try:
            resolved = await self._resolve_portal_config_uncached(
                organization_id=organization_id, location_id=location_id
            )
        except CaptivePortalConfigNotConfiguredError as exc:
            await self._cache_set(
                organization_id,
                location_id,
                {_NOT_CONFIGURED_MARKER: str(exc.organization_id)},
                index_organization_id=uuid.UUID(str(exc.organization_id)),
                negative=True,
            )
            future.set_exception(exc)
            # Mark retrieved even with no waiters, so asyncio does not log
            # "exception was never retrieved" when the future is collected.
            future.exception()
            raise
        except BaseException as exc:
            future.set_exception(exc)
            future.exception()
            raise
        else:
            future.set_result(resolved)
            await self._cache_set(
                organization_id,
                location_id,
                resolved.to_cache_payload(),
                index_organization_id=resolved.config.organization_id,
            )
            return resolved
        finally:
            _INFLIGHT_RESOLUTIONS.pop(key, None)

    async def _resolve_portal_config_uncached(
        self,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
    ) -> ResolvedPortalConfig:
        resolved_organization_id = organization_id
        location_country: str | None = None
        location_name: str | None = None
        if location_id is not None:
            location = await self.location_lookup.get_location(
                location_id, requesting_organization_id=organization_id
            )
            resolved_organization_id = location.organization_id
            location_country = location.country
            location_name = location.name
            location_config = await self.repository.find_active_for_location(
                resolved_organization_id, location_id
            )
            if location_config is not None:
                return ResolvedPortalConfig(
                    config=location_config,
                    resolved_via_location_override=True,
                    location_country=location_country,
                    location_name=location_name,
                    branding=await self._maybe_resolve_branding(
                        location_config, resolved_organization_id
                    ),
                )
        else:
            # organization_id is guaranteed non-None here by the guard
            # above; confirm it is a real organization before reporting
            # "not configured" rather than "not found".
            await self.organization_lookup.get_organization(resolved_organization_id)

        org_default = await self.repository.find_active_org_default(
            resolved_organization_id
        )
        if org_default is not None:
            return ResolvedPortalConfig(
                config=org_default,
                resolved_via_location_override=False,
                location_country=location_country,
                location_name=location_name,
                branding=await self._maybe_resolve_branding(
                    org_default, resolved_organization_id
                ),
            )
        raise CaptivePortalConfigNotConfiguredError(resolved_organization_id)

    async def _maybe_resolve_branding(
        self,
        config: CaptivePortalConfig,
        organization_id: uuid.UUID,
    ) -> ResolvedBranding | None:
        """Fetches the organization's ``brandings`` row -- but only when
        this config row actually leaves a logo/background for it to fill
        in, which is the exact condition
        ``router.resolve_captive_portal_config`` used to test before
        running this query itself (design spec §5 S7).

        Preserving that condition matters: a config supplying both its
        own URLs never needed the row and still doesn't, so folding the
        fetch into the cache does not turn a skipped query into an
        unconditional one -- it only moves the queries that were already
        happening to the cold path.
        """
        if self.branding_lookup is None:
            return None
        if config.logo_url is not None and config.background_image_url is not None:
            return None
        row = await self.branding_lookup.get_by_organization(organization_id)
        return ResolvedBranding.from_row(row) if row is not None else None

    # ========================================================================
    # Internal helpers
    # ========================================================================

    async def _clear_existing_default(
        self,
        organization_id: uuid.UUID,
        *,
        exclude_config_id: uuid.UUID | None = None,
    ) -> None:
        """Flips the organization's current org-level default (if any, and
        if it isn't the row already being promoted) to
        ``is_default=False`` -- see module docstring's single-default
        enforcement write-up."""
        existing = await self.repository.find_default_for_organization(organization_id)
        if existing is not None and existing.id != exclude_config_id:
            await self.repository.update_config(existing, {"is_default": False})

    async def _invalidate_resolve_cache(
        self,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
    ) -> None:
        """Invalidates the guest-facing resolve cache for every key shape a
        real guest call could have populated for this exact config row --
        see ``cache.CaptivePortalResolveCache``'s module docstring for the
        one gap this doesn't cover (an org-level default's edit not fanning
        out to *other* locations falling back to it)."""
        if self.resolve_cache is None:
            return
        try:
            await self._invalidate_resolve_cache_unguarded(
                organization_id, location_id
            )
        except Exception as exc:  # noqa: BLE001 -- see below
            # Same fail-open posture as ``_cache_get``/``_cache_set``
            # (design spec §5 S10), applied to the admin write path. A
            # failed invalidation means this config stays stale for up to
            # one TTL -- which is exactly the backstop this cache is
            # already documented as relying on. Failing the admin's save
            # instead would be worse: they would retry a write that had
            # already been committed.
            logger.warning(
                "captive_portal_resolve_cache_invalidation_failed",
                extra={
                    "organization_id": str(organization_id),
                    "location_id": str(location_id),
                    "error": str(exc),
                },
            )

    async def _invalidate_resolve_cache_unguarded(
        self,
        organization_id: uuid.UUID,
        location_id: uuid.UUID | None,
    ) -> None:
        if self.resolve_cache is None:
            return
        await self.resolve_cache.invalidate(organization_id, location_id)
        if location_id is not None:
            # A guest resolving via ``location_id`` alone -- the common
            # real-world call shape, since a location's own QR code/
            # redirect only ever encodes ``location_id`` -- caches under a
            # ``(None, location_id)`` key distinct from this
            # ``(organization_id, location_id)`` pair. Both must be
            # invalidated, or a location-scoped edit would keep serving a
            # stale cached result to that call shape until TTL expiry.
            await self.resolve_cache.invalidate(None, location_id)
            return

        # An organization-*level* config (no location_id) is the fallback
        # every location without its own override resolves to, so editing
        # it changes the answer for all of them -- including any that
        # cached a negative "not configured" result under a key whose
        # organization is not recoverable from the key itself (design spec
        # §5 S10). The per-organization index added for §5 S7 is what
        # makes that fan-out possible; this is the gap this module's own
        # docstring previously recorded as TTL-backstopped only.
        await self.resolve_cache.invalidate_organization(organization_id)

    def _enforce_tenant_scope(
        self,
        config: CaptivePortalConfig,
        requesting_organization_id: uuid.UUID | None,
    ) -> None:
        if (
            requesting_organization_id is not None
            and config.organization_id != requesting_organization_id
        ):
            raise CrossOrganizationCaptivePortalConfigAccessError()

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        config: CaptivePortalConfig,
        description: str,
    ) -> None:
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=action.value,
            entity_type="captive_portal_config",
            entity_id=config.id,
            description=description,
            event_metadata={
                "is_active": config.is_active,
                "is_default": config.is_default,
            },
            organization_id=config.organization_id,
            location_id=config.location_id,
        )


class PoweredByAttributionResetService:
    """The second half of the ``powered_by_enabled`` white-label policy.

    ``CaptivePortalService._enforce_powered_by_entitlement`` gates the
    tenant-facing write path (402 without ``PlanFeatureKey.WHITE_LABEL``),
    and the unauthenticated resolve path deliberately honours the stored
    value with no per-request entitlement check -- which that gate's own
    docstring documents as leaving one gap open: a tenant who turns the
    attribution off while entitled and then downgrades keeps it off. This
    service closes the gap at the moment the plan actually changes:
    ``app.domains.billing.service.LicenseService`` calls
    ``restore_powered_by_attribution`` on a downgrade to a plan without
    ``WHITE_LABEL`` (via the narrow ``WhiteLabelResetProtocol`` shape this
    class satisfies structurally), flipping every ``powered_by_enabled=
    False`` config in the organization back to ``True``.

    Deliberately a separate, minimal class rather than a method on
    ``CaptivePortalService``: this is a system-side entitlement action, not
    a tenant request, so it must go straight through the repository --
    constructing it without an entitlement checker *by shape* makes it
    impossible for the 402 gate (or any tenant-scope check) to fire on the
    reset itself. Nothing guest-facing is emitted: the guest simply sees
    the attribution again on their next resolve, once the organization's
    cache entries are invalidated.
    """

    def __init__(
        self,
        repository: CaptivePortalRepositoryProtocol,
        *,
        resolve_cache: CaptivePortalResolveCacheProtocol | None = None,
        audit_writer: AuditLogWriter | None = None,
    ) -> None:
        self.repository = repository
        self.resolve_cache = resolve_cache
        self.audit_writer = audit_writer

    async def restore_powered_by_attribution(
        self,
        organization_id: uuid.UUID,
        *,
        actor_user_id: uuid.UUID | None = None,
    ) -> int:
        """Flip every ``powered_by_enabled=False`` config the organization
        owns back to ``True``, invalidate the organization's resolve-cache
        fan-out, and write one audit entry per flipped config. Idempotent:
        an organization with nothing to reset is a pure no-op (no cache
        invalidation, no audit noise). Returns the number of configs
        flipped.

        ``actor_user_id`` is whoever drove the plan change, or ``None``
        for a system-driven downgrade -- the same convention
        ``LICENSE_EXPIRED`` established for system events.
        """
        configs = await self.repository.list_powered_by_disabled(organization_id)
        if not configs:
            return 0
        for config in configs:
            updated = await self.repository.update_config(
                config, {"powered_by_enabled": True, "updated_by": actor_user_id}
            )
            await self._audit(actor_user_id, updated)
        if self.resolve_cache is not None:
            await self.resolve_cache.invalidate_organization(organization_id)
        event = CaptivePortalPoweredByRestored(
            organization_id=organization_id, reset_config_count=len(configs)
        )
        logger.info("captive_portal_powered_by_restored", extra=_event_extra(event))
        return len(configs)

    async def _audit(
        self, actor_user_id: uuid.UUID | None, config: CaptivePortalConfig
    ) -> None:
        if self.audit_writer is None:
            return
        await self.audit_writer.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=AuditAction.CAPTIVE_PORTAL_POWERED_BY_RESTORED.value,
            entity_type="captive_portal_config",
            entity_id=config.id,
            description=(
                f"Captive portal config '{config.name}': 'Powered by' "
                "attribution restored by license downgrade (white_label "
                "entitlement removed)"
            ),
            event_metadata={
                "is_active": config.is_active,
                "is_default": config.is_default,
            },
            organization_id=config.organization_id,
            location_id=config.location_id,
        )


__all__ = [
    "BrandingLookupProtocol",
    "BrandingRowProtocol",
    "CaptivePortalService",
    "PoweredByAttributionResetService",
    "OrganizationLookupProtocol",
    "LocationLookupProtocol",
    "AuditLogWriter",
    "CaptivePortalResolveCacheProtocol",
    "ResolvedBranding",
    "ResolvedPortalConfig",
]
