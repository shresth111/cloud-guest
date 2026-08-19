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

import dataclasses
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from app.domains.location.models import Location
from app.domains.organization.models import Organization
from app.domains.rbac.enums import AuditAction

from .constants import PRIVACY_POLICY_LABEL, TERMS_AND_CONDITIONS_LABEL
from .events import (
    CaptivePortalConfigActivated,
    CaptivePortalConfigCreated,
    CaptivePortalConfigDeactivated,
    CaptivePortalConfigDeleted,
    CaptivePortalConfigUpdated,
)
from .exceptions import (
    CaptivePortalConfigNotConfiguredError,
    CaptivePortalConfigNotFoundError,
    CrossOrganizationCaptivePortalConfigAccessError,
    MissingPortalResolutionParamsError,
)
from .models import CaptivePortalConfig
from .repository import CaptivePortalRepositoryProtocol
from .validators import (
    validate_business_hours_schedule,
    validate_business_hours_timezone,
    validate_default_scope,
    validate_hex_color,
    validate_single_content_source,
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


class AuditLogWriter(Protocol):
    """The minimal surface this service needs to write into RBAC's shared
    ``audit_log_entries`` table -- the same narrow, duck-typed protocol
    shape every other domain's service already defines for itself."""

    async def create_audit_log_entry(self, **fields: object) -> object: ...


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
    ) -> None: ...

    async def invalidate(
        self,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
    ) -> None: ...


# ============================================================================
# Read model
# ============================================================================


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
    ) -> None:
        self.repository = repository
        self.organization_lookup = organization_lookup
        self.location_lookup = location_lookup
        self.audit_writer = audit_writer
        self.resolve_cache = resolve_cache

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
            otp_sms_enabled=otp_sms_enabled,
            otp_email_enabled=otp_email_enabled,
            otp_whatsapp_enabled=otp_whatsapp_enabled,
            voucher_enabled=voucher_enabled,
            username_password_enabled=username_password_enabled,
            pin_login_enabled=pin_login_enabled,
            social_login_enabled=social_login_enabled,
            social_login_providers=list(social_login_providers),
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
            validate_business_hours_timezone(str(update_data["business_hours_timezone"]))
        if "business_hours_schedule" in update_data:
            validate_business_hours_schedule(
                dict(update_data["business_hours_schedule"] or {})
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

        if self.resolve_cache is not None:
            cached = await self.resolve_cache.get(organization_id, location_id)
            if cached is not None:
                return ResolvedPortalConfig.from_cache_payload(cached)

        resolved = await self._resolve_portal_config_uncached(
            organization_id=organization_id, location_id=location_id
        )

        if self.resolve_cache is not None:
            await self.resolve_cache.set(
                organization_id, location_id, resolved.to_cache_payload()
            )
        return resolved

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
            )
        raise CaptivePortalConfigNotConfiguredError(resolved_organization_id)

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


__all__ = [
    "CaptivePortalService",
    "OrganizationLookupProtocol",
    "LocationLookupProtocol",
    "AuditLogWriter",
    "CaptivePortalResolveCacheProtocol",
    "ResolvedPortalConfig",
]
