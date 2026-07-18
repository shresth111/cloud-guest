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
from typing import Protocol

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


# ============================================================================
# Read model
# ============================================================================


@dataclass(frozen=True, slots=True)
class ResolvedPortalConfig:
    """Wraps the resolved config together with which tier answered the
    lookup -- useful for the guest-facing response/tests to assert
    resolution actually preferred the location override when both exist,
    without re-deriving it from the raw row."""

    config: CaptivePortalConfig
    resolved_via_location_override: bool


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
    ) -> None:
        self.repository = repository
        self.organization_lookup = organization_lookup
        self.location_lookup = location_lookup
        self.audit_writer = audit_writer

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
        voucher_enabled: bool,
        username_password_enabled: bool,
        social_login_enabled: bool,
        social_login_providers: list[str],
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
            voucher_enabled=voucher_enabled,
            username_password_enabled=username_password_enabled,
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

        resolved_organization_id = organization_id
        if location_id is not None:
            location = await self.location_lookup.get_location(
                location_id, requesting_organization_id=organization_id
            )
            resolved_organization_id = location.organization_id
            location_config = await self.repository.find_active_for_location(
                resolved_organization_id, location_id
            )
            if location_config is not None:
                return ResolvedPortalConfig(
                    config=location_config, resolved_via_location_override=True
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
                config=org_default, resolved_via_location_override=False
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
    "ResolvedPortalConfig",
]
