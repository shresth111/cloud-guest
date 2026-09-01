"""Unit tests for the Captive Portal domain (BE-010 Part 3): config CRUD,
single-default-per-organization enforcement, location-override-vs-
organization-default resolution (including the "neither configured" error
case), hex color validation, text/url mutual-exclusivity validation for
terms and conditions/privacy policy, cross-tenant location rejection, and
the social-login flag being a schema-only placeholder (no real OAuth is
ever attempted).

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_voucher.py``); ``asyncio_mode = "auto"`` runs async tests
directly. ``CaptivePortalService`` is exercised against small, hand-rolled
in-memory fakes for its repository, audit writer, and organization/location
lookups (mirroring ``test_voucher.py``'s own ``FakeOrganizationLookup``/
``FakeLocationLookup`` shape) -- there is no live Postgres in this
environment.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from app.domains.billing.constants import PlanFeatureKey
from app.domains.captive_portal.constants import (
    DEFAULT_BACKGROUND_FOCAL_X,
    DEFAULT_BACKGROUND_FOCAL_Y,
    DEFAULT_BACKGROUND_OVERLAY_STRENGTH,
    DEFAULT_GUEST_FONT_CHOICE,
    POST_LOGIN_HTML_MAX_BYTES,
    SPLASH_HEADLINE_MAX_LENGTH,
    SPLASH_WELCOME_MESSAGE_MAX_LENGTH,
    TERMS_AND_CONDITIONS_LABEL,
    GuestFontChoice,
)
from app.domains.captive_portal.exceptions import (
    CaptivePortalConfigNotConfiguredError,
    CaptivePortalConfigNotFoundError,
    CrossOrganizationCaptivePortalConfigAccessError,
    InvalidBackgroundFocalPointError,
    InvalidBackgroundOverlayStrengthError,
    InvalidDefaultConfigScopeError,
    InvalidGuestFontChoiceError,
    InvalidHexColorError,
    InvalidPortalContentSourceError,
    MissingPortalResolutionParamsError,
    PostLoginHtmlTooLargeError,
    PoweredByAttributionNotEntitledError,
    SplashTextTooLongError,
)
from app.domains.captive_portal.html_sanitizer import (
    sanitize_post_login_html,
    sanitize_stylesheet,
)
from app.domains.captive_portal.models import CaptivePortalConfig
from app.domains.captive_portal.service import (
    CaptivePortalService,
    PoweredByAttributionResetService,
    ResolvedPortalConfig,
)
from app.domains.captive_portal.validators import (
    validate_background_focal_point,
    validate_background_overlay_strength,
    validate_default_scope,
    validate_guest_font_choice,
    validate_hex_color,
    validate_single_content_source,
    validate_splash_text_length,
)
from app.domains.location.exceptions import (
    CrossOrganizationLocationAccessError,
    LocationNotFoundError,
)
from app.domains.location.models import Location
from app.domains.organization.enums import OrganizationType
from app.domains.organization.exceptions import OrganizationNotFoundError
from app.domains.organization.models import Organization

# ============================================================================
# Test doubles
# ============================================================================


def _now() -> datetime:
    return datetime.now(UTC)


def _base_fields(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": uuid.uuid4(),
        "created_at": _now(),
        "updated_at": _now(),
        "deleted_at": None,
        "is_deleted": False,
        "created_by": None,
        "updated_by": None,
        "version": 1,
    }
    base.update(overrides)
    return base


@dataclass
class FakeAuditLogWriter:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> dict[str, object]:
        self.entries.append(fields)
        return fields


@dataclass
class FakeOrganizationLookup:
    organizations: dict[uuid.UUID, Organization] = field(default_factory=dict)

    async def get_organization(
        self, organization_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Organization:
        organization = self.organizations.get(organization_id)
        if organization is None or (organization.is_deleted and not include_deleted):
            raise OrganizationNotFoundError(organization_id)
        return organization

    def add(self) -> Organization:
        organization = Organization(
            **_base_fields(
                name="Org",
                slug=f"org-{uuid.uuid4()}",
                legal_name=None,
                org_type=OrganizationType.STANDARD.value,
                status="active",
                parent_organization_id=None,
                contact_email="admin@example.com",
                contact_phone=None,
                timezone="UTC",
                default_locale="en",
                settings={},
                subscription_tier=None,
            )
        )
        self.organizations[organization.id] = organization
        return organization


@dataclass
class FakeLocationLookup:
    locations: dict[uuid.UUID, Location] = field(default_factory=dict)

    async def get_location(
        self,
        location_id: uuid.UUID,
        *,
        requesting_organization_id: uuid.UUID | None = None,
        include_deleted: bool = False,
    ) -> Location:
        location = self.locations.get(location_id)
        if location is None or (location.is_deleted and not include_deleted):
            raise LocationNotFoundError(location_id)
        if (
            requesting_organization_id is not None
            and location.organization_id != requesting_organization_id
        ):
            raise CrossOrganizationLocationAccessError()
        return location

    def add(self, *, organization_id: uuid.UUID, country: str = "US") -> Location:
        location = Location(
            **_base_fields(
                organization_id=organization_id,
                name="HQ",
                slug=f"hq-{uuid.uuid4()}",
                status="active",
                address_line1="1 Main St",
                address_line2=None,
                city="Austin",
                state_province="TX",
                postal_code="78701",
                country=country,
                timezone="UTC",
                latitude=None,
                longitude=None,
                contact_name=None,
                contact_phone=None,
                contact_email=None,
                settings={},
            )
        )
        self.locations[location.id] = location
        return location


@dataclass
class FakeCaptivePortalRepository:
    """In-memory stand-in for ``CaptivePortalRepositoryProtocol`` --
    reimplements the same ``IS NULL``/``is_default``/``is_active`` filtering
    the real ``CaptivePortalRepository``'s hand-written ``select``
    statements perform, since ``GenericRepository``'s filters dict cannot
    express an explicit ``IS NULL`` predicate (see ``repository.py``'s
    module docstring)."""

    configs: dict[uuid.UUID, CaptivePortalConfig] = field(default_factory=dict)

    async def create_config(self, **fields: object) -> CaptivePortalConfig:
        config = CaptivePortalConfig(**_base_fields(**fields))
        self.configs[config.id] = config
        return config

    async def get_config(self, config_id: uuid.UUID) -> CaptivePortalConfig | None:
        config = self.configs.get(config_id)
        if config is None or config.is_deleted:
            return None
        return config

    async def update_config(
        self, config: CaptivePortalConfig, data: dict[str, object]
    ) -> CaptivePortalConfig:
        for key, value in data.items():
            setattr(config, key, value)
        config.version += 1
        config.updated_at = _now()
        return config

    async def soft_delete_config(
        self, config: CaptivePortalConfig
    ) -> CaptivePortalConfig:
        config.is_deleted = True
        config.deleted_at = _now()
        return config

    async def list_powered_by_disabled(
        self, organization_id: uuid.UUID
    ) -> list[CaptivePortalConfig]:
        return [
            config
            for config in self.configs.values()
            if config.organization_id == organization_id
            and config.powered_by_enabled is False
            and not config.is_deleted
        ]

    async def list_configs(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = "created_at",
        sort_order: object = None,
        **_: object,
    ) -> tuple[list[CaptivePortalConfig], object]:
        from app.database.constants import SortOrder
        from app.database.utils.pagination import PageParams, PaginationMeta

        sort_order = sort_order or SortOrder.DESC
        items = [c for c in self.configs.values() if not c.is_deleted]
        for key, value in (filters or {}).items():
            if value is None:
                continue
            items = [item for item in items if getattr(item, key) == value]
        items.sort(
            key=lambda item: getattr(item, sort_by),
            reverse=(sort_order == SortOrder.DESC),
        )
        params = PageParams(page=page, page_size=page_size)
        total = len(items)
        page_items = items[params.offset : params.offset + params.page_size]
        return page_items, PaginationMeta.from_total(params, total)

    async def find_default_for_organization(
        self, organization_id: uuid.UUID
    ) -> CaptivePortalConfig | None:
        for config in self.configs.values():
            if (
                config.organization_id == organization_id
                and config.location_id is None
                and config.is_default
                and not config.is_deleted
            ):
                return config
        return None

    async def find_active_org_default(
        self, organization_id: uuid.UUID
    ) -> CaptivePortalConfig | None:
        for config in self.configs.values():
            if (
                config.organization_id == organization_id
                and config.location_id is None
                and config.is_default
                and config.is_active
                and not config.is_deleted
            ):
                return config
        return None

    async def find_active_for_location(
        self, organization_id: uuid.UUID, location_id: uuid.UUID
    ) -> CaptivePortalConfig | None:
        candidates = [
            c
            for c in self.configs.values()
            if c.organization_id == organization_id
            and c.location_id == location_id
            and c.is_active
            and not c.is_deleted
        ]
        if not candidates:
            return None
        candidates.sort(key=lambda c: c.updated_at, reverse=True)
        return candidates[0]


@dataclass
class FakeCaptivePortalResolveCache:
    """In-memory stand-in for ``cache.CaptivePortalResolveCache`` -- same
    ``get``/``set``/``invalidate`` surface as
    ``service.CaptivePortalResolveCacheProtocol``, keyed identically (a
    ``(organization_id, location_id)`` pair, with a ``"-"`` sentinel for
    ``None``) but backed by a plain dict instead of Redis."""

    store: dict[tuple[str, str], dict[str, object]] = field(default_factory=dict)
    org_index: dict[str, set[tuple[str, str]]] = field(default_factory=dict)
    negative_keys: set[tuple[str, str]] = field(default_factory=set)

    @staticmethod
    def _key(
        organization_id: uuid.UUID | None, location_id: uuid.UUID | None
    ) -> tuple[str, str]:
        return (
            str(organization_id) if organization_id else "-",
            str(location_id) if location_id else "-",
        )

    async def get(
        self, organization_id: uuid.UUID | None, location_id: uuid.UUID | None
    ) -> dict[str, object] | None:
        return self.store.get(self._key(organization_id, location_id))

    async def set(
        self,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        payload: dict[str, object],
        *,
        index_organization_id: uuid.UUID | None = None,
        negative: bool = False,
    ) -> None:
        key = self._key(organization_id, location_id)
        self.store[key] = payload
        self.negative_keys.discard(key)
        if negative:
            self.negative_keys.add(key)
        if index_organization_id is not None:
            self.org_index.setdefault(str(index_organization_id), set()).add(key)

    async def invalidate(
        self, organization_id: uuid.UUID | None, location_id: uuid.UUID | None
    ) -> None:
        self.store.pop(self._key(organization_id, location_id), None)

    async def invalidate_organization(self, organization_id: uuid.UUID) -> None:
        for key in self.org_index.pop(str(organization_id), set()):
            self.store.pop(key, None)


@dataclass
class FakeBrandingLookup:
    """In-memory stand-in for
    ``app.domains.branding.repository.BrandingRepository`` -- only
    ``get_by_organization``, the single method
    ``service.BrandingLookupProtocol`` names. ``calls`` records every
    lookup so a test can prove the query is (or is not) reaching the
    database, which is the whole point of design spec §5 S7."""

    rows: dict[uuid.UUID, SimpleNamespace] = field(default_factory=dict)
    calls: list[uuid.UUID] = field(default_factory=list)

    def add(
        self,
        organization_id: uuid.UUID,
        *,
        logo_key: str | None = None,
        logo_url: str | None = None,
        background_image_key: str | None = None,
        background_luminance: int | None = None,
        background_top_luminance: int | None = None,
        background_entropy: int | None = None,
    ) -> SimpleNamespace:
        row = SimpleNamespace(
            logo_key=logo_key,
            logo_url=logo_url,
            background_image_key=background_image_key,
            background_luminance=background_luminance,
            background_top_luminance=background_top_luminance,
            background_entropy=background_entropy,
        )
        self.rows[organization_id] = row
        return row

    async def get_by_organization(
        self, organization_id: uuid.UUID
    ) -> SimpleNamespace | None:
        self.calls.append(organization_id)
        return self.rows.get(organization_id)


@dataclass
class Fixture:
    repository: FakeCaptivePortalRepository
    audit_writer: FakeAuditLogWriter
    organization_lookup: FakeOrganizationLookup
    location_lookup: FakeLocationLookup
    service: CaptivePortalService
    organization: Organization
    resolve_cache: FakeCaptivePortalResolveCache | None = None
    branding_lookup: FakeBrandingLookup | None = None


def make_service(
    *, with_cache: bool = False, with_branding: bool = False
) -> Fixture:
    repository = FakeCaptivePortalRepository()
    audit_writer = FakeAuditLogWriter()
    organization_lookup = FakeOrganizationLookup()
    location_lookup = FakeLocationLookup()
    organization = organization_lookup.add()
    resolve_cache = FakeCaptivePortalResolveCache() if with_cache else None
    branding_lookup = FakeBrandingLookup() if with_branding else None
    service = CaptivePortalService(
        repository,
        organization_lookup,
        location_lookup,
        audit_writer=audit_writer,
        resolve_cache=resolve_cache,
        branding_lookup=branding_lookup,
    )
    return Fixture(
        repository=repository,
        audit_writer=audit_writer,
        organization_lookup=organization_lookup,
        location_lookup=location_lookup,
        service=service,
        organization=organization,
        resolve_cache=resolve_cache,
        branding_lookup=branding_lookup,
    )


async def _create_config(
    fx: Fixture,
    *,
    location_id: uuid.UUID | None = None,
    name: str = "Test Portal",
    is_active: bool = True,
    is_default: bool = False,
    theme: str = "light",
    primary_color: str = "#1A73E8",
    secondary_color: str = "#FFFFFF",
    terms_and_conditions_text: str | None = None,
    terms_and_conditions_url: str | None = None,
    privacy_policy_text: str | None = None,
    privacy_policy_url: str | None = None,
    social_login_enabled: bool = False,
    social_login_providers: list[str] | None = None,
    splash_headline: str | None = None,
    splash_welcome_message: str | None = None,
    # True (the real, standard "OTP once, then a saved password" baseline
    # -- see CaptivePortalConfig.username_password_enabled's own
    # docstring) mirrors this helper's own otp_sms_enabled/voucher_enabled
    # defaults being the actually-enabled-by-default methods.
    username_password_enabled: bool = True,
    pin_login_enabled: bool = False,
    post_login_html: str | None = None,
    requesting_organization_id: uuid.UUID | None = None,
    organization_id: uuid.UUID | None = None,
) -> CaptivePortalConfig:
    return await fx.service.create_config(
        actor_user_id=uuid.uuid4(),
        requesting_organization_id=(
            requesting_organization_id
            if requesting_organization_id is not None
            else fx.organization.id
        ),
        organization_id=(
            organization_id if organization_id is not None else fx.organization.id
        ),
        location_id=location_id,
        name=name,
        is_active=is_active,
        is_default=is_default,
        theme=theme,
        logo_url=None,
        background_image_url=None,
        primary_color=primary_color,
        secondary_color=secondary_color,
        default_language="en",
        supported_languages=["en"],
        advertisement_banner_url=None,
        advertisement_banner_link=None,
        terms_and_conditions_text=terms_and_conditions_text,
        terms_and_conditions_url=terms_and_conditions_url,
        privacy_policy_text=privacy_policy_text,
        privacy_policy_url=privacy_policy_url,
        splash_headline=splash_headline,
        splash_welcome_message=splash_welcome_message,
        redirect_url=None,
        otp_sms_enabled=True,
        otp_email_enabled=False,
        otp_whatsapp_enabled=False,
        voucher_enabled=True,
        username_password_enabled=username_password_enabled,
        pin_login_enabled=pin_login_enabled,
        social_login_enabled=social_login_enabled,
        social_login_providers=social_login_providers or [],
        post_login_html=post_login_html,
    )


# ============================================================================
# CRUD
# ============================================================================


class TestCrud:
    async def test_create_config(self) -> None:
        fx = make_service()
        config = await _create_config(fx, is_default=True)
        assert config.organization_id == fx.organization.id
        assert config.location_id is None
        assert config.is_default is True

    async def test_get_config(self) -> None:
        fx = make_service()
        config = await _create_config(fx)
        fetched = await fx.service.get_config(
            config.id, requesting_organization_id=fx.organization.id
        )
        assert fetched.id == config.id

    async def test_get_missing_config_raises(self) -> None:
        fx = make_service()
        with pytest.raises(CaptivePortalConfigNotFoundError):
            await fx.service.get_config(uuid.uuid4())

    async def test_list_configs_scoped_to_organization(self) -> None:
        fx = make_service()
        await _create_config(fx, name="A")
        await _create_config(fx, name="B")
        other_org = fx.organization_lookup.add()
        await _create_config(
            fx,
            name="Other org config",
            requesting_organization_id=other_org.id,
            organization_id=other_org.id,
        )
        items, meta = await fx.service.list_configs(
            requesting_organization_id=fx.organization.id
        )
        assert meta.total_items == 2
        assert {c.name for c in items} == {"A", "B"}

    async def test_update_config_changes_fields(self) -> None:
        fx = make_service()
        config = await _create_config(fx)
        updated = await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"name": "Renamed Portal", "splash_headline": "Hi!"},
        )
        assert updated.name == "Renamed Portal"
        assert updated.splash_headline == "Hi!"

    async def test_update_ignores_organization_and_location_id(self) -> None:
        fx = make_service()
        config = await _create_config(fx)
        other_org = fx.organization_lookup.add()
        updated = await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"organization_id": other_org.id, "location_id": uuid.uuid4()},
        )
        assert updated.organization_id == fx.organization.id
        assert updated.location_id is None

    async def test_delete_config_soft_deletes_and_deactivates(self) -> None:
        fx = make_service()
        config = await _create_config(fx)
        deleted = await fx.service.delete_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
        )
        assert deleted.is_deleted is True
        assert deleted.is_active is False
        with pytest.raises(CaptivePortalConfigNotFoundError):
            await fx.service.get_config(config.id)

    async def test_activate_and_deactivate_config(self) -> None:
        fx = make_service()
        config = await _create_config(fx, is_active=False)
        activated = await fx.service.activate_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
        )
        assert activated.is_active is True
        deactivated = await fx.service.deactivate_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
        )
        assert deactivated.is_active is False


# ============================================================================
# Audit coverage
# ============================================================================


class TestAudit:
    async def test_create_update_activate_deactivate_delete_are_all_audited(
        self,
    ) -> None:
        fx = make_service()
        config = await _create_config(fx)
        await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"name": "New name"},
        )
        await fx.service.deactivate_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
        )
        await fx.service.activate_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
        )
        await fx.service.delete_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
        )
        actions = [entry["action"] for entry in fx.audit_writer.entries]
        assert "captive_portal_config_created" in actions
        assert "captive_portal_config_updated" in actions
        assert "captive_portal_config_deactivated" in actions
        assert "captive_portal_config_activated" in actions
        assert "captive_portal_config_deleted" in actions


# ============================================================================
# Single-default-per-organization enforcement
# ============================================================================


class TestSingleDefaultEnforcement:
    async def test_second_default_undefaults_the_first(self) -> None:
        fx = make_service()
        first = await _create_config(fx, name="First default", is_default=True)
        second = await _create_config(fx, name="Second default", is_default=True)

        refreshed_first = await fx.service.get_config(first.id)
        refreshed_second = await fx.service.get_config(second.id)
        assert refreshed_first.is_default is False
        assert refreshed_second.is_default is True

    async def test_update_to_default_undefaults_prior_default(self) -> None:
        fx = make_service()
        first = await _create_config(fx, name="First", is_default=True)
        second = await _create_config(fx, name="Second", is_default=False)

        await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=second.id,
            requesting_organization_id=fx.organization.id,
            data={"is_default": True},
        )
        refreshed_first = await fx.service.get_config(first.id)
        refreshed_second = await fx.service.get_config(second.id)
        assert refreshed_first.is_default is False
        assert refreshed_second.is_default is True

    async def test_is_default_with_location_id_rejected_on_create(self) -> None:
        fx = make_service()
        location = fx.location_lookup.add(organization_id=fx.organization.id)
        with pytest.raises(InvalidDefaultConfigScopeError):
            await _create_config(fx, location_id=location.id, is_default=True)

    async def test_is_default_with_location_id_rejected_on_update(self) -> None:
        fx = make_service()
        location = fx.location_lookup.add(organization_id=fx.organization.id)
        config = await _create_config(fx, location_id=location.id, is_default=False)
        with pytest.raises(InvalidDefaultConfigScopeError):
            await fx.service.update_config(
                actor_user_id=uuid.uuid4(),
                config_id=config.id,
                requesting_organization_id=fx.organization.id,
                data={"is_default": True},
            )

    async def test_validate_default_scope_directly(self) -> None:
        with pytest.raises(InvalidDefaultConfigScopeError):
            validate_default_scope(is_default=True, location_id=uuid.uuid4())
        # Legal combinations never raise.
        validate_default_scope(is_default=True, location_id=None)
        validate_default_scope(is_default=False, location_id=uuid.uuid4())


# ============================================================================
# Resolution: location override vs. organization default
# ============================================================================


class TestResolution:
    async def test_resolves_org_default_when_no_location_override(self) -> None:
        fx = make_service()
        default_config = await _create_config(fx, name="Org default", is_default=True)
        resolved = await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )
        assert resolved.config.id == default_config.id
        assert resolved.resolved_via_location_override is False

    async def test_location_override_wins_over_org_default(self) -> None:
        fx = make_service()
        location = fx.location_lookup.add(organization_id=fx.organization.id)
        await _create_config(fx, name="Org default", is_default=True)
        location_config = await _create_config(
            fx, name="Location override", location_id=location.id
        )
        resolved = await fx.service.resolve_portal_config(
            organization_id=None, location_id=location.id
        )
        assert resolved.config.id == location_config.id
        assert resolved.resolved_via_location_override is True

    async def test_falls_back_to_org_default_when_location_has_no_override(
        self,
    ) -> None:
        fx = make_service()
        location = fx.location_lookup.add(organization_id=fx.organization.id)
        default_config = await _create_config(fx, name="Org default", is_default=True)
        resolved = await fx.service.resolve_portal_config(
            organization_id=None, location_id=location.id
        )
        assert resolved.config.id == default_config.id
        assert resolved.resolved_via_location_override is False

    async def test_inactive_location_override_is_ignored(self) -> None:
        fx = make_service()
        location = fx.location_lookup.add(organization_id=fx.organization.id)
        default_config = await _create_config(fx, name="Org default", is_default=True)
        await _create_config(
            fx,
            name="Inactive override",
            location_id=location.id,
            is_active=False,
        )
        resolved = await fx.service.resolve_portal_config(
            organization_id=None, location_id=location.id
        )
        assert resolved.config.id == default_config.id

    async def test_neither_location_nor_org_default_raises(self) -> None:
        fx = make_service()
        with pytest.raises(CaptivePortalConfigNotConfiguredError):
            await fx.service.resolve_portal_config(
                organization_id=fx.organization.id, location_id=None
            )

    async def test_inactive_org_default_does_not_resolve(self) -> None:
        fx = make_service()
        await _create_config(fx, is_default=True, is_active=False)
        with pytest.raises(CaptivePortalConfigNotConfiguredError):
            await fx.service.resolve_portal_config(
                organization_id=fx.organization.id, location_id=None
            )

    async def test_missing_both_params_raises(self) -> None:
        fx = make_service()
        with pytest.raises(MissingPortalResolutionParamsError):
            await fx.service.resolve_portal_config(
                organization_id=None, location_id=None
            )

    async def test_resolve_by_location_derives_organization(self) -> None:
        fx = make_service()
        location = fx.location_lookup.add(organization_id=fx.organization.id)
        default_config = await _create_config(fx, is_default=True)
        # No organization_id supplied at all -- derived from the location.
        resolved = await fx.service.resolve_portal_config(
            organization_id=None, location_id=location.id
        )
        assert resolved.config.id == default_config.id

    async def test_resolve_rejects_mismatched_organization_and_location(self) -> None:
        fx = make_service()
        other_org = fx.organization_lookup.add()
        foreign_location = fx.location_lookup.add(organization_id=other_org.id)
        with pytest.raises(CrossOrganizationLocationAccessError):
            await fx.service.resolve_portal_config(
                organization_id=fx.organization.id, location_id=foreign_location.id
            )

    async def test_location_country_populated_via_location_override(self) -> None:
        fx = make_service()
        location = fx.location_lookup.add(
            organization_id=fx.organization.id, country="IN"
        )
        await _create_config(fx, name="Location override", location_id=location.id)
        resolved = await fx.service.resolve_portal_config(
            organization_id=None, location_id=location.id
        )
        assert resolved.location_country == "IN"

    async def test_location_country_populated_via_org_default_fallback(self) -> None:
        """A location_id is supplied but has no override config of its own
        -- resolution falls back to the org default, but the *location's*
        own country should still come through (a guest hitting this exact
        location's portal link should get that location's real country,
        not None, even though the config itself is the org-wide default)."""
        fx = make_service()
        location = fx.location_lookup.add(
            organization_id=fx.organization.id, country="IN"
        )
        await _create_config(fx, name="Org default", is_default=True)
        resolved = await fx.service.resolve_portal_config(
            organization_id=None, location_id=location.id
        )
        assert resolved.resolved_via_location_override is False
        assert resolved.location_country == "IN"

    async def test_location_country_is_none_when_resolved_by_organization_only(
        self,
    ) -> None:
        fx = make_service()
        await _create_config(fx, name="Org default", is_default=True)
        resolved = await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )
        assert resolved.location_country is None

    async def test_location_name_populated_alongside_location_country(self) -> None:
        """``location_name`` is sourced off the exact same
        ``location_lookup.get_location`` call ``location_country`` already
        piggybacks on -- see ``ResolvedPortalConfig.location_name``'s own
        docstring for why this replaces a second, router-level query."""
        fx = make_service()
        location = fx.location_lookup.add(organization_id=fx.organization.id)
        await _create_config(fx, name="Org default", is_default=True)
        resolved = await fx.service.resolve_portal_config(
            organization_id=None, location_id=location.id
        )
        assert resolved.location_name == location.name

    async def test_location_name_is_none_when_resolved_by_organization_only(
        self,
    ) -> None:
        fx = make_service()
        await _create_config(fx, name="Org default", is_default=True)
        resolved = await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )
        assert resolved.location_name is None


# ============================================================================
# Guest-facing resolve cache
# ============================================================================


class TestResolveCache:
    """``resolve_portal_config`` is opt-in cache-or-fetch (a ``None``
    ``resolve_cache`` -- ``make_service()``'s default -- behaves exactly as
    it always has, per every test above this class). These tests exercise
    ``make_service(with_cache=True)``, proving both that a cache hit really
    does short-circuit the repository, and that every mutation invalidates
    the real keys a guest call could have populated -- including the
    ``(None, location_id)`` key shape a location-only guest call warms."""

    async def test_second_resolve_is_served_from_cache(self) -> None:
        fx = make_service(with_cache=True)
        config = await _create_config(fx, name="Org default", is_default=True)
        first = await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )
        assert first.config.id == config.id

        # Delete the row straight out of the backing store, bypassing the
        # service entirely -- if the second call still succeeds with the
        # same data, it can only have come from the cache, not a real
        # repository lookup.
        del fx.repository.configs[config.id]

        second = await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )
        assert second.config.id == config.id
        assert second.config.name == "Org default"

    async def test_update_invalidates_org_default_cache_entry(self) -> None:
        fx = make_service(with_cache=True)
        config = await _create_config(fx, name="Org default", is_default=True)
        await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )
        await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"splash_headline": "New headline"},
        )
        resolved = await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )
        assert resolved.config.splash_headline == "New headline"

    async def test_update_invalidates_both_key_shapes_for_location_config(
        self,
    ) -> None:
        """A real guest call for a location-scoped config commonly supplies
        ``location_id`` alone (no ``organization_id``) -- that resolution
        is cached under a ``(None, location_id)`` key distinct from
        ``(organization_id, location_id)``. An edit must invalidate both,
        or this exact call shape would keep serving stale data."""
        fx = make_service(with_cache=True)
        location = fx.location_lookup.add(organization_id=fx.organization.id)
        config = await _create_config(
            fx, name="Location override", location_id=location.id
        )
        # Warm the (None, location_id) cache entry -- the location-only
        # call shape.
        await fx.service.resolve_portal_config(
            organization_id=None, location_id=location.id
        )
        await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"splash_headline": "Updated"},
        )
        resolved = await fx.service.resolve_portal_config(
            organization_id=None, location_id=location.id
        )
        assert resolved.config.splash_headline == "Updated"

    async def test_activate_deactivate_invalidate_cache(self) -> None:
        fx = make_service(with_cache=True)
        config = await _create_config(fx, is_default=True, is_active=False)
        with pytest.raises(CaptivePortalConfigNotConfiguredError):
            await fx.service.resolve_portal_config(
                organization_id=fx.organization.id, location_id=None
            )
        await fx.service.activate_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
        )
        activated = await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )
        assert activated.config.id == config.id

        await fx.service.deactivate_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
        )
        with pytest.raises(CaptivePortalConfigNotConfiguredError):
            await fx.service.resolve_portal_config(
                organization_id=fx.organization.id, location_id=None
            )

    async def test_delete_invalidates_cache(self) -> None:
        fx = make_service(with_cache=True)
        config = await _create_config(fx, is_default=True)
        await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )
        await fx.service.delete_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
        )
        with pytest.raises(CaptivePortalConfigNotConfiguredError):
            await fx.service.resolve_portal_config(
                organization_id=fx.organization.id, location_id=None
            )

    async def test_create_new_default_invalidates_stale_not_configured_cache(
        self,
    ) -> None:
        """Guards against caching a *negative* result forever: nothing
        warms the cache on a ``CaptivePortalConfigNotConfiguredError`` (it's
        raised before ``resolve_cache.set`` is ever reached), so creating
        the first config for a previously-unconfigured organization must be
        immediately resolvable, not stuck behind a cached miss."""
        fx = make_service(with_cache=True)
        with pytest.raises(CaptivePortalConfigNotConfiguredError):
            await fx.service.resolve_portal_config(
                organization_id=fx.organization.id, location_id=None
            )
        config = await _create_config(fx, name="First config", is_default=True)
        resolved = await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )
        assert resolved.config.id == config.id

    async def test_cached_payload_round_trips_via_resolved_portal_config(self) -> None:
        """The cached payload isn't merely equal-looking data -- it's the
        exact ``ResolvedPortalConfig`` a caller gets on a cache miss too,
        round-tripped through ``to_cache_payload``/``from_cache_payload``
        (JSON-serializable primitives only, since the real cache is Redis)."""
        fx = make_service(with_cache=True)
        location = fx.location_lookup.add(
            organization_id=fx.organization.id, country="IN"
        )
        await _create_config(fx, name="Location override", location_id=location.id)
        first = await fx.service.resolve_portal_config(
            organization_id=None, location_id=location.id
        )
        second = await fx.service.resolve_portal_config(
            organization_id=None, location_id=location.id
        )
        assert second.config.id == first.config.id
        assert second.config.name == first.config.name
        assert second.resolved_via_location_override is True
        assert second.location_country == "IN"
        assert second.location_name == location.name


# ============================================================================
# Hex color validation
# ============================================================================


class TestHexColorValidation:
    def test_valid_hex_colors_pass(self) -> None:
        for value in ("#1A73E8", "#FFFFFF", "#000000", "#abcdef"):
            validate_hex_color(value, field_name="primary_color")

    @pytest.mark.parametrize(
        "value",
        ["1A73E8", "#FFF", "#GGGGGG", "blue", "#12345", "#1234567", ""],
    )
    def test_invalid_hex_colors_raise(self, value: str) -> None:
        with pytest.raises(InvalidHexColorError):
            validate_hex_color(value, field_name="primary_color")

    async def test_create_rejects_invalid_primary_color(self) -> None:
        fx = make_service()
        with pytest.raises(InvalidHexColorError):
            await _create_config(fx, primary_color="not-a-color")

    async def test_create_rejects_invalid_secondary_color(self) -> None:
        fx = make_service()
        with pytest.raises(InvalidHexColorError):
            await _create_config(fx, secondary_color="#XYZ")

    async def test_update_rejects_invalid_color(self) -> None:
        fx = make_service()
        config = await _create_config(fx)
        with pytest.raises(InvalidHexColorError):
            await fx.service.update_config(
                actor_user_id=uuid.uuid4(),
                config_id=config.id,
                requesting_organization_id=fx.organization.id,
                data={"primary_color": "nope"},
            )


# ============================================================================
# Terms and conditions / privacy policy mutual-exclusivity validation
# ============================================================================


class TestContentSourceValidation:
    def test_neither_set_is_legal(self) -> None:
        validate_single_content_source(
            None, None, field_label=TERMS_AND_CONDITIONS_LABEL
        )

    def test_only_text_set_is_legal(self) -> None:
        validate_single_content_source(
            "Some text", None, field_label=TERMS_AND_CONDITIONS_LABEL
        )

    def test_only_url_set_is_legal(self) -> None:
        validate_single_content_source(
            None, "https://example.com/terms", field_label=TERMS_AND_CONDITIONS_LABEL
        )

    def test_both_set_raises(self) -> None:
        with pytest.raises(InvalidPortalContentSourceError):
            validate_single_content_source(
                "Some text",
                "https://example.com/terms",
                field_label=TERMS_AND_CONDITIONS_LABEL,
            )

    async def test_create_rejects_both_terms_text_and_url(self) -> None:
        fx = make_service()
        with pytest.raises(InvalidPortalContentSourceError):
            await _create_config(
                fx,
                terms_and_conditions_text="Inline text",
                terms_and_conditions_url="https://example.com/terms",
            )

    async def test_create_rejects_both_privacy_text_and_url(self) -> None:
        fx = make_service()
        with pytest.raises(InvalidPortalContentSourceError):
            await _create_config(
                fx,
                privacy_policy_text="Inline text",
                privacy_policy_url="https://example.com/privacy",
            )

    async def test_update_merging_with_existing_value_still_validated(self) -> None:
        """A patch that only sets the URL, when the existing row already
        has inline text populated, must still be rejected -- the "at most
        one" rule is enforced against the *merged* final state, not just
        the fields present in the patch."""
        fx = make_service()
        config = await _create_config(
            fx, terms_and_conditions_text="Existing inline text"
        )
        with pytest.raises(InvalidPortalContentSourceError):
            await fx.service.update_config(
                actor_user_id=uuid.uuid4(),
                config_id=config.id,
                requesting_organization_id=fx.organization.id,
                data={"terms_and_conditions_url": "https://example.com/terms"},
            )


# ============================================================================
# Tenant isolation
# ============================================================================


class TestTenantIsolation:
    async def test_cross_organization_get_raises(self) -> None:
        fx = make_service()
        config = await _create_config(fx)
        other_org = fx.organization_lookup.add()
        with pytest.raises(CrossOrganizationCaptivePortalConfigAccessError):
            await fx.service.get_config(
                config.id, requesting_organization_id=other_org.id
            )

    async def test_create_for_another_organization_raises(self) -> None:
        fx = make_service()
        other_org = fx.organization_lookup.add()
        with pytest.raises(CrossOrganizationCaptivePortalConfigAccessError):
            await _create_config(
                fx,
                requesting_organization_id=other_org.id,
                organization_id=fx.organization.id,
            )

    async def test_location_must_belong_to_config_organization(self) -> None:
        fx = make_service()
        other_org = fx.organization_lookup.add()
        foreign_location = fx.location_lookup.add(organization_id=other_org.id)
        with pytest.raises(CrossOrganizationLocationAccessError):
            await _create_config(fx, location_id=foreign_location.id)

    async def test_platform_level_caller_may_access_any_organization(self) -> None:
        fx = make_service()
        config = await _create_config(fx)
        fetched = await fx.service.get_config(
            config.id, requesting_organization_id=None
        )
        assert fetched.id == config.id


# ============================================================================
# Social login: schema-only placeholder, no real OAuth
# ============================================================================


class TestSocialLoginPlaceholder:
    async def test_social_login_flag_and_providers_round_trip_verbatim(self) -> None:
        fx = make_service()
        config = await _create_config(
            fx,
            social_login_enabled=True,
            social_login_providers=["google", "facebook"],
        )
        assert config.social_login_enabled is True
        assert config.social_login_providers == ["google", "facebook"]

    async def test_social_login_disabled_by_default(self) -> None:
        fx = make_service()
        config = await _create_config(fx)
        assert config.social_login_enabled is False
        assert config.social_login_providers == []

    async def test_username_password_enabled_by_default(self) -> None:
        """The standard baseline every location gets: a guest verifies
        once via OTP, sets a password right after, and signs in with
        phone/email + password from then on -- real and on by default,
        same as otp_sms_enabled/voucher_enabled (an admin can still turn
        it off per location, e.g. an SMS-OTP-only kiosk)."""
        fx = make_service()
        config = await _create_config(fx)
        assert config.username_password_enabled is True

    async def test_username_password_can_be_disabled_per_location(self) -> None:
        fx = make_service()
        config = await _create_config(fx, username_password_enabled=False)
        assert config.username_password_enabled is False

    async def test_no_provider_registry_validation_is_performed(self) -> None:
        """Any string is accepted as a provider slug -- there is no real
        provider registry anywhere in this codebase to validate against."""
        fx = make_service()
        config = await _create_config(
            fx,
            social_login_enabled=True,
            social_login_providers=["not-a-real-provider", ""],
        )
        assert config.social_login_providers == ["not-a-real-provider", ""]


# ============================================================================
# Guest font choice validation (v6 design spec §3.2) -- curated allowlist,
# never free text.
# ============================================================================


class TestGuestFontChoiceValidation:
    @pytest.mark.parametrize(
        "value",
        ["system", "modern-sans", "editorial-serif", "bold-display"],
    )
    def test_valid_choices_pass(self, value: str) -> None:
        validate_guest_font_choice(value)

    @pytest.mark.parametrize(
        "value",
        ["Comic Sans MS", "inter", "MODERN-SANS", "", "system "],
    )
    def test_invalid_choices_raise(self, value: str) -> None:
        with pytest.raises(InvalidGuestFontChoiceError):
            validate_guest_font_choice(value)

    def test_allowlist_matches_enum_exactly(self) -> None:
        """Guards against the allowlist and the GuestFontChoice enum
        silently drifting apart -- every enum member must validate, and
        nothing else may."""
        assert {c.value for c in GuestFontChoice} == {
            "system",
            "modern-sans",
            "editorial-serif",
            "bold-display",
        }

    async def test_update_accepts_a_curated_choice(self) -> None:
        fx = make_service()
        config = await _create_config(fx)
        updated = await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"guest_font_choice": "bold-display"},
        )
        assert updated.guest_font_choice == "bold-display"

    async def test_update_rejects_a_free_text_font_name(self) -> None:
        """The one thing this field must never become -- see spec §3.2/
        §6.2 item 9 ("let guestFontChoice become free text")."""
        fx = make_service()
        config = await _create_config(fx)
        with pytest.raises(InvalidGuestFontChoiceError):
            await fx.service.update_config(
                actor_user_id=uuid.uuid4(),
                config_id=config.id,
                requesting_organization_id=fx.organization.id,
                data={"guest_font_choice": "Comic Sans MS"},
            )


# ============================================================================
# Background overlay strength validation (v6 design spec §4.2) -- the real
# per-venue admin lever replacing three sequential hardcoded opacity
# guesses.
# ============================================================================


class TestBackgroundOverlayStrengthValidation:
    @pytest.mark.parametrize("value", [0, 1, 55, 99, 100])
    def test_valid_range_passes(self, value: int) -> None:
        validate_background_overlay_strength(value)

    @pytest.mark.parametrize("value", [-1, 101, 1000, -100])
    def test_out_of_range_raises(self, value: int) -> None:
        with pytest.raises(InvalidBackgroundOverlayStrengthError):
            validate_background_overlay_strength(value)

    @pytest.mark.parametrize("value", [True, False, "55", 55.0, None])
    def test_non_integer_raises(self, value: object) -> None:
        """``bool`` is explicitly excluded even though Python's ``bool``
        is a subclass of ``int`` -- True/False are never a legal overlay
        strength."""
        with pytest.raises(InvalidBackgroundOverlayStrengthError):
            validate_background_overlay_strength(value)

    async def test_update_accepts_a_valid_strength(self) -> None:
        fx = make_service()
        config = await _create_config(fx)
        updated = await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"background_overlay_strength": 80},
        )
        assert updated.background_overlay_strength == 80

    async def test_update_accepts_boundary_values(self) -> None:
        fx = make_service()
        config = await _create_config(fx)
        for boundary in (0, 100):
            updated = await fx.service.update_config(
                actor_user_id=uuid.uuid4(),
                config_id=config.id,
                requesting_organization_id=fx.organization.id,
                data={"background_overlay_strength": boundary},
            )
            assert updated.background_overlay_strength == boundary

    async def test_update_rejects_out_of_range_strength(self) -> None:
        fx = make_service()
        config = await _create_config(fx)
        with pytest.raises(InvalidBackgroundOverlayStrengthError):
            await fx.service.update_config(
                actor_user_id=uuid.uuid4(),
                config_id=config.id,
                requesting_organization_id=fx.organization.id,
                data={"background_overlay_strength": 150},
            )

    async def test_update_rejects_negative_strength(self) -> None:
        fx = make_service()
        config = await _create_config(fx)
        with pytest.raises(InvalidBackgroundOverlayStrengthError):
            await fx.service.update_config(
                actor_user_id=uuid.uuid4(),
                config_id=config.id,
                requesting_organization_id=fx.organization.id,
                data={"background_overlay_strength": -5},
            )


# ============================================================================
# Model defaults (v6 design spec §3.2/§4.2) -- background_overlay_strength
# defaults to 55 specifically to reproduce today's hardcoded 0.55 scrim
# opacity exactly, so any pre-v6 config row (which never explicitly set
# these two new columns) renders unchanged.
# ============================================================================


class TestGuestFontChoiceAndOverlayStrengthDefaults:
    def test_model_column_defaults_match_the_documented_constants(self) -> None:
        """Asserts the real SQLAlchemy column-level defaults (applied on
        INSERT for any row that doesn't set these explicitly) match the
        spec's documented constants."""
        table = CaptivePortalConfig.__table__
        assert table.c.guest_font_choice.default.arg == DEFAULT_GUEST_FONT_CHOICE.value
        # Was "system" -- that value reproduced the column's own migration-
        # time behavior for pre-v6 rows, a one-time backfill-safety concern
        # unrelated to what a *new* row should default to going forward.
        # Deliberately changed: a freshly-provisioned venue now gets a
        # real, distinctive heading face (self-hosted, Latin-subsetted,
        # metric-matched) out of the box instead of the plain system
        # stack, per direct product feedback that the guest portal needs
        # a distinctive typeface. Every venue can still switch back to
        # System via its own branding settings.
        assert table.c.guest_font_choice.default.arg == "modern-sans"
        assert (
            table.c.background_overlay_strength.default.arg
            == DEFAULT_BACKGROUND_OVERLAY_STRENGTH
        )
        assert table.c.background_overlay_strength.default.arg == 55

    def test_columns_are_not_nullable(self) -> None:
        table = CaptivePortalConfig.__table__
        assert table.c.guest_font_choice.nullable is False
        assert table.c.background_overlay_strength.nullable is False


# ============================================================================
# Guest-facing resolve surfaces the two new fields (v6 design spec §6.1
# item 4: "Surface both on GET /captive-portal/resolve")
# ============================================================================


class TestGuestFontChoiceAndOverlayStrengthResolve:
    async def test_resolve_surfaces_a_custom_font_choice_and_overlay_strength(
        self,
    ) -> None:
        fx = make_service()
        config = await _create_config(fx, name="Org default", is_default=True)
        await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={
                "guest_font_choice": "editorial-serif",
                "background_overlay_strength": 72,
            },
        )
        resolved = await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )
        assert resolved.config.guest_font_choice == "editorial-serif"
        assert resolved.config.background_overlay_strength == 72

    async def test_resolve_cache_round_trips_the_two_new_fields(self) -> None:
        """The cached payload (Redis-backed in production, a plain dict in
        this fake) must preserve these two fields across a cache hit --
        not just the fields every pre-existing cache test already
        covers."""
        fx = make_service(with_cache=True)
        config = await _create_config(fx, name="Org default", is_default=True)
        await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={
                "guest_font_choice": "bold-display",
                "background_overlay_strength": 30,
            },
        )
        first = await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )
        assert first.config.guest_font_choice == "bold-display"
        assert first.config.background_overlay_strength == 30

        # Second call must be served from cache (repository row deleted
        # directly, bypassing the service) -- same proof technique as
        # TestResolveCache.test_second_resolve_is_served_from_cache.
        del fx.repository.configs[config.id]
        second = await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )
        assert second.config.guest_font_choice == "bold-display"
        assert second.config.background_overlay_strength == 30


# ============================================================================
# Per-venue background focal point (v7 design spec §1.4 C4)
# ============================================================================


class TestBackgroundFocalPointValidation:
    @pytest.mark.parametrize("value", [0, 1, 25, 50, 99, 100])
    def test_valid_range_passes(self, value: int) -> None:
        validate_background_focal_point("x", value)
        validate_background_focal_point("y", value)

    @pytest.mark.parametrize("value", [-1, 101, 1000, -100])
    def test_out_of_range_raises(self, value: int) -> None:
        with pytest.raises(InvalidBackgroundFocalPointError):
            validate_background_focal_point("x", value)

    @pytest.mark.parametrize("value", [True, False, "50", 50.0, None])
    def test_non_integer_raises(self, value: object) -> None:
        """``bool`` excluded for the same reason
        ``validate_background_overlay_strength`` excludes it: Python's
        ``bool`` subclasses ``int``, and ``True`` is never a legal focal
        percentage."""
        with pytest.raises(InvalidBackgroundFocalPointError):
            validate_background_focal_point("y", value)

    def test_error_names_the_offending_axis(self) -> None:
        """An admin who mistypes one of two adjacent numeric fields needs
        to be told which one."""
        with pytest.raises(InvalidBackgroundFocalPointError) as exc:
            validate_background_focal_point("y", 140)
        assert "background_focal_y" in str(exc.value)

    async def test_update_accepts_a_valid_focal_point(self) -> None:
        fx = make_service()
        config = await _create_config(fx)
        updated = await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"background_focal_x": 30, "background_focal_y": 70},
        )
        assert updated.background_focal_x == 30
        assert updated.background_focal_y == 70

    async def test_update_accepts_boundary_values(self) -> None:
        fx = make_service()
        config = await _create_config(fx)
        for boundary in (0, 100):
            updated = await fx.service.update_config(
                actor_user_id=uuid.uuid4(),
                config_id=config.id,
                requesting_organization_id=fx.organization.id,
                data={
                    "background_focal_x": boundary,
                    "background_focal_y": boundary,
                },
            )
            assert updated.background_focal_x == boundary
            assert updated.background_focal_y == boundary

    async def test_update_rejects_out_of_range_x(self) -> None:
        fx = make_service()
        config = await _create_config(fx)
        with pytest.raises(InvalidBackgroundFocalPointError):
            await fx.service.update_config(
                actor_user_id=uuid.uuid4(),
                config_id=config.id,
                requesting_organization_id=fx.organization.id,
                data={"background_focal_x": 120},
            )

    async def test_update_rejects_out_of_range_y(self) -> None:
        fx = make_service()
        config = await _create_config(fx)
        with pytest.raises(InvalidBackgroundFocalPointError):
            await fx.service.update_config(
                actor_user_id=uuid.uuid4(),
                config_id=config.id,
                requesting_organization_id=fx.organization.id,
                data={"background_focal_y": -3},
            )


class TestBackgroundFocalPointDefaults:
    def test_model_column_defaults_reproduce_todays_center_25_percent(self) -> None:
        """50/25 is the whole point of these defaults: it is exactly the
        frontend's current hardcoded ``background-position: center 25%``,
        so the migration that adds these columns changes nothing that
        any existing venue renders."""
        table = CaptivePortalConfig.__table__
        assert table.c.background_focal_x.default.arg == DEFAULT_BACKGROUND_FOCAL_X
        assert table.c.background_focal_x.default.arg == 50
        assert table.c.background_focal_y.default.arg == DEFAULT_BACKGROUND_FOCAL_Y
        assert table.c.background_focal_y.default.arg == 25

    def test_columns_are_not_nullable(self) -> None:
        table = CaptivePortalConfig.__table__
        assert table.c.background_focal_x.nullable is False
        assert table.c.background_focal_y.nullable is False


class TestBackgroundFocalPointResolve:
    async def test_resolve_surfaces_the_focal_point(self) -> None:
        fx = make_service()
        config = await _create_config(fx, name="Org default", is_default=True)
        await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"background_focal_x": 20, "background_focal_y": 80},
        )
        resolved = await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )
        assert resolved.config.background_focal_x == 20
        assert resolved.config.background_focal_y == 80

    async def test_resolve_cache_round_trips_the_focal_point(self) -> None:
        fx = make_service(with_cache=True)
        config = await _create_config(fx, name="Org default", is_default=True)
        await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"background_focal_x": 15, "background_focal_y": 60},
        )
        first = await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )
        assert first.config.background_focal_x == 15

        # Served from cache -- repository row deleted directly, bypassing
        # the service, same proof technique as TestResolveCache.
        del fx.repository.configs[config.id]
        second = await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )
        assert second.config.background_focal_x == 15
        assert second.config.background_focal_y == 60


class TestBrandingFoldedIntoResolveCache:
    """Design spec §5 S7. The branding row used to be fetched by the
    *route*, outside the resolve cache, on every resolve whose config
    left a logo/background unset -- so a "cache hit" still cost a
    ``SELECT brandings``, a connection checkout, and (because
    ``get_db_session`` commits unconditionally) a COMMIT on a read-only
    guest request."""

    async def test_cache_hit_issues_no_branding_query(self) -> None:
        """The actual S7 claim, measured rather than asserted by
        inspection: the branding lookup is called once on the cold
        resolve and never again while the entry is cached."""
        fx = make_service(with_cache=True, with_branding=True)
        await _create_config(fx, name="Org default", is_default=True)
        fx.branding_lookup.add(
            fx.organization.id, logo_key="branding/x/logo/a.png"
        )

        await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )
        assert len(fx.branding_lookup.calls) == 1

        for _ in range(5):
            await fx.service.resolve_portal_config(
                organization_id=fx.organization.id, location_id=None
            )
        assert len(fx.branding_lookup.calls) == 1

    async def test_branding_survives_the_cache_round_trip(self) -> None:
        fx = make_service(with_cache=True, with_branding=True)
        config = await _create_config(fx, name="Org default", is_default=True)
        fx.branding_lookup.add(
            fx.organization.id,
            background_image_key="branding/x/background/abc.webp",
            background_luminance=18,
            background_top_luminance=71,
            background_entropy=64,
        )

        await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )
        # Served from cache -- repository row and branding row both
        # removed, so anything still correct came out of the payload.
        del fx.repository.configs[config.id]
        fx.branding_lookup.rows.clear()

        cached = await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )
        assert cached.branding is not None
        assert cached.branding.background_image_key == "branding/x/background/abc.webp"
        assert cached.branding.background_luminance == 18
        assert cached.branding.background_top_luminance == 71
        assert cached.branding.background_entropy == 64

    async def test_config_supplying_both_urls_never_queries_branding(self) -> None:
        """S7 must not turn a query that was being *skipped* into one
        that always runs. The route's old ``needs_logo or
        needs_background`` guard is preserved inside the service."""
        fx = make_service(with_branding=True)
        config = await _create_config(fx, name="Org default", is_default=True)
        await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={
                "logo_url": "https://cdn.example.com/logo.png",
                "background_image_url": "https://cdn.example.com/bg.jpg",
            },
        )

        resolved = await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )
        assert fx.branding_lookup.calls == []
        assert resolved.branding is None

    async def test_missing_branding_row_caches_as_none(self) -> None:
        """A "not consulted" and a "no row exists" branding both land as
        None, and both round-trip -- so an organization with no branding
        row does not re-query on every resolve either."""
        fx = make_service(with_cache=True, with_branding=True)
        await _create_config(fx, name="Org default", is_default=True)

        first = await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )
        second = await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )
        assert first.branding is None
        assert second.branding is None
        assert len(fx.branding_lookup.calls) == 1

    async def test_url_construction_stays_out_of_the_cached_payload(self) -> None:
        """``request.base_url`` is per-request. Baking an absolute URL
        into a shared entry would let one origin's first guest pin the
        URL every other origin then serves -- the exact mixed-content
        class of bug the route's own comment records an incident for."""
        fx = make_service(with_cache=True, with_branding=True)
        await _create_config(fx, name="Org default", is_default=True)
        fx.branding_lookup.add(
            fx.organization.id, logo_key="branding/x/logo/a.png"
        )

        await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )
        payload = next(iter(fx.resolve_cache.store.values()))
        assert payload["branding"]["logo_key"] == "branding/x/logo/a.png"
        assert "http" not in json.dumps(payload["branding"])

    async def test_organization_invalidation_fans_out_to_every_location(self) -> None:
        """A single ``brandings`` row now backs one cached entry per
        location that falls back to it. Without the org index, an admin
        uploading a logo would stay invisible to all of them for up to a
        full TTL -- a real regression against the uncached per-request
        fetch S7 replaces."""
        fx = make_service(with_cache=True, with_branding=True)
        await _create_config(fx, name="Org default", is_default=True)
        location_a = fx.location_lookup.add(organization_id=fx.organization.id)
        location_b = fx.location_lookup.add(organization_id=fx.organization.id)
        fx.branding_lookup.add(
            fx.organization.id, logo_key="branding/x/logo/old.png"
        )

        for location in (location_a, location_b):
            await fx.service.resolve_portal_config(
                organization_id=None, location_id=location.id
            )
        await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )
        assert len(fx.resolve_cache.store) == 3

        await fx.resolve_cache.invalidate_organization(fx.organization.id)
        assert fx.resolve_cache.store == {}


class TestBrandingWritesInvalidateTheResolveCache:
    """The other half of S7: ``brandings`` is written by the *branding*
    domain, which had no reason to know the captive-portal resolve cache
    existed. Once the row is folded into that cache, every branding
    write must fan out to it."""

    async def test_every_mutating_method_invalidates(self) -> None:
        import inspect

        from app.domains.branding import service as branding_service

        source = inspect.getsource(branding_service.BrandingService)
        # Each mutating method ends by returning a BrandingResponse built
        # from the row it just wrote; each must invalidate first.
        assert source.count("_invalidate_portal_resolve_cache(organization_id)") == 5

    async def test_invalidation_failure_never_fails_the_upload(self) -> None:
        """Redis being momentarily unreachable must not fail an admin's
        logo upload -- the resolve cache's own TTL is the backstop."""
        from app.domains.branding.service import BrandingService

        class _ExplodingCache:
            async def invalidate_organization(
                self, organization_id: uuid.UUID
            ) -> None:
                raise RuntimeError("redis down")

        service = BrandingService(
            repository=SimpleNamespace(),
            portal_resolve_cache=_ExplodingCache(),
        )
        # Must not raise.
        await service._invalidate_portal_resolve_cache(uuid.uuid4())

    async def test_no_cache_wired_is_a_no_op(self) -> None:
        from app.domains.branding.service import BrandingService

        service = BrandingService(repository=SimpleNamespace())
        await service._invalidate_portal_resolve_cache(uuid.uuid4())



class TestResolveCacheFailsOpen:
    """Design spec §5 S10, first problem. ``GET /captive-portal/resolve``
    is unauthenticated and is the first request a guest's device makes on
    a WiFi join. The cache ``await`` was unguarded, so a Redis blip raised
    straight out of it -- taking guest WiFi down platform-wide for what is
    only ever an optimization."""

    class _ExplodingCache:
        def __init__(self, *, fail_get: bool = True, fail_set: bool = True) -> None:
            self.fail_get = fail_get
            self.fail_set = fail_set
            self.get_calls = 0
            self.set_calls = 0

        async def get(self, organization_id, location_id):
            self.get_calls += 1
            if self.fail_get:
                raise ConnectionError("redis down")
            return None

        async def set(self, organization_id, location_id, payload, **kwargs):
            self.set_calls += 1
            if self.fail_set:
                raise ConnectionError("redis down")

        async def invalidate(self, organization_id, location_id):
            raise ConnectionError("redis down")

        async def invalidate_organization(self, organization_id):
            raise ConnectionError("redis down")

    async def test_a_read_failure_degrades_to_a_query_not_a_500(self) -> None:
        fx = make_service()
        cache = self._ExplodingCache()
        fx.service.resolve_cache = cache
        config = await _create_config(fx, name="Org default", is_default=True)

        resolved = await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )

        assert resolved.config.id == config.id
        assert cache.get_calls == 1

    async def test_a_write_failure_never_reaches_the_guest(self) -> None:
        fx = make_service()
        cache = self._ExplodingCache(fail_get=False)
        fx.service.resolve_cache = cache
        config = await _create_config(fx, name="Org default", is_default=True)

        resolved = await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )

        assert resolved.config.id == config.id
        assert cache.set_calls == 1

    async def test_a_corrupt_payload_is_treated_as_a_miss(self) -> None:
        """The real Redis-backed cache already swallows a JSON decode
        failure; this pins that a payload that decodes but is *shaped*
        wrong cannot be silently served either."""
        fx = make_service(with_cache=True)
        await _create_config(fx, name="Org default", is_default=True)
        await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )
        key = next(iter(fx.resolve_cache.store))
        fx.resolve_cache.store[key] = {"config": {}, "branding": None}

        with pytest.raises(KeyError):
            await fx.service.resolve_portal_config(
                organization_id=fx.organization.id, location_id=None
            )


class TestNegativeResolveCaching:
    """Design spec §5 S10, second problem. A misconfigured location paid
    the full resolution walk -- location lookup, location-config query,
    org-default query -- on every guest device that joined, forever,
    because the walk ends in an exception and nothing ever warmed."""

    async def test_a_not_configured_result_is_cached(self) -> None:
        fx = make_service(with_cache=True)

        with pytest.raises(CaptivePortalConfigNotConfiguredError):
            await fx.service.resolve_portal_config(
                organization_id=fx.organization.id, location_id=None
            )

        assert len(fx.resolve_cache.store) == 1
        payload = next(iter(fx.resolve_cache.store.values()))
        assert "__not_configured__" in payload

    async def test_the_second_miss_does_not_repeat_the_walk(self) -> None:
        fx = make_service(with_cache=True)
        calls: list[uuid.UUID] = []
        original = fx.repository.find_active_org_default

        async def _counting(organization_id):
            calls.append(organization_id)
            return await original(organization_id)

        fx.repository.find_active_org_default = _counting

        for _ in range(5):
            with pytest.raises(CaptivePortalConfigNotConfiguredError):
                await fx.service.resolve_portal_config(
                    organization_id=fx.organization.id, location_id=None
                )

        assert len(calls) == 1, "the walk must run once, not once per guest"

    async def test_the_cached_negative_raises_the_same_error(self) -> None:
        fx = make_service(with_cache=True)
        with pytest.raises(CaptivePortalConfigNotConfiguredError) as first:
            await fx.service.resolve_portal_config(
                organization_id=fx.organization.id, location_id=None
            )
        with pytest.raises(CaptivePortalConfigNotConfiguredError) as second:
            await fx.service.resolve_portal_config(
                organization_id=fx.organization.id, location_id=None
            )
        assert str(first.value) == str(second.value)

    async def test_it_is_written_with_the_short_negative_ttl(self) -> None:
        """A negative result must not be held as long as a real one -- an
        operator who just configured a venue would otherwise watch the
        portal keep saying 'not configured'."""
        fx = make_service(with_cache=True)
        with pytest.raises(CaptivePortalConfigNotConfiguredError):
            await fx.service.resolve_portal_config(
                organization_id=fx.organization.id, location_id=None
            )
        key = next(iter(fx.resolve_cache.store))
        assert key in fx.resolve_cache.negative_keys

    async def test_configuring_the_venue_clears_the_negative_immediately(self) -> None:
        """The pre-existing guarantee this must not break: creating the
        first config for a previously-unconfigured organization is
        resolvable at once, not stuck behind a cached miss."""
        fx = make_service(with_cache=True)
        with pytest.raises(CaptivePortalConfigNotConfiguredError):
            await fx.service.resolve_portal_config(
                organization_id=fx.organization.id, location_id=None
            )
        config = await _create_config(fx, name="First config", is_default=True)

        resolved = await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )
        assert resolved.config.id == config.id

    async def test_creating_an_org_default_clears_a_locations_negative(self) -> None:
        """The operator-facing case: a location resolving by location_id
        alone cached "not configured"; the admin then creates the
        organization default that location falls back to. That key's own
        organization is not recoverable from the key, so only the
        per-organization fan-out can reach it."""
        fx = make_service(with_cache=True)
        location = fx.location_lookup.add(organization_id=fx.organization.id)
        with pytest.raises(CaptivePortalConfigNotConfiguredError):
            await fx.service.resolve_portal_config(
                organization_id=None, location_id=location.id
            )

        config = await _create_config(fx, name="Org default", is_default=True)

        resolved = await fx.service.resolve_portal_config(
            organization_id=None, location_id=location.id
        )
        assert resolved.config.id == config.id

    async def test_the_negative_is_indexed_for_organization_invalidation(self) -> None:
        """A location resolving by location_id alone caches under a key
        whose organization is not knowable from the key -- it must still
        be reachable by an organization-scoped invalidation."""
        fx = make_service(with_cache=True)
        location = fx.location_lookup.add(organization_id=fx.organization.id)

        with pytest.raises(CaptivePortalConfigNotConfiguredError):
            await fx.service.resolve_portal_config(
                organization_id=None, location_id=location.id
            )
        assert len(fx.resolve_cache.store) == 1

        await fx.resolve_cache.invalidate_organization(fx.organization.id)
        assert fx.resolve_cache.store == {}


class TestResolveSingleFlight:
    """Design spec §5 S10, third problem. With a 60s TTL and a venue's
    worth of devices joining at once, every expiry was a small stampede --
    every concurrent miss running the same walk against the same rows to
    compute the same answer."""

    async def test_concurrent_misses_collapse_onto_one_walk(self) -> None:
        fx = make_service(with_cache=True)
        config = await _create_config(fx, name="Org default", is_default=True)

        walks = 0
        original = fx.repository.find_active_org_default

        async def _slow(organization_id):
            nonlocal walks
            walks += 1
            # Yield, so every coroutine is genuinely in flight together.
            await asyncio.sleep(0.01)
            return await original(organization_id)

        fx.repository.find_active_org_default = _slow

        results = await asyncio.gather(
            *[
                fx.service.resolve_portal_config(
                    organization_id=fx.organization.id, location_id=None
                )
                for _ in range(20)
            ]
        )

        assert walks == 1, f"20 concurrent misses ran {walks} walks"
        assert all(r.config.id == config.id for r in results)

    async def test_waiters_see_the_same_error_not_their_own_walk(self) -> None:
        fx = make_service(with_cache=True)
        walks = 0
        original = fx.repository.find_active_org_default

        async def _slow(organization_id):
            nonlocal walks
            walks += 1
            await asyncio.sleep(0.01)
            return await original(organization_id)

        fx.repository.find_active_org_default = _slow

        results = await asyncio.gather(
            *[
                fx.service.resolve_portal_config(
                    organization_id=fx.organization.id, location_id=None
                )
                for _ in range(10)
            ],
            return_exceptions=True,
        )

        assert walks == 1
        assert all(
            isinstance(r, CaptivePortalConfigNotConfiguredError) for r in results
        )

    async def test_different_keys_do_not_block_each_other(self) -> None:
        fx = make_service(with_cache=True)
        location = fx.location_lookup.add(organization_id=fx.organization.id)
        await _create_config(fx, name="Org default", is_default=True)
        await _create_config(fx, name="Loc override", location_id=location.id)

        by_org, by_location = await asyncio.gather(
            fx.service.resolve_portal_config(
                organization_id=fx.organization.id, location_id=None
            ),
            fx.service.resolve_portal_config(
                organization_id=None, location_id=location.id
            ),
        )

        assert by_org.resolved_via_location_override is False
        assert by_location.resolved_via_location_override is True

    async def test_the_registry_is_empty_once_resolution_settles(self) -> None:
        """A leaked entry would make every later request for that key
        await a future nobody will ever complete."""
        from app.domains.captive_portal.service import _INFLIGHT_RESOLUTIONS

        fx = make_service(with_cache=True)
        await _create_config(fx, name="Org default", is_default=True)
        await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )
        assert _INFLIGHT_RESOLUTIONS == {}

        fx2 = make_service(with_cache=True)
        with pytest.raises(CaptivePortalConfigNotConfiguredError):
            await fx2.service.resolve_portal_config(
                organization_id=fx2.organization.id, location_id=None
            )
        assert _INFLIGHT_RESOLUTIONS == {}

    async def test_the_registry_is_shared_across_service_instances(self) -> None:
        """``CaptivePortalService`` is constructed per request, so a
        per-instance registry would collapse exactly nothing -- which is
        the whole point of the module-level one."""
        from app.domains.captive_portal.service import _INFLIGHT_RESOLUTIONS

        assert isinstance(_INFLIGHT_RESOLUTIONS, dict)
        first = make_service()
        second = make_service()
        assert first.service is not second.service


class TestResolveCacheKeyVersion:
    def test_cache_key_is_v6(self) -> None:
        """Spec §0.3: the version must be bumped in the same change that
        changes the cached field set. Skipping it makes every payload
        written by the previous build raise KeyError out of the
        unauthenticated guest resolve endpoint -- a 500 for every guest
        joining WiFi until the TTL expires.

        v6 is ``post_login_html``, the venue's own post-sign-in page,
        joining ``_CACHED_CONFIG_SCALAR_FIELDS``."""
        from app.domains.captive_portal.cache import _CACHE_KEY_TEMPLATE

        key = _CACHE_KEY_TEMPLATE.format(organization_id="org", location_id="loc")
        assert key == "captive_portal:resolve:v6:org:loc"

    def test_org_index_key_is_versioned_in_lockstep_with_the_payload_key(self) -> None:
        """The index names payload keys. Left at an older version it
        would fan a delete out to keys nothing reads anymore, silently
        doing nothing -- so its version must move with the payload's."""
        from app.domains.captive_portal.cache import (
            _CACHE_KEY_TEMPLATE,
            _ORG_INDEX_KEY_TEMPLATE,
        )

        payload_version = _CACHE_KEY_TEMPLATE.split(":")[2]
        index_version = _ORG_INDEX_KEY_TEMPLATE.split(":")[2]
        assert payload_version == index_version == "v6"

    def test_a_payload_from_the_previous_key_version_would_raise(self) -> None:
        """The mechanism §0.3 is actually about, asserted rather than
        assumed: ``from_cache_payload`` indexes unguarded, so a payload
        written by the *previous* build -- one with no ``"branding"``
        key -- raises ``KeyError``. That is deliberate (a missing field
        must fail loudly in tests rather than degrade silently), and it
        is precisely why the key version had to move: under a bumped
        key, no such payload is ever read back in the first place."""
        v3_payload = {
            "config": {},
            "resolved_via_location_override": False,
            "location_country": None,
            "location_name": None,
        }
        with pytest.raises(KeyError):
            ResolvedPortalConfig.from_cache_payload(v3_payload)

    def test_every_cached_field_exists_on_the_model(self) -> None:
        """The versioning only protects a *deploy*; this catches the
        other half -- a name in the tuple that no column backs, which
        would fail at write time instead."""
        from app.domains.captive_portal.service import _CACHED_CONFIG_SCALAR_FIELDS

        columns = set(CaptivePortalConfig.__table__.c.keys())
        assert set(_CACHED_CONFIG_SCALAR_FIELDS) <= columns
        assert "background_focal_x" in _CACHED_CONFIG_SCALAR_FIELDS
        assert "background_focal_y" in _CACHED_CONFIG_SCALAR_FIELDS
        assert "powered_by_enabled" in _CACHED_CONFIG_SCALAR_FIELDS
        assert "post_login_html" in _CACHED_CONFIG_SCALAR_FIELDS


# ============================================================================
# Guest-facing resolve surfaces the branding-side image measurements
# (v7 design spec §1.4 C3/C5).
#
# These three live on ``brandings``, not ``captive_portal_configs``, so
# unlike the focal point they are not part of the resolve cache payload
# -- they ride along on the branding row the resolve route already
# fetches for the logo/background fallback. Exercised at the *route*
# level because that fallback, and therefore the whole passthrough, only
# exists there.
# ============================================================================


@dataclass
class _FakeBranding:
    background_image_key: str | None = None
    logo_key: str | None = None
    logo_url: str | None = None
    background_luminance: int | None = None
    background_top_luminance: int | None = None
    background_entropy: int | None = None


def _resolve_request() -> object:
    from starlette.requests import Request

    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/v1/captive-portal/resolve",
            "headers": [],
            "scheme": "https",
            "server": ("api.example.com", 443),
            "query_string": b"",
        }
    )
    request.state.request_id = "test-request-id"
    return request


def _apply_column_defaults(config: CaptivePortalConfig) -> None:
    """SQLAlchemy column-level ``default=``s are applied by the INSERT,
    which never runs against ``FakeCaptivePortalRepository`` -- so a fake
    config carries ``None`` for every column the service does not set
    explicitly (``business_hours_schedule``, ``guest_font_choice``,
    ``background_focal_x`` ...). Harmless for the service-level tests
    above, which read one field at a time, but the *route* builds a full
    response model and would trip over the Nones for reasons that have
    nothing to do with what is being tested. Applied here rather than
    hand-listing the columns so this cannot go stale as columns are
    added."""
    for column in CaptivePortalConfig.__table__.columns:
        if getattr(config, column.name, None) is None and column.default is not None:
            arg = column.default.arg
            setattr(config, column.name, arg(None) if callable(arg) else arg)


async def _call_resolve_route(fx: Fixture, branding: _FakeBranding | None) -> dict:
    from app.domains.captive_portal import router as router_module

    for config in fx.repository.configs.values():
        _apply_column_defaults(config)

    # Design spec §5 S7: the route no longer runs its own
    # ``BrandingRepository`` query (and no longer takes a ``db`` session
    # at all) -- the branding row now arrives pre-resolved and cacheable
    # on ``ResolvedPortalConfig.branding``. So the fake is installed on
    # the *service*, which is where the lookup actually happens now.
    original = fx.service.branding_lookup
    fx.service.branding_lookup = SimpleNamespace(
        get_by_organization=_returning(branding)
    )
    try:
        response = await router_module.resolve_captive_portal_config(
            _resolve_request(),
            organization_id=fx.organization.id,
            location_id=None,
            service=fx.service,
        )
    finally:
        fx.service.branding_lookup = original
    return response["data"]


def _returning(value: object):
    async def _get(_organization_id: uuid.UUID) -> object:
        return value

    return _get


class TestResolveSurfacesBackgroundImageMetrics:
    async def test_metrics_ride_along_with_the_branding_background(self) -> None:
        fx = make_service()
        await _create_config(fx, name="Org default", is_default=True)

        data = await _call_resolve_route(
            fx,
            _FakeBranding(
                background_image_key="branding/x/background/abc.webp",
                background_luminance=18,
                background_top_luminance=71,
                background_entropy=64,
            ),
        )

        assert data["background_image_url"].endswith("/background-image/public")
        assert data["background_luminance"] == 18
        assert data["background_top_luminance"] == 71
        assert data["background_entropy"] == 64

    async def test_metrics_are_none_when_no_branding_row_exists(self) -> None:
        fx = make_service()
        await _create_config(fx, name="Org default", is_default=True)

        data = await _call_resolve_route(fx, None)

        assert data["background_luminance"] is None
        assert data["background_top_luminance"] is None
        assert data["background_entropy"] is None

    async def test_unmeasured_image_reports_none_not_zero(self) -> None:
        """A pre-v7 image nobody has backfilled. None must reach the
        frontend as None: 0 is a legitimate reading (a black photo), and
        conflating the two would let the frontend use *less* scrim than
        the §1.3 floor on an image it has never seen."""
        fx = make_service()
        await _create_config(fx, name="Org default", is_default=True)

        data = await _call_resolve_route(
            fx, _FakeBranding(background_image_key="branding/x/background/old.jpg")
        )

        assert data["background_image_url"] is not None
        assert data["background_luminance"] is None
        assert data["background_entropy"] is None

    async def test_no_metrics_when_the_config_has_its_own_background_url(self) -> None:
        """The config's own typed-in URL points at a file nothing
        measured. Reporting the organization photo's numbers for a
        *different* image would be worse than reporting nothing."""
        fx = make_service()
        config = await _create_config(fx, name="Org default", is_default=True)
        await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"background_image_url": "https://cdn.example.com/venue.jpg"},
        )

        data = await _call_resolve_route(
            fx,
            _FakeBranding(
                background_image_key="branding/x/background/abc.webp",
                background_luminance=18,
                background_top_luminance=71,
                background_entropy=64,
            ),
        )

        assert data["background_image_url"] == "https://cdn.example.com/venue.jpg"
        assert data["background_luminance"] is None

    async def test_focal_point_reaches_the_guest_response(self) -> None:
        fx = make_service()
        config = await _create_config(fx, name="Org default", is_default=True)
        await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"background_focal_x": 35, "background_focal_y": 15},
        )

        data = await _call_resolve_route(fx, None)

        assert data["background_focal_x"] == 35
        assert data["background_focal_y"] == 15


# ============================================================================
# v7 §Part 2 (W2) -- splash text length limits
# ============================================================================


# Realistic venue copy, one string per script, sized to sit exactly on each
# side of the limit. Written out rather than generated from "x" * N so the
# per-script cases are genuinely per-script: the whole point of the limit is
# that the same character count renders as a different number of lines in
# different scripts, and a test that only ever measures `len()` of ASCII
# would pass even if the constant were derived from the wrong script.
_WELCOME_AT_LIMIT = {
    "en": (
        "Welcome to The Grand Palace Hotel. Enjoy complimentary WiFi"
        " during your stay."
    ),
    "hi": (
        "ग्रैंड पैलेस होटल में आपका स्वागत है।"
        " निःशुल्क वाईफाई का आनंद लें।"
    ),
    "ta": (
        "கிராண்ட் பேலஸ் ஹோட்டலுக்கு வரவேற்கிறோம்."
        " இலவச வைஃபையை அனுபவியுங்கள்."
    ),
    "ml": (
        "ഗ്രാൻഡ് പാലസിലേക്ക് സ്വാഗതം."
        " സൗജന്യ വൈഫൈ ആസ്വദിക്കൂ. നന്ദി."
    ),
    "ar": (
        "مرحبًا بكم في فندق جراند بالاس."
        " استمتعوا بإنترنت لاسلكي مجاني طوال إقامتكم."
    ),
}


class TestSplashTextLengthConstants:
    """The limits are load-bearing numbers with a written derivation
    (constants.py). Pin them so a casual edit to either is a failing test
    and not a silently-shipped layout regression."""

    def test_limits_are_the_derived_values(self) -> None:
        assert SPLASH_WELCOME_MESSAGE_MAX_LENGTH == 78
        assert SPLASH_HEADLINE_MAX_LENGTH == 26

    def test_headline_limit_is_tighter_than_the_welcome_limit(self) -> None:
        # pg-title is 26px against pg-body's 15px -- the same character
        # count buys far fewer headline lines, so one limit cannot cover
        # both fields.
        assert SPLASH_HEADLINE_MAX_LENGTH < SPLASH_WELCOME_MESSAGE_MAX_LENGTH

    def test_headline_limit_is_inside_the_stored_column(self) -> None:
        # splash_headline is String(200); the domain limit must stay
        # strictly tighter or the validator stops being the thing that
        # rejects over-length input.
        column = CaptivePortalConfig.__table__.columns["splash_headline"]
        assert column.type.length > SPLASH_HEADLINE_MAX_LENGTH


class TestSplashTextLengthValidator:
    def test_accepts_value_exactly_at_the_limit(self) -> None:
        validate_splash_text_length(
            "splash_welcome_message", "x" * SPLASH_WELCOME_MESSAGE_MAX_LENGTH
        )

    def test_rejects_one_character_over_the_limit(self) -> None:
        with pytest.raises(SplashTextTooLongError) as exc:
            validate_splash_text_length(
                "splash_welcome_message",
                "x" * (SPLASH_WELCOME_MESSAGE_MAX_LENGTH + 1),
            )
        assert exc.value.status_code == 400

    def test_error_carries_the_limit_and_the_actual_length(self) -> None:
        # The dashboard has to be able to render "80 of 78" next to a live
        # counter; a bare "string too long" would be worse than the render
        # truncation this replaces.
        over = SPLASH_WELCOME_MESSAGE_MAX_LENGTH + 2
        with pytest.raises(SplashTextTooLongError) as exc:
            validate_splash_text_length("splash_welcome_message", "x" * over)
        assert exc.value.data == {
            "field": "splash_welcome_message",
            "max_length": SPLASH_WELCOME_MESSAGE_MAX_LENGTH,
            "actual_length": over,
        }

    def test_counts_the_stripped_value(self) -> None:
        # The frontend renders `splashWelcomeMessage?.trim()`, so leading
        # and trailing whitespace costs zero rendered width and must not
        # be charged against the venue.
        padded = "   " + "x" * SPLASH_WELCOME_MESSAGE_MAX_LENGTH + "   "
        validate_splash_text_length("splash_welcome_message", padded)

    def test_counts_code_points_not_utf16_units(self) -> None:
        # An emoji is one code point to Python and two UTF-16 units to
        # JavaScript's `.length`. The backend counts code points, so the
        # dashboard counter must use `[...value].length` to agree.
        value = "\U0001f60a" * SPLASH_WELCOME_MESSAGE_MAX_LENGTH
        assert len(value) == SPLASH_WELCOME_MESSAGE_MAX_LENGTH
        validate_splash_text_length("splash_welcome_message", value)

    def test_none_and_blank_always_pass(self) -> None:
        # Clearing a splash string is always legal; v5 §3.2 requires a
        # venue with no welcome message to render no line at all.
        validate_splash_text_length("splash_welcome_message", None)
        validate_splash_text_length("splash_welcome_message", "")
        validate_splash_text_length("splash_welcome_message", "     ")

    def test_unknown_field_is_a_no_op(self) -> None:
        validate_splash_text_length("primary_color", "x" * 5000)

    @pytest.mark.parametrize("language", sorted(_WELCOME_AT_LIMIT))
    def test_realistic_copy_at_the_limit_passes_in_every_script(
        self, language: str
    ) -> None:
        sample = _WELCOME_AT_LIMIT[language]
        assert len(sample) <= SPLASH_WELCOME_MESSAGE_MAX_LENGTH, (
            f"{language} sample is {len(sample)} chars, over the limit"
        )
        validate_splash_text_length("splash_welcome_message", sample)

    @pytest.mark.parametrize("language", sorted(_WELCOME_AT_LIMIT))
    def test_realistic_copy_over_the_limit_is_rejected_in_every_script(
        self, language: str
    ) -> None:
        # Same real sentence in each script, extended past the ceiling --
        # the limit is a single global number, so it must bite identically
        # whichever script the venue writes in.
        sample = _WELCOME_AT_LIMIT[language]
        padding = "०" if language in {"hi"} else "a"
        over = sample + padding * (
            SPLASH_WELCOME_MESSAGE_MAX_LENGTH - len(sample) + 1
        )
        with pytest.raises(SplashTextTooLongError) as exc:
            validate_splash_text_length("splash_welcome_message", over)
        assert exc.value.data["actual_length"] == len(over)


class TestSplashTextLengthOnCreate:
    async def test_over_limit_welcome_message_is_rejected(self) -> None:
        fx = make_service()
        with pytest.raises(SplashTextTooLongError):
            await _create_config(
                fx,
                splash_welcome_message="x" * (SPLASH_WELCOME_MESSAGE_MAX_LENGTH + 1),
            )

    async def test_over_limit_headline_is_rejected(self) -> None:
        fx = make_service()
        with pytest.raises(SplashTextTooLongError) as exc:
            await _create_config(
                fx, splash_headline="x" * (SPLASH_HEADLINE_MAX_LENGTH + 1)
            )
        assert exc.value.data["field"] == "splash_headline"

    async def test_at_limit_values_are_accepted(self) -> None:
        fx = make_service()
        config = await _create_config(
            fx,
            splash_headline="x" * SPLASH_HEADLINE_MAX_LENGTH,
            splash_welcome_message="x" * SPLASH_WELCOME_MESSAGE_MAX_LENGTH,
        )
        assert len(config.splash_welcome_message) == SPLASH_WELCOME_MESSAGE_MAX_LENGTH


class TestSplashTextLengthOnUpdate:
    async def test_over_limit_edit_is_rejected(self) -> None:
        fx = make_service()
        config = await _create_config(fx, splash_welcome_message="Short and sweet.")
        with pytest.raises(SplashTextTooLongError):
            await fx.service.update_config(
                actor_user_id=uuid.uuid4(),
                config_id=config.id,
                requesting_organization_id=fx.organization.id,
                data={
                    "splash_welcome_message": "y"
                    * (SPLASH_WELCOME_MESSAGE_MAX_LENGTH + 1)
                },
            )

    async def test_existing_over_limit_row_can_still_be_edited_elsewhere(self) -> None:
        # The grandfathering case, and the reason the check fires on change
        # rather than on presence: there are live rows over the ceiling
        # (these fields shipped with no validation at all), and a venue
        # with a long legacy message must not be blocked from changing
        # their logo until they rewrite their copy. The dashboard PUTs its
        # whole form, so the field is present on every save.
        fx = make_service()
        legacy = "z" * (SPLASH_WELCOME_MESSAGE_MAX_LENGTH + 40)
        config = await _create_config(fx)
        config.splash_welcome_message = legacy  # simulate a pre-validation row

        updated = await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={
                "logo_url": "https://cdn.example.com/logo.png",
                "splash_welcome_message": legacy,
            },
        )
        assert updated.logo_url == "https://cdn.example.com/logo.png"
        assert updated.splash_welcome_message == legacy

    async def test_whitespace_only_difference_is_not_a_change(self) -> None:
        # The renderer trims, so a value differing only in surrounding
        # whitespace changes nothing on the portal and must not trip the
        # validator on a grandfathered row.
        fx = make_service()
        legacy = "z" * (SPLASH_WELCOME_MESSAGE_MAX_LENGTH + 10)
        config = await _create_config(fx)
        config.splash_welcome_message = legacy

        updated = await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"splash_welcome_message": f"  {legacy}  "},
        )
        assert updated.splash_welcome_message == f"  {legacy}  "

    async def test_grandfathered_row_editing_the_field_is_rejected(self) -> None:
        # The limit binds the moment the venue next touches that string --
        # which is also the only moment a live counter is in front of them.
        fx = make_service()
        legacy = "z" * (SPLASH_WELCOME_MESSAGE_MAX_LENGTH + 40)
        config = await _create_config(fx)
        config.splash_welcome_message = legacy

        with pytest.raises(SplashTextTooLongError):
            await fx.service.update_config(
                actor_user_id=uuid.uuid4(),
                config_id=config.id,
                requesting_organization_id=fx.organization.id,
                data={"splash_welcome_message": legacy + " and one more sentence."},
            )

    async def test_grandfathered_row_can_be_brought_under_the_limit(self) -> None:
        fx = make_service()
        config = await _create_config(fx)
        config.splash_welcome_message = "z" * (SPLASH_WELCOME_MESSAGE_MAX_LENGTH + 40)

        updated = await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"splash_welcome_message": "Free WiFi, on us."},
        )
        assert updated.splash_welcome_message == "Free WiFi, on us."

    async def test_clearing_an_over_limit_value_is_allowed(self) -> None:
        fx = make_service()
        config = await _create_config(fx)
        config.splash_welcome_message = "z" * (SPLASH_WELCOME_MESSAGE_MAX_LENGTH + 40)

        updated = await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"splash_welcome_message": None},
        )
        assert updated.splash_welcome_message is None

    async def test_headline_and_welcome_are_validated_independently(self) -> None:
        fx = make_service()
        config = await _create_config(fx)
        # A value legal for the welcome message is over the headline's own,
        # much tighter, ceiling.
        between = "x" * (SPLASH_HEADLINE_MAX_LENGTH + 1)
        assert len(between) <= SPLASH_WELCOME_MESSAGE_MAX_LENGTH

        updated = await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"splash_welcome_message": between},
        )
        assert updated.splash_welcome_message == between

        with pytest.raises(SplashTextTooLongError) as exc:
            await fx.service.update_config(
                actor_user_id=uuid.uuid4(),
                config_id=config.id,
                requesting_organization_id=fx.organization.id,
                data={"splash_headline": between},
            )
        assert exc.value.data["field"] == "splash_headline"


# ============================================================================
# v7 §Part 3 (P4) -- powered_by_enabled as a white-label entitlement
# ============================================================================


@dataclass
class FakeEntitlementSnapshot:
    features: set[str] = field(default_factory=set)

    def has_feature(self, feature_key: object) -> bool:
        return str(getattr(feature_key, "value", feature_key)) in self.features


@dataclass
class FakeEntitlementChecker:
    """Stand-in for ``billing.service.EntitlementChecker``. ``calls``
    records every organization asked about, so a test can assert the gate
    did *not* reach billing at all on the paths that must stay free."""

    entitled: bool = True
    calls: list[uuid.UUID] = field(default_factory=list)

    async def get_snapshot(self, organization_id: uuid.UUID):
        self.calls.append(organization_id)
        return FakeEntitlementSnapshot(
            features={PlanFeatureKey.WHITE_LABEL.value} if self.entitled else set()
        )


def make_entitled_service(*, entitled: bool) -> tuple[Fixture, FakeEntitlementChecker]:
    fx = make_service()
    checker = FakeEntitlementChecker(entitled=entitled)
    fx.service.entitlement_checker = checker
    return fx, checker


class TestPoweredByEnabledDefaults:
    async def test_defaults_to_true_on_create(self) -> None:
        # Every row predating this column rendered the attribution, so True
        # is the "unchanged" value -- and the only default that cannot leak
        # revenue the moment the migration deploys.
        fx = make_service()
        config = await _create_config(fx)
        assert config.powered_by_enabled is True

    def test_column_is_not_nullable_and_defaults_true(self) -> None:
        column = CaptivePortalConfig.__table__.columns["powered_by_enabled"]
        assert column.nullable is False
        assert column.default.arg is True

    def test_is_part_of_the_resolve_cache_payload(self) -> None:
        from app.domains.captive_portal.service import _CACHED_CONFIG_SCALAR_FIELDS

        assert "powered_by_enabled" in _CACHED_CONFIG_SCALAR_FIELDS


class TestPoweredByEntitlementOnUpdate:
    async def test_turning_off_without_entitlement_is_402(self) -> None:
        fx, checker = make_entitled_service(entitled=False)
        config = await _create_config(fx)
        with pytest.raises(PoweredByAttributionNotEntitledError) as exc:
            await fx.service.update_config(
                actor_user_id=uuid.uuid4(),
                config_id=config.id,
                requesting_organization_id=fx.organization.id,
                data={"powered_by_enabled": False},
            )
        # 402, not 403: the caller holds captive_portal.update and is
        # allowed to make this request -- their plan just does not include
        # the feature. A 403 would send an admin off to ask for a
        # permission that would not help them.
        assert exc.value.status_code == 402
        assert exc.value.data == {
            "field": "powered_by_enabled",
            "required_feature": PlanFeatureKey.WHITE_LABEL.value,
        }
        assert config.powered_by_enabled is True

    async def test_turning_off_with_entitlement_succeeds(self) -> None:
        fx, checker = make_entitled_service(entitled=True)
        config = await _create_config(fx)
        updated = await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"powered_by_enabled": False},
        )
        assert updated.powered_by_enabled is False
        assert checker.calls == [fx.organization.id]

    async def test_turning_on_without_entitlement_succeeds(self) -> None:
        # Turning attribution back ON must always be free, or a tenant who
        # downgrades is stuck with a setting they cannot revert.
        fx, checker = make_entitled_service(entitled=False)
        config = await _create_config(fx)
        config.powered_by_enabled = False

        updated = await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"powered_by_enabled": True},
        )
        assert updated.powered_by_enabled is True
        assert checker.calls == [], "turning attribution on must not consult billing"

    async def test_other_fields_are_not_gated(self) -> None:
        # The check is service-layer and field-scoped precisely so it does
        # not become a gate on the whole PUT: a non-entitled tenant must
        # still be able to change their logo and their colours.
        fx, checker = make_entitled_service(entitled=False)
        config = await _create_config(fx)
        updated = await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={
                "logo_url": "https://cdn.example.com/logo.png",
                "primary_color": "#FF0000",
            },
        )
        assert updated.logo_url == "https://cdn.example.com/logo.png"
        assert updated.primary_color == "#FF0000"
        assert checker.calls == []

    async def test_absent_field_never_consults_billing(self) -> None:
        fx, checker = make_entitled_service(entitled=False)
        config = await _create_config(fx)
        await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"name": "Renamed"},
        )
        assert checker.calls == []


class TestPoweredByEntitlementAfterDowngrade:
    """The downgrade path, which is the case with a revenue consequence."""

    async def test_downgraded_tenant_can_still_edit_other_fields(self) -> None:
        # The tenant turned the mark off while entitled, then lost the
        # feature. The dashboard PUTs its whole form, so `powered_by_enabled:
        # false` is present on every subsequent save. Re-asserting a value
        # that is already false is not a new purchase -- gating it would
        # lock a downgraded tenant out of every other field on the page.
        fx, checker = make_entitled_service(entitled=True)
        config = await _create_config(fx)
        await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"powered_by_enabled": False},
        )
        checker.entitled = False  # the downgrade
        checker.calls.clear()

        updated = await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={
                "powered_by_enabled": False,
                "logo_url": "https://cdn.example.com/new-logo.png",
            },
        )
        assert updated.logo_url == "https://cdn.example.com/new-logo.png"
        assert updated.powered_by_enabled is False
        assert checker.calls == []

    async def test_downgraded_tenant_who_turns_it_on_cannot_turn_it_off_again(
        self,
    ) -> None:
        # The other half of the same policy: once they revert to attribution
        # ON, turning it back off is a fresh purchase and is gated.
        fx, checker = make_entitled_service(entitled=True)
        config = await _create_config(fx)
        await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"powered_by_enabled": False},
        )
        checker.entitled = False

        await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"powered_by_enabled": True},
        )
        with pytest.raises(PoweredByAttributionNotEntitledError):
            await fx.service.update_config(
                actor_user_id=uuid.uuid4(),
                config_id=config.id,
                requesting_organization_id=fx.organization.id,
                data={"powered_by_enabled": False},
            )

    async def test_resolve_honours_the_stored_false_after_downgrade(self) -> None:
        # POLICY, stated rather than left to the code: resolve returns what
        # is stored and never consults billing. The read path is
        # unauthenticated and a 402 there would break the portal outright
        # for every non-entitled tenant, so it is not gated -- which means
        # a tenant who turned the mark off while entitled keeps it off
        # after downgrading. Closing that belongs on the licence-downgrade
        # path, not on the guest hot path. See
        # _enforce_powered_by_entitlement's docstring.
        fx, checker = make_entitled_service(entitled=True)
        await _create_config(fx, is_default=True)
        config = next(iter(fx.repository.configs.values()))
        await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"powered_by_enabled": False},
        )
        checker.entitled = False
        checker.calls.clear()

        resolved = await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )
        assert resolved.config.powered_by_enabled is False
        assert checker.calls == [], "resolve must never consult billing"


class TestPoweredByEntitlementOnCreate:
    """Create is gated too. The spec names ``update_config`` only, but
    leaving create open is a one-request bypass: POST a fresh config with
    ``powered_by_enabled=false`` and the update gate is never consulted."""

    async def test_creating_with_attribution_off_without_entitlement_is_402(
        self,
    ) -> None:
        fx, _ = make_entitled_service(entitled=False)
        with pytest.raises(PoweredByAttributionNotEntitledError):
            await fx.service.create_config(
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=fx.organization.id,
                organization_id=fx.organization.id,
                location_id=None,
                name="Bypass Portal",
                is_active=True,
                is_default=False,
                theme="light",
                logo_url=None,
                background_image_url=None,
                primary_color="#1A73E8",
                secondary_color="#FFFFFF",
                default_language="en",
                supported_languages=["en"],
                advertisement_banner_url=None,
                advertisement_banner_link=None,
                terms_and_conditions_text=None,
                terms_and_conditions_url=None,
                privacy_policy_text=None,
                privacy_policy_url=None,
                splash_headline=None,
                splash_welcome_message=None,
                redirect_url=None,
                otp_sms_enabled=True,
                otp_email_enabled=False,
                otp_whatsapp_enabled=False,
                voucher_enabled=True,
                username_password_enabled=True,
                social_login_enabled=False,
                social_login_providers=[],
                powered_by_enabled=False,
            )

    async def test_creating_with_attribution_on_never_consults_billing(self) -> None:
        fx, checker = make_entitled_service(entitled=False)
        config = await _create_config(fx)
        assert config.powered_by_enabled is True
        assert checker.calls == []


class TestPoweredByWithoutAnEntitlementChecker:
    """``entitlement_checker=None`` disables the gate. That is the shape
    the one pre-existing non-HTTP caller relies on --
    ``location.provisioning_service`` creates configs during smart-location
    provisioning and never sets this field."""

    async def test_gate_is_inert_without_a_checker(self) -> None:
        fx = make_service()
        assert fx.service.entitlement_checker is None
        config = await _create_config(fx)
        updated = await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"powered_by_enabled": False},
        )
        assert updated.powered_by_enabled is False


class TestPoweredByRouterWiring:
    def test_write_endpoints_use_the_entitlement_aware_service(self) -> None:
        """The gate is only real if the write routes actually receive a
        service that has a checker. Asserted structurally so a future
        refactor that swaps the dependency back cannot pass silently."""
        from app.domains.captive_portal import router as router_module

        aware = router_module.get_entitlement_aware_captive_portal_service
        for handler in (
            router_module.create_captive_portal_config,
            router_module.update_captive_portal_config,
        ):
            default = inspect.signature(handler).parameters["service"].default
            assert default.dependency is aware, handler.__name__

    def test_resolve_endpoint_does_not_get_a_checker(self) -> None:
        """The read path must stay unauthenticated and ungated -- a 402
        there would break the portal for every non-entitled tenant."""
        from app.domains.captive_portal import router as router_module

        default = (
            inspect.signature(router_module.resolve_captive_portal_config)
            .parameters["service"]
            .default
        )
        assert (
            default.dependency
            is not router_module.get_entitlement_aware_captive_portal_service
        )


class TestPoweredByAttributionReset:
    """``PoweredByAttributionResetService`` -- the system-side reset the
    ``_enforce_powered_by_entitlement`` docstring names as the right place
    to recover the white-label revenue: at the moment the plan changes,
    never on the guest hot path."""

    def _reset_service(self, fx: Fixture) -> PoweredByAttributionResetService:
        return PoweredByAttributionResetService(
            fx.repository,
            resolve_cache=fx.resolve_cache,
            audit_writer=fx.audit_writer,
        )

    async def _seed_org_cache(self, fx: Fixture) -> None:
        await fx.resolve_cache.set(
            fx.organization.id,
            None,
            {"cached": True},
            index_organization_id=fx.organization.id,
        )

    async def test_reset_flips_configs_invalidates_cache_and_audits(self) -> None:
        fx = make_service(with_cache=True)
        hidden = await _create_config(fx, name="Hidden")
        hidden.powered_by_enabled = False
        untouched = await _create_config(fx, name="Untouched")
        await self._seed_org_cache(fx)
        fx.audit_writer.entries.clear()

        count = await self._reset_service(fx).restore_powered_by_attribution(
            fx.organization.id
        )

        assert count == 1
        assert hidden.powered_by_enabled is True
        assert untouched.powered_by_enabled is True
        assert await fx.resolve_cache.get(fx.organization.id, None) is None
        [entry] = fx.audit_writer.entries
        assert entry["action"] == "captive_portal_powered_by_restored"
        assert entry["entity_id"] == hidden.id
        assert entry["entity_type"] == "captive_portal_config"
        assert entry["organization_id"] == fx.organization.id
        assert entry["actor_user_id"] is None

    async def test_inactive_configs_are_reset_too(self) -> None:
        # A dormant config must not resurrect a False value the plan no
        # longer includes when it is later re-activated.
        fx = make_service(with_cache=True)
        dormant = await _create_config(fx, name="Dormant", is_active=False)
        dormant.powered_by_enabled = False

        count = await self._reset_service(fx).restore_powered_by_attribution(
            fx.organization.id
        )

        assert count == 1
        assert dormant.powered_by_enabled is True

    async def test_deleted_configs_are_left_alone(self) -> None:
        fx = make_service(with_cache=True)
        config = await _create_config(fx, name="Gone")
        config.powered_by_enabled = False
        await fx.repository.soft_delete_config(config)
        fx.audit_writer.entries.clear()

        count = await self._reset_service(fx).restore_powered_by_attribution(
            fx.organization.id
        )

        assert count == 0
        assert config.powered_by_enabled is False
        assert fx.audit_writer.entries == []

    async def test_nothing_to_reset_is_a_pure_noop(self) -> None:
        fx = make_service(with_cache=True)
        await _create_config(fx, name="Fine")
        await self._seed_org_cache(fx)
        fx.audit_writer.entries.clear()

        count = await self._reset_service(fx).restore_powered_by_attribution(
            fx.organization.id
        )

        assert count == 0
        # No pointless fan-out: the cached entry survives untouched.
        assert await fx.resolve_cache.get(fx.organization.id, None) == {
            "cached": True
        }
        assert fx.audit_writer.entries == []

    async def test_reset_is_idempotent(self) -> None:
        fx = make_service(with_cache=True)
        config = await _create_config(fx, name="Once")
        config.powered_by_enabled = False
        reset = self._reset_service(fx)

        assert await reset.restore_powered_by_attribution(fx.organization.id) == 1
        fx.audit_writer.entries.clear()
        assert await reset.restore_powered_by_attribution(fx.organization.id) == 0
        assert fx.audit_writer.entries == []

    async def test_reset_bypasses_the_402_gate_end_to_end(self) -> None:
        # The full wiring: a LicenseService downgrade drives the real
        # PoweredByAttributionResetService for an organization that no
        # longer holds white_label -- the flip must go through the
        # repository layer and never raise
        # PoweredByAttributionNotEntitledError, because it is a system
        # action, not a tenant write.
        from decimal import Decimal

        from app.domains.billing.constants import (
            BillingCycle,
            PlanFeatureType,
            PlanType,
        )
        from app.domains.billing.service import LicenseService, PlanService
        from tests.unit.test_billing_plans_licenses_usage import (
            FakeLicenseRepository,
            FakeOrganizationComposer,
            FakePlanRepository,
            _FakeOrganization,
        )

        fx = make_service(with_cache=True)
        config = await _create_config(fx, name="Downgraded venue")
        config.powered_by_enabled = False
        await self._seed_org_cache(fx)
        fx.audit_writer.entries.clear()

        org_id = fx.organization.id
        plan_repository = FakePlanRepository()
        plan_service = PlanService(plan_repository)

        async def _plan(slug: str, features: list[dict[str, object]]):
            return await plan_service.create_plan(
                actor_user_id=None,
                name=slug.title(),
                slug=slug,
                plan_type=PlanType.STARTER.value,
                description=None,
                billing_cycle=BillingCycle.MONTHLY.value,
                base_price=Decimal("49.99"),
                currency="USD",
                is_active=True,
                is_public=True,
                sort_order=0,
                features=features,
            )

        pro = await _plan(
            "pro-e2e",
            [
                {
                    "feature_key": PlanFeatureKey.WHITE_LABEL.value,
                    "feature_type": PlanFeatureType.BOOLEAN.value,
                    "is_enabled": True,
                }
            ],
        )
        starter = await _plan("starter-e2e", [])

        license_service = LicenseService(
            FakeLicenseRepository(),
            plan_repository,
            organization_sync=FakeOrganizationComposer(
                organizations={org_id: _FakeOrganization(id=org_id)}
            ),
            white_label_reset=self._reset_service(fx),
        )
        license_ = await license_service.assign_license(
            actor_user_id=None, organization_id=org_id, plan_id=pro.id
        )
        await license_service.activate_license(
            actor_user_id=None, license_id=license_.id
        )

        await license_service.downgrade_license(
            actor_user_id=None, license_id=license_.id, new_plan_id=starter.id
        )

        assert config.powered_by_enabled is True
        assert await fx.resolve_cache.get(org_id, None) is None
        assert [
            e["action"]
            for e in fx.audit_writer.entries
            if e["action"] == "captive_portal_powered_by_restored"
        ] == ["captive_portal_powered_by_restored"]


# ============================================================================
# post_login_html: the venue's own post-sign-in page
# ============================================================================


class TestPostLoginHtmlSanitizerStripsExecutableMarkup:
    """The allowlist half of ``html_sanitizer``.

    Every case here is a way of getting script to run on a page a *guest*
    is shown, on the origin that also handles their OTP code. The frontend
    renders this HTML in an iframe sandboxed without ``allow-scripts`` or
    ``allow-same-origin``, so none of these would execute there today --
    which is exactly why they are asserted at this layer instead. The
    sandbox is one renderer's decision; the stored bytes outlive it.
    """

    def test_script_element_is_removed_with_its_source(self) -> None:
        out = sanitize_post_login_html("<script>alert(1)</script><p>hi</p>")
        assert out == "<p>hi</p>"
        # Removed *with* its content, not unwrapped -- unwrapping would
        # paste the program into the page as visible text.
        assert "alert" not in out

    def test_framing_and_plugin_elements_are_removed(self) -> None:
        out = sanitize_post_login_html(
            '<iframe src="https://evil.example"></iframe>'
            '<object data="x"></object><embed src="y">'
        )
        assert out is None

    def test_document_head_elements_are_removed(self) -> None:
        """``base`` rewrites every relative URL on the page, ``meta``
        http-equiv can redirect it, and ``link`` pulls in a stylesheet
        whose contents this sanitizer never sees."""
        out = sanitize_post_login_html(
            '<base href="https://evil.example/">'
            '<meta http-equiv="refresh" content="0;url=https://evil.example">'
            '<link rel="stylesheet" href="https://evil.example/x.css">'
        )
        assert out is None

    def test_form_and_its_inputs_are_removed(self) -> None:
        """A form on the post-login page is a phishing surface: it looks
        like part of the venue's WiFi flow and can POST anywhere."""
        out = sanitize_post_login_html(
            '<form action="https://evil.example"><input name="otp"></form>'
            "<p>after</p>"
        )
        assert out == "<p>after</p>"

    def test_every_event_handler_attribute_is_dropped(self) -> None:
        out = sanitize_post_login_html(
            '<p onclick="alert(1)" onmouseover="x" onerror="y">hi</p>'
        )
        assert out == "<p>hi</p>"

    def test_javascript_url_in_href_is_dropped_but_the_anchor_survives(
        self,
    ) -> None:
        out = sanitize_post_login_html('<a href="javascript:alert(1)">click</a>')
        assert "javascript" not in out
        assert ">click</a>" in out

    def test_data_url_in_img_src_is_dropped(self) -> None:
        """``data:image/svg+xml`` is a whole document that can carry
        script, and the MIME label is author-controlled -- so no ``data:``
        survives, not even the harmless PNG case."""
        out = sanitize_post_login_html(
            '<img src="data:image/svg+xml;base64,PHN2Zz4="><p>x</p>'
        )
        assert "data:" not in out

    def test_svg_and_math_are_removed_with_their_content(self) -> None:
        """Foreign-content elements re-enter HTML parsing under different
        rules; ``<svg onload=...>`` is the classic sanitizer bypass."""
        assert sanitize_post_login_html("<svg onload=alert(1)></svg>") is None

    def test_comments_are_stripped(self) -> None:
        out = sanitize_post_login_html(
            "<p>ok</p><!--[if IE]><script>x</script><![endif]-->"
        )
        assert out == "<p>ok</p>"

    def test_relative_urls_are_denied(self) -> None:
        """A relative URL resolves against whatever origin renders the
        page -- for this field, the one handling guest OTP codes."""
        out = sanitize_post_login_html('<a href="/admin">x</a>')
        assert "/admin" not in out


class TestPostLoginHtmlSanitizerKeepsWhatAVenueActuallyWrites:
    """The other half: a sanitizer that eats the venue's page is not
    secure, it is broken. These are the constructs the feature exists to
    support."""

    def test_formatting_and_layout_survive(self) -> None:
        out = sanitize_post_login_html(
            "<div><h1>Welcome</h1><p><strong>Enjoy</strong> your stay</p>"
            "<ul><li>Menu</li></ul></div>"
        )
        assert "<h1>Welcome</h1>" in out
        assert "<strong>Enjoy</strong>" in out
        assert "<li>Menu</li>" in out

    def test_http_image_and_link_survive_with_link_hardening(self) -> None:
        out = sanitize_post_login_html(
            '<img src="https://cdn.example/promo.png" alt="Promo">'
            '<a href="https://venue.example/menu">Menu</a>'
        )
        assert '<img src="https://cdn.example/promo.png" alt="Promo">' in out
        assert 'href="https://venue.example/menu"' in out
        assert 'rel="noopener noreferrer"' in out
        assert 'target="_blank"' in out

    def test_author_supplied_target_is_replaced_not_trusted(self) -> None:
        """``target="_top"`` would break out of a framing renderer. The
        attribute is not allowlisted at all; ``_blank`` is then set
        unconditionally, so the hostile value is unexpressible rather than
        merely discouraged."""
        out = sanitize_post_login_html(
            '<a href="https://ok.example/" target="_top" rel="me">x</a>'
        )
        assert 'target="_blank"' in out
        assert "_top" not in out
        assert 'rel="noopener noreferrer"' in out

    def test_mailto_and_tel_survive(self) -> None:
        out = sanitize_post_login_html(
            '<a href="mailto:hi@venue.example">Email</a>'
            '<a href="tel:+911234567890">Call</a>'
        )
        assert "mailto:hi@venue.example" in out
        assert "tel:+911234567890" in out

    def test_inline_style_and_style_block_survive(self) -> None:
        out = sanitize_post_login_html(
            "<style>.card{border-radius:8px;padding:16px}</style>"
            '<div class="card" style="color:#1a73e8;font-size:18px">Hi</div>'
        )
        assert "border-radius:8px" in out
        assert "color:#1a73e8" in out
        assert 'class="card"' in out

    def test_http_backgrounds_and_font_faces_survive_in_css(self) -> None:
        out = sanitize_post_login_html(
            "<style>@font-face{font-family:F;src:url(https://cdn.example/f.woff2)}"
            ".hero{background:url('https://cdn.example/bg.png') no-repeat}</style>"
        )
        assert "https://cdn.example/f.woff2" in out
        assert "https://cdn.example/bg.png" in out

    def test_media_queries_survive(self) -> None:
        out = sanitize_post_login_html(
            "<style>@media (max-width:600px){.hero{font-size:14px}}</style>"
        )
        assert "@media (max-width:600px)" in out
        assert "font-size:14px" in out


class TestPostLoginHtmlCssSanitizer:
    """``nh3``/``ammonia`` filters tags, attributes and URL schemes and
    stops there -- it never looks inside a ``style`` value or a
    ``<style>`` element. Allowing styling therefore means owning the CSS,
    which is what these cover."""

    def test_javascript_url_in_a_style_attribute_is_dropped(self) -> None:
        out = sanitize_post_login_html(
            '<p style="color:red;background:url(javascript:alert(1));width:50%">x</p>'
        )
        assert "javascript" not in out
        # Surgical: the offending declaration goes, the venue's other two
        # survive.
        assert "color:red" in out
        assert "width:50%" in out

    def test_ie_script_from_css_vectors_are_dropped(self) -> None:
        out = sanitize_post_login_html(
            '<p style="behavior:url(#x);-moz-binding:url(http://e/x.xml);color:blue">'
            "x</p>"
        )
        assert "behavior" not in out
        assert "-moz-binding" not in out
        assert "color:blue" in out

    def test_backslash_escaped_expression_is_caught(self) -> None:
        r"""``expr\ession(`` is what the renderer resolves to
        ``expression(``; a probe that matched only the literal spelling
        would miss it."""
        out = sanitize_post_login_html(
            '<p style="color:expr\\ession(alert(1));font-size:14px">x</p>'
        )
        assert "ession" not in out
        assert "font-size:14px" in out

    def test_comment_split_expression_is_caught(self) -> None:
        """``expr/**/ession(`` is the same trick using a CSS comment as
        the splitter -- which is why comments are stripped *before* the
        banned-substring probe runs, on the attribute path too."""
        out = sanitize_post_login_html(
            '<p style="color:expr/**/ession(alert(1));font-size:14px">x</p>'
        )
        assert "ession" not in out
        assert "font-size:14px" in out

    def test_at_import_is_dropped_without_taking_the_sheet_with_it(self) -> None:
        """``@import`` is a remote load whose contents this sanitizer
        never sees and whose owner can swap them after the fact. The rest
        of the stylesheet must survive it -- dropping the whole sheet over
        one line would be the kind of over-firing that gets a sanitizer
        turned off."""
        out = sanitize_post_login_html(
            '<style>@import url("https://evil.example/x.css");'
            ".card{color:red}</style>"
        )
        assert "@import" not in out
        assert "color:red" in out

    def test_javascript_url_inside_a_nested_block_is_dropped(self) -> None:
        out = sanitize_stylesheet(
            "@media screen{.a{color:blue;background:url(javascript:1)}}"
        )
        assert "javascript" not in out
        assert "color:blue" in out

    def test_stylesheet_braces_are_balanced_even_when_the_input_is_not(
        self,
    ) -> None:
        """An unclosed rule that leaked through would swallow whatever a
        future renderer concatenated after it."""
        out = sanitize_stylesheet(".a{color:red")
        assert out.count("{") == out.count("}")


class TestPostLoginHtmlSizeCap:
    def test_over_the_cap_raises_with_both_numbers(self) -> None:
        """A bare "string too long" would leave the venue guessing how
        much to cut, which is the entire argument for validating at
        authoring time rather than truncating at render."""
        oversized = "<p>" + ("a" * (POST_LOGIN_HTML_MAX_BYTES + 1)) + "</p>"
        with pytest.raises(PostLoginHtmlTooLargeError) as exc_info:
            sanitize_post_login_html(oversized)
        error = exc_info.value
        assert error.status_code == 400
        assert error.data["max_bytes"] == POST_LOGIN_HTML_MAX_BYTES
        assert error.data["actual_bytes"] == len(oversized.encode("utf-8"))
        assert str(POST_LOGIN_HTML_MAX_BYTES) in str(error)
        assert str(len(oversized.encode("utf-8"))) in str(error)

    def test_the_cap_is_bytes_not_characters(self) -> None:
        """Counted in UTF-8 bytes, unlike the splash ceilings, because
        this is a resource limit on something parsed, cached and shipped
        -- not a rendered-line budget. A page of Devanagari is three
        bytes per code point and must be charged for all three."""
        # Just under the cap in code points, comfortably over it in bytes.
        payload = "क" * (POST_LOGIN_HTML_MAX_BYTES // 2)
        assert len(payload) < POST_LOGIN_HTML_MAX_BYTES
        with pytest.raises(PostLoginHtmlTooLargeError):
            sanitize_post_login_html(payload)

    def test_exactly_at_the_cap_is_accepted(self) -> None:
        payload = "a" * POST_LOGIN_HTML_MAX_BYTES
        assert sanitize_post_login_html(payload) == payload

    def test_the_cap_is_measured_before_sanitizing(self) -> None:
        """The number in the error has to be the number the venue sees in
        their own editor. Measuring the *output* would report a size for
        bytes they never wrote."""
        oversized = "<script>" + ("a" * POST_LOGIN_HTML_MAX_BYTES) + "</script>"
        with pytest.raises(PostLoginHtmlTooLargeError) as exc_info:
            sanitize_post_login_html(oversized)
        # Sanitizing first would have reduced this to nothing at all.
        assert exc_info.value.data["actual_bytes"] > POST_LOGIN_HTML_MAX_BYTES


class TestPostLoginHtmlEmptiness:
    def test_none_stays_none(self) -> None:
        assert sanitize_post_login_html(None) is None

    def test_blank_becomes_none_not_empty_string(self) -> None:
        """Null and "" both mean "no page, use today's redirect/success
        behaviour". Storing two values for one meaning invites a renderer
        to eventually treat them differently."""
        assert sanitize_post_login_html("   \n ") is None

    def test_html_that_sanitizes_away_entirely_becomes_none(self) -> None:
        assert sanitize_post_login_html("<script>alert(1)</script>") is None


class TestPostLoginHtmlServiceWiring:
    async def test_create_stores_the_sanitized_bytes_not_the_input(self) -> None:
        fx = make_service()
        config = await _create_config(
            fx,
            post_login_html='<p onclick="alert(1)">Thanks!</p><script>x</script>',
        )
        assert config.post_login_html == "<p>Thanks!</p>"

    async def test_create_defaults_to_none_so_nothing_existing_changes(self) -> None:
        """The whole compatibility claim in one assertion: a config
        created without the field renders exactly as every config does
        today."""
        fx = make_service()
        config = await _create_config(fx)
        assert config.post_login_html is None

    async def test_update_stores_the_sanitized_bytes(self) -> None:
        fx = make_service()
        config = await _create_config(fx)
        updated = await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"post_login_html": "<p>Hi</p><iframe src='https://e/'></iframe>"},
        )
        assert updated.post_login_html == "<p>Hi</p>"

    async def test_update_without_the_key_leaves_the_page_untouched(self) -> None:
        """The dashboard PUTs its whole form; a save that never mentions
        the field must not clear a page the venue already published."""
        fx = make_service()
        config = await _create_config(fx, post_login_html="<p>Keep me</p>")
        updated = await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"name": "Renamed"},
        )
        assert updated.post_login_html == "<p>Keep me</p>"

    async def test_update_to_none_clears_the_page(self) -> None:
        fx = make_service()
        config = await _create_config(fx, post_login_html="<p>Bye</p>")
        updated = await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"post_login_html": None},
        )
        assert updated.post_login_html is None

    async def test_oversized_update_is_rejected_before_any_write(self) -> None:
        fx = make_service()
        config = await _create_config(fx, post_login_html="<p>Original</p>")
        with pytest.raises(PostLoginHtmlTooLargeError):
            await fx.service.update_config(
                actor_user_id=uuid.uuid4(),
                config_id=config.id,
                requesting_organization_id=fx.organization.id,
                data={"post_login_html": "a" * (POST_LOGIN_HTML_MAX_BYTES + 1)},
            )
        assert config.post_login_html == "<p>Original</p>"

    async def test_post_login_html_and_redirect_url_coexist(self) -> None:
        """They are not alternatives. With both set the venue's page
        renders *and* the continue-to-URL affordance stays -- this layer's
        only obligation is that neither field suppresses the other."""
        fx = make_service()
        config = await _create_config(fx, post_login_html="<p>Thanks</p>")
        updated = await fx.service.update_config(
            actor_user_id=uuid.uuid4(),
            config_id=config.id,
            requesting_organization_id=fx.organization.id,
            data={"redirect_url": "https://venue.example/"},
        )
        assert updated.post_login_html == "<p>Thanks</p>"
        assert updated.redirect_url == "https://venue.example/"

    async def test_resolve_returns_the_page_and_survives_the_cache_round_trip(
        self,
    ) -> None:
        """``resolve`` is what the portal actually reads, and it answers
        from a Redis payload rebuilt into a stand-in object -- a field
        missing from ``_CACHED_CONFIG_SCALAR_FIELDS`` would be silently
        absent on the second guest, not the first."""
        fx = make_service(with_cache=True)
        await _create_config(
            fx, is_default=True, post_login_html="<p>Welcome online</p>"
        )
        first = await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )
        assert first.config.post_login_html == "<p>Welcome online</p>"
        second = await fx.service.resolve_portal_config(
            organization_id=fx.organization.id, location_id=None
        )
        assert second.config.post_login_html == "<p>Welcome online</p>"
