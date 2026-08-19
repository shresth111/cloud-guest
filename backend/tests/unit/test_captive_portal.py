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

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from app.domains.captive_portal.constants import (
    DEFAULT_BACKGROUND_FOCAL_X,
    DEFAULT_BACKGROUND_FOCAL_Y,
    DEFAULT_BACKGROUND_OVERLAY_STRENGTH,
    DEFAULT_GUEST_FONT_CHOICE,
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
)
from app.domains.captive_portal.models import CaptivePortalConfig
from app.domains.captive_portal.service import (
    CaptivePortalService,
    ResolvedPortalConfig,
)
from app.domains.captive_portal.validators import (
    validate_background_focal_point,
    validate_background_overlay_strength,
    validate_default_scope,
    validate_guest_font_choice,
    validate_hex_color,
    validate_single_content_source,
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
    ) -> None:
        key = self._key(organization_id, location_id)
        self.store[key] = payload
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
    # True (the real, standard "OTP once, then a saved password" baseline
    # -- see CaptivePortalConfig.username_password_enabled's own
    # docstring) mirrors this helper's own otp_sms_enabled/voucher_enabled
    # defaults being the actually-enabled-by-default methods.
    username_password_enabled: bool = True,
    pin_login_enabled: bool = False,
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
        splash_headline=None,
        splash_welcome_message=None,
        redirect_url=None,
        otp_sms_enabled=True,
        otp_email_enabled=False,
        otp_whatsapp_enabled=False,
        voucher_enabled=True,
        username_password_enabled=username_password_enabled,
        pin_login_enabled=pin_login_enabled,
        social_login_enabled=social_login_enabled,
        social_login_providers=social_login_providers or [],
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
        assert table.c.guest_font_choice.default.arg == "system"
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


class TestResolveCacheKeyVersion:
    def test_cache_key_is_v4(self) -> None:
        """Spec §0.3: the version must be bumped in the same change that
        changes the cached field set. Skipping it makes every payload
        written by the previous build raise KeyError out of the
        unauthenticated guest resolve endpoint -- a 500 for every guest
        joining WiFi until the TTL expires.

        v4 is design spec §5 S7: the ``brandings`` row joined the payload
        under a new top-level ``"branding"`` key."""
        from app.domains.captive_portal.cache import _CACHE_KEY_TEMPLATE

        key = _CACHE_KEY_TEMPLATE.format(organization_id="org", location_id="loc")
        assert key == "captive_portal:resolve:v4:org:loc"

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
        assert payload_version == index_version == "v4"

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
