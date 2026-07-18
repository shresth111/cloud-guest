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

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.domains.captive_portal.constants import TERMS_AND_CONDITIONS_LABEL
from app.domains.captive_portal.exceptions import (
    CaptivePortalConfigNotConfiguredError,
    CaptivePortalConfigNotFoundError,
    CrossOrganizationCaptivePortalConfigAccessError,
    InvalidDefaultConfigScopeError,
    InvalidHexColorError,
    InvalidPortalContentSourceError,
    MissingPortalResolutionParamsError,
)
from app.domains.captive_portal.models import CaptivePortalConfig
from app.domains.captive_portal.service import CaptivePortalService
from app.domains.captive_portal.validators import (
    validate_default_scope,
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

    def add(self, *, organization_id: uuid.UUID) -> Location:
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
                country="US",
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
class Fixture:
    repository: FakeCaptivePortalRepository
    audit_writer: FakeAuditLogWriter
    organization_lookup: FakeOrganizationLookup
    location_lookup: FakeLocationLookup
    service: CaptivePortalService
    organization: Organization


def make_service() -> Fixture:
    repository = FakeCaptivePortalRepository()
    audit_writer = FakeAuditLogWriter()
    organization_lookup = FakeOrganizationLookup()
    location_lookup = FakeLocationLookup()
    organization = organization_lookup.add()
    service = CaptivePortalService(
        repository,
        organization_lookup,
        location_lookup,
        audit_writer=audit_writer,
    )
    return Fixture(
        repository=repository,
        audit_writer=audit_writer,
        organization_lookup=organization_lookup,
        location_lookup=location_lookup,
        service=service,
        organization=organization,
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
        voucher_enabled=True,
        username_password_enabled=False,
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

    async def test_username_password_disabled_by_default(self) -> None:
        fx = make_service()
        config = await _create_config(fx)
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
