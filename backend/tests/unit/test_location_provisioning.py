"""Unit tests for Smart Location Provisioning
(``app.domains.location.provisioning_service.LocationProvisioningService``).

Follows this project's established convention (see ``test_location.py``'s
own module docstring): plain ``assert`` / native ``async def`` tests,
in-memory fake stand-ins for every composed cross-domain protocol rather
than a live Postgres/Redis instance. ``LocationService`` itself (the
domain this task extends) is exercised as the *real* class -- backed by
small in-memory fakes for its own dependencies, exactly like
``test_location.py`` already does -- rather than faked at the
``LocationProvisioningService`` boundary, since that is the strongest
available proof that this orchestration composes the real, unmodified
Location domain rather than reimplementing it. Every *other* composed
domain (Organization/User/RBAC/Router/Router Provisioning/WireGuard/
Billing/Captive Portal) is exercised through a small spy fake that
implements the *exact* narrow protocol
``app.domains.location.provisioning_service`` defines for it and records
every call it receives -- the same "duck-typed protocol + fake" testing
style this codebase's own domains already use for their own cross-domain
composition (e.g. ``test_location.py``'s ``FakeOrganizationLookup``),
extended here to prove each step really is a call to that domain's real
public method contract, not a reimplementation of it.
"""

from __future__ import annotations

import asyncio
import dataclasses
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import pytest

from app.domains.auth.service import AuthService, PasswordChangeRequiredError
from app.domains.billing.constants import PlanFeatureKey, PlanFeatureType, PlanType
from app.domains.location.enums import PropertyType
from app.domains.location.exceptions import (
    DefaultConfigTemplateNotFoundError,
    NewOrganizationRequiredError,
)
from app.domains.location.number_generator import generate_location_code
from app.domains.location.provisioning_service import (
    FeatureOverride,
    LocationInput,
    LocationProvisioningService,
    NewOrganizationInput,
    OwnerInput,
    OwnerNotProvisionedError,
    OwnerRoleNotSeededError,
    ProvisionLocationInput,
    RouterInput,
    _generate_temporary_password,
    _generate_username,
)
from app.domains.location.service import LocationService
from app.domains.organization.enums import OrganizationStatus, OrganizationType
from app.domains.organization.exceptions import (
    DuplicateSlugError,
    OrganizationArchivedError,
    OrganizationNotFoundError,
)
from app.domains.organization.models import Organization
from app.domains.rbac.enums import AuditAction
from app.domains.rbac.seed import SYSTEM_ROLES
from app.domains.rbac.seed import PermissionModule as _M

# ============================================================================
# Shared "unit of work" test double -- the real transactional mechanism proof
# ============================================================================


@dataclass
class FakeSharedSession:
    """Stands in for the single, request-scoped ``AsyncSession``
    ``app.database.session.get_db_session`` yields. Every fake repository
    below calls ``flush(tag)`` to record a write the same way
    ``GenericRepository.create``/``update`` call ``session.flush()`` (never
    ``session.commit()``) -- this object's own ``commit``/``rollback`` are
    only ever called by ``run_within_transaction`` below, mirroring
    ``get_db_session``'s exact shape."""

    flushed: list[str] = field(default_factory=list)
    committed: bool = False
    rolled_back: bool = False

    def flush(self, tag: str) -> None:
        self.flushed.append(tag)

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True


async def run_within_transaction(session: FakeSharedSession, awaitable: Any) -> Any:
    """A faithful, minimal mirror of
    ``app.database.session.get_db_session``'s own body:

    ```
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
    ```

    -- proving the exact same commit-once-at-the-end /
    rollback-on-any-exception behavior against this test's shared fake
    session, without needing FastAPI's own request lifecycle."""
    try:
        result = await awaitable
        session.commit()
        return result
    except Exception:
        session.rollback()
        raise


# ============================================================================
# Fakes: same-domain (LocationService) -- the REAL service class, backed by
# minimal in-memory fakes (mirrors test_location.py's own convention).
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
class FakeLocationRepository:
    session: FakeSharedSession
    locations: dict[uuid.UUID, Any] = field(default_factory=dict)

    async def get_by_id(self, location_id: uuid.UUID, *, include_deleted: bool = False):
        return self.locations.get(location_id)

    async def get_by_slug(self, organization_id: uuid.UUID, slug: str):
        return next(
            (
                loc
                for loc in self.locations.values()
                if loc.organization_id == organization_id and loc.slug == slug
            ),
            None,
        )

    async def create_location(self, **fields: object):
        from app.domains.location.models import Location

        defaults = {
            "address_line2": None,
            "latitude": None,
            "longitude": None,
            "contact_name": None,
            "contact_phone": None,
            "contact_email": None,
            "settings": {},
        }
        location = Location(**_base_fields(**{**defaults, **fields}))
        self.locations[location.id] = location
        self.session.flush("location.create")
        return location

    async def update_location(self, location, data: dict[str, object]):
        for key, value in data.items():
            setattr(location, key, value)
        self.session.flush("location.update")
        return location

    async def soft_delete_location(self, location):
        location.is_deleted = True
        return location

    async def list_locations(self, **kwargs):
        raise NotImplementedError


@dataclass
class FakeLocationCodeCounterRepository:
    session: FakeSharedSession
    counters: dict[str, int] = field(default_factory=dict)

    async def increment_and_get_next(self, counter_key: str) -> int:
        next_value = self.counters.get(counter_key, 0) + 1
        self.counters[counter_key] = next_value
        self.session.flush("location_code_counter.increment")
        return next_value

    async def peek_next(self, counter_key: str) -> int:
        return self.counters.get(counter_key, 0) + 1


@dataclass
class FakeOrganizationLookupForLocation:
    """Minimal ``OrganizationLookupProtocol`` (LocationService's own,
    narrower one) -- just enough for ``create_location``'s org-active
    check."""

    organizations: dict[uuid.UUID, Organization]

    async def get_organization(
        self, organization_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Organization:
        return self.organizations[organization_id]


# ============================================================================
# Fakes: cross-domain protocol spies -- record every call in a single shared
# execution-order list, proving both correct composition and correct
# ordering/short-circuiting on failure.
# ============================================================================


@dataclass
class FakeUser:
    id: uuid.UUID
    first_name: str
    last_name: str
    email: str
    username: str
    must_change_password: bool = False


@dataclass
class FakeRole:
    id: uuid.UUID
    slug: str


@dataclass
class FakeRouter:
    id: uuid.UUID
    name: str
    organization_id: uuid.UUID
    location_id: uuid.UUID


@dataclass
class FakeConfigTemplate:
    id: uuid.UUID
    is_system_template: bool
    is_active: bool
    created_at: datetime


@dataclass
class FakePeer:
    tunnel_ip_address: str


@dataclass
class FakeTunnelDeliveryInfo:
    peer: FakePeer


@dataclass
class FakePlan:
    id: uuid.UUID
    name: str
    slug: str
    billing_cycle: str = "monthly"
    base_price: Decimal = Decimal("49.00")
    currency: str = "USD"
    sort_order: int = 0
    is_public: bool = True
    plan_type: str = "professional"


@dataclass
class FakePlanFeature:
    feature_key: str
    feature_type: str
    limit_value: Decimal | None = None
    is_enabled: bool | None = None
    tier_value: str | None = None


@dataclass
class FakeSubscription:
    id: uuid.UUID
    organization_id: uuid.UUID
    plan_id: uuid.UUID


@dataclass
class ProvisioningFakes:
    """Bundles every composed cross-domain spy fake, all sharing one
    ``FakeSharedSession`` and one ``calls`` execution-order log."""

    session: FakeSharedSession
    calls: list[str] = field(default_factory=list)

    organizations: dict[uuid.UUID, Organization] = field(default_factory=dict)
    users_by_id: dict[uuid.UUID, FakeUser] = field(default_factory=dict)
    roles_by_slug: dict[str, FakeRole] = field(default_factory=dict)
    plans_by_id: dict[uuid.UUID, FakePlan] = field(default_factory=dict)
    features_by_plan_id: dict[uuid.UUID, list[FakePlanFeature]] = field(
        default_factory=dict
    )
    system_templates: list[FakeConfigTemplate] = field(default_factory=list)
    audit_entries: list[dict[str, object]] = field(default_factory=list)
    emails_sent: list[tuple[str, str, str]] = field(default_factory=list)
    sms_sent: list[tuple[str, str]] = field(default_factory=list)

    fail_at: str | None = None

    def _maybe_fail(self, step: str) -> None:
        if self.fail_at == step:
            raise RuntimeError(f"forced failure at step '{step}'")

    # -- OrganizationProvisioningProtocol ---------------------------------

    async def get_organization(self, organization_id, *, include_deleted=False):
        self._maybe_fail("organization.get")
        return self.organizations[organization_id]

    async def get_by_slug(self, slug: str):
        self._maybe_fail("organization.get_by_slug")
        for organization in self.organizations.values():
            if organization.slug == slug:
                return organization
        raise OrganizationNotFoundError(slug)

    async def create_organization(self, *, actor_user_id, name, slug, **kwargs):
        self._maybe_fail("organization.create")
        organization = Organization(
            **_base_fields(
                name=name,
                slug=slug,
                legal_name=kwargs.get("legal_name"),
                org_type=OrganizationType.STANDARD.value,
                status=OrganizationStatus.ACTIVE.value,
                parent_organization_id=None,
                contact_email=kwargs.get("contact_email", "owner@example.com"),
                contact_phone=kwargs.get("contact_phone"),
                timezone=kwargs.get("timezone", "UTC"),
                default_locale=kwargs.get("default_locale", "en"),
                settings=kwargs.get("settings") or {},
                subscription_tier=None,
            )
        )
        self.organizations[organization.id] = organization
        self.session.flush("organization.create")
        self.calls.append("organization.create")
        return organization

    async def activate_organization(
        self, *, actor_user_id, organization_id, requesting_organization_id
    ):
        self._maybe_fail("organization.activate")
        organization = self.organizations[organization_id]
        organization.status = OrganizationStatus.ACTIVE.value
        self.session.flush("organization.activate")
        self.calls.append("organization.activate")
        return organization

    # -- UserProvisioningProtocol ------------------------------------------

    async def create_user(
        self,
        *,
        actor_user_id,
        first_name,
        last_name,
        email,
        username,
        temporary_password,
        requesting_organization_id,
        organization_id=None,
        initial_role_id=None,
        **kwargs,
    ):
        self._maybe_fail("user.create")
        user = FakeUser(
            id=uuid.uuid4(),
            first_name=first_name,
            last_name=last_name,
            email=email,
            username=username,
        )
        self.users_by_id[user.id] = user
        self.session.flush("user.create")
        self.calls.append("user.create")
        return user

    # -- IdentityUpdateProtocol ---------------------------------------------

    async def get_user_by_id(self, user_id):
        return self.users_by_id.get(user_id)

    async def update_user(self, user, **fields):
        self._maybe_fail("identity.update_user")
        for key, value in fields.items():
            setattr(user, key, value)
        self.session.flush("identity.update_user")
        self.calls.append("identity.update_user")
        return user

    # -- RbacSupportProtocol -------------------------------------------------

    async def get_role_by_slug(self, slug, organization_id):
        self._maybe_fail("rbac.get_role_by_slug")
        return self.roles_by_slug.get(slug)

    async def create_audit_log_entry(self, **fields):
        self._maybe_fail("rbac.create_audit_log_entry")
        self.audit_entries.append(fields)
        self.session.flush("rbac.create_audit_log_entry")
        self.calls.append(f"audit:{fields['action']}")
        return fields

    # -- RouterProvisioningProtocol ------------------------------------------

    async def create_router(
        self, *, actor_user_id, location_id, requesting_organization_id, name, **kwargs
    ):
        self._maybe_fail("router.create")
        router = FakeRouter(
            id=uuid.uuid4(),
            name=name,
            organization_id=uuid.uuid4(),
            location_id=location_id,
        )
        self.session.flush("router.create")
        self.calls.append("router.create")
        return router

    # -- ConfigTemplateAssignmentProtocol -------------------------------------

    async def list_templates(self, *, requesting_organization_id, page=1, page_size=25):
        self._maybe_fail("router_provisioning.list_templates")
        self.calls.append("router_provisioning.list_templates")
        return list(self.system_templates), None

    async def assign_profile(
        self, *, actor_user_id, router_id, template_id, requesting_organization_id
    ):
        self._maybe_fail("router_provisioning.assign_profile")
        self.session.flush("router_provisioning.assign_profile")
        self.calls.append("router_provisioning.assign_profile")
        return object(), object()

    # -- WireGuardProvisioningProtocol ---------------------------------------

    async def create_tunnel(
        self, *, actor_user_id, router_id, requesting_organization_id
    ):
        self._maybe_fail("wireguard.create_tunnel")
        self.session.flush("wireguard.create_tunnel")
        self.calls.append("wireguard.create_tunnel")
        return FakeTunnelDeliveryInfo(peer=FakePeer(tunnel_ip_address="10.100.0.5"))

    # -- PlanProvisioningProtocol ---------------------------------------------

    async def get_plan(self, plan_id, *, include_deleted=False):
        self._maybe_fail("plan.get_plan")
        return self.plans_by_id[plan_id]

    async def list_features(self, plan_id):
        self._maybe_fail("plan.list_features")
        return self.features_by_plan_id.get(plan_id, [])

    async def create_plan(
        self,
        *,
        actor_user_id,
        name,
        slug,
        plan_type,
        description,
        billing_cycle,
        base_price,
        currency,
        is_active,
        is_public,
        sort_order,
        features,
    ):
        self._maybe_fail("plan.create_plan")
        plan = FakePlan(
            id=uuid.uuid4(),
            name=name,
            slug=slug,
            billing_cycle=billing_cycle,
            base_price=base_price,
            currency=currency,
            sort_order=sort_order,
            is_public=is_public,
            plan_type=plan_type,
        )
        self.plans_by_id[plan.id] = plan
        self.features_by_plan_id[plan.id] = [
            FakePlanFeature(
                feature_key=row["feature_key"].value
                if hasattr(row["feature_key"], "value")
                else row["feature_key"],
                feature_type=row["feature_type"].value
                if hasattr(row["feature_type"], "value")
                else row["feature_type"],
                limit_value=row["limit_value"],
                is_enabled=row["is_enabled"],
                tier_value=row["tier_value"],
            )
            for row in features
        ]
        self.session.flush("plan.create_plan")
        self.calls.append("plan.create_plan")
        return plan

    # -- SubscriptionProvisioningProtocol -------------------------------------

    async def create_subscription(
        self, *, actor_user_id, organization_id, plan_id, coupon_code=None
    ):
        self._maybe_fail("subscription.create")
        self.session.flush("subscription.create")
        self.calls.append("subscription.create")
        return FakeSubscription(
            id=uuid.uuid4(), organization_id=organization_id, plan_id=plan_id
        )

    # -- CaptivePortalProvisioningProtocol -------------------------------------

    async def create_config(self, **fields):
        self._maybe_fail("captive_portal.create_config")
        self.session.flush("captive_portal.create_config")
        self.calls.append("captive_portal.create_config")
        return object()

    # -- EmailProviderProtocol / SmsProviderProtocol --------------------------

    async def send_email(self, email, subject, body):
        self._maybe_fail("email.send")
        self.emails_sent.append((email, subject, body))
        self.calls.append("email.send")

    async def send_sms(self, phone_number, message):
        self._maybe_fail("sms.send")
        self.sms_sent.append((phone_number, message))
        self.calls.append("sms.send")


class _EmailProviderAdapter:
    def __init__(self, fakes: ProvisioningFakes) -> None:
        self._fakes = fakes

    async def send(self, email: str, subject: str, body: str) -> None:
        await self._fakes.send_email(email, subject, body)


class _SmsProviderAdapter:
    def __init__(self, fakes: ProvisioningFakes) -> None:
        self._fakes = fakes

    async def send(self, phone_number: str, message: str) -> None:
        await self._fakes.send_sms(phone_number, message)


# ============================================================================
# Test rig assembly
# ============================================================================


def make_service(
    *, fail_at: str | None = None
) -> tuple[LocationProvisioningService, ProvisioningFakes, FakeSharedSession]:
    session = FakeSharedSession()
    fakes = ProvisioningFakes(session=session, fail_at=fail_at)
    fakes.roles_by_slug["organization-owner"] = FakeRole(
        id=uuid.uuid4(), slug="organization-owner"
    )
    fakes.system_templates.append(
        FakeConfigTemplate(
            id=uuid.uuid4(), is_system_template=True, is_active=True, created_at=_now()
        )
    )
    base_plan_id = uuid.uuid4()
    fakes.plans_by_id[base_plan_id] = FakePlan(
        id=base_plan_id, name="Professional", slug="professional"
    )
    fakes.features_by_plan_id[base_plan_id] = [
        FakePlanFeature(
            feature_key=PlanFeatureKey.MAX_LOCATIONS.value,
            feature_type=PlanFeatureType.LIMIT.value,
            limit_value=Decimal("5"),
        ),
        FakePlanFeature(
            feature_key=PlanFeatureKey.ANALYTICS.value,
            feature_type=PlanFeatureType.BOOLEAN.value,
            is_enabled=True,
        ),
        FakePlanFeature(
            feature_key=PlanFeatureKey.MOBILE_OTP.value,
            feature_type=PlanFeatureType.BOOLEAN.value,
            is_enabled=True,
        ),
        FakePlanFeature(
            feature_key=PlanFeatureKey.VOUCHER_LOGIN.value,
            feature_type=PlanFeatureType.BOOLEAN.value,
            is_enabled=False,
        ),
    ]

    location_repository = FakeLocationRepository(session=session)
    location_code_counter = FakeLocationCodeCounterRepository(session=session)
    organization_lookup = FakeOrganizationLookupForLocation(fakes.organizations)
    location_service = LocationService(
        location_repository,
        organization_lookup,
        location_code_counter=location_code_counter,
        audit_writer=fakes,
    )

    service = LocationProvisioningService(
        location_service,
        fakes,
        fakes,
        fakes,
        fakes,
        fakes,
        fakes,
        fakes,
        fakes,
        fakes,
        fakes,
        _EmailProviderAdapter(fakes),
        _SmsProviderAdapter(fakes),
    )
    return service, fakes, base_plan_id


def _input(
    *,
    existing_organization_id: uuid.UUID | None = None,
    new_organization: NewOrganizationInput | None = None,
    plan_id: uuid.UUID,
    feature_overrides: tuple[FeatureOverride, ...] = (),
) -> ProvisionLocationInput:
    return ProvisionLocationInput(
        location=LocationInput(
            name="Downtown Branch",
            slug="downtown-branch",
            property_type=PropertyType.HOTEL,
            address_line1="123 Main St",
            city="Austin",
            state_province="TX",
            postal_code="78701",
            country="US",
        ),
        owner=OwnerInput(
            first_name="Priya",
            last_name="Shah",
            email="priya@example.com",
        ),
        router=RouterInput(
            name="Lobby Router",
            serial_number="SN-00001",
            mac_address="AA:BB:CC:DD:EE:01",
            model="RB5009",
        ),
        plan_id=plan_id,
        existing_organization_id=existing_organization_id,
        new_organization=new_organization,
        feature_overrides=feature_overrides,
    )


def _new_org() -> NewOrganizationInput:
    return NewOrganizationInput(
        name="Grand Plaza Hotel",
        slug=f"grand-plaza-{uuid.uuid4().hex[:6]}",
        contact_email="ops@grandplaza.example.com",
    )


# ============================================================================
# Preview (Enterprise SaaS Phase C: read-only dry run)
# ============================================================================


class TestPreviewProvisionLocation:
    async def test_preview_never_creates_anything(self) -> None:
        service, fakes, base_plan_id = make_service()

        preview = await service.preview_provision_location(
            data=_input(new_organization=_new_org(), plan_id=base_plan_id)
        )

        assert preview.organization_id is None
        assert fakes.organizations == {}
        assert fakes.users_by_id == {}
        # Only real, read-only lookups happen (e.g. resolving the default
        # config template) -- never a create/assign/update call.
        assert not any(
            call.split(".", 1)[1].startswith(("create", "assign", "update"))
            for call in fakes.calls
        )

    async def test_preview_new_organization_previews_customer_and_site_ids(
        self,
    ) -> None:
        service, _fakes, base_plan_id = make_service()
        new_org = _new_org()

        preview = await service.preview_provision_location(
            data=_input(new_organization=new_org, plan_id=base_plan_id)
        )

        assert preview.customer_id == new_org.slug
        assert preview.site_id.startswith("LOC-")
        assert preview.nas_id == f"NAS-{preview.site_id}-0001"
        assert preview.controller_id == "SN-00001"
        assert preview.plan_name == "Professional"

    async def test_preview_does_not_consume_the_real_location_code_counter(
        self,
    ) -> None:
        service, fakes, base_plan_id = make_service()
        data = _input(new_organization=_new_org(), plan_id=base_plan_id)

        first_preview = await service.preview_provision_location(data=data)
        second_preview = await service.preview_provision_location(data=data)

        assert first_preview.site_id == second_preview.site_id
        assert fakes.session.flushed == []

    async def test_preview_existing_organization_uses_its_real_slug(self) -> None:
        service, fakes, base_plan_id = make_service()
        organization = Organization(
            **_base_fields(
                name="Existing Co",
                slug="existing-co",
                legal_name=None,
                org_type=OrganizationType.STANDARD.value,
                status=OrganizationStatus.ACTIVE.value,
                parent_organization_id=None,
                contact_email="ops@existing.example.com",
                contact_phone=None,
                timezone="UTC",
                default_locale="en",
                settings={},
                subscription_tier=None,
            )
        )
        fakes.organizations[organization.id] = organization

        preview = await service.preview_provision_location(
            data=_input(
                existing_organization_id=organization.id, plan_id=base_plan_id
            )
        )

        assert preview.organization_id == organization.id
        assert preview.customer_id == "existing-co"

    async def test_preview_rejects_archived_organization(self) -> None:
        service, fakes, base_plan_id = make_service()
        organization = Organization(
            **_base_fields(
                name="Archived Co",
                slug="archived-co",
                legal_name=None,
                org_type=OrganizationType.STANDARD.value,
                status=OrganizationStatus.ARCHIVED.value,
                parent_organization_id=None,
                contact_email="ops@archived.example.com",
                contact_phone=None,
                timezone="UTC",
                default_locale="en",
                settings={},
                subscription_tier=None,
            )
        )
        fakes.organizations[organization.id] = organization

        with pytest.raises(OrganizationArchivedError):
            await service.preview_provision_location(
                data=_input(
                    existing_organization_id=organization.id, plan_id=base_plan_id
                )
            )

    async def test_preview_rejects_duplicate_new_organization_slug(self) -> None:
        service, fakes, base_plan_id = make_service()
        taken_slug = "taken-slug"
        organization = Organization(
            **_base_fields(
                name="Taken Co",
                slug=taken_slug,
                legal_name=None,
                org_type=OrganizationType.STANDARD.value,
                status=OrganizationStatus.ACTIVE.value,
                parent_organization_id=None,
                contact_email="ops@taken.example.com",
                contact_phone=None,
                timezone="UTC",
                default_locale="en",
                settings={},
                subscription_tier=None,
            )
        )
        fakes.organizations[organization.id] = organization

        with pytest.raises(DuplicateSlugError):
            await service.preview_provision_location(
                data=_input(
                    new_organization=NewOrganizationInput(
                        name="Duplicate Co",
                        slug=taken_slug,
                        contact_email="ops@duplicate.example.com",
                    ),
                    plan_id=base_plan_id,
                )
            )

    async def test_preview_raises_when_owner_role_not_seeded(self) -> None:
        service, fakes, base_plan_id = make_service()
        fakes.roles_by_slug.clear()

        with pytest.raises(OwnerRoleNotSeededError):
            await service.preview_provision_location(
                data=_input(new_organization=_new_org(), plan_id=base_plan_id)
            )

    async def test_preview_raises_when_plan_not_found(self) -> None:
        service, _fakes, _base_plan_id = make_service()

        with pytest.raises(KeyError):
            await service.preview_provision_location(
                data=_input(new_organization=_new_org(), plan_id=uuid.uuid4())
            )


# ============================================================================
# Happy path
# ============================================================================


class TestHappyPath:
    async def test_full_provisioning_flow_composes_every_step(self) -> None:
        service, fakes, base_plan_id = make_service()
        actor_id = uuid.uuid4()

        result = await service.provision_location(
            actor_user_id=actor_id,
            data=_input(new_organization=_new_org(), plan_id=base_plan_id),
        )

        # Every composed step ran, in the documented order (LocationService's
        # own CRUD-lifecycle audit entries -- "location_created" for step b,
        # "location_updated" for step i's settings write -- also appear in
        # this shared call log, since the *same* fake audit writer backs
        # both LocationService and this orchestration; assert relative
        # ordering of the orchestration's own key steps via subsequence
        # containment rather than brittle exact-list equality).
        expected_order = [
            "organization.create",
            "user.create",
            "identity.update_user",
            "router.create",
            "wireguard.create_tunnel",
            "router_provisioning.list_templates",
            "router_provisioning.assign_profile",
            "subscription.create",
            "captive_portal.create_config",
            "audit:location_provisioned",
            "email.send",
        ]
        positions = [fakes.calls.index(step) for step in expected_order]
        assert positions == sorted(positions), f"steps out of order: {fakes.calls}"

        assert result.organization_name == "Grand Plaza Hotel"
        assert result.location_name == "Downtown Branch"
        assert result.location_code.startswith("LOC-")
        assert result.property_type == PropertyType.HOTEL
        assert result.plan_id == base_plan_id
        assert result.owner_username
        assert result.owner_temporary_password
        assert len(result.owner_temporary_password) == 16
        assert result.tunnel_ip_address == "10.100.0.5"
        assert result.feature_summary[PlanFeatureKey.MAX_LOCATIONS.value] == 5.0
        assert result.feature_summary[PlanFeatureKey.ANALYTICS.value] is True

        # must_change_password was really flipped via the identity repository.
        owner = fakes.users_by_id[result.owner_user_id]
        assert owner.must_change_password is True

        # Owner user id was recorded on Location.settings (enables resend).
        location_repository = service.location_service.repository
        location = location_repository.locations[result.location_id]  # type: ignore[attr-defined]
        assert location.settings["owner_user_id"] == str(result.owner_user_id)

        # Welcome email actually composed the real EmailProviderProtocol.
        assert len(fakes.emails_sent) == 1
        to_email, subject, body = fakes.emails_sent[0]
        assert to_email == "priya@example.com"
        assert result.owner_temporary_password in body

        # The temporary password is returned exactly once, in the response
        # only -- never persisted into Location.settings.
        assert "password" not in str(location.settings).lower()

    async def test_captive_portal_login_methods_reuse_resolved_feature_flags(
        self,
    ) -> None:
        service, fakes, base_plan_id = make_service()
        captured: dict[str, object] = {}

        original_create_config = fakes.create_config

        async def _spy_create_config(**fields):
            captured.update(fields)
            return await original_create_config(**fields)

        fakes.create_config = _spy_create_config  # type: ignore[method-assign]

        await service.provision_location(
            actor_user_id=uuid.uuid4(),
            data=_input(new_organization=_new_org(), plan_id=base_plan_id),
        )

        # MOBILE_OTP=True on the plan -> both OTP channels enabled;
        # VOUCHER_LOGIN=False on the plan -> voucher disabled.
        assert captured["otp_sms_enabled"] is True
        assert captured["otp_email_enabled"] is True
        assert captured["voucher_enabled"] is False
        assert captured["is_default"] is False
        assert captured["location_id"] is not None


# ============================================================================
# Existing-vs-new-organization conditional
# ============================================================================


class TestOrganizationConditional:
    async def test_reuses_existing_organization_without_creating_a_new_one(
        self,
    ) -> None:
        service, fakes, base_plan_id = make_service()
        existing = Organization(
            **_base_fields(
                name="Existing Co",
                slug="existing-co",
                legal_name=None,
                org_type=OrganizationType.STANDARD.value,
                status=OrganizationStatus.ACTIVE.value,
                parent_organization_id=None,
                contact_email="existing@example.com",
                contact_phone=None,
                timezone="UTC",
                default_locale="en",
                settings={},
                subscription_tier=None,
            )
        )
        fakes.organizations[existing.id] = existing

        result = await service.provision_location(
            actor_user_id=uuid.uuid4(),
            data=_input(existing_organization_id=existing.id, plan_id=base_plan_id),
        )

        assert "organization.create" not in fakes.calls
        assert result.organization_id == existing.id
        assert result.organization_name == "Existing Co"

    async def test_requires_exactly_one_of_existing_or_new_organization(self) -> None:
        service, _fakes, base_plan_id = make_service()
        data = _input(plan_id=base_plan_id)  # neither existing nor new supplied

        with pytest.raises(NewOrganizationRequiredError):
            await service.provision_location(actor_user_id=uuid.uuid4(), data=data)


# ============================================================================
# Real single-transaction rollback proof
# ============================================================================


class TestTransactionalRollback:
    async def test_forced_failure_rolls_back_and_stops_subsequent_steps(self) -> None:
        """Forces a failure inside step (e) (WireGuard tunnel creation) --
        after Organization/Location/User/Router have already flushed -- and
        proves: (1) no step after (e) ever ran, (2) the shared fake session's
        rollback fired, (3) commit never fired, mirroring
        ``app.database.session.get_db_session``'s real commit-once /
        rollback-on-exception shape exactly (see
        ``run_within_transaction`` above)."""
        service, fakes, base_plan_id = make_service(fail_at="wireguard.create_tunnel")

        with pytest.raises(RuntimeError, match="forced failure"):
            await run_within_transaction(
                fakes.session,
                service.provision_location(
                    actor_user_id=uuid.uuid4(),
                    data=_input(new_organization=_new_org(), plan_id=base_plan_id),
                ),
            )

        # Steps before the failure point ran (and flushed)...
        assert "organization.create" in fakes.calls
        assert "user.create" in fakes.calls
        assert "router.create" in fakes.calls
        assert "location.create" in fakes.session.flushed

        # ...but nothing from or after the failing step ever executed.
        assert "router_provisioning.assign_profile" not in fakes.calls
        assert "subscription.create" not in fakes.calls
        assert "captive_portal.create_config" not in fakes.calls
        assert "email.send" not in fakes.calls
        assert not any(
            call == f"audit:{AuditAction.LOCATION_PROVISIONED.value}"
            for call in fakes.calls
        )

        # The shared session was rolled back, never committed -- the entire
        # point of the single-transaction guarantee.
        assert fakes.session.rolled_back is True
        assert fakes.session.committed is False

    async def test_forced_failure_late_in_the_flow_still_rolls_back_everything(
        self,
    ) -> None:
        """Same proof, but failing at the very last composed step
        (captive portal config) -- confirms rollback discards even a nearly-
        complete flow, not just an early failure."""
        service, fakes, base_plan_id = make_service(
            fail_at="captive_portal.create_config"
        )

        with pytest.raises(RuntimeError, match="forced failure"):
            await run_within_transaction(
                fakes.session,
                service.provision_location(
                    actor_user_id=uuid.uuid4(),
                    data=_input(new_organization=_new_org(), plan_id=base_plan_id),
                ),
            )

        assert "subscription.create" in fakes.calls
        assert "email.send" not in fakes.calls
        # The overall-event audit entry (written last, step k) never fired --
        # LocationService's own earlier CRUD audits (steps b/i) legitimately
        # did, before the forced failure.
        assert not any(
            call == f"audit:{AuditAction.LOCATION_PROVISIONED.value}"
            for call in fakes.calls
        )
        assert fakes.session.rolled_back is True
        assert fakes.session.committed is False

    async def test_successful_flow_commits_exactly_once_and_never_rolls_back(
        self,
    ) -> None:
        service, fakes, base_plan_id = make_service()

        await run_within_transaction(
            fakes.session,
            service.provision_location(
                actor_user_id=uuid.uuid4(),
                data=_input(new_organization=_new_org(), plan_id=base_plan_id),
            ),
        )

        assert fakes.session.committed is True
        assert fakes.session.rolled_back is False


# ============================================================================
# Default router config template resolution / gap
# ============================================================================


class TestDefaultConfigTemplate:
    async def test_uses_explicit_template_id_when_supplied(self) -> None:
        service, fakes, base_plan_id = make_service()
        explicit_template_id = uuid.uuid4()
        data = dataclasses.replace(
            _input(new_organization=_new_org(), plan_id=base_plan_id),
            router_config_template_id=explicit_template_id,
        )

        captured: dict[str, object] = {}
        original_assign_profile = fakes.assign_profile

        async def _spy_assign_profile(**kwargs):
            captured.update(kwargs)
            return await original_assign_profile(**kwargs)

        fakes.assign_profile = _spy_assign_profile  # type: ignore[method-assign]

        await service.provision_location(actor_user_id=uuid.uuid4(), data=data)

        assert captured["template_id"] == explicit_template_id
        # No fallback lookup was needed.
        assert "router_provisioning.list_templates" not in fakes.calls

    async def test_raises_a_clear_error_when_no_default_template_exists(self) -> None:
        service, fakes, base_plan_id = make_service()
        fakes.system_templates.clear()  # simulate the real, honest fixture gap

        with pytest.raises(DefaultConfigTemplateNotFoundError):
            await service.provision_location(
                actor_user_id=uuid.uuid4(),
                data=_input(new_organization=_new_org(), plan_id=base_plan_id),
            )


# ============================================================================
# Billing feature-override / custom-plan cloning
# ============================================================================


class TestFeatureOverrides:
    async def test_no_overrides_subscribes_directly_to_the_base_plan(self) -> None:
        service, fakes, base_plan_id = make_service()

        result = await service.provision_location(
            actor_user_id=uuid.uuid4(),
            data=_input(new_organization=_new_org(), plan_id=base_plan_id),
        )

        assert result.plan_id == base_plan_id
        assert "plan.create_plan" not in fakes.calls

    async def test_overrides_clone_a_private_custom_plan(self) -> None:
        service, fakes, base_plan_id = make_service()
        overrides = (
            FeatureOverride(feature_key=PlanFeatureKey.VOUCHER_LOGIN, is_enabled=True),
            FeatureOverride(
                feature_key=PlanFeatureKey.MAX_LOCATIONS, limit_value=Decimal("25")
            ),
        )

        result = await service.provision_location(
            actor_user_id=uuid.uuid4(),
            data=_input(
                new_organization=_new_org(),
                plan_id=base_plan_id,
                feature_overrides=overrides,
            ),
        )

        assert "plan.create_plan" in fakes.calls
        assert result.plan_id != base_plan_id
        custom_plan = fakes.plans_by_id[result.plan_id]
        assert custom_plan.is_public is False
        assert custom_plan.plan_type == PlanType.CUSTOM.value

        # Overridden values win; untouched base-plan features carry over.
        assert result.feature_summary[PlanFeatureKey.VOUCHER_LOGIN.value] is True
        assert result.feature_summary[PlanFeatureKey.MAX_LOCATIONS.value] == 25.0
        # Untouched base-plan feature carried over unchanged.
        assert result.feature_summary[PlanFeatureKey.ANALYTICS.value] is True


# ============================================================================
# location_code generator: format + collision safety
# ============================================================================


class TestLocationCodeGenerator:
    async def test_format_and_year_based_sequence(self) -> None:
        session = FakeSharedSession()
        counter = FakeLocationCodeCounterRepository(session=session)
        at = datetime(2026, 1, 1, tzinfo=UTC)

        first = await generate_location_code(counter, at=at)
        second = await generate_location_code(counter, at=at)

        assert first == "LOC-2026-000001"
        assert second == "LOC-2026-000002"

    async def test_concurrent_callers_never_collide(self) -> None:
        """Mirrors ``billing``'s own concurrency-test rigor for its
        identical counter mechanism: many concurrent ``asyncio`` callers
        against the same in-memory counter must never receive the same
        sequence number -- the same guarantee the real atomic Postgres
        ``INSERT ... ON CONFLICT DO UPDATE ... RETURNING`` statement
        provides at the database level (see ``number_generator.py``'s
        module docstring)."""
        session = FakeSharedSession()
        counter = FakeLocationCodeCounterRepository(session=session)
        at = datetime(2026, 1, 1, tzinfo=UTC)

        codes = await asyncio.gather(
            *(generate_location_code(counter, at=at) for _ in range(50))
        )

        assert len(set(codes)) == 50  # every code is unique, no collisions


# ============================================================================
# Owner role / owner-not-provisioned edge cases
# ============================================================================


class TestOwnerRoleAndResend:
    async def test_resend_welcome_email_does_not_include_a_password(self) -> None:
        service, fakes, base_plan_id = make_service()
        result = await service.provision_location(
            actor_user_id=uuid.uuid4(),
            data=_input(new_organization=_new_org(), plan_id=base_plan_id),
        )
        fakes.emails_sent.clear()

        location, owner_email = await service.resend_welcome_email(
            location_id=result.location_id
        )

        assert owner_email == "priya@example.com"
        assert len(fakes.emails_sent) == 1
        _to, _subject, body = fakes.emails_sent[0]
        assert result.owner_temporary_password not in body
        assert any(
            call == f"audit:{AuditAction.LOCATION_WELCOME_EMAIL_SENT.value}"
            for call in fakes.calls
        )

    async def test_resend_welcome_email_raises_if_location_never_provisioned(
        self,
    ) -> None:
        service, fakes, _base_plan_id = make_service()
        # A location created without ever going through provision_location
        # (no owner_user_id in settings).
        organization = Organization(
            **_base_fields(
                name="Org",
                slug="org",
                legal_name=None,
                org_type=OrganizationType.STANDARD.value,
                status=OrganizationStatus.ACTIVE.value,
                parent_organization_id=None,
                contact_email="a@example.com",
                contact_phone=None,
                timezone="UTC",
                default_locale="en",
                settings={},
                subscription_tier=None,
            )
        )
        fakes.organizations[organization.id] = organization
        location = await service.location_service.create_location(
            actor_user_id=uuid.uuid4(),
            organization_id=organization.id,
            requesting_organization_id=None,
            name="Bare Location",
            slug="bare-location",
            address_line1="1 St",
            city="City",
            state_province="ST",
            postal_code="00000",
            country="US",
        )

        with pytest.raises(OwnerNotProvisionedError):
            await service.resend_welcome_email(location_id=location.id)


# ============================================================================
# Generation helpers
# ============================================================================


class TestGenerationHelpers:
    def test_generated_temporary_passwords_contain_every_character_class(self) -> None:
        import string

        for _ in range(25):
            password = _generate_temporary_password()
            assert len(password) == 16
            assert any(c.isupper() for c in password)
            assert any(c.islower() for c in password)
            assert any(c.isdigit() for c in password)
            assert any(c in "!@#$%^&*()-_=+" for c in password)
            allowed = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
            assert all(c in allowed for c in password)

    def test_generated_passwords_are_not_all_identical(self) -> None:
        passwords = {_generate_temporary_password() for _ in range(25)}
        assert len(passwords) == 25  # vanishingly unlikely to collide

    def test_generated_username_derives_from_email_local_part(self) -> None:
        username = _generate_username("Priya.Shah+hotel@Example.com")
        assert username.startswith("priyashahhotel.")
        assert len(username) > len("priyashahhotel.")


# ============================================================================
# Super-Admin / GLOBAL-scope-only gating
# ============================================================================


class TestSuperAdminGating:
    def test_only_super_admin_and_platform_admin_hold_locations_manage_at_global(
        self,
    ) -> None:
        """Regression test for the exact claim documented in
        ``app.domains.location.router``'s module docstring for
        ``POST /locations/provision``: with the endpoint gated by
        ``RequirePermission("locations.manage", scope=ScopeType.GLOBAL)``,
        only roles seeded with a GLOBAL scope_type AND a non-NONE grant for
        the LOCATIONS module's MANAGE action can ever pass that check."""
        qualifying_roles = set()
        for role_def in SYSTEM_ROLES:
            if role_def.scope_type.value != "global":
                continue
            grants = role_def.grants()
            locations_grant = grants.get(_M.LOCATIONS, ())
            locations_actions = {action.value for action in locations_grant}
            if "manage" in locations_actions:
                qualifying_roles.add(role_def.slug)

        assert qualifying_roles == {"platform-admin", "super-admin"}


# ============================================================================
# must_change_password auth enforcement (real, minimal, additive check)
# ============================================================================


class TestMustChangePasswordEnforcement:
    async def test_login_raises_when_must_change_password_is_set(self) -> None:
        from tests.unit.test_auth import (  # local import: reuse existing auth fakes
            FakeAuthRepository,
            FakeRedis,
            make_device_info,
        )

        repository = FakeAuthRepository()
        user = await repository.create_user(
            first_name="Priya",
            last_name="Shah",
            email="priya@example.com",
            username="priya",
            password_hash=_hash("Sup3rSecret!123"),
            is_active=True,
            is_verified=True,
            must_change_password=True,
        )
        service = AuthService(repository, FakeRedis())

        with pytest.raises(PasswordChangeRequiredError):
            await service.login(
                "priya@example.com", "Sup3rSecret!123", make_device_info()
            )

        assert user.must_change_password is True  # untouched by the raise itself


def _hash(password: str) -> str:
    from app.domains.auth.password import PasswordManager

    return PasswordManager.hash(password)
