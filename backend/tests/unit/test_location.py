"""Unit tests for the Location domain: site CRUD, slug uniqueness within an
organization, organization-must-exist-and-not-be-archived validation,
organization_id immutability after creation, lifecycle (suspend/activate/
archive), tenant scoping (platform vs. org-scoped vs. MSP-child access), and
the RBAC ``location_id`` FK follow-up (confirmed via the RBAC test suite
itself still passing, plus a direct check here that the FK/column wiring is
sane).

Follows this project's plain-``assert`` / native-``async def`` style (see
``tests/unit/test_organization.py``, ``tests/unit/test_rbac.py``);
``asyncio_mode = "auto"`` runs async tests directly. Exercises
``LocationService`` against small in-memory fake repository/organization-
lookup/audit-writer, mirroring ``FakeOrganizationRepository``, since there is
no live Postgres/Redis in this environment.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.location.enums import LocationStatus
from app.domains.location.exceptions import (
    CrossOrganizationLocationAccessError,
    DuplicateLocationSlugError,
    LocationArchivedError,
    LocationNotFoundError,
)
from app.domains.location.models import Location
from app.domains.location.service import LocationService
from app.domains.organization.enums import OrganizationType
from app.domains.organization.exceptions import (
    OrganizationArchivedError,
    OrganizationNotFoundError,
)
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
    """In-memory stand-in for the ``AuditLogWriter`` protocol, mirroring
    ``test_organization.py``'s own fake."""

    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> dict[str, object]:
        self.entries.append(fields)
        return fields


@dataclass
class FakeOrganizationLookup:
    """In-memory stand-in for ``LocationService``'s
    ``OrganizationLookupProtocol`` -- deliberately independent of
    ``OrganizationService``/``FakeOrganizationRepository`` so this test file
    has no hard dependency on the organization test module, while still
    exercising the exact duck-typed contract ``LocationService`` composes
    with."""

    organizations: dict[uuid.UUID, Organization] = field(default_factory=dict)

    async def get_organization(
        self, organization_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Organization:
        organization = self.organizations.get(organization_id)
        if organization is None or (organization.is_deleted and not include_deleted):
            raise OrganizationNotFoundError(organization_id)
        return organization

    def add(
        self,
        *,
        status: str = "active",
        org_type: str = OrganizationType.STANDARD.value,
        parent_organization_id: uuid.UUID | None = None,
    ) -> Organization:
        organization = Organization(
            **_base_fields(
                name="Org",
                slug=f"org-{uuid.uuid4()}",
                legal_name=None,
                org_type=org_type,
                status=status,
                parent_organization_id=parent_organization_id,
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
class FakeLocationRepository:
    """In-memory stand-in for :class:`LocationRepositoryProtocol`."""

    locations: dict[uuid.UUID, Location] = field(default_factory=dict)

    async def get_by_id(
        self, location_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Location | None:
        location = self.locations.get(location_id)
        if location is None:
            return None
        if location.is_deleted and not include_deleted:
            return None
        return location

    async def get_by_slug(
        self, organization_id: uuid.UUID, slug: str
    ) -> Location | None:
        return next(
            (
                loc
                for loc in self.locations.values()
                if loc.organization_id == organization_id
                and loc.slug == slug
                and not loc.is_deleted
            ),
            None,
        )

    async def create_location(self, **fields: object) -> Location:
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
        return location

    async def update_location(
        self, location: Location, data: dict[str, object]
    ) -> Location:
        for key, value in data.items():
            if hasattr(location, key):
                setattr(location, key, value)
        location.version += 1
        return location

    async def soft_delete_location(self, location: Location) -> Location:
        location.is_deleted = True
        location.deleted_at = _now()
        return location

    async def list_locations(
        self,
        *,
        organization_id: uuid.UUID,
        page: int,
        page_size: int,
        search: str | None = None,
        status: str | None = None,
    ) -> tuple[list[Location], PaginationMeta]:
        values = [
            loc
            for loc in self.locations.values()
            if loc.organization_id == organization_id and not loc.is_deleted
        ]
        if status is not None:
            values = [loc for loc in values if loc.status == status]
        if search:
            lowered = search.lower()
            values = [
                loc
                for loc in values
                if lowered in loc.name.lower()
                or lowered in loc.slug.lower()
                or lowered in loc.city.lower()
            ]
        values.sort(key=lambda loc: loc.created_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))


def make_service(
    repo: FakeLocationRepository | None = None,
    org_lookup: FakeOrganizationLookup | None = None,
) -> tuple[
    LocationService, FakeLocationRepository, FakeOrganizationLookup, FakeAuditLogWriter
]:
    repository = repo or FakeLocationRepository()
    organization_lookup = org_lookup or FakeOrganizationLookup()
    audit_writer = FakeAuditLogWriter()
    return (
        LocationService(repository, organization_lookup, audit_writer=audit_writer),
        repository,
        organization_lookup,
        audit_writer,
    )


async def make_location(
    repo: FakeLocationRepository,
    *,
    organization_id: uuid.UUID,
    name: str = "Downtown Branch",
    slug: str | None = None,
    status: LocationStatus = LocationStatus.ACTIVE,
) -> Location:
    return await repo.create_location(
        organization_id=organization_id,
        name=name,
        slug=slug or name.lower().replace(" ", "-"),
        status=status.value,
        address_line1="123 Main St",
        city="Austin",
        state_province="TX",
        postal_code="78701",
        country="US",
        timezone="UTC",
    )


def _create_kwargs(**overrides: object) -> dict[str, object]:
    base = {
        "name": "Downtown Branch",
        "slug": "downtown-branch",
        "address_line1": "123 Main St",
        "city": "Austin",
        "state_province": "TX",
        "postal_code": "78701",
        "country": "us",
    }
    base.update(overrides)
    return base


# ============================================================================
# Location CRUD
# ============================================================================


class TestLocationCRUD:
    async def test_create_location_success(self) -> None:
        service, _repo, org_lookup, audit = make_service()
        organization = org_lookup.add()

        location = await service.create_location(
            actor_user_id=uuid.uuid4(),
            organization_id=organization.id,
            requesting_organization_id=None,
            **_create_kwargs(
                slug="Downtown-Branch", contact_email="Site@Acme.example.com"
            ),
        )

        assert location.name == "Downtown Branch"
        assert location.slug == "downtown-branch"
        assert location.country == "US"
        assert location.contact_email == "site@acme.example.com"
        assert location.status == LocationStatus.ACTIVE.value
        assert location.organization_id == organization.id
        assert any(e["action"] == "location_created" for e in audit.entries)

    async def test_create_location_rejects_duplicate_slug_in_same_org(self) -> None:
        service, _repo, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        await service.create_location(
            actor_user_id=uuid.uuid4(),
            organization_id=organization.id,
            requesting_organization_id=None,
            **_create_kwargs(),
        )

        with pytest.raises(DuplicateLocationSlugError):
            await service.create_location(
                actor_user_id=uuid.uuid4(),
                organization_id=organization.id,
                requesting_organization_id=None,
                **_create_kwargs(name="Downtown Branch Again"),
            )

    async def test_create_location_allows_same_slug_in_different_orgs(self) -> None:
        service, _repo, org_lookup, _audit = make_service()
        org_a = org_lookup.add()
        org_b = org_lookup.add()
        await service.create_location(
            actor_user_id=uuid.uuid4(),
            organization_id=org_a.id,
            requesting_organization_id=None,
            **_create_kwargs(),
        )

        location_b = await service.create_location(
            actor_user_id=uuid.uuid4(),
            organization_id=org_b.id,
            requesting_organization_id=None,
            **_create_kwargs(),
        )

        assert location_b.slug == "downtown-branch"
        assert location_b.organization_id == org_b.id

    async def test_create_location_under_nonexistent_organization_raises(self) -> None:
        service, _repo, _org_lookup, _audit = make_service()

        with pytest.raises(OrganizationNotFoundError):
            await service.create_location(
                actor_user_id=uuid.uuid4(),
                organization_id=uuid.uuid4(),
                requesting_organization_id=None,
                **_create_kwargs(),
            )

    async def test_create_location_under_archived_organization_raises(self) -> None:
        service, _repo, org_lookup, _audit = make_service()
        organization = org_lookup.add(status="archived")

        with pytest.raises(OrganizationArchivedError):
            await service.create_location(
                actor_user_id=uuid.uuid4(),
                organization_id=organization.id,
                requesting_organization_id=None,
                **_create_kwargs(),
            )

    async def test_get_location_not_found_raises(self) -> None:
        service, _repo, _org_lookup, _audit = make_service()
        with pytest.raises(LocationNotFoundError):
            await service.get_location(uuid.uuid4())

    async def test_get_by_slug_normalizes_case(self) -> None:
        service, repo, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        await make_location(repo, organization_id=organization.id)

        location = await service.get_by_slug(organization.id, "DOWNTOWN-BRANCH")

        assert location.name == "Downtown Branch"

    async def test_update_location_renames_and_audits(self) -> None:
        service, repo, org_lookup, audit = make_service()
        organization = org_lookup.add()
        location = await make_location(repo, organization_id=organization.id)

        updated = await service.update_location(
            actor_user_id=uuid.uuid4(),
            location_id=location.id,
            requesting_organization_id=None,
            data={"name": "Downtown Branch Renamed"},
        )

        assert updated.name == "Downtown Branch Renamed"
        assert any(e["action"] == "location_updated" for e in audit.entries)

    async def test_update_location_rejects_duplicate_slug_within_org(self) -> None:
        service, repo, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        await make_location(repo, organization_id=organization.id, name="Branch A")
        other = await make_location(
            repo, organization_id=organization.id, name="Branch B"
        )

        with pytest.raises(DuplicateLocationSlugError):
            await service.update_location(
                actor_user_id=uuid.uuid4(),
                location_id=other.id,
                requesting_organization_id=None,
                data={"slug": "branch-a"},
            )

    async def test_update_location_ignores_organization_id_if_present(self) -> None:
        """``organization_id`` is immutable after creation -- the schema
        layer never exposes it, but the service defensively strips it if a
        caller constructs ``data`` by hand, so behavior can never silently
        diverge from the documented immutability decision."""
        service, repo, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        other_organization = org_lookup.add()
        location = await make_location(repo, organization_id=organization.id)

        updated = await service.update_location(
            actor_user_id=uuid.uuid4(),
            location_id=location.id,
            requesting_organization_id=None,
            data={"organization_id": other_organization.id, "name": "Still Same Org"},
        )

        assert updated.organization_id == organization.id
        assert updated.name == "Still Same Org"

    async def test_update_archived_location_raises(self) -> None:
        service, repo, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        location = await make_location(
            repo, organization_id=organization.id, status=LocationStatus.ARCHIVED
        )

        with pytest.raises(LocationArchivedError):
            await service.update_location(
                actor_user_id=uuid.uuid4(),
                location_id=location.id,
                requesting_organization_id=None,
                data={"name": "New Name"},
            )

    async def test_archive_location_soft_deletes_and_sets_status(self) -> None:
        service, repo, org_lookup, audit = make_service()
        organization = org_lookup.add()
        location = await make_location(repo, organization_id=organization.id)

        archived = await service.archive_location(
            actor_user_id=uuid.uuid4(),
            location_id=location.id,
            requesting_organization_id=None,
        )

        assert archived.status == LocationStatus.ARCHIVED.value
        assert archived.is_deleted is True
        assert any(e["action"] == "location_archived" for e in audit.entries)

    async def test_suspend_and_activate_location(self) -> None:
        service, repo, org_lookup, audit = make_service()
        organization = org_lookup.add()
        location = await make_location(repo, organization_id=organization.id)

        suspended = await service.suspend_location(
            actor_user_id=uuid.uuid4(),
            location_id=location.id,
            requesting_organization_id=None,
        )
        assert suspended.status == LocationStatus.SUSPENDED.value

        activated = await service.activate_location(
            actor_user_id=uuid.uuid4(),
            location_id=location.id,
            requesting_organization_id=None,
        )
        assert activated.status == LocationStatus.ACTIVE.value
        assert any(e["action"] == "location_suspended" for e in audit.entries)
        assert any(e["action"] == "location_activated" for e in audit.entries)

    async def test_list_locations_within_organization(self) -> None:
        service, repo, org_lookup, _audit = make_service()
        org_a = org_lookup.add()
        org_b = org_lookup.add()
        await make_location(repo, organization_id=org_a.id, name="A1")
        await make_location(repo, organization_id=org_a.id, name="A2")
        await make_location(repo, organization_id=org_b.id, name="B1")

        locations, meta = await service.list_locations(
            organization_id=org_a.id, requesting_organization_id=None
        )

        assert meta.total_items == 2
        assert {loc.name for loc in locations} == {"A1", "A2"}


# ============================================================================
# Tenant scoping (list/read/write access)
# ============================================================================


class TestLocationTenantScoping:
    async def test_platform_scope_can_access_any_location(self) -> None:
        service, repo, org_lookup, _audit = make_service()
        organization = org_lookup.add()
        location = await make_location(repo, organization_id=organization.id)

        fetched = await service.get_location(
            location.id, requesting_organization_id=None
        )

        assert fetched.id == location.id

    async def test_org_scoped_caller_cannot_access_other_orgs_location(self) -> None:
        service, repo, org_lookup, _audit = make_service()
        org_a = org_lookup.add()
        org_b = org_lookup.add()
        location_b = await make_location(repo, organization_id=org_b.id)

        with pytest.raises(CrossOrganizationLocationAccessError):
            await service.get_location(
                location_b.id, requesting_organization_id=org_a.id
            )

    async def test_msp_can_access_its_childs_location(self) -> None:
        service, repo, org_lookup, _audit = make_service()
        msp = org_lookup.add(org_type=OrganizationType.MSP.value)
        child = org_lookup.add(parent_organization_id=msp.id)
        location = await make_location(repo, organization_id=child.id)

        fetched = await service.get_location(
            location.id, requesting_organization_id=msp.id
        )

        assert fetched.id == location.id

    async def test_create_location_outside_scope_raises(self) -> None:
        service, _repo, org_lookup, _audit = make_service()
        org_a = org_lookup.add()
        org_b = org_lookup.add()

        with pytest.raises(CrossOrganizationLocationAccessError):
            await service.create_location(
                actor_user_id=uuid.uuid4(),
                organization_id=org_b.id,
                requesting_organization_id=org_a.id,
                **_create_kwargs(),
            )

    async def test_list_locations_outside_scope_raises(self) -> None:
        service, _repo, org_lookup, _audit = make_service()
        org_a = org_lookup.add()
        org_b = org_lookup.add()

        with pytest.raises(CrossOrganizationLocationAccessError):
            await service.list_locations(
                organization_id=org_b.id, requesting_organization_id=org_a.id
            )


# ============================================================================
# RBAC location_id FK follow-up (models-level sanity, not the FK itself since
# SQLite/no-DB unit tests can't exercise a real Postgres constraint -- the FK
# constraint itself is exercised by running the full RBAC suite, confirmed
# unaffected by this change).
# ============================================================================


class TestRbacLocationFkFollowUp:
    def test_rbac_models_declare_location_fk(self) -> None:
        from app.domains.rbac.models import (
            AuditLogEntry,
            LocationRole,
            PermissionOverride,
            UserRole,
        )

        for model in (UserRole, PermissionOverride, LocationRole, AuditLogEntry):
            column = model.__table__.columns["location_id"]
            assert len(column.foreign_keys) == 1
            foreign_key = next(iter(column.foreign_keys))
            assert foreign_key.target_fullname == "locations.id"

    def test_location_role_location_id_still_not_nullable(self) -> None:
        from app.domains.rbac.models import LocationRole

        assert LocationRole.__table__.columns["location_id"].nullable is False

    def test_router_id_columns_remain_fk_less(self) -> None:
        from app.domains.rbac.models import PermissionOverride, UserRole

        for model in (UserRole, PermissionOverride):
            column = model.__table__.columns["router_id"]
            assert len(column.foreign_keys) == 0
