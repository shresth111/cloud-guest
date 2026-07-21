"""Unit tests for the Organization domain: tenant CRUD, slug uniqueness, MSP
hierarchy validation (child creation, circular-parent prevention, non-MSP-
cannot-have-children), membership lifecycle (invite/accept/remove, duplicate-
membership prevention, last-active-member protection), and the RBAC
``organization_id`` FK follow-up (confirmed via the RBAC test suite itself
still passing, plus a direct check here that the FK/column wiring is sane).

Follows this project's plain-``assert`` / native-``async def`` style (see
``tests/unit/test_auth.py``, ``tests/unit/test_rbac.py``); ``asyncio_mode =
"auto"`` runs async tests directly. Exercises ``OrganizationService`` against
a small in-memory fake repository/audit-writer, mirroring
``FakeRBACRepository``, since there is no live Postgres/Redis in this
environment.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.organization.enums import (
    MembershipStatus,
    OrganizationStatus,
    OrganizationType,
)
from app.domains.organization.exceptions import (
    CircularOrganizationHierarchyError,
    CrossOrganizationAccessError,
    DuplicateMembershipError,
    DuplicateSlugError,
    InvalidBrandingFieldError,
    InvalidMembershipStatusTransitionError,
    LastActiveMemberError,
    MembershipSuspendedError,
    MspDowngradeWithChildrenError,
    NotAnMspOrganizationError,
    OrganizationArchivedError,
    OrganizationMembershipNotFoundError,
    OrganizationNotFoundError,
)
from app.domains.organization.models import Organization, OrganizationMember
from app.domains.organization.service import OrganizationService

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
    ``FakeRBACRepository.audit_log_rows`` from ``test_rbac.py``."""

    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> dict[str, object]:
        self.entries.append(fields)
        return fields


@dataclass
class FakeOrganizationRepository:
    """In-memory stand-in for :class:`OrganizationRepositoryProtocol`."""

    organizations: dict[uuid.UUID, Organization] = field(default_factory=dict)
    member_rows: list[OrganizationMember] = field(default_factory=list)

    # -- organizations -------------------------------------------------------

    async def get_by_id(
        self, organization_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Organization | None:
        organization = self.organizations.get(organization_id)
        if organization is None:
            return None
        if organization.is_deleted and not include_deleted:
            return None
        return organization

    async def get_by_slug(self, slug: str) -> Organization | None:
        return next(
            (
                org
                for org in self.organizations.values()
                if org.slug == slug and not org.is_deleted
            ),
            None,
        )

    async def create_organization(self, **fields: object) -> Organization:
        defaults = {
            "legal_name": None,
            "contact_phone": None,
            "settings": {},
            "subscription_tier": None,
            "parent_organization_id": None,
        }
        organization = Organization(**_base_fields(**{**defaults, **fields}))
        self.organizations[organization.id] = organization
        return organization

    async def update_organization(
        self, organization: Organization, data: dict[str, object]
    ) -> Organization:
        for key, value in data.items():
            if hasattr(organization, key):
                setattr(organization, key, value)
        organization.version += 1
        return organization

    async def soft_delete_organization(
        self, organization: Organization
    ) -> Organization:
        organization.is_deleted = True
        organization.deleted_at = _now()
        return organization

    async def list_organizations(
        self,
        *,
        page: int,
        page_size: int,
        search: str | None = None,
        status: str | None = None,
        org_type: str | None = None,
        scope_organization_id: uuid.UUID | None = None,
    ) -> tuple[list[Organization], PaginationMeta]:
        values = [org for org in self.organizations.values() if not org.is_deleted]
        if status is not None:
            values = [org for org in values if org.status == status]
        if org_type is not None:
            values = [org for org in values if org.org_type == org_type]
        if search:
            lowered = search.lower()
            values = [
                org
                for org in values
                if lowered in org.name.lower() or lowered in org.slug.lower()
            ]
        if scope_organization_id is not None:
            values = [
                org
                for org in values
                if org.id == scope_organization_id
                or org.parent_organization_id == scope_organization_id
            ]
        values.sort(key=lambda org: org.created_at, reverse=True)
        params = PageParams(page=page, page_size=page_size)
        paged = values[params.offset : params.offset + params.page_size]
        return paged, PaginationMeta.from_total(params, len(values))

    async def list_children(
        self, parent_organization_id: uuid.UUID
    ) -> list[Organization]:
        return [
            org
            for org in self.organizations.values()
            if org.parent_organization_id == parent_organization_id
            and not org.is_deleted
        ]

    async def get_parent_chain(
        self, organization_id: uuid.UUID, *, max_depth: int
    ) -> list[Organization]:
        chain: list[Organization] = []
        seen = {organization_id}
        current = self.organizations.get(organization_id)
        depth = 0
        while (
            current is not None and current.parent_organization_id and depth < max_depth
        ):
            parent = self.organizations.get(current.parent_organization_id)
            if parent is None or parent.id in seen:
                break
            chain.append(parent)
            seen.add(parent.id)
            current = parent
            depth += 1
        return chain

    # -- membership ------------------------------------------------------------

    async def get_membership(
        self, organization_id: uuid.UUID, user_id: uuid.UUID
    ) -> OrganizationMember | None:
        matches = [
            row
            for row in self.member_rows
            if row.organization_id == organization_id and row.user_id == user_id
        ]
        matches.sort(key=lambda row: row.created_at, reverse=True)
        return matches[0] if matches else None

    async def get_membership_by_id(
        self, member_id: uuid.UUID
    ) -> OrganizationMember | None:
        return next((row for row in self.member_rows if row.id == member_id), None)

    async def list_members(
        self, organization_id: uuid.UUID, *, status: str | None = None
    ) -> list[OrganizationMember]:
        rows = [
            row for row in self.member_rows if row.organization_id == organization_id
        ]
        if status is not None:
            rows = [row for row in rows if row.status == status]
        return rows

    async def list_user_memberships(
        self, user_id: uuid.UUID, *, status: str | None = None
    ) -> list[OrganizationMember]:
        rows = [row for row in self.member_rows if row.user_id == user_id]
        if status is not None:
            rows = [row for row in rows if row.status == status]
        return rows

    async def count_active_members(self, organization_id: uuid.UUID) -> int:
        return len(
            [
                row
                for row in self.member_rows
                if row.organization_id == organization_id
                and row.status == MembershipStatus.ACTIVE.value
            ]
        )

    async def create_membership(self, **fields: object) -> OrganizationMember:
        defaults = {
            "invited_by_user_id": None,
            "joined_at": None,
            "is_primary_contact": False,
        }
        row = OrganizationMember(**_base_fields(**{**defaults, **fields}))
        self.member_rows.append(row)
        return row

    async def update_membership(
        self, member: OrganizationMember, data: dict[str, object]
    ) -> OrganizationMember:
        for key, value in data.items():
            if hasattr(member, key):
                setattr(member, key, value)
        member.version += 1
        return member


def make_service(
    repo: FakeOrganizationRepository | None = None,
) -> tuple[OrganizationService, FakeOrganizationRepository, FakeAuditLogWriter]:
    repository = repo or FakeOrganizationRepository()
    audit_writer = FakeAuditLogWriter()
    return (
        OrganizationService(repository, audit_writer=audit_writer),
        repository,
        audit_writer,
    )


async def make_organization(
    repo: FakeOrganizationRepository,
    name: str,
    *,
    org_type: OrganizationType = OrganizationType.STANDARD,
    status: OrganizationStatus = OrganizationStatus.ACTIVE,
    parent_organization_id: uuid.UUID | None = None,
) -> Organization:
    return await repo.create_organization(
        name=name,
        slug=name.lower().replace(" ", "-"),
        org_type=org_type.value,
        status=status.value,
        parent_organization_id=parent_organization_id,
        contact_email=f"{name.lower().replace(' ', '')}@example.com",
        timezone="UTC",
        default_locale="en",
    )


async def make_active_member(
    repo: FakeOrganizationRepository,
    *,
    organization_id: uuid.UUID,
    user_id: uuid.UUID,
    is_primary_contact: bool = False,
) -> OrganizationMember:
    return await repo.create_membership(
        organization_id=organization_id,
        user_id=user_id,
        status=MembershipStatus.ACTIVE.value,
        invited_by_user_id=None,
        invited_at=_now(),
        joined_at=_now(),
        is_primary_contact=is_primary_contact,
    )


# ============================================================================
# Org-wide product branding (Enterprise SaaS Phase B, White Label)
# ============================================================================


class TestOrganizationBranding:
    async def test_get_branding_defaults_to_empty(self) -> None:
        service, repo, _ = make_service()
        org = await make_organization(repo, "Acme")

        branding = await service.get_branding(org.id)

        assert branding == {}

    async def test_update_branding_persists_under_settings(self) -> None:
        service, repo, audit_writer = make_service()
        org = await make_organization(repo, "Acme")

        branding = await service.update_branding(
            org.id,
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=None,
            data={"app_name": "Acme Guest WiFi", "support_email": "Help@Acme.com"},
        )

        assert branding["app_name"] == "Acme Guest WiFi"
        assert branding["support_email"] == "help@acme.com"
        assert org.settings["branding"]["app_name"] == "Acme Guest WiFi"
        assert len(audit_writer.entries) == 1

    async def test_update_branding_merges_rather_than_replaces(self) -> None:
        service, repo, _ = make_service()
        org = await make_organization(repo, "Acme")
        await service.update_branding(
            org.id,
            actor_user_id=None,
            requesting_organization_id=None,
            data={"app_name": "Acme Guest WiFi"},
        )

        branding = await service.update_branding(
            org.id,
            actor_user_id=None,
            requesting_organization_id=None,
            data={"support_email": "help@acme.com"},
        )

        assert branding["app_name"] == "Acme Guest WiFi"
        assert branding["support_email"] == "help@acme.com"

    async def test_update_branding_rejects_invalid_custom_domain(self) -> None:
        service, repo, _ = make_service()
        org = await make_organization(repo, "Acme")

        with pytest.raises(InvalidBrandingFieldError):
            await service.update_branding(
                org.id,
                actor_user_id=None,
                requesting_organization_id=None,
                data={"custom_domain": "not a domain"},
            )

    async def test_update_branding_accepts_valid_custom_domain(self) -> None:
        service, repo, _ = make_service()
        org = await make_organization(repo, "Acme")

        branding = await service.update_branding(
            org.id,
            actor_user_id=None,
            requesting_organization_id=None,
            data={"custom_domain": "Guest.Acme.example.COM"},
        )

        assert branding["custom_domain"] == "guest.acme.example.com"

    async def test_update_branding_rejects_archived_organization(self) -> None:
        service, repo, _ = make_service()
        org = await make_organization(
            repo, "Acme", status=OrganizationStatus.ARCHIVED
        )

        with pytest.raises(OrganizationArchivedError):
            await service.update_branding(
                org.id,
                actor_user_id=None,
                requesting_organization_id=None,
                data={"app_name": "New Name"},
            )

    async def test_branding_enforces_cross_organization_access(self) -> None:
        service, repo, _ = make_service()
        org = await make_organization(repo, "Acme")

        with pytest.raises(CrossOrganizationAccessError):
            await service.get_branding(
                org.id, requesting_organization_id=uuid.uuid4()
            )


# ============================================================================
# Organization CRUD
# ============================================================================


class TestOrganizationCRUD:
    async def test_create_organization_success(self) -> None:
        service, _repo, audit = make_service()
        actor_id = uuid.uuid4()

        organization = await service.create_organization(
            actor_user_id=actor_id,
            name="Acme Corp",
            slug="Acme-Corp",
            contact_email="Admin@ACME.example.com",
        )

        assert organization.name == "Acme Corp"
        # slug and email are normalized (lowercased)
        assert organization.slug == "acme-corp"
        assert organization.contact_email == "admin@acme.example.com"
        assert organization.org_type == OrganizationType.STANDARD.value
        assert organization.status == OrganizationStatus.ACTIVE.value
        assert any(e["action"] == "organization_created" for e in audit.entries)

    async def test_create_organization_rejects_duplicate_slug(self) -> None:
        service, _repo, _audit = make_service()
        await service.create_organization(
            actor_user_id=uuid.uuid4(),
            name="Acme Corp",
            slug="acme-corp",
            contact_email="admin@acme.example.com",
        )

        with pytest.raises(DuplicateSlugError):
            await service.create_organization(
                actor_user_id=uuid.uuid4(),
                name="Acme Corp Again",
                slug="acme-corp",
                contact_email="other@acme.example.com",
            )

    async def test_get_organization_not_found_raises(self) -> None:
        service, _repo, _audit = make_service()
        with pytest.raises(OrganizationNotFoundError):
            await service.get_organization(uuid.uuid4())

    async def test_get_by_slug_normalizes_case(self) -> None:
        service, _repo, _audit = make_service()
        await service.create_organization(
            actor_user_id=uuid.uuid4(),
            name="Acme Corp",
            slug="acme-corp",
            contact_email="admin@acme.example.com",
        )

        organization = await service.get_by_slug("ACME-CORP")

        assert organization.name == "Acme Corp"

    async def test_update_organization_renames_and_audits(self) -> None:
        service, repo, audit = make_service()
        organization = await make_organization(repo, "Acme Corp")

        updated = await service.update_organization(
            actor_user_id=uuid.uuid4(),
            organization_id=organization.id,
            requesting_organization_id=None,
            data={"name": "Acme Corporation"},
        )

        assert updated.name == "Acme Corporation"
        assert any(e["action"] == "organization_updated" for e in audit.entries)

    async def test_update_organization_rejects_duplicate_slug(self) -> None:
        service, repo, _audit = make_service()
        await make_organization(repo, "Acme Corp")
        other = await make_organization(repo, "Globex")

        with pytest.raises(DuplicateSlugError):
            await service.update_organization(
                actor_user_id=uuid.uuid4(),
                organization_id=other.id,
                requesting_organization_id=None,
                data={"slug": "acme-corp"},
            )

    async def test_update_archived_organization_raises(self) -> None:
        service, repo, _audit = make_service()
        organization = await make_organization(
            repo, "Acme Corp", status=OrganizationStatus.ARCHIVED
        )

        with pytest.raises(OrganizationArchivedError):
            await service.update_organization(
                actor_user_id=uuid.uuid4(),
                organization_id=organization.id,
                requesting_organization_id=None,
                data={"name": "New Name"},
            )

    async def test_archive_organization_soft_deletes_and_sets_status(self) -> None:
        service, repo, audit = make_service()
        organization = await make_organization(repo, "Acme Corp")

        archived = await service.archive_organization(
            actor_user_id=uuid.uuid4(),
            organization_id=organization.id,
            requesting_organization_id=None,
        )

        assert archived.status == OrganizationStatus.ARCHIVED.value
        assert archived.is_deleted is True
        assert any(e["action"] == "organization_archived" for e in audit.entries)

    async def test_suspend_and_activate_organization(self) -> None:
        service, repo, audit = make_service()
        organization = await make_organization(repo, "Acme Corp")

        suspended = await service.suspend_organization(
            actor_user_id=uuid.uuid4(),
            organization_id=organization.id,
            requesting_organization_id=None,
        )
        assert suspended.status == OrganizationStatus.SUSPENDED.value

        activated = await service.activate_organization(
            actor_user_id=uuid.uuid4(),
            organization_id=organization.id,
            requesting_organization_id=None,
        )
        assert activated.status == OrganizationStatus.ACTIVE.value
        assert any(e["action"] == "organization_suspended" for e in audit.entries)
        assert any(e["action"] == "organization_activated" for e in audit.entries)


# ============================================================================
# Tenant scoping (list/read/write access)
# ============================================================================


class TestTenantScoping:
    async def test_platform_scope_sees_all_organizations(self) -> None:
        service, repo, _audit = make_service()
        await make_organization(repo, "Acme Corp")
        await make_organization(repo, "Globex")

        organizations, meta = await service.list_organizations(
            requesting_organization_id=None
        )

        assert meta.total_items == 2
        assert {o.name for o in organizations} == {"Acme Corp", "Globex"}

    async def test_org_scoped_caller_sees_only_self_and_children(self) -> None:
        service, repo, _audit = make_service()
        msp = await make_organization(
            repo, "Reseller MSP", org_type=OrganizationType.MSP
        )
        child = await make_organization(repo, "Client A", parent_organization_id=msp.id)
        await make_organization(repo, "Unrelated Org")

        organizations, meta = await service.list_organizations(
            requesting_organization_id=msp.id
        )

        names = {o.name for o in organizations}
        assert names == {"Reseller MSP", "Client A"}
        assert meta.total_items == 2
        assert child.parent_organization_id == msp.id

    async def test_update_organization_outside_scope_raises(self) -> None:
        service, repo, _audit = make_service()
        org_a = await make_organization(repo, "Org A")
        org_b = await make_organization(repo, "Org B")

        with pytest.raises(CrossOrganizationAccessError):
            await service.update_organization(
                actor_user_id=uuid.uuid4(),
                organization_id=org_b.id,
                requesting_organization_id=org_a.id,
                data={"name": "Hijacked"},
            )

    async def test_msp_can_update_its_child(self) -> None:
        service, repo, _audit = make_service()
        msp = await make_organization(
            repo, "Reseller MSP", org_type=OrganizationType.MSP
        )
        child = await make_organization(repo, "Client A", parent_organization_id=msp.id)

        updated = await service.update_organization(
            actor_user_id=uuid.uuid4(),
            organization_id=child.id,
            requesting_organization_id=msp.id,
            data={"name": "Client A Renamed"},
        )

        assert updated.name == "Client A Renamed"


# ============================================================================
# MSP hierarchy
# ============================================================================


class TestMspHierarchy:
    async def test_create_child_under_msp_succeeds(self) -> None:
        service, repo, _audit = make_service()
        msp = await make_organization(
            repo, "Reseller MSP", org_type=OrganizationType.MSP
        )

        child = await service.create_organization(
            actor_user_id=uuid.uuid4(),
            name="Client A",
            slug="client-a",
            contact_email="admin@client-a.example.com",
            parent_organization_id=msp.id,
        )

        assert child.parent_organization_id == msp.id

    async def test_create_child_under_non_msp_raises(self) -> None:
        service, repo, _audit = make_service()
        standard_org = await make_organization(repo, "Not An MSP")

        with pytest.raises(NotAnMspOrganizationError):
            await service.create_organization(
                actor_user_id=uuid.uuid4(),
                name="Client A",
                slug="client-a",
                contact_email="admin@client-a.example.com",
                parent_organization_id=standard_org.id,
            )

    async def test_list_children_of_non_msp_raises(self) -> None:
        service, repo, _audit = make_service()
        standard_org = await make_organization(repo, "Not An MSP")

        with pytest.raises(NotAnMspOrganizationError):
            await service.list_children(standard_org.id)

    async def test_list_children_of_msp_returns_only_its_children(self) -> None:
        service, repo, _audit = make_service()
        msp = await make_organization(
            repo, "Reseller MSP", org_type=OrganizationType.MSP
        )
        child = await make_organization(repo, "Client A", parent_organization_id=msp.id)
        await make_organization(repo, "Unrelated Org")

        children = await service.list_children(msp.id)

        assert [c.id for c in children] == [child.id]

    async def test_reparenting_to_self_raises_circular_error(self) -> None:
        service, repo, _audit = make_service()
        msp = await make_organization(
            repo, "Reseller MSP", org_type=OrganizationType.MSP
        )

        with pytest.raises(CircularOrganizationHierarchyError):
            await service.update_organization(
                actor_user_id=uuid.uuid4(),
                organization_id=msp.id,
                requesting_organization_id=None,
                data={"parent_organization_id": msp.id},
            )

    async def test_reparenting_creates_deep_cycle_raises(self) -> None:
        service, repo, _audit = make_service()
        grandparent_msp = await make_organization(
            repo, "Grandparent MSP", org_type=OrganizationType.MSP
        )
        parent_msp = await make_organization(
            repo,
            "Parent MSP",
            org_type=OrganizationType.MSP,
            parent_organization_id=grandparent_msp.id,
        )

        # Attempting to make the grandparent a child of its own descendant
        # (parent_msp) would create a cycle.
        with pytest.raises(CircularOrganizationHierarchyError):
            await service.update_organization(
                actor_user_id=uuid.uuid4(),
                organization_id=grandparent_msp.id,
                requesting_organization_id=None,
                data={"parent_organization_id": parent_msp.id},
            )

    async def test_downgrading_msp_with_children_raises(self) -> None:
        service, repo, _audit = make_service()
        msp = await make_organization(
            repo, "Reseller MSP", org_type=OrganizationType.MSP
        )
        await make_organization(repo, "Client A", parent_organization_id=msp.id)

        with pytest.raises(MspDowngradeWithChildrenError):
            await service.update_organization(
                actor_user_id=uuid.uuid4(),
                organization_id=msp.id,
                requesting_organization_id=None,
                data={"org_type": OrganizationType.STANDARD},
            )

    async def test_downgrading_msp_without_children_succeeds(self) -> None:
        service, repo, _audit = make_service()
        msp = await make_organization(
            repo, "Reseller MSP", org_type=OrganizationType.MSP
        )

        updated = await service.update_organization(
            actor_user_id=uuid.uuid4(),
            organization_id=msp.id,
            requesting_organization_id=None,
            data={"org_type": OrganizationType.STANDARD},
        )

        assert updated.org_type == OrganizationType.STANDARD.value


# ============================================================================
# Membership lifecycle
# ============================================================================


class TestMembershipLifecycle:
    async def test_invite_member_creates_invited_row(self) -> None:
        service, repo, audit = make_service()
        organization = await make_organization(repo, "Acme Corp")
        inviter_id = uuid.uuid4()
        invitee_id = uuid.uuid4()

        member = await service.invite_member(
            actor_user_id=inviter_id,
            organization_id=organization.id,
            user_id=invitee_id,
        )

        assert member.status == MembershipStatus.INVITED.value
        assert member.invited_by_user_id == inviter_id
        assert member.joined_at is None
        assert any(e["action"] == "organization_member_invited" for e in audit.entries)

    async def test_invite_already_active_member_raises(self) -> None:
        service, repo, _audit = make_service()
        organization = await make_organization(repo, "Acme Corp")
        user_id = uuid.uuid4()
        await make_active_member(repo, organization_id=organization.id, user_id=user_id)

        with pytest.raises(DuplicateMembershipError):
            await service.invite_member(
                actor_user_id=uuid.uuid4(),
                organization_id=organization.id,
                user_id=user_id,
            )

    async def test_invite_already_pending_member_raises(self) -> None:
        service, repo, _audit = make_service()
        organization = await make_organization(repo, "Acme Corp")
        user_id = uuid.uuid4()
        await service.invite_member(
            actor_user_id=uuid.uuid4(),
            organization_id=organization.id,
            user_id=user_id,
        )

        with pytest.raises(DuplicateMembershipError):
            await service.invite_member(
                actor_user_id=uuid.uuid4(),
                organization_id=organization.id,
                user_id=user_id,
            )

    async def test_invite_suspended_member_raises_must_reactivate(self) -> None:
        service, repo, _audit = make_service()
        organization = await make_organization(repo, "Acme Corp")
        user_id = uuid.uuid4()
        member = await make_active_member(
            repo, organization_id=organization.id, user_id=user_id
        )
        await repo.update_membership(
            member, {"status": MembershipStatus.SUSPENDED.value}
        )

        with pytest.raises(MembershipSuspendedError):
            await service.invite_member(
                actor_user_id=uuid.uuid4(),
                organization_id=organization.id,
                user_id=user_id,
            )

    async def test_invite_removed_member_allows_re_invite(self) -> None:
        service, repo, _audit = make_service()
        organization = await make_organization(repo, "Acme Corp")
        user_id = uuid.uuid4()
        member = await make_active_member(
            repo, organization_id=organization.id, user_id=user_id
        )
        await repo.update_membership(member, {"status": MembershipStatus.REMOVED.value})

        new_invite = await service.invite_member(
            actor_user_id=uuid.uuid4(),
            organization_id=organization.id,
            user_id=user_id,
        )

        assert new_invite.status == MembershipStatus.INVITED.value
        assert new_invite.id != member.id

    async def test_accept_invite_activates_membership(self) -> None:
        service, repo, audit = make_service()
        organization = await make_organization(repo, "Acme Corp")
        user_id = uuid.uuid4()
        member = await service.invite_member(
            actor_user_id=uuid.uuid4(),
            organization_id=organization.id,
            user_id=user_id,
        )

        accepted = await service.accept_invite(
            user_id=user_id, organization_id=organization.id, member_id=member.id
        )

        assert accepted.status == MembershipStatus.ACTIVE.value
        assert accepted.joined_at is not None
        assert any(e["action"] == "organization_member_accepted" for e in audit.entries)

    async def test_accept_invite_by_wrong_user_raises(self) -> None:
        service, repo, _audit = make_service()
        organization = await make_organization(repo, "Acme Corp")
        invitee_id = uuid.uuid4()
        member = await service.invite_member(
            actor_user_id=uuid.uuid4(),
            organization_id=organization.id,
            user_id=invitee_id,
        )

        with pytest.raises(OrganizationMembershipNotFoundError):
            await service.accept_invite(
                user_id=uuid.uuid4(),
                organization_id=organization.id,
                member_id=member.id,
            )

    async def test_accept_already_active_invite_raises(self) -> None:
        service, repo, _audit = make_service()
        organization = await make_organization(repo, "Acme Corp")
        user_id = uuid.uuid4()
        member = await make_active_member(
            repo, organization_id=organization.id, user_id=user_id
        )

        with pytest.raises(InvalidMembershipStatusTransitionError):
            await service.accept_invite(
                user_id=user_id,
                organization_id=organization.id,
                member_id=member.id,
            )

    async def test_remove_member_success(self) -> None:
        service, repo, audit = make_service()
        organization = await make_organization(repo, "Acme Corp")
        user_id = uuid.uuid4()
        member = await make_active_member(
            repo, organization_id=organization.id, user_id=user_id
        )
        # A second active member so removing the first isn't "last active".
        await make_active_member(
            repo, organization_id=organization.id, user_id=uuid.uuid4()
        )

        removed = await service.remove_member(
            actor_user_id=uuid.uuid4(),
            organization_id=organization.id,
            member_id=member.id,
        )

        assert removed.status == MembershipStatus.REMOVED.value
        assert any(e["action"] == "organization_member_removed" for e in audit.entries)

    async def test_remove_last_active_member_raises(self) -> None:
        service, repo, _audit = make_service()
        organization = await make_organization(repo, "Acme Corp")
        user_id = uuid.uuid4()
        member = await make_active_member(
            repo, organization_id=organization.id, user_id=user_id
        )

        with pytest.raises(LastActiveMemberError):
            await service.remove_member(
                actor_user_id=uuid.uuid4(),
                organization_id=organization.id,
                member_id=member.id,
            )

    async def test_remove_already_removed_member_raises(self) -> None:
        service, repo, _audit = make_service()
        organization = await make_organization(repo, "Acme Corp")
        user_id = uuid.uuid4()
        member = await make_active_member(
            repo, organization_id=organization.id, user_id=user_id
        )
        await make_active_member(
            repo, organization_id=organization.id, user_id=uuid.uuid4()
        )
        await service.remove_member(
            actor_user_id=uuid.uuid4(),
            organization_id=organization.id,
            member_id=member.id,
        )

        with pytest.raises(InvalidMembershipStatusTransitionError):
            await service.remove_member(
                actor_user_id=uuid.uuid4(),
                organization_id=organization.id,
                member_id=member.id,
            )

    async def test_change_member_status_suspends_member(self) -> None:
        service, repo, audit = make_service()
        organization = await make_organization(repo, "Acme Corp")
        user_id = uuid.uuid4()
        member = await make_active_member(
            repo, organization_id=organization.id, user_id=user_id
        )

        suspended = await service.change_member_status(
            actor_user_id=uuid.uuid4(),
            organization_id=organization.id,
            member_id=member.id,
            new_status=MembershipStatus.SUSPENDED,
        )

        assert suspended.status == MembershipStatus.SUSPENDED.value
        assert any(
            e["action"] == "organization_member_status_changed" for e in audit.entries
        )

    async def test_list_my_organizations_returns_all_statuses(self) -> None:
        service, repo, _audit = make_service()
        organization = await make_organization(repo, "Acme Corp")
        user_id = uuid.uuid4()
        await make_active_member(repo, organization_id=organization.id, user_id=user_id)

        memberships = await service.list_user_organizations(user_id)

        assert len(memberships) == 1
        assert memberships[0].organization_id == organization.id


# ============================================================================
# RBAC organization_id FK follow-up (models-level sanity, not the FK itself
# since SQLite/no-DB unit tests can't exercise a real Postgres constraint --
# the FK constraint itself is exercised by running the full RBAC suite,
# confirmed unaffected by this change).
# ============================================================================


class TestRbacOrganizationFkFollowUp:
    def test_rbac_models_declare_organization_fk(self) -> None:
        from app.domains.rbac.models import (
            AuditLogEntry,
            OrganizationRole,
            PermissionOverride,
            Role,
            UserRole,
        )

        for model in (
            Role,
            UserRole,
            OrganizationRole,
            PermissionOverride,
            AuditLogEntry,
        ):
            column = model.__table__.columns["organization_id"]
            assert len(column.foreign_keys) == 1
            foreign_key = next(iter(column.foreign_keys))
            assert foreign_key.target_fullname == "organizations.id"

    def test_permission_scope_has_no_organization_column(self) -> None:
        from app.domains.rbac.models import PermissionScope

        assert "organization_id" not in PermissionScope.__table__.columns
