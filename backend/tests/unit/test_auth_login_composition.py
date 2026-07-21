"""Unit tests for Enterprise SaaS Phase E's role-aware ``/auth/login``
response composition (``app.domains.auth.router``'s private
``_role_assignment_summaries``/``_organization_membership_summaries``/
``_membership_summary`` helpers).

Follows this project's plain-``assert``/native-``async def`` style and the
"import private helpers directly for a focused unit test" precedent
``tests/unit/test_location_provisioning.py`` already establishes for
``_generate_temporary_password``/``_generate_username``. Exercises the
helpers against small in-memory fakes for ``RoleResolver``/
``OrganizationService``/``LicenseService`` rather than a live Postgres/
Redis instance.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.domains.auth.router import (
    _membership_summary,
    _organization_membership_summaries,
    _role_assignment_summaries,
)
from app.domains.billing.constants import LicenseStatus
from app.domains.billing.exceptions import LicenseNotFoundError
from app.domains.billing.service import EntitlementSnapshot
from app.domains.organization.enums import MembershipStatus, OrganizationType
from app.domains.organization.models import Organization, OrganizationMember
from app.domains.rbac.authorization import ActiveRoleAssignment
from app.domains.rbac.enums import ScopeType
from app.domains.rbac.models import Role, UserRole


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


def _make_role(**overrides: object) -> Role:
    fields: dict[str, object] = {
        "name": "Organization Owner",
        "slug": "organization-owner",
        "description": None,
        "is_system_role": True,
        "is_template": False,
        "is_active": True,
        "scope_type": ScopeType.ORGANIZATION.value,
        "organization_id": None,
        "parent_role_id": None,
    }
    fields.update(overrides)
    return Role(**_base_fields(**fields))


def _make_user_role(role: Role, **overrides: object) -> UserRole:
    fields: dict[str, object] = {
        "user_id": uuid.uuid4(),
        "role_id": role.id,
        "scope_type": role.scope_type,
        "msp_id": None,
        "organization_id": uuid.uuid4(),
        "location_id": None,
        "router_id": None,
        "granted_at": _now(),
        "granted_by": None,
        "expires_at": None,
        "is_active": True,
    }
    fields.update(overrides)
    return UserRole(**_base_fields(**fields))


def _make_organization(**overrides: object) -> Organization:
    fields: dict[str, object] = {
        "name": "Acme Corp",
        "slug": "acme-corp",
        "legal_name": None,
        "org_type": OrganizationType.STANDARD.value,
        "status": "active",
        "parent_organization_id": None,
        "contact_email": "admin@acme.example.com",
        "contact_phone": None,
        "timezone": "UTC",
        "default_locale": "en",
        "settings": {},
        "subscription_tier": None,
    }
    fields.update(overrides)
    return Organization(**_base_fields(**fields))


def _make_membership(
    organization_id: uuid.UUID, **overrides: object
) -> OrganizationMember:
    fields: dict[str, object] = {
        "organization_id": organization_id,
        "user_id": uuid.uuid4(),
        "status": MembershipStatus.ACTIVE.value,
        "invited_by_user_id": None,
        "invited_at": _now(),
        "joined_at": _now(),
        "is_primary_contact": False,
    }
    fields.update(overrides)
    return OrganizationMember(**_base_fields(**fields))


@dataclass
class FakeRoleResolver:
    assignments: list[ActiveRoleAssignment] = field(default_factory=list)

    async def get_active_assignments(
        self, user_id: uuid.UUID
    ) -> list[ActiveRoleAssignment]:
        return [
            item for item in self.assignments if item.assignment.user_id == user_id
        ]


@dataclass
class FakeOrganizationService:
    organizations: dict[uuid.UUID, Organization] = field(default_factory=dict)
    memberships: list[OrganizationMember] = field(default_factory=list)

    async def list_user_organizations(
        self, user_id: uuid.UUID, *, status: MembershipStatus | None = None
    ) -> list[OrganizationMember]:
        rows = [m for m in self.memberships if m.user_id == user_id]
        if status is not None:
            rows = [m for m in rows if m.status == status.value]
        return rows

    async def get_organization(self, organization_id: uuid.UUID) -> Organization:
        return self.organizations[organization_id]


@dataclass
class FakeLicenseService:
    snapshots: dict[uuid.UUID, EntitlementSnapshot] = field(default_factory=dict)

    async def get_entitlement_snapshot(
        self, organization_id: uuid.UUID
    ) -> EntitlementSnapshot:
        snapshot = self.snapshots.get(organization_id)
        if snapshot is None:
            raise LicenseNotFoundError(organization_id)
        return snapshot


class TestRoleAssignmentSummaries:
    async def test_returns_one_summary_per_active_assignment(self) -> None:
        user_id = uuid.uuid4()
        role = _make_role()
        org_id = uuid.uuid4()
        assignment = _make_user_role(role, user_id=user_id, organization_id=org_id)
        resolver = FakeRoleResolver(
            assignments=[ActiveRoleAssignment(assignment=assignment, role=role)]
        )

        summaries = await _role_assignment_summaries(resolver, user_id)

        assert len(summaries) == 1
        assert summaries[0].role_slug == "organization-owner"
        assert summaries[0].scope_type == ScopeType.ORGANIZATION.value
        assert summaries[0].organization_id == str(org_id)
        assert summaries[0].location_id is None
        assert summaries[0].router_id is None

    async def test_no_assignments_returns_empty_list(self) -> None:
        resolver = FakeRoleResolver()
        summaries = await _role_assignment_summaries(resolver, uuid.uuid4())
        assert summaries == []


class TestOrganizationMembershipSummaries:
    async def test_includes_only_active_memberships_org_details_and_features(
        self,
    ) -> None:
        user_id = uuid.uuid4()
        organization = _make_organization()
        org_service = FakeOrganizationService(
            organizations={organization.id: organization},
            memberships=[
                _make_membership(
                    organization.id, user_id=user_id, is_primary_contact=True
                )
            ],
        )
        license_service = FakeLicenseService(
            snapshots={
                organization.id: EntitlementSnapshot(
                    organization_id=organization.id,
                    plan_id=uuid.uuid4(),
                    license_status=LicenseStatus.ACTIVE.value,
                    expires_at=None,
                    enabled_features=frozenset({"audit_logs", "white_label"}),
                    limits={},
                    tiers={},
                )
            }
        )

        summaries = await _organization_membership_summaries(
            org_service, license_service, user_id
        )

        assert len(summaries) == 1
        summary = summaries[0]
        assert summary.organization_id == str(organization.id)
        assert summary.organization_slug == "acme-corp"
        assert summary.is_primary_contact is True
        assert summary.enabled_features == ["audit_logs", "white_label"]

    async def test_no_license_yields_empty_features_not_an_error(self) -> None:
        user_id = uuid.uuid4()
        organization = _make_organization()
        org_service = FakeOrganizationService(
            organizations={organization.id: organization},
            memberships=[_make_membership(organization.id, user_id=user_id)],
        )
        license_service = FakeLicenseService()

        summary = await _membership_summary(
            org_service, license_service, org_service.memberships[0]
        )

        assert summary.enabled_features == []

    async def test_invited_but_not_active_membership_is_excluded(self) -> None:
        user_id = uuid.uuid4()
        organization = _make_organization()
        org_service = FakeOrganizationService(
            organizations={organization.id: organization},
            memberships=[
                _make_membership(
                    organization.id,
                    user_id=user_id,
                    status=MembershipStatus.INVITED.value,
                )
            ],
        )
        license_service = FakeLicenseService()

        summaries = await _organization_membership_summaries(
            org_service, license_service, user_id
        )

        assert summaries == []
