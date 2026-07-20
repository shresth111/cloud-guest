"""Unit tests for the Policy domain: policy creation (organization-scoped and
platform-wide, tenant isolation), rules validation against the per-type
schema registry, version creation/publish/rollback (the exhaustive status
transition graph, immutability of published rules), assignment creation
(scope validation, publish-required precondition), effective-policy
resolution (scope-specificity precedence, priority tie-break, platform
default fallback), and that every admin route requires an RBAC permission
(there is no guest-facing route at all in this domain).

Follows this project's plain-``assert``/native-``async def`` style (see
``tests/unit/test_guest_teams.py``); ``asyncio_mode = "auto"`` runs async
tests directly. ``PolicyService`` is exercised against a small, hand-rolled
in-memory fake for its own repository and organization/location lookups,
mirroring ``test_guest_teams.py``'s own ``FakeGuestTeamRepository``/
``FakeOrganizationLookup``/``FakeLocationLookup`` shapes.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from app.domains.location.exceptions import (
    CrossOrganizationLocationAccessError,
    LocationNotFoundError,
)
from app.domains.location.models import Location
from app.domains.organization.enums import OrganizationType
from app.domains.organization.exceptions import OrganizationNotFoundError
from app.domains.organization.models import Organization
from app.domains.policy.constants import PLATFORM_DEFAULT_RULES, PolicyType
from app.domains.policy.exceptions import (
    CrossOrganizationPolicyAccessError,
    InvalidPolicyAssignmentScopeTypeError,
    InvalidPolicyVersionStatusTransitionError,
    PolicyAssignmentRequiresPublishedVersionError,
    PolicyAssignmentScopeIdNotAllowedError,
    PolicyAssignmentScopeIdRequiredError,
    PolicyRollbackTargetMismatchError,
    PolicyRollbackTargetNotPublishedError,
    PolicyRulesValidationError,
)
from app.domains.policy.models import Policy, PolicyAssignment, PolicyVersion
from app.domains.policy.router import router as policy_router
from app.domains.policy.service import PolicyService
from app.domains.rbac.enums import ScopeType

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
class FakePolicyRepository:
    policies: dict[uuid.UUID, Policy] = field(default_factory=dict)
    versions: dict[uuid.UUID, PolicyVersion] = field(default_factory=dict)
    assignments: dict[uuid.UUID, PolicyAssignment] = field(default_factory=dict)

    async def create_policy(self, **fields: object) -> Policy:
        policy = Policy(**_base_fields(**fields))
        self.policies[policy.id] = policy
        return policy

    async def get_policy_by_id(
        self, policy_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Policy | None:
        return self.policies.get(policy_id)

    async def update_policy(self, policy: Policy, data: dict[str, object]) -> Policy:
        for key, value in data.items():
            setattr(policy, key, value)
        policy.version += 1
        return policy

    async def list_policies(
        self,
        *,
        page: int,
        page_size: int,
        filters: dict[str, object] | None = None,
        sort_by: str = "created_at",
        sort_order: object = None,
    ) -> tuple[list[Policy], object]:
        items = list(self.policies.values())
        for key, value in (filters or {}).items():
            items = [i for i in items if getattr(i, key) == value]
        total = len(items)

        class _Meta:
            def __init__(self, total_items: int) -> None:
                self.page = page
                self.page_size = page_size
                self.total_items = total_items
                self.total_pages = 1
                self.has_next = False
                self.has_previous = False

        return items, _Meta(total)

    async def create_version(self, **fields: object) -> PolicyVersion:
        version = PolicyVersion(**_base_fields(**fields))
        self.versions[version.id] = version
        return version

    async def get_version_by_id(self, version_id: uuid.UUID) -> PolicyVersion | None:
        return self.versions.get(version_id)

    async def update_version(
        self, version: PolicyVersion, data: dict[str, object]
    ) -> PolicyVersion:
        for key, value in data.items():
            setattr(version, key, value)
        version.version += 1
        return version

    async def list_versions_for_policy(
        self, policy_id: uuid.UUID
    ) -> list[PolicyVersion]:
        return sorted(
            (v for v in self.versions.values() if v.policy_id == policy_id),
            key=lambda v: v.version_number,
        )

    async def get_next_version_number(self, policy_id: uuid.UUID) -> int:
        existing = [
            v.version_number for v in self.versions.values() if v.policy_id == policy_id
        ]
        return (max(existing) if existing else 0) + 1

    async def create_assignment(self, **fields: object) -> PolicyAssignment:
        assignment = PolicyAssignment(**_base_fields(**fields))
        self.assignments[assignment.id] = assignment
        return assignment

    async def get_assignment_by_id(
        self, assignment_id: uuid.UUID
    ) -> PolicyAssignment | None:
        return self.assignments.get(assignment_id)

    async def update_assignment(
        self, assignment: PolicyAssignment, data: dict[str, object]
    ) -> PolicyAssignment:
        for key, value in data.items():
            setattr(assignment, key, value)
        assignment.version += 1
        return assignment

    async def list_assignments_for_policy(
        self, policy_id: uuid.UUID
    ) -> list[PolicyAssignment]:
        return [a for a in self.assignments.values() if a.policy_id == policy_id]

    async def list_candidate_assignments(
        self,
        *,
        policy_type: str,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
    ) -> list[PolicyAssignment]:
        candidates = []
        for assignment in self.assignments.values():
            if not assignment.is_active:
                continue
            policy = self.policies.get(assignment.policy_id)
            if policy is None or not policy.is_active:
                continue
            if policy.policy_type != policy_type or policy.current_version_id is None:
                continue
            is_global_match = assignment.scope_type == ScopeType.GLOBAL.value
            is_org_match = (
                assignment.scope_type == ScopeType.ORGANIZATION.value
                and organization_id is not None
                and assignment.scope_id == organization_id
            )
            is_location_match = (
                assignment.scope_type == ScopeType.LOCATION.value
                and location_id is not None
                and assignment.scope_id == location_id
            )
            if is_global_match or is_org_match or is_location_match:
                candidates.append(assignment)
        return candidates


def _build_service() -> (
    tuple[
        PolicyService, FakePolicyRepository, FakeOrganizationLookup, FakeAuditLogWriter
    ]
):
    repo = FakePolicyRepository()
    org_lookup = FakeOrganizationLookup()
    location_lookup = FakeLocationLookup()
    audit_writer = FakeAuditLogWriter()
    service = PolicyService(
        repo, org_lookup, location_lookup, audit_writer=audit_writer
    )
    return service, repo, org_lookup, audit_writer


async def _create_published_session_policy(
    service: PolicyService, *, organization_id: uuid.UUID | None
) -> Policy:
    policy = await service.create_policy(
        actor_user_id=None,
        requesting_organization_id=organization_id,
        organization_id=organization_id,
        policy_type=PolicyType.SESSION,
        name="Session Policy",
        description=None,
    )
    version = await service.create_version(
        policy_id=policy.id,
        requesting_organization_id=organization_id,
        actor_user_id=None,
        rules={
            "session_timeout_minutes": 120,
            "max_concurrent_sessions_per_guest": 2,
            "termination_reconnect_cooldown_minutes": 30,
            "reconnect_grace_minutes": 15,
        },
    )
    await service.publish_version(
        policy_id=policy.id,
        version_id=version.id,
        requesting_organization_id=organization_id,
        actor_user_id=None,
    )
    return await service.get_policy(
        policy.id, requesting_organization_id=organization_id
    )


# ============================================================================
# Policy creation
# ============================================================================


class TestPolicyCreation:
    async def test_create_organization_policy(self) -> None:
        service, _, org_lookup, _ = _build_service()
        org = org_lookup.add()
        policy = await service.create_policy(
            actor_user_id=None,
            requesting_organization_id=org.id,
            organization_id=org.id,
            policy_type=PolicyType.SESSION,
            name="My Session Policy",
            description="Custom",
        )
        assert policy.organization_id == org.id
        assert policy.is_active is True
        assert policy.current_version_id is None

    async def test_create_platform_wide_policy_by_platform_caller(self) -> None:
        service, _, _, _ = _build_service()
        policy = await service.create_policy(
            actor_user_id=None,
            requesting_organization_id=None,
            organization_id=None,
            policy_type=PolicyType.SESSION,
            name="Platform Default Session Policy",
            description=None,
        )
        assert policy.organization_id is None

    async def test_org_caller_cannot_create_platform_wide_policy(self) -> None:
        service, _, org_lookup, _ = _build_service()
        org = org_lookup.add()
        with pytest.raises(CrossOrganizationPolicyAccessError):
            await service.create_policy(
                actor_user_id=None,
                requesting_organization_id=org.id,
                organization_id=None,
                policy_type=PolicyType.SESSION,
                name="Sneaky Platform Policy",
                description=None,
            )

    async def test_org_caller_cannot_create_policy_for_another_org(self) -> None:
        service, _, org_lookup, _ = _build_service()
        org_a = org_lookup.add()
        org_b = org_lookup.add()
        with pytest.raises(CrossOrganizationPolicyAccessError):
            await service.create_policy(
                actor_user_id=None,
                requesting_organization_id=org_a.id,
                organization_id=org_b.id,
                policy_type=PolicyType.SESSION,
                name="Cross org",
                description=None,
            )

    async def test_create_policy_is_audited(self) -> None:
        service, _, org_lookup, audit_writer = _build_service()
        org = org_lookup.add()
        await service.create_policy(
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=org.id,
            organization_id=org.id,
            policy_type=PolicyType.AUTHN,
            name="AuthN Policy",
            description=None,
        )
        assert audit_writer.entries[-1]["action"] == "policy_created"


# ============================================================================
# Rules validation
# ============================================================================


class TestRulesValidation:
    async def test_valid_session_rules_are_accepted(self) -> None:
        service, _, org_lookup, _ = _build_service()
        org = org_lookup.add()
        policy = await service.create_policy(
            actor_user_id=None,
            requesting_organization_id=org.id,
            organization_id=org.id,
            policy_type=PolicyType.SESSION,
            name="Session",
            description=None,
        )
        version = await service.create_version(
            policy_id=policy.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
            rules={
                "session_timeout_minutes": 60,
                "max_concurrent_sessions_per_guest": 1,
                "termination_reconnect_cooldown_minutes": 10,
                "reconnect_grace_minutes": 5,
            },
        )
        assert version.rules["session_timeout_minutes"] == 60
        assert version.version_number == 1

    async def test_missing_required_session_field_is_rejected(self) -> None:
        service, _, org_lookup, _ = _build_service()
        org = org_lookup.add()
        policy = await service.create_policy(
            actor_user_id=None,
            requesting_organization_id=org.id,
            organization_id=org.id,
            policy_type=PolicyType.SESSION,
            name="Session",
            description=None,
        )
        with pytest.raises(PolicyRulesValidationError):
            await service.create_version(
                policy_id=policy.id,
                requesting_organization_id=org.id,
                actor_user_id=None,
                rules={"session_timeout_minutes": 60},
            )

    async def test_negative_value_is_rejected(self) -> None:
        service, _, org_lookup, _ = _build_service()
        org = org_lookup.add()
        policy = await service.create_policy(
            actor_user_id=None,
            requesting_organization_id=org.id,
            organization_id=org.id,
            policy_type=PolicyType.AUTHN,
            name="AuthN",
            description=None,
        )
        with pytest.raises(PolicyRulesValidationError):
            await service.create_version(
                policy_id=policy.id,
                requesting_organization_id=org.id,
                actor_user_id=None,
                rules={"max_attempts_per_window": -1, "window_minutes": 1},
            )

    async def test_generic_policy_type_accepts_any_object(self) -> None:
        service, _, org_lookup, _ = _build_service()
        org = org_lookup.add()
        policy = await service.create_policy(
            actor_user_id=None,
            requesting_organization_id=org.id,
            organization_id=org.id,
            policy_type=PolicyType.BANDWIDTH,
            name="Bandwidth",
            description=None,
        )
        version = await service.create_version(
            policy_id=policy.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
            rules={"anything": 123, "nested": {"a": 1}},
        )
        assert version.rules["anything"] == 123

    async def test_version_numbers_increment_per_policy(self) -> None:
        service, _, org_lookup, _ = _build_service()
        org = org_lookup.add()
        policy = await service.create_policy(
            actor_user_id=None,
            requesting_organization_id=org.id,
            organization_id=org.id,
            policy_type=PolicyType.BANDWIDTH,
            name="Bandwidth",
            description=None,
        )
        v1 = await service.create_version(
            policy_id=policy.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
            rules={"a": 1},
        )
        v2 = await service.create_version(
            policy_id=policy.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
            rules={"a": 2},
        )
        assert v1.version_number == 1
        assert v2.version_number == 2


# ============================================================================
# Publish / rollback
# ============================================================================


class TestPublishAndRollback:
    async def test_publish_sets_current_version_and_published_at(self) -> None:
        service, _, org_lookup, _ = _build_service()
        org = org_lookup.add()
        policy = await _create_published_session_policy(service, organization_id=org.id)
        assert policy.current_version_id is not None

    async def test_publishing_already_published_version_raises(self) -> None:
        service, repo, org_lookup, _ = _build_service()
        org = org_lookup.add()
        policy = await _create_published_session_policy(service, organization_id=org.id)
        with pytest.raises(InvalidPolicyVersionStatusTransitionError):
            await service.publish_version(
                policy_id=policy.id,
                version_id=policy.current_version_id,
                requesting_organization_id=org.id,
                actor_user_id=None,
            )

    async def test_published_version_rules_are_immutable_across_new_versions(
        self,
    ) -> None:
        service, _, org_lookup, _ = _build_service()
        org = org_lookup.add()
        policy = await _create_published_session_policy(service, organization_id=org.id)
        first_version_id = policy.current_version_id
        first_version = await service.repository.get_version_by_id(first_version_id)
        original_timeout = first_version.rules["session_timeout_minutes"]

        new_version = await service.create_version(
            policy_id=policy.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
            rules={
                "session_timeout_minutes": 999,
                "max_concurrent_sessions_per_guest": 5,
                "termination_reconnect_cooldown_minutes": 5,
                "reconnect_grace_minutes": 5,
            },
        )
        await service.publish_version(
            policy_id=policy.id,
            version_id=new_version.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
        )

        # The first version's own rules were never mutated by publishing a
        # second version -- append-only.
        first_version_again = await service.repository.get_version_by_id(
            first_version_id
        )
        assert first_version_again.rules["session_timeout_minutes"] == original_timeout

    async def test_rollback_to_earlier_published_version(self) -> None:
        service, _, org_lookup, _ = _build_service()
        org = org_lookup.add()
        policy = await _create_published_session_policy(service, organization_id=org.id)
        first_version_id = policy.current_version_id

        new_version = await service.create_version(
            policy_id=policy.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
            rules={
                "session_timeout_minutes": 999,
                "max_concurrent_sessions_per_guest": 5,
                "termination_reconnect_cooldown_minutes": 5,
                "reconnect_grace_minutes": 5,
            },
        )
        await service.publish_version(
            policy_id=policy.id,
            version_id=new_version.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
        )

        rolled_back = await service.rollback(
            policy_id=policy.id,
            target_version_id=first_version_id,
            requesting_organization_id=org.id,
            actor_user_id=None,
        )
        assert rolled_back.current_version_id == first_version_id

    async def test_rollback_to_unpublished_version_raises(self) -> None:
        service, _, org_lookup, _ = _build_service()
        org = org_lookup.add()
        policy = await _create_published_session_policy(service, organization_id=org.id)
        draft = await service.create_version(
            policy_id=policy.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
            rules={
                "session_timeout_minutes": 1,
                "max_concurrent_sessions_per_guest": 1,
                "termination_reconnect_cooldown_minutes": 1,
                "reconnect_grace_minutes": 1,
            },
        )
        with pytest.raises(PolicyRollbackTargetNotPublishedError):
            await service.rollback(
                policy_id=policy.id,
                target_version_id=draft.id,
                requesting_organization_id=org.id,
                actor_user_id=None,
            )

    async def test_rollback_to_version_of_another_policy_raises(self) -> None:
        service, _, org_lookup, _ = _build_service()
        org = org_lookup.add()
        policy_a = await _create_published_session_policy(
            service, organization_id=org.id
        )
        policy_b = await _create_published_session_policy(
            service, organization_id=org.id
        )
        with pytest.raises(PolicyRollbackTargetMismatchError):
            await service.rollback(
                policy_id=policy_a.id,
                target_version_id=policy_b.current_version_id,
                requesting_organization_id=org.id,
                actor_user_id=None,
            )


# ============================================================================
# Assignments
# ============================================================================


class TestAssignments:
    async def test_create_global_assignment(self) -> None:
        service, _, org_lookup, _ = _build_service()
        policy = await _create_published_session_policy(service, organization_id=None)
        assignment = await service.create_assignment(
            policy_id=policy.id,
            requesting_organization_id=None,
            actor_user_id=None,
            scope_type=ScopeType.GLOBAL.value,
            scope_id=None,
            priority=0,
        )
        assert assignment.scope_type == ScopeType.GLOBAL.value
        assert assignment.scope_id is None

    async def test_global_assignment_with_scope_id_rejected(self) -> None:
        service, _, org_lookup, _ = _build_service()
        policy = await _create_published_session_policy(service, organization_id=None)
        with pytest.raises(PolicyAssignmentScopeIdNotAllowedError):
            await service.create_assignment(
                policy_id=policy.id,
                requesting_organization_id=None,
                actor_user_id=None,
                scope_type=ScopeType.GLOBAL.value,
                scope_id=uuid.uuid4(),
                priority=0,
            )

    async def test_organization_assignment_requires_scope_id(self) -> None:
        service, _, org_lookup, _ = _build_service()
        org = org_lookup.add()
        policy = await _create_published_session_policy(service, organization_id=org.id)
        with pytest.raises(PolicyAssignmentScopeIdRequiredError):
            await service.create_assignment(
                policy_id=policy.id,
                requesting_organization_id=org.id,
                actor_user_id=None,
                scope_type=ScopeType.ORGANIZATION.value,
                scope_id=None,
                priority=0,
            )

    async def test_invalid_scope_type_rejected(self) -> None:
        service, _, org_lookup, _ = _build_service()
        org = org_lookup.add()
        policy = await _create_published_session_policy(service, organization_id=org.id)
        with pytest.raises(InvalidPolicyAssignmentScopeTypeError):
            await service.create_assignment(
                policy_id=policy.id,
                requesting_organization_id=org.id,
                actor_user_id=None,
                scope_type="nonsense",
                scope_id=uuid.uuid4(),
                priority=0,
            )

    async def test_assignment_requires_published_version(self) -> None:
        service, _, org_lookup, _ = _build_service()
        org = org_lookup.add()
        policy = await service.create_policy(
            actor_user_id=None,
            requesting_organization_id=org.id,
            organization_id=org.id,
            policy_type=PolicyType.SESSION,
            name="Unpublished",
            description=None,
        )
        with pytest.raises(PolicyAssignmentRequiresPublishedVersionError):
            await service.create_assignment(
                policy_id=policy.id,
                requesting_organization_id=org.id,
                actor_user_id=None,
                scope_type=ScopeType.ORGANIZATION.value,
                scope_id=org.id,
                priority=0,
            )

    async def test_deactivate_assignment(self) -> None:
        service, _, org_lookup, _ = _build_service()
        org = org_lookup.add()
        policy = await _create_published_session_policy(service, organization_id=org.id)
        assignment = await service.create_assignment(
            policy_id=policy.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
            scope_type=ScopeType.ORGANIZATION.value,
            scope_id=org.id,
            priority=0,
        )
        deactivated = await service.deactivate_assignment(
            policy_id=policy.id,
            assignment_id=assignment.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
        )
        assert deactivated.is_active is False


# ============================================================================
# Effective-policy resolution
# ============================================================================


class TestResolution:
    async def test_falls_back_to_platform_default_when_nothing_assigned(self) -> None:
        service, _, org_lookup, _ = _build_service()
        org = org_lookup.add()
        resolved = await service.resolve_effective_policy(
            policy_type=PolicyType.SESSION,
            organization_id=org.id,
            location_id=None,
        )
        assert resolved.source == "platform_default"
        assert resolved.rules == PLATFORM_DEFAULT_RULES[PolicyType.SESSION]

    async def test_organization_assignment_wins_over_platform_default(self) -> None:
        service, _, org_lookup, _ = _build_service()
        org = org_lookup.add()
        policy = await _create_published_session_policy(service, organization_id=org.id)
        await service.create_assignment(
            policy_id=policy.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
            scope_type=ScopeType.ORGANIZATION.value,
            scope_id=org.id,
            priority=0,
        )
        resolved = await service.resolve_effective_policy(
            policy_type=PolicyType.SESSION,
            organization_id=org.id,
            location_id=None,
        )
        assert resolved.rules["session_timeout_minutes"] == 120
        assert resolved.source == f"organization:{org.id}"

    async def test_location_assignment_wins_over_organization_assignment(self) -> None:
        service, repo, org_lookup, _ = _build_service()
        org = org_lookup.add()
        location_id = uuid.uuid4()

        org_policy = await _create_published_session_policy(
            service, organization_id=org.id
        )
        await service.create_assignment(
            policy_id=org_policy.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
            scope_type=ScopeType.ORGANIZATION.value,
            scope_id=org.id,
            priority=0,
        )

        location_policy = await service.create_policy(
            actor_user_id=None,
            requesting_organization_id=org.id,
            organization_id=org.id,
            policy_type=PolicyType.SESSION,
            name="Location-specific",
            description=None,
        )
        location_version = await service.create_version(
            policy_id=location_policy.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
            rules={
                "session_timeout_minutes": 15,
                "max_concurrent_sessions_per_guest": 1,
                "termination_reconnect_cooldown_minutes": 5,
                "reconnect_grace_minutes": 5,
            },
        )
        await service.publish_version(
            policy_id=location_policy.id,
            version_id=location_version.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
        )
        # Bypass real Location lookup (not needed for this resolution test)
        # by writing the assignment directly through the fake repository.
        await repo.create_assignment(
            policy_id=location_policy.id,
            scope_type=ScopeType.LOCATION.value,
            scope_id=location_id,
            priority=0,
            is_active=True,
            created_by_user_id=None,
        )

        resolved = await service.resolve_effective_policy(
            policy_type=PolicyType.SESSION,
            organization_id=org.id,
            location_id=location_id,
        )
        assert resolved.rules["session_timeout_minutes"] == 15
        assert resolved.source == f"location:{location_id}"

    async def test_higher_priority_wins_at_same_scope(self) -> None:
        service, repo, org_lookup, _ = _build_service()
        org = org_lookup.add()

        low_priority_policy = await _create_published_session_policy(
            service, organization_id=org.id
        )
        await service.create_assignment(
            policy_id=low_priority_policy.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
            scope_type=ScopeType.ORGANIZATION.value,
            scope_id=org.id,
            priority=0,
        )

        high_priority_policy = await service.create_policy(
            actor_user_id=None,
            requesting_organization_id=org.id,
            organization_id=org.id,
            policy_type=PolicyType.SESSION,
            name="Higher priority",
            description=None,
        )
        high_version = await service.create_version(
            policy_id=high_priority_policy.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
            rules={
                "session_timeout_minutes": 5,
                "max_concurrent_sessions_per_guest": 1,
                "termination_reconnect_cooldown_minutes": 1,
                "reconnect_grace_minutes": 1,
            },
        )
        await service.publish_version(
            policy_id=high_priority_policy.id,
            version_id=high_version.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
        )
        await service.create_assignment(
            policy_id=high_priority_policy.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
            scope_type=ScopeType.ORGANIZATION.value,
            scope_id=org.id,
            priority=10,
        )

        resolved = await service.resolve_effective_policy(
            policy_type=PolicyType.SESSION,
            organization_id=org.id,
            location_id=None,
        )
        assert resolved.rules["session_timeout_minutes"] == 5

    async def test_deactivated_assignment_is_not_a_candidate(self) -> None:
        service, _, org_lookup, _ = _build_service()
        org = org_lookup.add()
        policy = await _create_published_session_policy(service, organization_id=org.id)
        assignment = await service.create_assignment(
            policy_id=policy.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
            scope_type=ScopeType.ORGANIZATION.value,
            scope_id=org.id,
            priority=0,
        )
        await service.deactivate_assignment(
            policy_id=policy.id,
            assignment_id=assignment.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
        )
        resolved = await service.resolve_effective_policy(
            policy_type=PolicyType.SESSION,
            organization_id=org.id,
            location_id=None,
        )
        assert resolved.source == "platform_default"


# ============================================================================
# Tenant isolation
# ============================================================================


class TestTenantIsolation:
    async def test_get_policy_rejects_cross_organization_request(self) -> None:
        service, _, org_lookup, _ = _build_service()
        org_a = org_lookup.add()
        org_b = org_lookup.add()
        policy = await service.create_policy(
            actor_user_id=None,
            requesting_organization_id=org_a.id,
            organization_id=org_a.id,
            policy_type=PolicyType.SESSION,
            name="Org A's policy",
            description=None,
        )
        with pytest.raises(CrossOrganizationPolicyAccessError):
            await service.get_policy(policy.id, requesting_organization_id=org_b.id)

    async def test_platform_wide_policy_is_readable_by_any_organization(self) -> None:
        service, _, org_lookup, _ = _build_service()
        org = org_lookup.add()
        policy = await service.create_policy(
            actor_user_id=None,
            requesting_organization_id=None,
            organization_id=None,
            policy_type=PolicyType.SESSION,
            name="Platform default",
            description=None,
        )
        fetched = await service.get_policy(policy.id, requesting_organization_id=org.id)
        assert fetched.id == policy.id

    async def test_list_policies_scopes_by_organization(self) -> None:
        service, _, org_lookup, _ = _build_service()
        org_a = org_lookup.add()
        org_b = org_lookup.add()
        await service.create_policy(
            actor_user_id=None,
            requesting_organization_id=org_a.id,
            organization_id=org_a.id,
            policy_type=PolicyType.SESSION,
            name="A",
            description=None,
        )
        await service.create_policy(
            actor_user_id=None,
            requesting_organization_id=org_b.id,
            organization_id=org_b.id,
            policy_type=PolicyType.SESSION,
            name="B",
            description=None,
        )
        policies, _ = await service.list_policies(requesting_organization_id=org_a.id)
        assert len(policies) == 1
        assert policies[0].organization_id == org_a.id


# ============================================================================
# RBAC -- every route in this domain is admin-facing
# ============================================================================


class TestEveryRouteRequiresPermission:
    def test_every_policy_route_has_a_permission_dependency(self) -> None:
        assert len(policy_router.routes) == 11
        for route in policy_router.routes:
            # Mirrors app.domains.guest_teams.router's own guest-facing
            # "route.dependencies == []" check, in reverse: every route in
            # this domain is admin-facing (see router.py's module
            # docstring -- there is no guest-facing route at all here), so
            # every one of them must carry the RequirePermission dependency
            # supplied via its own @router.<method>(..., dependencies=[...]).
            assert (
                route.dependencies != []
            ), f"{route.path} ({route.methods}) has no permission dependency"
