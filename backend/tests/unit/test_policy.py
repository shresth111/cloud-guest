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
from app.domains.policy.constants import (
    PLATFORM_DEFAULT_RULES,
    PolicyAssignmentTargetType,
    PolicyType,
)
from app.domains.policy.exceptions import (
    CrossOrganizationPolicyAccessError,
    InvalidPolicyAssignmentScopeTypeError,
    InvalidPolicyAssignmentTargetTypeError,
    InvalidPolicyVersionStatusTransitionError,
    PolicyAssignmentRequiresPublishedVersionError,
    PolicyAssignmentScopeIdNotAllowedError,
    PolicyAssignmentScopeIdRequiredError,
    PolicyAssignmentTargetIdNotAllowedError,
    PolicyAssignmentTargetIdRequiredError,
    PolicyAssignmentTargetRoleNotFoundError,
    PolicyAssignmentTargetUserNotFoundError,
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
        user_id: uuid.UUID | None = None,
        role_ids: list[uuid.UUID] | None = None,
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
            if not (is_global_match or is_org_match or is_location_match):
                continue

            # Unflushed test fixtures that construct a PolicyAssignment
            # directly (bypassing PolicyService.create_assignment) never
            # get the column's "none" default applied -- normalize None
            # the same way a real flush/DB read would.
            target_type = getattr(assignment, "target_type", None) or "none"
            is_untargeted = target_type == "none"
            is_user_match = (
                target_type == "user"
                and user_id is not None
                and assignment.target_id == user_id
            )
            is_role_match = (
                target_type == "role"
                and role_ids
                and assignment.target_id in role_ids
            )
            if is_untargeted or is_user_match or is_role_match:
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


@dataclass
class FakeUserLookup:
    """In-memory stand-in for ``PolicyService.UserLookupProtocol``."""

    known_user_ids: set[uuid.UUID] = field(default_factory=set)

    async def get_user_by_id(self, user_id: uuid.UUID) -> object | None:
        return object() if user_id in self.known_user_ids else None


@dataclass
class FakeRoleLookup:
    """In-memory stand-in for ``PolicyService.RoleLookupProtocol``."""

    known_role_ids: set[uuid.UUID] = field(default_factory=set)

    async def get_role_by_id(
        self, role_id: uuid.UUID, *, include_deleted: bool = False
    ) -> object | None:
        return object() if role_id in self.known_role_ids else None


def _build_service_with_targeting() -> tuple[
    PolicyService, FakePolicyRepository, FakeUserLookup, FakeRoleLookup
]:
    repo = FakePolicyRepository()
    org_lookup = FakeOrganizationLookup()
    location_lookup = FakeLocationLookup()
    audit_writer = FakeAuditLogWriter()
    user_lookup = FakeUserLookup()
    role_lookup = FakeRoleLookup()
    service = PolicyService(
        repo,
        org_lookup,
        location_lookup,
        audit_writer=audit_writer,
        user_lookup=user_lookup,
        role_lookup=role_lookup,
    )
    return service, repo, user_lookup, role_lookup


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

    async def test_bandwidth_rules_validates_against_typed_schema(self) -> None:
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
            rules={"download_rate_kbps": 5000, "upload_rate_kbps": 1000},
        )
        assert version.rules["download_rate_kbps"] == 5000
        assert version.rules["burst_download_kbps"] is None

    async def test_bandwidth_rules_rejects_missing_required_field(self) -> None:
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
        with pytest.raises(PolicyRulesValidationError):
            await service.create_version(
                policy_id=policy.id,
                requesting_organization_id=org.id,
                actor_user_id=None,
                rules={"download_rate_kbps": 5000},
            )

    async def test_bandwidth_rules_rejects_unexpected_field(self) -> None:
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
        with pytest.raises(PolicyRulesValidationError):
            await service.create_version(
                policy_id=policy.id,
                requesting_organization_id=org.id,
                actor_user_id=None,
                rules={
                    "download_rate_kbps": 5000,
                    "upload_rate_kbps": 1000,
                    "unexpected": True,
                },
            )

    async def test_qos_rules_validates_against_typed_schema(self) -> None:
        service, _, org_lookup, _ = _build_service()
        org = org_lookup.add()
        policy = await service.create_policy(
            actor_user_id=None,
            requesting_organization_id=org.id,
            organization_id=org.id,
            policy_type=PolicyType.QOS,
            name="QoS",
            description=None,
        )
        version = await service.create_version(
            policy_id=policy.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
            rules={"traffic_class": "voice", "guaranteed_bandwidth_kbps": 256},
        )
        assert version.rules["traffic_class"] == "voice"
        assert version.rules["dscp_marking"] is None

    async def test_fup_rules_validates_against_typed_schema(self) -> None:
        service, _, org_lookup, _ = _build_service()
        org = org_lookup.add()
        policy = await service.create_policy(
            actor_user_id=None,
            requesting_organization_id=org.id,
            organization_id=org.id,
            policy_type=PolicyType.FUP,
            name="Fair Usage",
            description=None,
        )
        version = await service.create_version(
            policy_id=policy.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
            rules={"daily_data_limit_mb": 500, "monthly_data_limit_mb": 10000},
        )
        assert version.rules["daily_data_limit_mb"] == 500
        assert version.rules["weekly_data_limit_mb"] is None

    async def test_business_hours_rules_validates_named_windows(self) -> None:
        service, _, org_lookup, _ = _build_service()
        org = org_lookup.add()
        policy = await service.create_policy(
            actor_user_id=None,
            requesting_organization_id=org.id,
            organization_id=org.id,
            policy_type=PolicyType.BUSINESS_HOURS,
            name="Business Hours",
            description=None,
        )
        version = await service.create_version(
            policy_id=policy.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
            rules={
                "night_mode": [
                    {"days_of_week": [], "start_time": "22:00", "end_time": "06:00"}
                ]
            },
        )
        assert version.rules["night_mode"][0]["start_time"] == "22:00"
        assert version.rules["peak_hours"] == []

    async def test_voucher_rules_validates_against_typed_schema(self) -> None:
        service, _, org_lookup, _ = _build_service()
        org = org_lookup.add()
        policy = await service.create_policy(
            actor_user_id=None,
            requesting_organization_id=org.id,
            organization_id=org.id,
            policy_type=PolicyType.VOUCHER,
            name="Voucher Rules",
            description=None,
        )
        version = await service.create_version(
            policy_id=policy.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
            rules={"max_active_vouchers_per_guest": 2},
        )
        assert version.rules["max_active_vouchers_per_guest"] == 2
        assert version.rules["allow_multi_use"] is True

    async def test_device_rules_validates_against_typed_schema(self) -> None:
        service, _, org_lookup, _ = _build_service()
        org = org_lookup.add()
        policy = await service.create_policy(
            actor_user_id=None,
            requesting_organization_id=org.id,
            organization_id=org.id,
            policy_type=PolicyType.DEVICE,
            name="Device Rules",
            description=None,
        )
        version = await service.create_version(
            policy_id=policy.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
            rules={"max_devices_per_guest": 5},
        )
        assert version.rules["max_devices_per_guest"] == 5
        assert version.rules["require_known_device"] is False

    async def test_device_policy_has_a_seeded_platform_default(self) -> None:
        service, _, org_lookup, _ = _build_service()
        resolved = await service.resolve_effective_policy(
            policy_type=PolicyType.DEVICE, organization_id=None, location_id=None
        )
        assert resolved.rules["max_devices_per_guest"] == 3
        assert resolved.source == "platform_default"

    async def test_generic_policy_type_accepts_any_object(self) -> None:
        # PolicyType.ACCESS has no concrete rule schema (unlike BANDWIDTH/
        # QOS/FUP/BUSINESS_HOURS/VOUCHER/DEVICE, which all gained typed
        # schemas as their own composing domains were built) -- see
        # schemas.GenericPolicyRules.
        service, _, org_lookup, _ = _build_service()
        org = org_lookup.add()
        policy = await service.create_policy(
            actor_user_id=None,
            requesting_organization_id=org.id,
            organization_id=org.id,
            policy_type=PolicyType.ACCESS,
            name="Access",
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
            policy_type=PolicyType.ACCESS,
            name="Access",
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
# WHO-targeting (Enterprise SaaS Phase F: per-user / per-role assignments)
# ============================================================================


class TestPolicyAssignmentTargeting:
    async def test_create_assignment_rejects_invalid_target_type(self) -> None:
        service, _repo, _user_lookup, _role_lookup = _build_service_with_targeting()
        org = service.organization_lookup.add()
        policy = await _create_published_session_policy(service, organization_id=org.id)

        with pytest.raises(InvalidPolicyAssignmentTargetTypeError):
            await service.create_assignment(
                policy_id=policy.id,
                requesting_organization_id=org.id,
                actor_user_id=None,
                scope_type=ScopeType.GLOBAL.value,
                scope_id=None,
                priority=0,
                target_type="department",
                target_id=uuid.uuid4(),
            )

    async def test_create_assignment_rejects_target_id_for_none_target_type(
        self,
    ) -> None:
        service, _repo, _user_lookup, _role_lookup = _build_service_with_targeting()
        org = service.organization_lookup.add()
        policy = await _create_published_session_policy(service, organization_id=org.id)

        with pytest.raises(PolicyAssignmentTargetIdNotAllowedError):
            await service.create_assignment(
                policy_id=policy.id,
                requesting_organization_id=org.id,
                actor_user_id=None,
                scope_type=ScopeType.GLOBAL.value,
                scope_id=None,
                priority=0,
                target_type=PolicyAssignmentTargetType.NONE.value,
                target_id=uuid.uuid4(),
            )

    async def test_create_assignment_requires_target_id_for_user_target_type(
        self,
    ) -> None:
        service, _repo, _user_lookup, _role_lookup = _build_service_with_targeting()
        org = service.organization_lookup.add()
        policy = await _create_published_session_policy(service, organization_id=org.id)

        with pytest.raises(PolicyAssignmentTargetIdRequiredError):
            await service.create_assignment(
                policy_id=policy.id,
                requesting_organization_id=org.id,
                actor_user_id=None,
                scope_type=ScopeType.GLOBAL.value,
                scope_id=None,
                priority=0,
                target_type=PolicyAssignmentTargetType.USER.value,
                target_id=None,
            )

    async def test_create_assignment_rejects_unknown_user_target(self) -> None:
        service, _repo, _user_lookup, _role_lookup = _build_service_with_targeting()
        org = service.organization_lookup.add()
        policy = await _create_published_session_policy(service, organization_id=org.id)

        with pytest.raises(PolicyAssignmentTargetUserNotFoundError):
            await service.create_assignment(
                policy_id=policy.id,
                requesting_organization_id=org.id,
                actor_user_id=None,
                scope_type=ScopeType.GLOBAL.value,
                scope_id=None,
                priority=0,
                target_type=PolicyAssignmentTargetType.USER.value,
                target_id=uuid.uuid4(),
            )

    async def test_create_assignment_rejects_unknown_role_target(self) -> None:
        service, _repo, _user_lookup, _role_lookup = _build_service_with_targeting()
        org = service.organization_lookup.add()
        policy = await _create_published_session_policy(service, organization_id=org.id)

        with pytest.raises(PolicyAssignmentTargetRoleNotFoundError):
            await service.create_assignment(
                policy_id=policy.id,
                requesting_organization_id=org.id,
                actor_user_id=None,
                scope_type=ScopeType.GLOBAL.value,
                scope_id=None,
                priority=0,
                target_type=PolicyAssignmentTargetType.ROLE.value,
                target_id=uuid.uuid4(),
            )

    async def test_create_assignment_accepts_known_user_target(self) -> None:
        service, _repo, user_lookup, _role_lookup = _build_service_with_targeting()
        org = service.organization_lookup.add()
        policy = await _create_published_session_policy(service, organization_id=org.id)
        user_id = uuid.uuid4()
        user_lookup.known_user_ids.add(user_id)

        assignment = await service.create_assignment(
            policy_id=policy.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
            scope_type=ScopeType.GLOBAL.value,
            scope_id=None,
            priority=0,
            target_type=PolicyAssignmentTargetType.USER.value,
            target_id=user_id,
        )
        assert assignment.target_type == PolicyAssignmentTargetType.USER.value
        assert assignment.target_id == user_id

    async def test_user_targeted_assignment_wins_over_untargeted(self) -> None:
        service, _repo, user_lookup, _role_lookup = _build_service_with_targeting()
        org = service.organization_lookup.add()
        policy = await _create_published_session_policy(service, organization_id=org.id)
        # Untargeted, organization-scoped assignment -- applies to everyone.
        await service.create_assignment(
            policy_id=policy.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
            scope_type=ScopeType.ORGANIZATION.value,
            scope_id=org.id,
            priority=0,
        )
        # A second published policy with a personalized override.
        personalized_policy = await _create_published_session_policy(
            service, organization_id=org.id
        )
        await service.create_version(
            policy_id=personalized_policy.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
            rules={
                "session_timeout_minutes": 9999,
                "max_concurrent_sessions_per_guest": 99,
                "termination_reconnect_cooldown_minutes": 99,
                "reconnect_grace_minutes": 99,
            },
        )
        user_id = uuid.uuid4()
        user_lookup.known_user_ids.add(user_id)
        await service.create_assignment(
            policy_id=personalized_policy.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
            scope_type=ScopeType.GLOBAL.value,
            scope_id=None,
            priority=0,
            target_type=PolicyAssignmentTargetType.USER.value,
            target_id=user_id,
        )

        resolved = await service.resolve_effective_policy(
            policy_type=PolicyType.SESSION,
            organization_id=org.id,
            location_id=None,
            user_id=user_id,
        )

        assert resolved.source == f"user:{user_id}"
        assert resolved.user_id == user_id

    async def test_role_targeted_assignment_wins_over_untargeted_but_not_user(
        self,
    ) -> None:
        service, _repo, user_lookup, role_lookup = _build_service_with_targeting()
        org = service.organization_lookup.add()
        base_policy = await _create_published_session_policy(
            service, organization_id=org.id
        )
        await service.create_assignment(
            policy_id=base_policy.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
            scope_type=ScopeType.ORGANIZATION.value,
            scope_id=org.id,
            priority=0,
        )

        role_policy = await _create_published_session_policy(
            service, organization_id=org.id
        )
        role_id = uuid.uuid4()
        role_lookup.known_role_ids.add(role_id)
        await service.create_assignment(
            policy_id=role_policy.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
            scope_type=ScopeType.GLOBAL.value,
            scope_id=None,
            priority=0,
            target_type=PolicyAssignmentTargetType.ROLE.value,
            target_id=role_id,
        )

        user_id = uuid.uuid4()
        user_lookup.known_user_ids.add(user_id)
        resolved = await service.resolve_effective_policy(
            policy_type=PolicyType.SESSION,
            organization_id=org.id,
            location_id=None,
            user_id=user_id,
            role_ids=[role_id],
        )
        assert resolved.source == f"role:{role_id}"

        # A user-targeted assignment on yet a third policy must still beat
        # the role-targeted one.
        user_policy = await _create_published_session_policy(
            service, organization_id=org.id
        )
        await service.create_assignment(
            policy_id=user_policy.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
            scope_type=ScopeType.GLOBAL.value,
            scope_id=None,
            priority=0,
            target_type=PolicyAssignmentTargetType.USER.value,
            target_id=user_id,
        )
        resolved_again = await service.resolve_effective_policy(
            policy_type=PolicyType.SESSION,
            organization_id=org.id,
            location_id=None,
            user_id=user_id,
            role_ids=[role_id],
        )
        assert resolved_again.source == f"user:{user_id}"

    async def test_role_assignment_not_a_candidate_for_a_different_role(self) -> None:
        service, _repo, _user_lookup, role_lookup = _build_service_with_targeting()
        org = service.organization_lookup.add()
        policy = await _create_published_session_policy(service, organization_id=org.id)
        role_id = uuid.uuid4()
        role_lookup.known_role_ids.add(role_id)
        await service.create_assignment(
            policy_id=policy.id,
            requesting_organization_id=org.id,
            actor_user_id=None,
            scope_type=ScopeType.GLOBAL.value,
            scope_id=None,
            priority=0,
            target_type=PolicyAssignmentTargetType.ROLE.value,
            target_id=role_id,
        )

        resolved = await service.resolve_effective_policy(
            policy_type=PolicyType.SESSION,
            organization_id=org.id,
            location_id=None,
            user_id=uuid.uuid4(),
            role_ids=[uuid.uuid4()],
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
