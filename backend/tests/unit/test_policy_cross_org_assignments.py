"""Cross-organization policy assignments (shared policy code, every vendor).

Defect: ``PolicyService.create_assignment`` checked only that the caller could
*see* the policy. Everything the request BODY names -- ``target_id`` (a guest,
role), ``scope_id`` (an organization, location), or ``scope_type=global`` --
was trusted, so org A could map org B's guest into A's tier (at MikroTik/Omada
that sets B's guest's speed), attach its policy to B's organization/location,
or make it a GLOBAL candidate for every tenant. Resolution applied whatever
matched. And "one guest, one tier" was checked platform-wide, so a foreign
row blocked the owning org and the 409 disclosed the foreign policy id.

Write side: every entry point is checked (path ``policy_id``, body
``scope_id``/``target_id``; there is no bulk endpoint -- pinned structurally
below). Read side: foreign-org candidates are ignored in
``resolve_effective_policy``. Uniqueness: per organization.
"""

from __future__ import annotations

import uuid

import pytest

from app.domains.location.exceptions import CrossOrganizationLocationAccessError
from app.domains.policy.constants import PolicyAssignmentTargetType, PolicyType
from app.domains.policy.exceptions import (
    CrossOrganizationPolicyAccessError,
    PolicyAssignmentGuestAlreadyMappedError,
    PolicyAssignmentTargetGuestNotFoundError,
    PolicyAssignmentTargetRoleNotFoundError,
)
from app.domains.policy.repository import PolicyRepository
from app.domains.policy.router import router as policy_router
from app.domains.policy.service import PolicyService
from app.domains.rbac.enums import ScopeType
from tests.unit.test_policy import (
    FakeAuditLogWriter,
    FakeLocationLookup,
    FakeOrganizationLookup,
    FakePolicyRepository,
    FakeUserLookup,
    _create_published_bandwidth_policy,
)


class FakeGuestLookup:
    def __init__(self) -> None:
        self.guests: dict[uuid.UUID, uuid.UUID] = {}

    def add(self, organization_id: uuid.UUID) -> uuid.UUID:
        guest_id = uuid.uuid4()
        self.guests[guest_id] = organization_id
        return guest_id

    async def get_guest_organization_id(self, guest_id: uuid.UUID) -> uuid.UUID | None:
        return self.guests.get(guest_id)


class FakeOrgRole:
    def __init__(self, organization_id: uuid.UUID | None) -> None:
        self.id = uuid.uuid4()
        self.organization_id = organization_id


class FakeRoleLookupWithOrg:
    def __init__(self) -> None:
        self.roles: dict[uuid.UUID, FakeOrgRole] = {}

    def add(self, organization_id: uuid.UUID | None) -> uuid.UUID:
        role = FakeOrgRole(organization_id)
        self.roles[role.id] = role
        return role.id

    async def get_role_by_id(
        self, role_id: uuid.UUID, *, include_deleted: bool = False
    ) -> FakeOrgRole | None:
        return self.roles.get(role_id)


class World:
    def __init__(self) -> None:
        self.repo = FakePolicyRepository()
        self.orgs = FakeOrganizationLookup()
        self.locations = FakeLocationLookup()
        self.guests = FakeGuestLookup()
        self.roles = FakeRoleLookupWithOrg()
        self.service = PolicyService(
            self.repo,
            self.orgs,
            self.locations,
            audit_writer=FakeAuditLogWriter(),
            user_lookup=FakeUserLookup(),
            role_lookup=self.roles,
            guest_lookup=self.guests,
        )
        self.org_a = self.orgs.add()
        self.org_b = self.orgs.add()

    async def tier(
        self, org_id: uuid.UUID | None, name: str = "Tier", kbps: int = 1024
    ):
        return await _create_published_bandwidth_policy(
            self.service, organization_id=org_id, name=name, download_rate_kbps=kbps
        )

    async def assign(
        self,
        policy,
        *,
        requester,
        scope_type,
        scope_id=None,
        target_type="none",
        target_id=None,
    ):
        return await self.service.create_assignment(
            policy_id=policy.id,
            requesting_organization_id=requester,
            actor_user_id=None,
            scope_type=scope_type,
            scope_id=scope_id,
            priority=0,
            target_type=target_type,
            target_id=target_id,
        )

    async def resolve(self, org_id, location_id, guest_id):
        return await self.service.resolve_effective_policy(
            policy_type=PolicyType.BANDWIDTH,
            organization_id=org_id,
            location_id=location_id,
            guest_id=guest_id,
        )


GUEST = PolicyAssignmentTargetType.GUEST.value
LOC = ScopeType.LOCATION.value


# ---------------------------------------------------------------------------
# Write side
# ---------------------------------------------------------------------------


class TestPathEntryPoint:
    async def test_cannot_assign_another_orgs_policy(self) -> None:
        w = World()
        b_tier = await w.tier(w.org_b.id)
        loc_a = w.locations.add(organization_id=w.org_a.id)
        with pytest.raises(CrossOrganizationPolicyAccessError):
            await w.assign(
                b_tier, requester=w.org_a.id, scope_type=LOC, scope_id=loc_a.id
            )


class TestBodyEntryPoint:
    async def test_foreign_guest_target_is_404(self) -> None:
        w = World()
        a_tier = await w.tier(w.org_a.id)
        loc_a = w.locations.add(organization_id=w.org_a.id)
        b_guest = w.guests.add(w.org_b.id)
        with pytest.raises(PolicyAssignmentTargetGuestNotFoundError) as exc:
            await w.assign(
                a_tier,
                requester=w.org_a.id,
                scope_type=LOC,
                scope_id=loc_a.id,
                target_type=GUEST,
                target_id=b_guest,
            )
        assert exc.value.status_code == 404
        assert w.repo.assignments == {}

    async def test_foreign_guest_target_via_global_scope_is_404(self) -> None:
        w = World()
        a_tier = await w.tier(w.org_a.id)
        b_guest = w.guests.add(w.org_b.id)
        with pytest.raises(PolicyAssignmentTargetGuestNotFoundError):
            await w.assign(
                a_tier,
                requester=w.org_a.id,
                scope_type=ScopeType.GLOBAL.value,
                target_type=GUEST,
                target_id=b_guest,
            )

    async def test_platform_caller_cannot_map_foreign_guest_into_org_policy(
        self,
    ) -> None:
        """The owner is the policy's org, not the caller: a Master caller
        (no org) still cannot cross-wire tenants."""
        w = World()
        a_tier = await w.tier(w.org_a.id)
        loc_a = w.locations.add(organization_id=w.org_a.id)
        b_guest = w.guests.add(w.org_b.id)
        with pytest.raises(PolicyAssignmentTargetGuestNotFoundError):
            await w.assign(
                a_tier,
                requester=None,
                scope_type=LOC,
                scope_id=loc_a.id,
                target_type=GUEST,
                target_id=b_guest,
            )

    async def test_unknown_guest_is_404(self) -> None:
        w = World()
        a_tier = await w.tier(w.org_a.id)
        loc_a = w.locations.add(organization_id=w.org_a.id)
        with pytest.raises(PolicyAssignmentTargetGuestNotFoundError):
            await w.assign(
                a_tier,
                requester=w.org_a.id,
                scope_type=LOC,
                scope_id=loc_a.id,
                target_type=GUEST,
                target_id=uuid.uuid4(),
            )

    async def test_foreign_organization_scope_is_403(self) -> None:
        w = World()
        a_tier = await w.tier(w.org_a.id)
        with pytest.raises(CrossOrganizationPolicyAccessError):
            await w.assign(
                a_tier,
                requester=w.org_a.id,
                scope_type=ScopeType.ORGANIZATION.value,
                scope_id=w.org_b.id,
            )

    async def test_foreign_location_scope_is_rejected_even_for_platform_caller(
        self,
    ) -> None:
        w = World()
        a_tier = await w.tier(w.org_a.id)
        loc_b = w.locations.add(organization_id=w.org_b.id)
        with pytest.raises(CrossOrganizationLocationAccessError):
            await w.assign(a_tier, requester=None, scope_type=LOC, scope_id=loc_b.id)

    async def test_org_policy_cannot_be_global_untargeted(self) -> None:
        w = World()
        a_tier = await w.tier(w.org_a.id)
        with pytest.raises(CrossOrganizationPolicyAccessError):
            await w.assign(
                a_tier, requester=w.org_a.id, scope_type=ScopeType.GLOBAL.value
            )

    async def test_org_caller_cannot_aim_platform_policy_at_another_org(self) -> None:
        w = World()
        platform_tier = await w.tier(None)
        loc_b = w.locations.add(organization_id=w.org_b.id)
        b_guest = w.guests.add(w.org_b.id)
        with pytest.raises(CrossOrganizationLocationAccessError):
            await w.assign(
                platform_tier, requester=w.org_a.id, scope_type=LOC, scope_id=loc_b.id
            )
        with pytest.raises(CrossOrganizationPolicyAccessError):
            await w.assign(
                platform_tier, requester=w.org_a.id, scope_type=ScopeType.GLOBAL.value
            )
        with pytest.raises(PolicyAssignmentTargetGuestNotFoundError):
            await w.assign(
                platform_tier,
                requester=w.org_a.id,
                scope_type=ScopeType.GLOBAL.value,
                target_type=GUEST,
                target_id=b_guest,
            )

    async def test_foreign_role_target_is_404(self) -> None:
        w = World()
        a_tier = await w.tier(w.org_a.id)
        loc_a = w.locations.add(organization_id=w.org_a.id)
        b_role = w.roles.add(w.org_b.id)
        with pytest.raises(PolicyAssignmentTargetRoleNotFoundError):
            await w.assign(
                a_tier,
                requester=w.org_a.id,
                scope_type=LOC,
                scope_id=loc_a.id,
                target_type=PolicyAssignmentTargetType.ROLE.value,
                target_id=b_role,
            )

    async def test_same_org_writes_still_work(self) -> None:
        w = World()
        a_tier = await w.tier(w.org_a.id)
        loc_a = w.locations.add(organization_id=w.org_a.id)
        a_guest = w.guests.add(w.org_a.id)
        system_role = w.roles.add(None)
        await w.assign(a_tier, requester=w.org_a.id, scope_type=LOC, scope_id=loc_a.id)
        await w.assign(
            a_tier,
            requester=w.org_a.id,
            scope_type=ScopeType.ORGANIZATION.value,
            scope_id=w.org_a.id,
        )
        await w.assign(
            a_tier,
            requester=w.org_a.id,
            scope_type=LOC,
            scope_id=loc_a.id,
            target_type=GUEST,
            target_id=a_guest,
        )
        await w.assign(
            a_tier,
            requester=w.org_a.id,
            scope_type=LOC,
            scope_id=loc_a.id,
            target_type=PolicyAssignmentTargetType.ROLE.value,
            target_id=system_role,
        )
        assert len(w.repo.assignments) == 4

    async def test_msp_parent_may_map_a_direct_childs_guest(self) -> None:
        w = World()
        child = w.orgs.add()
        child.parent_organization_id = w.org_a.id
        a_tier = await w.tier(w.org_a.id)
        child_guest = w.guests.add(child.id)
        await w.assign(
            a_tier,
            requester=w.org_a.id,
            scope_type=ScopeType.GLOBAL.value,
            target_type=GUEST,
            target_id=child_guest,
        )

    async def test_platform_policy_by_platform_caller_is_unrestricted(self) -> None:
        w = World()
        platform_tier = await w.tier(None)
        await w.assign(platform_tier, requester=None, scope_type=ScopeType.GLOBAL.value)


class TestNoBulkEntryPoint:
    def test_create_assignment_is_the_only_assignment_writer(self) -> None:
        """There is no bulk assignment endpoint: the dashboard's "Map guests"
        posts one assignment per guest to this route, which goes through
        ``PolicyService.create_assignment`` (checked above). If a bulk or
        update route is ever added it must reuse that method -- this test
        fails so whoever adds it has to look."""
        writers = {
            (method, route.path)
            for route in policy_router.routes
            for method in getattr(route, "methods", set())
            if method in {"POST", "PUT", "PATCH"} and "assignment" in route.path
        }
        assert writers == {("POST", "/policies/{policy_id}/assignments")}


# ---------------------------------------------------------------------------
# Read side (defense in depth): rows written before the checks existed
# ---------------------------------------------------------------------------


async def _raw_assignment(w: World, policy, **fields):
    return await w.repo.create_assignment(
        policy_id=policy.id,
        priority=0,
        is_active=True,
        created_by_user_id=None,
        **fields,
    )


class TestResolutionIgnoresForeignAssignments:
    async def test_foreign_guest_targeted_tier_is_ignored(self) -> None:
        w = World()
        loc_b = w.locations.add(organization_id=w.org_b.id)
        b_guest = w.guests.add(w.org_b.id)
        b_tier = await w.tier(w.org_b.id, name="B venue", kbps=5000)
        await _raw_assignment(w, b_tier, scope_type=LOC, scope_id=loc_b.id)
        a_tier = await w.tier(w.org_a.id, name="A hostile", kbps=1)
        await _raw_assignment(
            w,
            a_tier,
            scope_type=LOC,
            scope_id=loc_b.id,
            target_type=GUEST,
            target_id=b_guest,
        )

        resolved = await w.resolve(w.org_b.id, loc_b.id, b_guest)
        assert resolved.rules["download_rate_kbps"] == 5000
        assert resolved.source == f"location:{loc_b.id}"

    async def test_foreign_global_untargeted_row_is_ignored(self) -> None:
        w = World()
        a_tier = await w.tier(w.org_a.id, kbps=1)
        await _raw_assignment(w, a_tier, scope_type=ScopeType.GLOBAL.value)
        resolved = await w.resolve(w.org_b.id, None, None)
        assert resolved.source == "platform_default"

    async def test_platform_caller_resolving_a_location_also_filters(self) -> None:
        w = World()
        loc_b = w.locations.add(organization_id=w.org_b.id)
        b_guest = w.guests.add(w.org_b.id)
        a_tier = await w.tier(w.org_a.id, kbps=1)
        await _raw_assignment(
            w,
            a_tier,
            scope_type=LOC,
            scope_id=loc_b.id,
            target_type=GUEST,
            target_id=b_guest,
        )
        resolved = await w.resolve(None, loc_b.id, b_guest)
        assert resolved.source == "platform_default"

    async def test_same_org_and_platform_and_msp_parent_still_apply(self) -> None:
        w = World()
        loc_a = w.locations.add(organization_id=w.org_a.id)
        a_guest = w.guests.add(w.org_a.id)
        a_tier = await w.tier(w.org_a.id, kbps=777)
        await w.assign(
            a_tier,
            requester=w.org_a.id,
            scope_type=LOC,
            scope_id=loc_a.id,
            target_type=GUEST,
            target_id=a_guest,
        )
        resolved = await w.resolve(w.org_a.id, loc_a.id, a_guest)
        assert resolved.rules["download_rate_kbps"] == 777

        platform_tier = await w.tier(None, kbps=55)
        await _raw_assignment(w, platform_tier, scope_type=ScopeType.GLOBAL.value)
        resolved = await w.resolve(w.org_b.id, None, None)
        assert resolved.rules["download_rate_kbps"] == 55

        child = w.orgs.add()
        child.parent_organization_id = w.org_a.id
        child_guest = w.guests.add(child.id)
        await w.assign(
            a_tier,
            requester=w.org_a.id,
            scope_type=ScopeType.GLOBAL.value,
            target_type=GUEST,
            target_id=child_guest,
        )
        resolved = await w.resolve(child.id, None, child_guest)
        assert resolved.source == f"guest:{child_guest}"


# ---------------------------------------------------------------------------
# One guest, one tier -- per organization
# ---------------------------------------------------------------------------


class TestOneGuestOneTierIsPerOrganization:
    async def test_foreign_row_neither_blocks_nor_leaks(self) -> None:
        w = World()
        loc_b = w.locations.add(organization_id=w.org_b.id)
        b_guest = w.guests.add(w.org_b.id)
        a_tier = await w.tier(w.org_a.id)
        await _raw_assignment(
            w,
            a_tier,
            scope_type=LOC,
            scope_id=loc_b.id,
            target_type=GUEST,
            target_id=b_guest,
        )

        assert (
            await w.service.get_guest_group_assignment(
                guest_id=b_guest, requesting_organization_id=w.org_b.id
            )
            is None
        )
        b_tier = await w.tier(w.org_b.id)
        created = await w.assign(
            b_tier,
            requester=w.org_b.id,
            scope_type=LOC,
            scope_id=loc_b.id,
            target_type=GUEST,
            target_id=b_guest,
        )
        assert created.policy_id == b_tier.id

    async def test_same_org_second_tier_is_still_409(self) -> None:
        w = World()
        loc_a = w.locations.add(organization_id=w.org_a.id)
        a_guest = w.guests.add(w.org_a.id)
        first = await w.tier(w.org_a.id, name="Gold")
        second = await w.tier(w.org_a.id, name="Silver")
        await w.assign(
            first,
            requester=w.org_a.id,
            scope_type=LOC,
            scope_id=loc_a.id,
            target_type=GUEST,
            target_id=a_guest,
        )
        with pytest.raises(PolicyAssignmentGuestAlreadyMappedError):
            await w.assign(
                second,
                requester=w.org_a.id,
                scope_type=LOC,
                scope_id=loc_a.id,
                target_type=GUEST,
                target_id=a_guest,
            )


class TestRealRepositoryQueries:
    """The fakes above mirror these; pin the real SQL shape too."""

    def test_uniqueness_query_filters_by_policy_org(self) -> None:
        import inspect

        src = inspect.getsource(PolicyRepository.find_active_target_assignment)
        assert "Policy.organization_id == organization_id" in src

    def test_guest_lookup_reads_guests_table_only(self) -> None:
        from app.domains.policy import repository as repo_module

        assert repo_module._guests.name == "guests"
        assert {"id", "organization_id", "is_deleted"} <= set(
            repo_module._guests.c.keys()
        )

    def test_dependency_wires_the_guest_lookup(self) -> None:
        from app.domains.policy.dependencies import get_policy_service

        repo = PolicyRepository.__new__(PolicyRepository)
        service = get_policy_service(
            repository=repo,
            organization_service=object(),
            location_service=object(),
            audit_repository=object(),
            user_repository=object(),
        )
        assert service.guest_lookup is repo
