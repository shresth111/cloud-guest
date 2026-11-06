"""Front-desk staff may unblock a guest at their own venue -- and nowhere else.

The customer dashboard now offers "Unblock" on a blocked guest's row to
venue-scoped staff (owner decision, 2026-10-31). The seeded front-desk roles
(Reception Staff, Guest Operator, Location Manager) already hold
``guest_access.update`` at LOCATION scope, which is what
``POST /guest-access/{rules,device-rules}/{id}/deactivate`` checks, so no new
permission key is needed. What this file pins is the *boundary*:

* the deactivate routes check at an explicit LOCATION scope, so the caller's
  headers cannot choose the check level;
* a venue grant satisfies that check for its own venue only;
* the rule must be at one of the caller's venues (the service compares the
  rule's ``location_id`` against the caller's *grants*, not a header);
* an organization-wide rule (``location_id IS NULL``, a ban at every venue)
  cannot be lifted by a venue-confined caller -- the gap this change closes;
* the unblock still goes through the same device-release path as the owner's.
"""

from __future__ import annotations

import uuid

import pytest

from app.domains.guest_access.constants import AccessRuleType
from app.domains.guest_access.exceptions import (
    CrossLocationAccessRuleError,
    CrossOrganizationAccessRuleError,
    OrganizationWideRuleScopeError,
)
from app.domains.guest_access.router import router as guest_access_router
from app.domains.guest_access.service import GuestAccessService
from app.domains.rbac.authorization import ScopeResolver
from app.domains.rbac.context import GrantScope, ScopeContext
from app.domains.rbac.enums import PermissionModule, ScopeType
from app.domains.rbac.seed import SYSTEM_ROLES
from tests.unit.test_guest_access import (
    FakeAuditLogWriter,
    FakeGuestAccessRepository,
    FakeLocationLookup,
)

# ---------------------------------------------------------------------------
# Who holds what (seed facts the dashboard relies on)
# ---------------------------------------------------------------------------


def _role(slug: str):
    return next(r for r in SYSTEM_ROLES if r.slug == slug)


def _guest_access_actions(slug: str) -> set[str]:
    grants = _role(slug).grants()
    return {a.value for a in grants.get(PermissionModule.GUEST_ACCESS, ())}


class TestSeededGrants:
    @pytest.mark.parametrize(
        "slug", ["reception-staff", "guest-operator", "location-manager"]
    )
    def test_front_desk_roles_can_unblock_at_location_scope(self, slug: str) -> None:
        assert _role(slug).scope_type == ScopeType.LOCATION
        assert "update" in _guest_access_actions(slug)
        # OPERATE never includes delete: staff unblock, they do not erase
        # the record that the guest was ever blocked.
        assert "delete" not in _guest_access_actions(slug)

    def test_helpdesk_is_read_only_and_cannot_unblock(self) -> None:
        assert _guest_access_actions("helpdesk") == {"read"}


# ---------------------------------------------------------------------------
# The route's check level is fixed, not chosen by the caller's headers
# ---------------------------------------------------------------------------


def _permission_and_scope(path: str) -> tuple[str | None, ScopeType | None]:
    route = next(
        r
        for r in guest_access_router.routes
        if getattr(r, "path", None) == path and "POST" in getattr(r, "methods", ())
    )
    for dependency in route.dependant.dependencies:
        call = dependency.call
        freevars = getattr(call.__code__, "co_freevars", ())
        if "permission_key" in freevars:
            key = call.__closure__[freevars.index("permission_key")].cell_contents
            scope = call.__closure__[freevars.index("scope")].cell_contents
            return key, scope
    return None, None


@pytest.mark.parametrize(
    "path",
    [
        "/guest-access/rules/{rule_id}/deactivate",
        "/guest-access/device-rules/{rule_id}/deactivate",
    ],
)
def test_deactivate_routes_check_update_at_explicit_location_scope(path: str) -> None:
    assert _permission_and_scope(path) == ("guest_access.update", ScopeType.LOCATION)


class TestCheckLevel:
    org = uuid.uuid4()
    site_a = uuid.uuid4()
    site_b = uuid.uuid4()

    def test_staff_grant_satisfies_its_own_venue(self) -> None:
        grant = GrantScope(scope_type=ScopeType.LOCATION, location_id=self.site_a)
        ctx = ScopeContext(organization_id=self.org, location_id=self.site_a)
        assert ScopeResolver.satisfies(grant, ScopeType.LOCATION, ctx) is True

    def test_staff_grant_does_not_satisfy_another_venue(self) -> None:
        grant = GrantScope(scope_type=ScopeType.LOCATION, location_id=self.site_a)
        ctx = ScopeContext(organization_id=self.org, location_id=self.site_b)
        assert ScopeResolver.satisfies(grant, ScopeType.LOCATION, ctx) is False

    def test_staff_grant_without_a_venue_header_is_refused(self) -> None:
        grant = GrantScope(scope_type=ScopeType.LOCATION, location_id=self.site_a)
        ctx = ScopeContext(organization_id=self.org)
        assert ScopeResolver.satisfies(grant, ScopeType.LOCATION, ctx) is False

    def test_owner_grant_still_satisfies_with_only_the_org_header(self) -> None:
        grant = GrantScope(scope_type=ScopeType.ORGANIZATION, organization_id=self.org)
        ctx = ScopeContext(organization_id=self.org)
        assert ScopeResolver.satisfies(grant, ScopeType.LOCATION, ctx) is True


# ---------------------------------------------------------------------------
# Service: which rules a venue-confined caller may lift
# ---------------------------------------------------------------------------


class _World:
    def __init__(self) -> None:
        self.repo = FakeGuestAccessRepository()
        self.org = uuid.uuid4()
        self.other_org = uuid.uuid4()
        self.site_a = uuid.uuid4()
        self.site_b = uuid.uuid4()
        self.other_site = uuid.uuid4()
        self.lookup = FakeLocationLookup()
        self.lookup.add(self.site_a, self.org)
        self.lookup.add(self.site_b, self.org)
        self.lookup.add(self.other_site, self.other_org)
        self.actor = uuid.uuid4()

    def service(self, scope: frozenset[uuid.UUID] | None) -> GuestAccessService:
        return GuestAccessService(
            self.repo,
            block_enforcer=None,
            location_lookup=self.lookup,
            audit_writer=FakeAuditLogWriter(),
            caller_location_scope=scope,
        )

    @property
    def owner(self) -> GuestAccessService:
        return self.service(None)

    @property
    def staff_a(self) -> GuestAccessService:
        return self.service(frozenset({self.site_a}))

    async def guest_block(self, org: uuid.UUID, location: uuid.UUID | None):
        return await self.owner.create_guest_rule(
            organization_id=org,
            requesting_organization_id=org,
            location_id=location,
            identifier="+919812345678",
            rule_type=AccessRuleType.BLOCKLIST,
            reason=None,
            expires_at=None,
            actor_user_id=self.actor,
        )

    async def device_block(self, org: uuid.UUID, location: uuid.UUID | None):
        return await self.owner.create_device_rule(
            organization_id=org,
            requesting_organization_id=org,
            location_id=location,
            mac_address="AA:BB:CC:DD:EE:01",
            rule_type=AccessRuleType.BLOCKLIST,
            reason=None,
            expires_at=None,
            actor_user_id=self.actor,
        )


def _spy(service: GuestAccessService, name: str) -> list[object]:
    """Record calls to the device-release step while keeping its behaviour."""
    calls: list[object] = []
    original = getattr(service, name)

    async def _wrapped(rule):
        calls.append(rule.id)
        return await original(rule)

    setattr(service, name, _wrapped)
    return calls


class TestGuestRuleUnblock:
    async def test_staff_unblocks_a_guest_at_their_own_venue(self) -> None:
        w = _World()
        rule = await w.guest_block(w.org, w.site_a)
        staff = w.staff_a
        released = _spy(staff, "_release_controller_blocks")

        out = await staff.deactivate_guest_rule(
            rule_id=rule.id, requesting_organization_id=w.org, actor_user_id=w.actor
        )

        assert out.is_active is False
        # Same device path the owner's unblock takes -- not a new one.
        assert released == [rule.id]

    async def test_staff_cannot_unblock_at_another_venue_of_the_same_org(self) -> None:
        w = _World()
        rule = await w.guest_block(w.org, w.site_b)

        with pytest.raises(CrossLocationAccessRuleError) as exc:
            await w.staff_a.deactivate_guest_rule(
                rule_id=rule.id, requesting_organization_id=w.org, actor_user_id=w.actor
            )
        assert exc.value.status_code == 403
        assert w.repo.guest_rules[rule.id].is_active is True

    async def test_staff_cannot_unblock_in_another_organization(self) -> None:
        w = _World()
        rule = await w.guest_block(w.other_org, w.other_site)

        with pytest.raises(CrossOrganizationAccessRuleError) as exc:
            await w.staff_a.deactivate_guest_rule(
                rule_id=rule.id, requesting_organization_id=w.org, actor_user_id=w.actor
            )
        assert exc.value.status_code == 403
        assert w.repo.guest_rules[rule.id].is_active is True

    async def test_staff_cannot_lift_an_organization_wide_ban(self) -> None:
        w = _World()
        rule = await w.guest_block(w.org, None)
        staff = w.staff_a
        released = _spy(staff, "_release_controller_blocks")

        with pytest.raises(OrganizationWideRuleScopeError) as exc:
            await staff.deactivate_guest_rule(
                rule_id=rule.id, requesting_organization_id=w.org, actor_user_id=w.actor
            )
        assert exc.value.status_code == 403
        assert w.repo.guest_rules[rule.id].is_active is True
        # Refused before any device was touched.
        assert released == []

    async def test_staff_still_reads_the_organization_wide_ban(self) -> None:
        # The read side is unchanged: it applies at their venue, so they see it.
        w = _World()
        rule = await w.guest_block(w.org, None)
        got = await w.staff_a.get_guest_rule(rule.id, requesting_organization_id=w.org)
        assert got.id == rule.id

    async def test_staff_cannot_re_enforce_or_delete_an_organization_wide_ban(
        self,
    ) -> None:
        w = _World()
        rule = await w.guest_block(w.org, None)
        with pytest.raises(OrganizationWideRuleScopeError):
            await w.staff_a.enforce_guest_rule(
                rule_id=rule.id, requesting_organization_id=w.org, actor_user_id=w.actor
            )
        with pytest.raises(OrganizationWideRuleScopeError):
            await w.staff_a.delete_guest_rule(
                rule_id=rule.id, requesting_organization_id=w.org, actor_user_id=w.actor
            )
        assert rule.id in w.repo.guest_rules

    @pytest.mark.parametrize("where", ["site_a", "site_b", None])
    async def test_owner_unblock_is_unchanged(self, where: str | None) -> None:
        w = _World()
        rule = await w.guest_block(w.org, getattr(w, where) if where else None)
        out = await w.owner.deactivate_guest_rule(
            rule_id=rule.id, requesting_organization_id=w.org, actor_user_id=w.actor
        )
        assert out.is_active is False


class TestDeviceRuleUnblock:
    async def test_staff_unblocks_a_device_at_their_own_venue(self) -> None:
        w = _World()
        rule = await w.device_block(w.org, w.site_a)
        staff = w.staff_a
        released = _spy(staff, "_release_router_blocks")

        out = await staff.deactivate_device_rule(
            rule_id=rule.id, requesting_organization_id=w.org, actor_user_id=w.actor
        )

        assert out.is_active is False
        assert released == [rule.id]

    async def test_staff_cannot_unblock_a_device_at_another_venue(self) -> None:
        w = _World()
        rule = await w.device_block(w.org, w.site_b)
        with pytest.raises(CrossLocationAccessRuleError):
            await w.staff_a.deactivate_device_rule(
                rule_id=rule.id, requesting_organization_id=w.org, actor_user_id=w.actor
            )
        assert w.repo.device_rules[rule.id].is_active is True

    async def test_staff_cannot_lift_an_organization_wide_device_ban(self) -> None:
        w = _World()
        rule = await w.device_block(w.org, None)
        with pytest.raises(OrganizationWideRuleScopeError):
            await w.staff_a.deactivate_device_rule(
                rule_id=rule.id, requesting_organization_id=w.org, actor_user_id=w.actor
            )
        assert w.repo.device_rules[rule.id].is_active is True

    async def test_owner_device_unblock_is_unchanged(self) -> None:
        w = _World()
        rule = await w.device_block(w.org, None)
        out = await w.owner.deactivate_device_rule(
            rule_id=rule.id, requesting_organization_id=w.org, actor_user_id=w.actor
        )
        assert out.is_active is False
