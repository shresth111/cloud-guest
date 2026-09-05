"""A caller confined to one site must not reach another site's resources.

The class this closes is the one RBAC structurally cannot: resources reached by
their **own** id. ``DELETE /firewall-rules/{rule_id}`` names no organization,
no location and no router, so ``RequirePermission`` has nothing to pin the
check to -- a LOCATION-scoped grant on the caller's own site satisfies it --
and the service then compared only ``rule.organization_id``. Five domains
sampled carried ~100 organization comparisons between them and zero location
comparisons.

``firewall`` is the worked example and the shape the other domains follow.

## The failure mode to guard against is not a leak

It is locking real users out of their own data. An organization administrator
browsing site A still owns site B, and an ``X-Location-Id`` header says what
they are *looking at*, not what they are *entitled to*. So the confinement is
derived from the caller's role assignments, and every test below checks all
three actor kinds -- platform, organization, location -- rather than assuming
symmetry. The GLOBAL case is the one least likely to appear in fixtures and
the most damaging to get wrong.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.domains.firewall.exceptions import (
    CrossLocationFirewallRuleAccessError,
    CrossOrganizationFirewallRuleAccessError,
)
from app.domains.firewall.service import FirewallService
from app.domains.rbac.enums import ScopeType
from app.domains.rbac.location_scope import (
    CallerLocationScope,
    enforce_entity_location,
)

# ---------------------------------------------------------------------------
# Deriving the confinement from the caller's grants
# ---------------------------------------------------------------------------


class _Repo:
    """Matches what ``RoleResolver.get_active_assignments`` reads."""

    def __init__(self, rows) -> None:
        self._rows = rows

    async def get_active_user_roles(self, user_id, *, now=None):
        return self._rows


def _row(scope_type: ScopeType, *, location_id=None):
    return SimpleNamespace(
        scope_type=scope_type.value,
        location_id=location_id,
        organization_id=None,
        router_id=None,
        role=SimpleNamespace(is_active=True, is_deleted=False),
    )


class TestConfinementIsDerivedFromGrants:
    async def test_a_global_operator_is_unconfined(self) -> None:
        """The case least likely to be in a fixture and most damaging to get
        wrong: platform and support callers must keep working."""
        scope = await CallerLocationScope(
            user=SimpleNamespace(id=str(uuid.uuid4())),
            repository=_Repo([_row(ScopeType.GLOBAL)]),
        )
        assert scope is None

    async def test_an_organization_admin_is_unconfined(self) -> None:
        """They own every site in the organization; confining them to whichever
        one they happen to be viewing would be the lockout failure."""
        scope = await CallerLocationScope(
            user=SimpleNamespace(id=str(uuid.uuid4())),
            repository=_Repo([_row(ScopeType.ORGANIZATION)]),
        )
        assert scope is None

    async def test_a_location_scoped_account_is_confined_to_its_sites(self) -> None:
        site_a, site_b = uuid.uuid4(), uuid.uuid4()
        scope = await CallerLocationScope(
            user=SimpleNamespace(id=str(uuid.uuid4())),
            repository=_Repo(
                [
                    _row(ScopeType.LOCATION, location_id=site_a),
                    _row(ScopeType.LOCATION, location_id=site_b),
                ]
            ),
        )
        assert scope == frozenset({site_a, site_b})

    async def test_one_broad_role_unconfines_a_caller_who_also_holds_a_narrow_one(
        self,
    ) -> None:
        """A regional manager with an organization role *and* a site role is
        entitled to the whole organization. Intersecting would lock them out of
        sites they administer."""
        scope = await CallerLocationScope(
            user=SimpleNamespace(id=str(uuid.uuid4())),
            repository=_Repo(
                [
                    _row(ScopeType.LOCATION, location_id=uuid.uuid4()),
                    _row(ScopeType.ORGANIZATION),
                ]
            ),
        )
        assert scope is None

    async def test_a_caller_with_no_assignments_is_confined_to_nothing(self) -> None:
        """They hold no permissions either, so `RequirePermission` refused them
        long before any service saw this."""
        scope = await CallerLocationScope(
            user=SimpleNamespace(id=str(uuid.uuid4())), repository=_Repo([])
        )
        assert scope == frozenset()


class TestTheGuardItself:
    def test_an_unconfined_caller_passes(self) -> None:
        enforce_entity_location(
            entity_location_id=uuid.uuid4(),
            caller_location_scope=None,
            error=AssertionError("must not raise for an unconfined caller"),
        )

    def test_a_confined_caller_reaches_its_own_site(self) -> None:
        site = uuid.uuid4()
        enforce_entity_location(
            entity_location_id=site,
            caller_location_scope=frozenset({site}),
            error=AssertionError("must not raise for the caller's own site"),
        )

    def test_a_confined_caller_is_refused_another_site(self) -> None:
        with pytest.raises(CrossLocationFirewallRuleAccessError):
            enforce_entity_location(
                entity_location_id=uuid.uuid4(),
                caller_location_scope=frozenset({uuid.uuid4()}),
                error=CrossLocationFirewallRuleAccessError(),
            )

    def test_a_row_with_no_location_is_not_refused(self) -> None:
        """An organization-wide record has no site to compare, and refusing it
        would be the lockout failure again."""
        enforce_entity_location(
            entity_location_id=None,
            caller_location_scope=frozenset({uuid.uuid4()}),
            error=AssertionError("must not raise for a location-less row"),
        )


# ---------------------------------------------------------------------------
# The worked example, through the real service
# ---------------------------------------------------------------------------

_ORG = uuid.uuid4()
_SITE_A = uuid.uuid4()
_SITE_B = uuid.uuid4()


def _rule(location_id, *, organization_id=_ORG):
    return SimpleNamespace(
        id=uuid.uuid4(),
        organization_id=organization_id,
        location_id=location_id,
        router_id=uuid.uuid4(),
    )


class _FirewallRepo:
    def __init__(self, rule) -> None:
        self._rule = rule
        self.list_calls: list[dict] = []

    async def get_rule_by_id(self, rule_id, *, include_deleted=False):
        return self._rule

    async def list_rules(self, **kwargs):
        self.list_calls.append(kwargs)
        return [], SimpleNamespace(total_items=0)


def _service(rule) -> tuple[FirewallService, _FirewallRepo]:
    repo = _FirewallRepo(rule)
    return FirewallService(repo, router_lookup=None), repo


class TestFirewallRuleAccess:
    async def test_a_site_a_account_cannot_read_a_site_b_rule(self) -> None:
        """The worked example. Both rules are in the caller's own organization,
        so the organization comparison sees nothing wrong."""
        service, _ = _service(_rule(_SITE_B))

        with pytest.raises(CrossLocationFirewallRuleAccessError):
            await service.get_rule(
                uuid.uuid4(),
                requesting_organization_id=_ORG,
                caller_location_scope=frozenset({_SITE_A}),
            )

    async def test_a_site_a_account_cannot_delete_a_site_b_rule(self) -> None:
        """The write matters more than the read: this is network security
        configuration on someone else's site."""
        service, _ = _service(_rule(_SITE_B))

        with pytest.raises(CrossLocationFirewallRuleAccessError):
            await service.delete_rule(
                uuid.uuid4(),
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=_ORG,
                caller_location_scope=frozenset({_SITE_A}),
            )

    async def test_a_site_a_account_still_reaches_its_own_rule(self) -> None:
        service, _ = _service(_rule(_SITE_A))

        rule = await service.get_rule(
            uuid.uuid4(),
            requesting_organization_id=_ORG,
            caller_location_scope=frozenset({_SITE_A}),
        )

        assert rule.location_id == _SITE_A

    async def test_an_organization_admin_reaches_every_site(self) -> None:
        """`None` confinement -- the lockout guard."""
        service, _ = _service(_rule(_SITE_B))

        rule = await service.get_rule(
            uuid.uuid4(),
            requesting_organization_id=_ORG,
            caller_location_scope=None,
        )

        assert rule.location_id == _SITE_B

    async def test_a_platform_operator_reaches_every_site_and_tenant(self) -> None:
        service, _ = _service(_rule(_SITE_B, organization_id=uuid.uuid4()))

        rule = await service.get_rule(
            uuid.uuid4(), requesting_organization_id=None, caller_location_scope=None
        )

        assert rule is not None

    async def test_the_organization_boundary_still_takes_precedence(self) -> None:
        """A foreign *tenant's* rule is refused as cross-organization, not
        quietly reclassified as a location problem."""
        service, _ = _service(_rule(_SITE_A, organization_id=uuid.uuid4()))

        with pytest.raises(CrossOrganizationFirewallRuleAccessError):
            await service.get_rule(
                uuid.uuid4(),
                requesting_organization_id=_ORG,
                caller_location_scope=frozenset({_SITE_A}),
            )


class TestFirewallRuleListing:
    async def test_a_confined_caller_only_lists_its_own_sites(self) -> None:
        """A list is filtered rather than refused: asking for a list is a
        legitimate request whose answer is simply narrower."""
        service, repo = _service(None)

        await service.list_rules(
            requesting_organization_id=_ORG,
            caller_location_scope=frozenset({_SITE_A}),
        )

        assert repo.list_calls[0]["location_ids"] == frozenset({_SITE_A})

    async def test_an_unconfined_caller_lists_everything(self) -> None:
        service, repo = _service(None)

        await service.list_rules(
            requesting_organization_id=_ORG, caller_location_scope=None
        )

        assert repo.list_calls[0]["location_ids"] is None


def test_every_firewall_route_resolves_the_callers_confinement() -> None:
    """Structural: the service cannot enforce what the route never passes it,
    and the enforcement defaults to `None` (unconfined) so a route that forgets
    fails open. This is what makes forgetting visible."""
    from app.domains.rbac.location_scope import CallerLocationScope as _Dep
    from app.main import create_app

    def calls(dependant):
        found = {d.call for d in dependant.dependencies}
        for d in dependant.dependencies:
            found |= calls(d)
        return found

    missing = []
    for route in create_app().routes:
        path = getattr(route, "path", "")
        if not path.startswith("/api/v1/firewall-rules"):
            continue
        if _Dep not in calls(route.dependant):
            missing.append(f"{sorted(getattr(route, 'methods', []))} {path}")

    assert not missing, f"firewall routes not resolving CallerLocationScope: {missing}"
