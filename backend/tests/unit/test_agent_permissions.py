"""Unit tests for ``app.domains.agent_permissions``.

This domain had no test file, which is how all three of its methods came to
return or accept fiction:

* ``get_suggested_roles`` served a hardcoded eight-entry list whose slugs
  (``super_admin``, ``read_only``) did not match the seeded ones
  (``super-admin``, ``read-only``), with a literal ``perm_count = 10``
  fallback.
* ``get_permission_tree`` returned a hand-written literal tree instead of the
  permission rows the platform authorizes against.
* ``assign_agent_permissions`` called ``get_role`` inside
  ``contextlib.suppress(Exception)``, threw the result away, **persisted
  nothing**, and returned "Permissions assigned to agent" -- behind a
  ``roles.assign`` gate, so an operator granting a staff member access saw
  success and nothing changed.

Plain-``assert``/native-``async def`` style, in-memory fakes, no live
Postgres -- same convention as the rest of this suite.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from app.domains.agent_permissions.schemas import AgentPermissionAssignRequest
from app.domains.agent_permissions.service import AgentPermissionService
from app.domains.rbac.enums import OverrideEffect, ScopeType


def _role(*, name: str, slug: str, permission_count: int = 0, scope="organization"):
    return SimpleNamespace(
        id=uuid.uuid4(),
        name=name,
        slug=slug,
        description=None,
        role_permissions=[object()] * permission_count,
        is_system_role=True,
        scope_type=scope,
    )


class _FakeRBACService:
    def __init__(self, roles=None, groups=None, permissions=None) -> None:
        self._roles = roles or []
        self._groups = groups or []
        self._permissions = permissions or []
        self.assigned_roles: list[dict] = []
        self.granted_overrides: list[dict] = []
        self.raise_on_assign: Exception | None = None

    async def list_roles(self, *, requesting_organization_id, is_active=None):
        return self._roles

    async def list_permission_groups(self):
        return self._groups

    async def list_permissions(self, *, permission_group_id=None):
        return self._permissions

    async def assign_role_to_user(self, **kwargs):
        if self.raise_on_assign is not None:
            raise self.raise_on_assign
        self.assigned_roles.append(kwargs)
        return SimpleNamespace(id=uuid.uuid4())

    async def grant_permission_override(self, **kwargs):
        self.granted_overrides.append(kwargs)
        return SimpleNamespace(id=uuid.uuid4())


class TestSuggestedRolesAreReal:
    async def test_roles_come_from_rbac_not_a_hardcoded_list(self) -> None:
        rbac = _FakeRBACService(
            roles=[_role(name="Reception Staff", slug="reception-staff")]
        )
        service = AgentPermissionService(rbac_service=rbac)

        response = await service.get_suggested_roles()

        assert [r.slug for r in response.roles] == ["reception-staff"]

    async def test_slugs_are_the_seeded_hyphenated_ones(self) -> None:
        """The hardcoded list used underscores, so nothing a client sent back
        matched a real role."""
        rbac = _FakeRBACService(roles=[_role(name="Read Only", slug="read-only")])
        service = AgentPermissionService(rbac_service=rbac)

        response = await service.get_suggested_roles()

        assert response.roles[0].slug == "read-only"
        assert "_" not in response.roles[0].slug

    async def test_permission_count_is_counted_not_the_literal_ten(self) -> None:
        rbac = _FakeRBACService(
            roles=[_role(name="Helpdesk", slug="helpdesk", permission_count=4)]
        )
        service = AgentPermissionService(rbac_service=rbac)

        response = await service.get_suggested_roles()

        assert response.roles[0].permission_count == 4

    async def test_role_id_is_a_real_uuid_not_the_slug(self) -> None:
        """``id=sr["slug"]`` meant a client could never assign what it was
        offered -- ``assign_role_to_user`` takes a UUID."""
        role = _role(name="Helpdesk", slug="helpdesk")
        service = AgentPermissionService(rbac_service=_FakeRBACService(roles=[role]))

        response = await service.get_suggested_roles()

        assert response.roles[0].id == str(role.id)
        uuid.UUID(response.roles[0].id)


class TestPermissionTreeIsReal:
    async def test_tree_is_built_from_permission_rows(self) -> None:
        group = SimpleNamespace(
            id=uuid.uuid4(),
            key="guests",
            name="Guests",
            description=None,
            is_active=True,
        )
        permission = SimpleNamespace(
            id=uuid.uuid4(),
            permission_group_id=group.id,
            key="guest_users.read",
            name="Read guests",
            description=None,
            is_active=True,
        )
        service = AgentPermissionService(
            rbac_service=_FakeRBACService(groups=[group], permissions=[permission])
        )

        response = await service.get_permission_tree()

        assert [n.key for n in response.tree] == ["guests"]
        assert [c.key for c in response.tree[0].children] == ["guest_users.read"]

    async def test_inactive_permissions_are_left_out(self) -> None:
        group = SimpleNamespace(
            id=uuid.uuid4(), key="g", name="G", description=None, is_active=True
        )
        service = AgentPermissionService(
            rbac_service=_FakeRBACService(
                groups=[group],
                permissions=[
                    SimpleNamespace(
                        id=uuid.uuid4(),
                        permission_group_id=group.id,
                        key="dead.perm",
                        name="Dead",
                        description=None,
                        is_active=False,
                    )
                ],
            )
        )

        response = await service.get_permission_tree()

        assert response.tree[0].children == []


class TestAssignmentActuallyPersists:
    async def test_roles_are_really_assigned(self) -> None:
        """The bug: this returned success having written nothing."""
        rbac = _FakeRBACService()
        service = AgentPermissionService(rbac_service=rbac)
        agent_id, actor_id, org_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        role_id = uuid.uuid4()

        await service.assign_agent_permissions(
            agent_id,
            AgentPermissionAssignRequest(
                permission_keys=[], role_ids=[str(role_id)]
            ),
            actor_user_id=actor_id,
            requesting_organization_id=org_id,
        )

        assert len(rbac.assigned_roles) == 1
        call = rbac.assigned_roles[0]
        assert call["target_user_id"] == agent_id
        assert call["role_id"] == role_id
        assert call["actor_user_id"] == actor_id
        assert call["requesting_organization_id"] == org_id
        assert call["scope_type"] == ScopeType.ORGANIZATION

    async def test_permission_keys_become_real_allow_overrides(self) -> None:
        rbac = _FakeRBACService()
        service = AgentPermissionService(rbac_service=rbac)

        await service.assign_agent_permissions(
            uuid.uuid4(),
            AgentPermissionAssignRequest(permission_keys=["guest_users.read"]),
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=uuid.uuid4(),
        )

        assert len(rbac.granted_overrides) == 1
        assert rbac.granted_overrides[0]["permission_key"] == "guest_users.read"
        assert rbac.granted_overrides[0]["effect"] == OverrideEffect.ALLOW

    async def test_a_platform_caller_assigns_at_global_scope(self) -> None:
        rbac = _FakeRBACService()
        service = AgentPermissionService(rbac_service=rbac)

        await service.assign_agent_permissions(
            uuid.uuid4(),
            AgentPermissionAssignRequest(
                permission_keys=[], role_ids=[str(uuid.uuid4())]
            ),
            actor_user_id=uuid.uuid4(),
            requesting_organization_id=None,
        )

        assert rbac.assigned_roles[0]["scope_type"] == ScopeType.GLOBAL

    async def test_a_failing_assignment_raises_instead_of_reporting_success(
        self,
    ) -> None:
        """``contextlib.suppress(Exception)`` meant a missing, inactive or
        cross-tenant role was silently skipped and still reported as assigned."""
        rbac = _FakeRBACService()
        rbac.raise_on_assign = RuntimeError("role does not exist")
        service = AgentPermissionService(rbac_service=rbac)

        with pytest.raises(RuntimeError):
            await service.assign_agent_permissions(
                uuid.uuid4(),
                AgentPermissionAssignRequest(
                    permission_keys=[], role_ids=[str(uuid.uuid4())]
                ),
                actor_user_id=uuid.uuid4(),
                requesting_organization_id=uuid.uuid4(),
            )


def test_assign_route_resolves_the_actor_and_organization() -> None:
    """Structural: without both, the service cannot scope or audit the write,
    which is how it ended up writing nothing at all."""
    from app.domains.rbac.dependencies import CurrentOrganization, CurrentUser
    from app.main import create_app

    def calls(dependant):
        found = {d.call for d in dependant.dependencies}
        for d in dependant.dependencies:
            found |= calls(d)
        return found

    route = next(
        r
        for r in create_app().routes
        if getattr(r, "path", None) == "/api/v1/agents/{agent_id}/permissions"
        and "POST" in getattr(r, "methods", set())
    )
    resolved = calls(route.dependant)
    assert CurrentUser in resolved
    assert CurrentOrganization in resolved
