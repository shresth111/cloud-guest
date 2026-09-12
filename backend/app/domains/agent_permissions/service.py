"""Agent permission management service.

Returns suggested roles, permission tree structure, and allows permission
assignment to router agents and admin users — composing the existing RBAC
service.
"""

from __future__ import annotations

import logging
import uuid

from app.domains.rbac.enums import OverrideEffect, ScopeType
from app.domains.rbac.service import RBACService

from .schemas import (
    AgentPermissionAssignRequest,
    AgentPermissionAssignResponse,
    PermissionTreeNode,
    PermissionTreeResponse,
    SuggestedRole,
    SuggestedRoleListResponse,
)

logger = logging.getLogger(__name__)

class AgentPermissionService:
    """Reads and writes the **real** RBAC tables.

    Every method here previously returned invented data:

    * ``get_suggested_roles`` served a hardcoded eight-entry Python list whose
      slugs (``super_admin``, ``read_only``) did not even match the seeded ones
      (``super-admin``, ``read-only``), and fell back to a literal
      ``perm_count = 10`` whenever the lookup it wrapped in ``except Exception``
      failed -- which it did, since it compared on ``name`` and never used the
      role's own id.
    * ``get_permission_tree`` returned a hand-written literal tree rather than
      the ``permission_groups``/``permissions`` rows the platform actually
      authorizes against, so it drifted from reality the moment either changed.
    * ``assign_agent_permissions`` looped over ``role_ids`` calling
      ``get_role`` inside ``contextlib.suppress(Exception)``, discarded the
      result, **persisted nothing**, and returned "Permissions assigned to
      agent". An operator granting a staff member access saw success and no
      access changed.

    The RBAC service has supported all three properly all along.
    """

    def __init__(self, rbac_service: RBACService) -> None:
        self.rbac_service = rbac_service

    async def get_suggested_roles(
        self, *, requesting_organization_id: uuid.UUID | None = None
    ) -> SuggestedRoleListResponse:
        """The roles that actually exist, with their real permission counts.

        Scoped through ``RBACService.list_roles``, so a tenant caller is never
        offered the platform-operator roles (Super Admin, Platform Admin, ...)
        that its own users could not legally hold -- the hardcoded list offered
        exactly those to everyone.
        """
        roles = await self.rbac_service.list_roles(
            requesting_organization_id=requesting_organization_id,
            is_active=True,
        )
        return SuggestedRoleListResponse(
            roles=[
                SuggestedRole(
                    id=str(role.id),
                    name=role.name,
                    slug=role.slug,
                    description=role.description,
                    permission_count=len(role.role_permissions),
                    is_system_role=role.is_system_role,
                    scope_type=role.scope_type,
                )
                for role in roles
            ]
        )

    async def get_permission_tree(self) -> PermissionTreeResponse:
        """The real permission catalogue, grouped by its own permission groups."""
        groups = await self.rbac_service.list_permission_groups()
        permissions = await self.rbac_service.list_permissions()

        by_group: dict[uuid.UUID, list[PermissionTreeNode]] = {}
        for permission in permissions:
            if not permission.is_active:
                continue
            by_group.setdefault(permission.permission_group_id, []).append(
                PermissionTreeNode(
                    id=str(permission.id),
                    key=permission.key,
                    name=permission.name,
                    description=permission.description,
                )
            )

        return PermissionTreeResponse(
            tree=[
                PermissionTreeNode(
                    id=str(group.id),
                    key=group.key,
                    name=group.name,
                    description=group.description,
                    children=sorted(
                        by_group.get(group.id, []), key=lambda node: node.key
                    ),
                )
                for group in groups
                if group.is_active
            ]
        )

    async def assign_agent_permissions(
        self,
        agent_id: uuid.UUID,
        request: AgentPermissionAssignRequest,
        *,
        actor_user_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> AgentPermissionAssignResponse:
        """Actually assigns the roles and permission overrides, or raises.

        Roles go through ``assign_role_to_user`` and individual permission
        keys through ``grant_permission_override`` -- both of which write real
        rows, write their own audit entries, and enforce their own tenant and
        escalation guards (``grant_permission_override`` refuses an ALLOW the
        actor could not itself exercise). Nothing here is suppressed: a role
        that does not exist, is inactive, or belongs to another tenant now
        fails the request instead of being silently skipped.
        """
        scope_type = (
            ScopeType.ORGANIZATION
            if requesting_organization_id is not None
            else ScopeType.GLOBAL
        )

        for role_id in request.role_ids or []:
            await self.rbac_service.assign_role_to_user(
                actor_user_id=actor_user_id,
                target_user_id=agent_id,
                role_id=uuid.UUID(role_id),
                scope_type=scope_type,
                requesting_organization_id=requesting_organization_id,
                organization_id=requesting_organization_id,
            )

        for permission_key in request.permission_keys:
            await self.rbac_service.grant_permission_override(
                actor_user_id=actor_user_id,
                target_user_id=agent_id,
                permission_key=permission_key,
                effect=OverrideEffect.ALLOW,
                scope_type=scope_type,
                organization_id=requesting_organization_id,
                reason="Granted via agent permission assignment",
            )

        return AgentPermissionAssignResponse(
            agent_id=str(agent_id),
            assigned_permissions=request.permission_keys,
            message=(
                f"Assigned {len(request.role_ids or [])} role(s) and "
                f"{len(request.permission_keys)} permission override(s)"
            ),
        )
