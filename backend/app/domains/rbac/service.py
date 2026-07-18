"""RBAC business logic: role CRUD, cloning, assignment, and permission overrides.

Every validation rule called out in the module brief lives here (duplicate
roles, circular parent-role hierarchies, invalid scope assignment,
unauthorized role escalation, cross-tenant access, and privilege escalation
via permission overrides), and every mutation that can change a user's
effective permissions calls through to :class:`PermissionCache` invalidation
and :meth:`RBACRepositoryProtocol.create_audit_log_entry`.

Design note on escalation checks: this module never asks "is the assigner a
Super Admin". Instead it asks two purely data-driven questions -- "does the
assigner's own effective permission set already cover everything the role/
override would grant, at this scope?" and, for override-granting only,
"does the assigner hold the dedicated `permissions.manage` permission at
GLOBAL scope?" (the documented, non-hardcoded stand-in for "super-admin-like
authority over permissions", since the Super Admin system role happens to be
seeded with that permission, along with everything else). See
RBAC_ARCHITECTURE.md.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from app.common.exceptions import CloudGuestError

from .authorization import AccessValidator
from .cache import PermissionCache
from .context import ScopeContext
from .enums import AuditAction, OverrideEffect, ScopeType
from .exceptions import (
    CircularRoleHierarchyError,
    CrossTenantAccessError,
    DuplicateRoleError,
    InvalidScopeAssignmentError,
    OverrideEscalationError,
    PermissionGroupNotFoundError,
    PermissionNotFoundError,
    RoleEscalationError,
    RoleInactiveError,
    RoleNotCloneableError,
    RoleNotFoundError,
    SystemRoleImmutableError,
    UserRoleAssignmentNotFoundError,
)
from .models import (
    OrganizationRole,
    Permission,
    PermissionGroup,
    PermissionOverride,
    Role,
    RolePermission,
    UserRole,
)
from .repository import RBACRepositoryProtocol

logger = logging.getLogger(__name__)

_ROLE_ASSIGN_PERMISSION = "roles.assign"
_PERMISSION_OVERRIDE_ASSIGN_PERMISSION = "permissions.assign"
_PERMISSION_MANAGE_BYPASS_PERMISSION = "permissions.manage"


class RBACService:
    """Core RBAC business logic, composed on top of :class:`AccessValidator`."""

    def __init__(
        self,
        repository: RBACRepositoryProtocol,
        cache: PermissionCache | None = None,
    ) -> None:
        self.repository = repository
        self.cache = cache
        self.access_validator = AccessValidator(repository, cache=cache)
        self.resolver = self.access_validator.resolver

    # -- permission groups / permissions (read-mostly; seeded data) ----------

    async def list_permission_groups(self) -> list[PermissionGroup]:
        return await self.repository.list_permission_groups()

    async def list_permissions(
        self, *, permission_group_id: uuid.UUID | None = None
    ) -> list[Permission]:
        if permission_group_id is not None:
            group = await self.repository.get_permission_group_by_id(
                permission_group_id
            )
            if group is None:
                raise PermissionGroupNotFoundError(permission_group_id)
        return await self.repository.list_permissions(
            permission_group_id=permission_group_id
        )

    # -- role reads ------------------------------------------------------------

    async def list_roles(
        self,
        *,
        requesting_organization_id: uuid.UUID | None,
        scope_type: ScopeType | None = None,
        is_active: bool | None = None,
    ) -> list[Role]:
        return await self.repository.list_roles(
            organization_id=requesting_organization_id,
            include_global=True,
            scope_type=scope_type,
            is_active=is_active,
        )

    async def get_role(
        self, role_id: uuid.UUID, *, requesting_organization_id: uuid.UUID | None
    ) -> Role:
        role = await self.repository.get_role_by_id(role_id)
        if role is None:
            raise RoleNotFoundError(role_id)
        self._enforce_role_tenant_access(role, requesting_organization_id)
        return role

    def _enforce_role_tenant_access(
        self, role: Role, requesting_organization_id: uuid.UUID | None
    ) -> None:
        """A caller acting within organization A must never see/mutate a
        role scoped to organization B. Global (organization_id IS NULL)
        roles are visible to everyone."""
        if role.organization_id is None:
            return
        if (
            requesting_organization_id is None
            or role.organization_id != requesting_organization_id
        ):
            raise CrossTenantAccessError()

    # -- role writes -----------------------------------------------------------

    async def create_role(
        self,
        *,
        actor_user_id: uuid.UUID,
        name: str,
        slug: str,
        description: str | None,
        scope_type: ScopeType,
        organization_id: uuid.UUID | None,
        requesting_organization_id: uuid.UUID | None,
        parent_role_id: uuid.UUID | None = None,
        is_template: bool = False,
        permission_keys: list[str] | None = None,
        allowed_scope_types: list[ScopeType] | None = None,
    ) -> Role:
        if (
            organization_id is not None
            and requesting_organization_id is not None
            and organization_id != requesting_organization_id
        ):
            raise CrossTenantAccessError()

        existing = await self.repository.get_role_by_slug(slug, organization_id)
        if existing is not None:
            raise DuplicateRoleError(slug, organization_id)

        if parent_role_id is not None:
            parent = await self.repository.get_role_by_id(parent_role_id)
            if parent is None:
                raise RoleNotFoundError(parent_role_id)

        role = await self.repository.create_role(
            name=name,
            slug=slug,
            description=description,
            is_system_role=False,
            is_template=is_template,
            is_active=True,
            scope_type=scope_type.value,
            organization_id=organization_id,
            parent_role_id=parent_role_id,
            created_by=actor_user_id,
        )

        for allowed in allowed_scope_types or []:
            await self.repository.add_role_scope(role.id, allowed)

        for permission_key in permission_keys or []:
            await self._attach_permission(
                role, permission_key, granted_by=actor_user_id
            )

        await self._audit(
            actor_user_id,
            AuditAction.ROLE_CREATED,
            entity_type="role",
            entity_id=role.id,
            description=f"Role '{role.name}' created",
            organization_id=organization_id,
        )
        return role

    async def update_role(
        self,
        *,
        actor_user_id: uuid.UUID,
        role_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        data: dict[str, object],
    ) -> Role:
        role = await self.get_role(
            role_id, requesting_organization_id=requesting_organization_id
        )

        if role.is_system_role and ({"name", "slug", "scope_type"} & data.keys()):
            raise SystemRoleImmutableError(role.name, "renamed or rescoped")

        new_parent_id = data.get("parent_role_id")
        if new_parent_id is not None:
            await self._assert_no_cycle(role.id, new_parent_id)  # type: ignore[arg-type]

        updated = await self.repository.update_role(
            role, {**data, "updated_by": actor_user_id}
        )
        await self._invalidate_role_holders(role.id)
        await self._audit(
            actor_user_id,
            AuditAction.ROLE_UPDATED,
            entity_type="role",
            entity_id=role.id,
            description=f"Role '{role.name}' updated",
            organization_id=role.organization_id,
        )
        return updated

    async def delete_role(
        self,
        *,
        actor_user_id: uuid.UUID,
        role_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> None:
        role = await self.get_role(
            role_id, requesting_organization_id=requesting_organization_id
        )
        if role.is_system_role:
            raise SystemRoleImmutableError(role.name, "deleted")

        affected_users = await self.repository.get_user_ids_with_role(role.id)
        await self.repository.soft_delete_role(role)
        await self._invalidate_users(affected_users)
        await self._audit(
            actor_user_id,
            AuditAction.ROLE_DELETED,
            entity_type="role",
            entity_id=role.id,
            description=f"Role '{role.name}' deleted",
            organization_id=role.organization_id,
        )

    async def set_role_active(
        self,
        *,
        actor_user_id: uuid.UUID,
        role_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        is_active: bool,
    ) -> Role:
        role = await self.get_role(
            role_id, requesting_organization_id=requesting_organization_id
        )
        updated = await self.repository.update_role(
            role, {"is_active": is_active, "updated_by": actor_user_id}
        )
        await self._invalidate_role_holders(role.id)
        await self._audit(
            actor_user_id,
            AuditAction.ROLE_ACTIVATED if is_active else AuditAction.ROLE_DEACTIVATED,
            entity_type="role",
            entity_id=role.id,
            description=(
                f"Role '{role.name}' " f"{'activated' if is_active else 'deactivated'}"
            ),
            organization_id=role.organization_id,
        )
        return updated

    async def clone_role(
        self,
        *,
        actor_user_id: uuid.UUID,
        source_role_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
        new_name: str,
        new_slug: str,
        target_organization_id: uuid.UUID | None = None,
    ) -> Role:
        source = await self.get_role(
            source_role_id, requesting_organization_id=requesting_organization_id
        )
        if not (source.is_system_role or source.is_template):
            raise RoleNotCloneableError(source.name)

        if (
            target_organization_id is not None
            and requesting_organization_id is not None
            and target_organization_id != requesting_organization_id
        ):
            raise CrossTenantAccessError()

        existing = await self.repository.get_role_by_slug(
            new_slug, target_organization_id
        )
        if existing is not None:
            raise DuplicateRoleError(new_slug, target_organization_id)

        clone = await self.repository.create_role(
            name=new_name,
            slug=new_slug,
            description=source.description,
            is_system_role=False,
            is_template=False,
            is_active=True,
            scope_type=source.scope_type,
            organization_id=target_organization_id,
            parent_role_id=source.id,
            created_by=actor_user_id,
        )

        for scope_type_value in await self.repository.get_role_scope_types(source.id):
            await self.repository.add_role_scope(clone.id, ScopeType(scope_type_value))

        for row in await self.repository.get_role_permissions(source.id):
            if row.permission is not None and row.permission.is_active:
                await self.repository.add_role_permission(
                    clone.id, row.permission_id, granted_by=actor_user_id
                )

        await self._audit(
            actor_user_id,
            AuditAction.ROLE_CLONED,
            entity_type="role",
            entity_id=clone.id,
            description=f"Role '{clone.name}' cloned from '{source.name}'",
            organization_id=target_organization_id,
            metadata={"source_role_id": str(source.id)},
        )
        return clone

    async def _assert_no_cycle(
        self, role_id: uuid.UUID, proposed_parent_id: uuid.UUID
    ) -> None:
        if proposed_parent_id == role_id:
            raise CircularRoleHierarchyError(role_id, proposed_parent_id)
        max_depth = 50
        chain = await self.repository.get_parent_chain(
            proposed_parent_id, max_depth=max_depth
        )
        if any(ancestor.id == role_id for ancestor in chain):
            raise CircularRoleHierarchyError(role_id, proposed_parent_id)

    # -- role <-> permission assignment ----------------------------------------

    async def assign_permission_to_role(
        self,
        *,
        actor_user_id: uuid.UUID,
        role_id: uuid.UUID,
        permission_key: str,
        requesting_organization_id: uuid.UUID | None,
    ) -> RolePermission:
        role = await self.get_role(
            role_id, requesting_organization_id=requesting_organization_id
        )
        if role.is_system_role:
            raise SystemRoleImmutableError(
                role.name, "modified directly (clone it instead)"
            )
        row = await self._attach_permission(
            role, permission_key, granted_by=actor_user_id
        )
        await self._invalidate_role_holders(role.id)
        await self._audit(
            actor_user_id,
            AuditAction.PERMISSION_ASSIGNED,
            entity_type="role",
            entity_id=role.id,
            description=f"Permission '{permission_key}' assigned to role '{role.name}'",
            organization_id=role.organization_id,
        )
        return row

    async def remove_permission_from_role(
        self,
        *,
        actor_user_id: uuid.UUID,
        role_id: uuid.UUID,
        permission_key: str,
        requesting_organization_id: uuid.UUID | None,
    ) -> None:
        role = await self.get_role(
            role_id, requesting_organization_id=requesting_organization_id
        )
        if role.is_system_role:
            raise SystemRoleImmutableError(
                role.name, "modified directly (clone it instead)"
            )
        permission = await self.repository.get_permission_by_key(permission_key)
        if permission is None:
            raise PermissionNotFoundError(permission_key)
        removed = await self.repository.remove_role_permission(role.id, permission.id)
        if not removed:
            raise PermissionNotFoundError(permission_key)
        await self._invalidate_role_holders(role.id)
        await self._audit(
            actor_user_id,
            AuditAction.PERMISSION_REMOVED,
            entity_type="role",
            entity_id=role.id,
            description=(
                f"Permission '{permission_key}' removed from role '{role.name}'"
            ),
            organization_id=role.organization_id,
        )

    async def _attach_permission(
        self, role: Role, permission_key: str, *, granted_by: uuid.UUID | None
    ) -> RolePermission:
        permission = await self.repository.get_permission_by_key(permission_key)
        if permission is None:
            raise PermissionNotFoundError(permission_key)

        allowed_scopes = await self.repository.get_permission_scope_types(permission.id)
        if allowed_scopes and role.scope_type not in allowed_scopes:
            raise InvalidScopeAssignmentError(
                f"Permission '{permission_key}' is not applicable at "
                f"'{role.scope_type}' scope (valid scopes: {', '.join(allowed_scopes)})"
            )
        return await self.repository.add_role_permission(
            role.id, permission.id, granted_by=granted_by
        )

    # -- user <-> role assignment -----------------------------------------------

    async def assign_role_to_user(
        self,
        *,
        actor_user_id: uuid.UUID,
        target_user_id: uuid.UUID,
        role_id: uuid.UUID,
        scope_type: ScopeType,
        requesting_organization_id: uuid.UUID | None,
        organization_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        router_id: uuid.UUID | None = None,
        expires_at: datetime | None = None,
    ) -> UserRole:
        role = await self.get_role(
            role_id, requesting_organization_id=requesting_organization_id
        )
        if not role.is_active:
            raise RoleInactiveError(role.name)

        if (
            organization_id is not None
            and requesting_organization_id is not None
            and organization_id != requesting_organization_id
        ):
            raise CrossTenantAccessError()

        await self._validate_scope_assignment(
            role,
            scope_type,
            organization_id=organization_id,
            location_id=location_id,
            router_id=router_id,
        )

        target_context = ScopeContext(
            organization_id=organization_id,
            location_id=location_id,
            router_id=router_id,
        )
        await self.access_validator.check(
            actor_user_id,
            _ROLE_ASSIGN_PERMISSION,
            scope_type=scope_type,
            scope_context=target_context,
        )
        await self._assert_no_role_escalation(
            actor_user_id, role, scope_type, target_context
        )

        assignment = await self.repository.create_user_role(
            user_id=target_user_id,
            role_id=role.id,
            scope_type=scope_type.value,
            organization_id=organization_id,
            location_id=location_id,
            router_id=router_id,
            granted_at=datetime.now(UTC),
            granted_by=actor_user_id,
            expires_at=expires_at,
            is_active=True,
        )
        await self._invalidate_users([target_user_id])
        await self._audit(
            actor_user_id,
            AuditAction.ROLE_ASSIGNED,
            entity_type="user_role",
            entity_id=assignment.id,
            description=f"Role '{role.name}' assigned to user {target_user_id}",
            organization_id=organization_id,
            location_id=location_id,
            metadata={"target_user_id": str(target_user_id), "role_id": str(role.id)},
        )
        return assignment

    async def revoke_role_from_user(
        self,
        *,
        actor_user_id: uuid.UUID,
        assignment_id: uuid.UUID,
        requesting_organization_id: uuid.UUID | None,
    ) -> None:
        assignment = await self.repository.get_user_role_assignment(assignment_id)
        if assignment is None:
            raise UserRoleAssignmentNotFoundError(assignment_id)
        if (
            assignment.organization_id is not None
            and requesting_organization_id is not None
            and assignment.organization_id != requesting_organization_id
        ):
            raise CrossTenantAccessError()

        await self.repository.deactivate_user_role(assignment)
        await self._invalidate_users([assignment.user_id])
        await self._audit(
            actor_user_id,
            AuditAction.ROLE_REVOKED,
            entity_type="user_role",
            entity_id=assignment.id,
            description=f"Role assignment {assignment.id} revoked",
            organization_id=assignment.organization_id,
            location_id=assignment.location_id,
            metadata={"target_user_id": str(assignment.user_id)},
        )

    async def _validate_scope_assignment(
        self,
        role: Role,
        scope_type: ScopeType,
        *,
        organization_id: uuid.UUID | None,
        location_id: uuid.UUID | None,
        router_id: uuid.UUID | None,
    ) -> None:
        allowed_scopes = await self.repository.get_role_scope_types(role.id)
        permitted = set(allowed_scopes) | {role.scope_type}
        if scope_type.value not in permitted:
            raise InvalidScopeAssignmentError(
                f"Role '{role.name}' cannot be assigned at '{scope_type.value}' scope "
                f"(permitted: {', '.join(sorted(permitted))})"
            )

        required_id_by_scope = {
            ScopeType.ORGANIZATION: organization_id,
            ScopeType.LOCATION: location_id,
            ScopeType.ROUTER: router_id,
        }
        if (
            scope_type in required_id_by_scope
            and required_id_by_scope[scope_type] is None
        ):
            raise InvalidScopeAssignmentError(
                f"Assigning at '{scope_type.value}' scope requires a matching "
                "identifier"
            )

    async def _assert_no_role_escalation(
        self,
        actor_user_id: uuid.UUID,
        role: Role,
        scope_type: ScopeType,
        target_context: ScopeContext,
    ) -> None:
        """The assigner must already effectively hold every permission the
        target role grants, at a scope covering the assignment -- otherwise
        they could hand out access broader than their own."""
        role_permission_keys = await self.resolver.resolve_role_permission_keys(role.id)
        for permission_key in role_permission_keys:
            has_it = await self.access_validator.has_permission(
                actor_user_id,
                permission_key,
                scope_type=scope_type,
                scope_context=target_context,
            )
            if not has_it:
                raise RoleEscalationError(
                    f"Cannot assign role '{role.name}': it grants '{permission_key}', "
                    "which you do not hold at the requested scope"
                )

    # -- permission overrides -------------------------------------------------

    async def get_user_permissions(self, user_id: uuid.UUID) -> set[str]:
        grants = await self.access_validator.get_effective_grants(user_id)
        return grants.permission_keys()

    async def grant_permission_override(
        self,
        *,
        actor_user_id: uuid.UUID,
        target_user_id: uuid.UUID,
        permission_key: str,
        effect: OverrideEffect,
        scope_type: ScopeType = ScopeType.GLOBAL,
        organization_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        router_id: uuid.UUID | None = None,
        reason: str | None = None,
        expires_at: datetime | None = None,
    ) -> PermissionOverride:
        permission = await self.repository.get_permission_by_key(permission_key)
        if permission is None:
            raise PermissionNotFoundError(permission_key)

        override_context = ScopeContext(
            organization_id=organization_id,
            location_id=location_id,
            router_id=router_id,
        )
        await self.access_validator.check(
            actor_user_id,
            _PERMISSION_OVERRIDE_ASSIGN_PERMISSION,
            scope_type=scope_type,
            scope_context=override_context,
        )

        if effect == OverrideEffect.ALLOW:
            already_has_it = await self.access_validator.has_permission(
                actor_user_id,
                permission_key,
                scope_type=scope_type,
                scope_context=override_context,
            )
            has_manage_bypass = await self.access_validator.has_permission(
                actor_user_id,
                _PERMISSION_MANAGE_BYPASS_PERMISSION,
                scope_type=ScopeType.GLOBAL,
                scope_context=ScopeContext.global_scope(),
            )
            if not already_has_it and not has_manage_bypass:
                raise OverrideEscalationError(
                    f"Cannot grant an ALLOW override for '{permission_key}': "
                    "you do not effectively hold it yourself"
                )

        override = await self.repository.create_permission_override(
            user_id=target_user_id,
            permission_id=permission.id,
            effect=effect.value,
            scope_type=scope_type.value,
            organization_id=organization_id,
            location_id=location_id,
            router_id=router_id,
            reason=reason,
            granted_at=datetime.now(UTC),
            granted_by=actor_user_id,
            expires_at=expires_at,
            is_active=True,
        )
        await self._invalidate_users([target_user_id])
        await self._audit(
            actor_user_id,
            AuditAction.PERMISSION_OVERRIDE_GRANTED,
            entity_type="permission_override",
            entity_id=override.id,
            description=(
                f"Permission override ({effect.value}) for '{permission_key}' "
                f"granted to user {target_user_id}"
            ),
            organization_id=organization_id,
            location_id=location_id,
            metadata={
                "target_user_id": str(target_user_id),
                "permission_key": permission_key,
            },
        )
        return override

    async def revoke_permission_override(
        self, *, actor_user_id: uuid.UUID, override_id: uuid.UUID
    ) -> None:
        overrides = await self.repository.get_permission_override_by_id(override_id)
        if overrides is None:
            raise PermissionNotFoundError(override_id)
        await self.access_validator.check(
            actor_user_id,
            _PERMISSION_OVERRIDE_ASSIGN_PERMISSION,
            scope_type=ScopeType(overrides.scope_type),
            scope_context=ScopeContext(
                organization_id=overrides.organization_id,
                location_id=overrides.location_id,
                router_id=overrides.router_id,
            ),
        )
        await self.repository.deactivate_permission_override(overrides)
        await self._invalidate_users([overrides.user_id])
        await self._audit(
            actor_user_id,
            AuditAction.PERMISSION_OVERRIDE_REVOKED,
            entity_type="permission_override",
            entity_id=overrides.id,
            description=f"Permission override {overrides.id} revoked",
            organization_id=overrides.organization_id,
            location_id=overrides.location_id,
        )

    # -- organization / location role configuration ----------------------------

    async def set_organization_role_config(
        self,
        *,
        organization_id: uuid.UUID,
        role_id: uuid.UUID,
        is_enabled: bool = True,
        is_default_for_new_members: bool = False,
    ) -> OrganizationRole:
        return await self.repository.upsert_organization_role(
            organization_id=organization_id,
            role_id=role_id,
            is_enabled=is_enabled,
            is_default_for_new_members=is_default_for_new_members,
        )

    # -- internal helpers -------------------------------------------------------

    async def _invalidate_role_holders(self, role_id: uuid.UUID) -> None:
        if self.cache is None:
            return
        user_ids = await self.repository.get_user_ids_with_role(role_id)
        await self.cache.invalidate_many(user_ids)

    async def _invalidate_users(self, user_ids: list[uuid.UUID]) -> None:
        if self.cache is None:
            return
        await self.cache.invalidate_many(user_ids)

    async def _audit(
        self,
        actor_user_id: uuid.UUID | None,
        action: AuditAction,
        *,
        entity_type: str,
        entity_id: uuid.UUID | None,
        description: str,
        organization_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
        metadata: dict[str, object] | None = None,
    ) -> None:
        await self.repository.create_audit_log_entry(
            actor_user_id=actor_user_id,
            action=action.value,
            entity_type=entity_type,
            entity_id=entity_id,
            description=description,
            event_metadata=metadata or {},
            organization_id=organization_id,
            location_id=location_id,
        )
        logger.info(
            "rbac_audit_event",
            extra={
                "action": action.value,
                "entity_type": entity_type,
                "entity_id": str(entity_id) if entity_id else None,
            },
        )


__all__ = [
    "RBACService",
    "CloudGuestError",
]
