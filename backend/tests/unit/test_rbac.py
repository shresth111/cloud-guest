"""Unit tests for the RBAC domain: role/permission CRUD, the authorization
engine (resolver/scope/access-validator), role assignment with scope and
escalation checks, cross-tenant isolation, permission inheritance, and
cache hit/miss/invalidation behavior.

Follows this project's plain-``assert`` / native-``async def`` style (see
``tests/unit/test_auth.py``); ``asyncio_mode = "auto"`` runs async tests
directly. Exercises ``RBACService``/``AccessValidator`` against a small
in-memory fake repository/cache, mirroring ``test_auth.py``'s
``FakeAuthRepository`` pattern, since there is no live Postgres/Redis in
this environment.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from app.domains.rbac.authorization import (
    AccessValidator,
    PermissionResolver,
    ScopeResolver,
)
from app.domains.rbac.cache import PermissionCache
from app.domains.rbac.context import GrantScope, ScopeContext
from app.domains.rbac.enums import OverrideEffect, PermissionModule, ScopeType
from app.domains.rbac.exceptions import (
    CrossTenantAccessError,
    DuplicateRoleError,
    InvalidScopeAssignmentError,
    OverrideEscalationError,
    PermissionDeniedError,
    RoleEscalationError,
    SystemRoleImmutableError,
)
from app.domains.rbac.models import (
    AuditLogEntry,
    LocationRole,
    OrganizationRole,
    Permission,
    PermissionGroup,
    PermissionOverride,
    PermissionScope,
    Role,
    RolePermission,
    RoleScope,
    UserRole,
)
from app.domains.rbac.seed import (
    MODULE_ACTIONS,
    MODULE_DISPLAY_NAMES,
    MODULE_NARROWEST_SCOPE,
    SYSTEM_ROLES,
    allowed_scope_types_for_module,
    generate_permission_matrix_markdown,
)
from app.domains.rbac.service import RBACService

# ============================================================================
# Test doubles
# ============================================================================


class FakeRedis:
    """Minimal async in-memory stand-in for ``redis.asyncio.Redis``."""

    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    async def get(self, key: str) -> str | None:
        return self._store.get(key)

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self._store[key] = str(value)

    async def delete(self, key: str) -> None:
        self._store.pop(key, None)


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
class FakeRBACRepository:
    """In-memory stand-in for :class:`RBACRepositoryProtocol`."""

    permission_groups: dict[uuid.UUID, PermissionGroup] = field(default_factory=dict)
    permissions: dict[uuid.UUID, Permission] = field(default_factory=dict)
    permission_scope_rows: list[PermissionScope] = field(default_factory=list)
    roles: dict[uuid.UUID, Role] = field(default_factory=dict)
    role_scope_rows: list[RoleScope] = field(default_factory=list)
    role_permission_rows: list[RolePermission] = field(default_factory=list)
    user_role_rows: list[UserRole] = field(default_factory=list)
    permission_override_rows: list[PermissionOverride] = field(default_factory=list)
    organization_role_rows: list[OrganizationRole] = field(default_factory=list)
    location_role_rows: list[LocationRole] = field(default_factory=list)
    audit_log_rows: list[AuditLogEntry] = field(default_factory=list)

    # -- permission groups -------------------------------------------------

    async def list_permission_groups(self) -> list[PermissionGroup]:
        return sorted(self.permission_groups.values(), key=lambda g: g.sort_order)

    async def get_permission_group_by_key(self, key: str) -> PermissionGroup | None:
        return next((g for g in self.permission_groups.values() if g.key == key), None)

    async def get_permission_group_by_id(
        self, group_id: uuid.UUID
    ) -> PermissionGroup | None:
        return self.permission_groups.get(group_id)

    async def create_permission_group(self, **fields: object) -> PermissionGroup:
        defaults = {"description": None, "sort_order": 0, "is_active": True}
        group = PermissionGroup(**_base_fields(**{**defaults, **fields}))
        self.permission_groups[group.id] = group
        return group

    # -- permissions ---------------------------------------------------------

    async def list_permissions(
        self, *, permission_group_id: uuid.UUID | None = None
    ) -> list[Permission]:
        values = list(self.permissions.values())
        if permission_group_id is not None:
            values = [p for p in values if p.permission_group_id == permission_group_id]
        return values

    async def get_permission_by_key(self, key: str) -> Permission | None:
        return next((p for p in self.permissions.values() if p.key == key), None)

    async def get_permission_by_id(self, permission_id: uuid.UUID) -> Permission | None:
        return self.permissions.get(permission_id)

    async def create_permission(self, **fields: object) -> Permission:
        defaults = {"description": None, "is_active": True}
        permission = Permission(**_base_fields(**{**defaults, **fields}))
        self.permissions[permission.id] = permission
        return permission

    async def get_permission_scope_types(self, permission_id: uuid.UUID) -> list[str]:
        return [
            row.scope_type
            for row in self.permission_scope_rows
            if row.permission_id == permission_id
        ]

    async def add_permission_scope(
        self, permission_id: uuid.UUID, scope_type: ScopeType
    ) -> PermissionScope:
        row = PermissionScope(
            **_base_fields(permission_id=permission_id, scope_type=scope_type.value)
        )
        self.permission_scope_rows.append(row)
        return row

    # -- roles -----------------------------------------------------------------

    async def get_role_by_id(
        self, role_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Role | None:
        role = self.roles.get(role_id)
        if role is None:
            return None
        if role.is_deleted and not include_deleted:
            return None
        return role

    async def get_role_by_slug(
        self, slug: str, organization_id: uuid.UUID | None
    ) -> Role | None:
        return next(
            (
                r
                for r in self.roles.values()
                if r.slug == slug
                and r.organization_id == organization_id
                and not r.is_deleted
            ),
            None,
        )

    async def list_roles(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        include_global: bool = True,
        scope_type: ScopeType | None = None,
        is_active: bool | None = None,
    ) -> list[Role]:
        values = [r for r in self.roles.values() if not r.is_deleted]
        if organization_id is not None and include_global:
            values = [r for r in values if r.organization_id in (organization_id, None)]
        elif organization_id is not None:
            values = [r for r in values if r.organization_id == organization_id]
        elif not include_global:
            values = [r for r in values if r.organization_id is not None]
        if scope_type is not None:
            values = [r for r in values if r.scope_type == scope_type.value]
        if is_active is not None:
            values = [r for r in values if r.is_active == is_active]
        return sorted(values, key=lambda r: r.name)

    async def create_role(self, **fields: object) -> Role:
        defaults = {
            "description": None,
            "is_template": False,
            "is_active": True,
            "organization_id": None,
            "parent_role_id": None,
        }
        role = Role(**_base_fields(**{**defaults, **fields}))
        self.roles[role.id] = role
        return role

    async def update_role(self, role: Role, data: dict[str, object]) -> Role:
        for key, value in data.items():
            if hasattr(role, key):
                setattr(role, key, value)
        role.version += 1
        return role

    async def soft_delete_role(self, role: Role) -> Role:
        role.is_deleted = True
        role.deleted_at = _now()
        return role

    async def get_role_scope_types(self, role_id: uuid.UUID) -> list[str]:
        return [
            row.scope_type for row in self.role_scope_rows if row.role_id == role_id
        ]

    async def add_role_scope(
        self, role_id: uuid.UUID, scope_type: ScopeType, *, is_default: bool = False
    ) -> RoleScope:
        row = RoleScope(
            **_base_fields(
                role_id=role_id, scope_type=scope_type.value, is_default=is_default
            )
        )
        self.role_scope_rows.append(row)
        return row

    async def get_role_permissions(self, role_id: uuid.UUID) -> list[RolePermission]:
        return [
            row
            for row in self.role_permission_rows
            if row.role_id == role_id and not row.is_deleted
        ]

    async def add_role_permission(
        self,
        role_id: uuid.UUID,
        permission_id: uuid.UUID,
        *,
        granted_by: uuid.UUID | None,
    ) -> RolePermission:
        row = RolePermission(
            **_base_fields(
                role_id=role_id,
                permission_id=permission_id,
                granted_at=_now(),
                granted_by=granted_by,
            )
        )
        row.permission = self.permissions.get(permission_id)
        self.role_permission_rows.append(row)
        return row

    async def remove_role_permission(
        self, role_id: uuid.UUID, permission_id: uuid.UUID
    ) -> bool:
        matches = [
            row
            for row in self.role_permission_rows
            if row.role_id == role_id and row.permission_id == permission_id
        ]
        for row in matches:
            self.role_permission_rows.remove(row)
        return bool(matches)

    async def get_parent_chain(
        self, role_id: uuid.UUID, *, max_depth: int
    ) -> list[Role]:
        chain: list[Role] = []
        seen = {role_id}
        current = self.roles.get(role_id)
        depth = 0
        while current is not None and current.parent_role_id and depth < max_depth:
            parent = self.roles.get(current.parent_role_id)
            if parent is None or parent.id in seen:
                break
            chain.append(parent)
            seen.add(parent.id)
            current = parent
            depth += 1
        return chain

    # -- user roles --------------------------------------------------------------

    async def get_active_user_roles(
        self, user_id: uuid.UUID, *, now: datetime | None = None
    ) -> list[UserRole]:
        moment = now or _now()
        rows = [
            row
            for row in self.user_role_rows
            if row.user_id == user_id
            and row.is_active
            and not row.is_deleted
            and (row.expires_at is None or row.expires_at > moment)
        ]
        for row in rows:
            row.role = self.roles.get(row.role_id)
        return rows

    async def get_user_role_assignment(
        self, assignment_id: uuid.UUID
    ) -> UserRole | None:
        return next(
            (row for row in self.user_role_rows if row.id == assignment_id), None
        )

    async def create_user_role(self, **fields: object) -> UserRole:
        defaults = {
            "msp_id": None,
            "organization_id": None,
            "location_id": None,
            "router_id": None,
            "expires_at": None,
            "is_active": True,
        }
        row = UserRole(**_base_fields(**{**defaults, **fields}))
        self.user_role_rows.append(row)
        return row

    async def deactivate_user_role(self, user_role: UserRole) -> UserRole:
        user_role.is_active = False
        return user_role

    async def get_user_ids_with_role(self, role_id: uuid.UUID) -> list[uuid.UUID]:
        return list(
            {
                row.user_id
                for row in self.user_role_rows
                if row.role_id == role_id and row.is_active and not row.is_deleted
            }
        )

    # -- permission overrides ------------------------------------------------

    async def get_active_overrides_for_user(
        self, user_id: uuid.UUID, *, now: datetime | None = None
    ) -> list[PermissionOverride]:
        moment = now or _now()
        rows = [
            row
            for row in self.permission_override_rows
            if row.user_id == user_id
            and row.is_active
            and not row.is_deleted
            and (row.expires_at is None or row.expires_at > moment)
        ]
        for row in rows:
            row.permission = self.permissions.get(row.permission_id)
        return rows

    async def get_permission_override_by_id(
        self, override_id: uuid.UUID
    ) -> PermissionOverride | None:
        return next(
            (row for row in self.permission_override_rows if row.id == override_id),
            None,
        )

    async def create_permission_override(self, **fields: object) -> PermissionOverride:
        defaults = {
            "organization_id": None,
            "location_id": None,
            "router_id": None,
            "reason": None,
            "expires_at": None,
            "is_active": True,
        }
        row = PermissionOverride(**_base_fields(**{**defaults, **fields}))
        self.permission_override_rows.append(row)
        return row

    async def deactivate_permission_override(
        self, override: PermissionOverride
    ) -> PermissionOverride:
        override.is_active = False
        return override

    # -- organization / location role configuration --------------------------

    async def get_organization_role(
        self, organization_id: uuid.UUID, role_id: uuid.UUID
    ) -> OrganizationRole | None:
        return next(
            (
                row
                for row in self.organization_role_rows
                if row.organization_id == organization_id and row.role_id == role_id
            ),
            None,
        )

    async def list_organization_roles(
        self, organization_id: uuid.UUID
    ) -> list[OrganizationRole]:
        return [
            row
            for row in self.organization_role_rows
            if row.organization_id == organization_id
        ]

    async def upsert_organization_role(self, **fields: object) -> OrganizationRole:
        existing = await self.get_organization_role(
            fields["organization_id"],
            fields["role_id"],  # type: ignore[arg-type]
        )
        if existing is not None:
            for key, value in fields.items():
                setattr(existing, key, value)
            return existing
        defaults = {"is_enabled": True, "is_default_for_new_members": False}
        row = OrganizationRole(**_base_fields(**{**defaults, **fields}))
        self.organization_role_rows.append(row)
        return row

    async def get_location_role(
        self, location_id: uuid.UUID, role_id: uuid.UUID
    ) -> LocationRole | None:
        return next(
            (
                row
                for row in self.location_role_rows
                if row.location_id == location_id and row.role_id == role_id
            ),
            None,
        )

    async def list_location_roles(self, location_id: uuid.UUID) -> list[LocationRole]:
        return [
            row for row in self.location_role_rows if row.location_id == location_id
        ]

    async def upsert_location_role(self, **fields: object) -> LocationRole:
        existing = await self.get_location_role(
            fields["location_id"],
            fields["role_id"],  # type: ignore[arg-type]
        )
        if existing is not None:
            for key, value in fields.items():
                setattr(existing, key, value)
            return existing
        defaults = {"is_enabled": True, "is_default_for_new_members": False}
        row = LocationRole(**_base_fields(**{**defaults, **fields}))
        self.location_role_rows.append(row)
        return row

    # -- audit log -------------------------------------------------------------

    async def create_audit_log_entry(self, **fields: object) -> AuditLogEntry:
        defaults = {"description": None, "organization_id": None, "location_id": None}
        entry = AuditLogEntry(**_base_fields(**{**defaults, **fields}))
        self.audit_log_rows.append(entry)
        return entry

    async def list_audit_log_entries(
        self, *, entity_type: str | None = None, entity_id: uuid.UUID | None = None
    ) -> list[AuditLogEntry]:
        rows = list(self.audit_log_rows)
        if entity_type is not None:
            rows = [row for row in rows if row.entity_type == entity_type]
        if entity_id is not None:
            rows = [row for row in rows if row.entity_id == entity_id]
        return rows


class CountingRepository(FakeRBACRepository):
    """Wraps ``get_active_user_roles`` with a call counter, for cache tests."""

    def __init__(self) -> None:
        super().__init__()
        self.resolve_calls = 0

    async def get_active_user_roles(
        self, user_id: uuid.UUID, *, now: datetime | None = None
    ) -> list[UserRole]:
        self.resolve_calls += 1
        return await super().get_active_user_roles(user_id, now=now)


# ============================================================================
# Scenario builders
# ============================================================================


async def make_permission(
    repo: FakeRBACRepository,
    module_key: str,
    action: str,
    *,
    group: PermissionGroup | None = None,
    scope_types: tuple[ScopeType, ...] = (),
) -> Permission:
    if group is None:
        group = await repo.get_permission_group_by_key(module_key)
        if group is None:
            group = await repo.create_permission_group(
                key=module_key, name=module_key.title()
            )
    permission = await repo.create_permission(
        permission_group_id=group.id,
        key=f"{module_key}.{action}",
        action=action,
        name=f"{module_key}.{action}",
    )
    for scope_type in scope_types:
        await repo.add_permission_scope(permission.id, scope_type)
    return permission


async def make_role(
    repo: FakeRBACRepository,
    name: str,
    *,
    scope_type: ScopeType,
    organization_id: uuid.UUID | None = None,
    is_system_role: bool = False,
    is_template: bool = False,
    parent_role_id: uuid.UUID | None = None,
) -> Role:
    return await repo.create_role(
        name=name,
        slug=name.lower().replace(" ", "-"),
        scope_type=scope_type.value,
        organization_id=organization_id,
        is_system_role=is_system_role,
        is_template=is_template,
        parent_role_id=parent_role_id,
    )


async def assign_role(
    repo: FakeRBACRepository,
    *,
    user_id: uuid.UUID,
    role: Role,
    scope_type: ScopeType,
    organization_id: uuid.UUID | None = None,
    location_id: uuid.UUID | None = None,
    router_id: uuid.UUID | None = None,
    expires_at: datetime | None = None,
    is_active: bool = True,
) -> UserRole:
    return await repo.create_user_role(
        user_id=user_id,
        role_id=role.id,
        scope_type=scope_type.value,
        organization_id=organization_id,
        location_id=location_id,
        router_id=router_id,
        granted_at=_now(),
        granted_by=None,
        expires_at=expires_at,
        is_active=is_active,
    )


def make_service(
    repo: FakeRBACRepository | None = None,
) -> tuple[RBACService, FakeRBACRepository, PermissionCache]:
    repository = repo or FakeRBACRepository()
    cache = PermissionCache(FakeRedis(), ttl_seconds=300)
    return RBACService(repository, cache), repository, cache


# ============================================================================
# Role CRUD
# ============================================================================


class TestRoleCRUD:
    async def test_create_role_success(self) -> None:
        service, _repo, _cache = make_service()
        actor_id = uuid.uuid4()

        role = await service.create_role(
            actor_user_id=actor_id,
            name="Front Desk",
            slug="front-desk",
            description="Custom role",
            scope_type=ScopeType.LOCATION,
            organization_id=None,
            requesting_organization_id=None,
        )

        assert role.name == "Front Desk"
        assert role.is_system_role is False
        assert role.is_active is True

    async def test_create_role_rejects_duplicate_slug_in_same_scope(self) -> None:
        service, _repo, _cache = make_service()
        actor_id = uuid.uuid4()
        org_id = uuid.uuid4()
        await service.create_role(
            actor_user_id=actor_id,
            name="Front Desk",
            slug="front-desk",
            description=None,
            scope_type=ScopeType.LOCATION,
            organization_id=org_id,
            requesting_organization_id=org_id,
        )

        with pytest.raises(DuplicateRoleError):
            await service.create_role(
                actor_user_id=actor_id,
                name="Front Desk Again",
                slug="front-desk",
                description=None,
                scope_type=ScopeType.LOCATION,
                organization_id=org_id,
                requesting_organization_id=org_id,
            )

    async def test_update_system_role_rename_raises(self) -> None:
        service, repo, _cache = make_service()
        role = await make_role(
            repo, "Super Admin", scope_type=ScopeType.GLOBAL, is_system_role=True
        )

        with pytest.raises(SystemRoleImmutableError):
            await service.update_role(
                actor_user_id=uuid.uuid4(),
                role_id=role.id,
                requesting_organization_id=None,
                data={"name": "Renamed"},
            )

    async def test_delete_system_role_raises(self) -> None:
        service, repo, _cache = make_service()
        role = await make_role(
            repo, "Super Admin", scope_type=ScopeType.GLOBAL, is_system_role=True
        )

        with pytest.raises(SystemRoleImmutableError):
            await service.delete_role(
                actor_user_id=uuid.uuid4(),
                role_id=role.id,
                requesting_organization_id=None,
            )

    async def test_delete_custom_role_soft_deletes_and_audits(self) -> None:
        service, repo, _cache = make_service()
        role = await make_role(repo, "Custom Role", scope_type=ScopeType.LOCATION)

        await service.delete_role(
            actor_user_id=uuid.uuid4(), role_id=role.id, requesting_organization_id=None
        )

        assert role.is_deleted is True
        assert any(entry.action == "role_deleted" for entry in repo.audit_log_rows)

    async def test_clone_role_copies_permissions(self) -> None:
        service, repo, _cache = make_service()
        permission = await make_permission(repo, "voucher", "create")
        source = await make_role(
            repo, "Location Manager", scope_type=ScopeType.LOCATION, is_system_role=True
        )
        await repo.add_role_permission(source.id, permission.id, granted_by=None)

        clone = await service.clone_role(
            actor_user_id=uuid.uuid4(),
            source_role_id=source.id,
            requesting_organization_id=None,
            new_name="Location Manager (Clone)",
            new_slug="location-manager-clone",
        )

        assert clone.parent_role_id == source.id
        clone_permission_ids = {
            row.permission_id for row in await repo.get_role_permissions(clone.id)
        }
        assert permission.id in clone_permission_ids


# ============================================================================
# Permission CRUD (read-mostly; seeded data)
# ============================================================================


class TestPermissionCRUD:
    async def test_list_permission_groups(self) -> None:
        service, repo, _cache = make_service()
        await repo.create_permission_group(key="users", name="Users")
        await repo.create_permission_group(key="roles", name="Roles")

        groups = await service.list_permission_groups()

        assert {g.key for g in groups} == {"users", "roles"}

    async def test_list_permissions_filtered_by_group(self) -> None:
        service, repo, _cache = make_service()
        users_perm = await make_permission(repo, "users", "create")
        await make_permission(repo, "roles", "create")

        permissions = await service.list_permissions(
            permission_group_id=users_perm.permission_group_id
        )

        assert len(permissions) == 1
        assert permissions[0].key == "users.create"


# ============================================================================
# PermissionResolver / inheritance
# ============================================================================


class TestPermissionResolver:
    async def test_resolves_permissions_from_active_role(self) -> None:
        repo = FakeRBACRepository()
        resolver = PermissionResolver(repo)
        permission = await make_permission(repo, "guest_users", "create")
        role = await make_role(repo, "Reception", scope_type=ScopeType.LOCATION)
        await repo.add_role_permission(role.id, permission.id, granted_by=None)
        user_id = uuid.uuid4()
        await assign_role(
            repo,
            user_id=user_id,
            role=role,
            scope_type=ScopeType.LOCATION,
            location_id=uuid.uuid4(),
        )

        grants = await resolver.resolve(user_id)

        assert "guest_users.create" in grants.permission_keys()

    async def test_inherits_parent_role_permissions_recursively(self) -> None:
        repo = FakeRBACRepository()
        resolver = PermissionResolver(repo)
        grandparent_permission = await make_permission(repo, "monitoring", "read")
        parent_permission = await make_permission(repo, "alerts", "read")
        grandparent = await make_role(
            repo, "Grandparent", scope_type=ScopeType.LOCATION
        )
        await repo.add_role_permission(
            grandparent.id, grandparent_permission.id, granted_by=None
        )
        parent = await make_role(
            repo, "Parent", scope_type=ScopeType.LOCATION, parent_role_id=grandparent.id
        )
        await repo.add_role_permission(parent.id, parent_permission.id, granted_by=None)
        child = await make_role(
            repo, "Child", scope_type=ScopeType.LOCATION, parent_role_id=parent.id
        )
        user_id = uuid.uuid4()
        await assign_role(
            repo,
            user_id=user_id,
            role=child,
            scope_type=ScopeType.LOCATION,
            location_id=uuid.uuid4(),
        )

        keys = await resolver.resolve_role_permission_keys(child.id)

        assert keys == {"monitoring.read", "alerts.read"}

    async def test_deactivated_role_grants_nothing(self) -> None:
        repo = FakeRBACRepository()
        resolver = PermissionResolver(repo)
        permission = await make_permission(repo, "billing", "read")
        role = await make_role(
            repo, "Billing Viewer", scope_type=ScopeType.ORGANIZATION
        )
        await repo.add_role_permission(role.id, permission.id, granted_by=None)
        role.is_active = False
        user_id = uuid.uuid4()
        await assign_role(
            repo,
            user_id=user_id,
            role=role,
            scope_type=ScopeType.ORGANIZATION,
            organization_id=uuid.uuid4(),
        )

        grants = await resolver.resolve(user_id)

        assert grants.permission_keys() == set()

    async def test_expired_assignment_grants_nothing(self) -> None:
        repo = FakeRBACRepository()
        resolver = PermissionResolver(repo)
        permission = await make_permission(repo, "billing", "read")
        role = await make_role(
            repo, "Billing Viewer", scope_type=ScopeType.ORGANIZATION
        )
        await repo.add_role_permission(role.id, permission.id, granted_by=None)
        user_id = uuid.uuid4()
        await assign_role(
            repo,
            user_id=user_id,
            role=role,
            scope_type=ScopeType.ORGANIZATION,
            organization_id=uuid.uuid4(),
            expires_at=_now() - timedelta(days=1),
        )

        grants = await resolver.resolve(user_id)

        assert grants.permission_keys() == set()


# ============================================================================
# ScopeResolver
# ============================================================================


class TestScopeResolver:
    def test_global_grant_satisfies_any_scope(self) -> None:
        grant = GrantScope(scope_type=ScopeType.GLOBAL)
        requested = ScopeContext(organization_id=uuid.uuid4())

        assert ScopeResolver.satisfies(grant, ScopeType.ORGANIZATION, requested) is True

    def test_organization_grant_satisfies_location_check_same_org(self) -> None:
        org_id = uuid.uuid4()
        grant = GrantScope(scope_type=ScopeType.ORGANIZATION, organization_id=org_id)
        requested = ScopeContext(organization_id=org_id, location_id=uuid.uuid4())

        assert ScopeResolver.satisfies(grant, ScopeType.LOCATION, requested) is True

    def test_organization_grant_does_not_satisfy_other_org(self) -> None:
        grant = GrantScope(
            scope_type=ScopeType.ORGANIZATION, organization_id=uuid.uuid4()
        )
        requested = ScopeContext(organization_id=uuid.uuid4())

        assert (
            ScopeResolver.satisfies(grant, ScopeType.ORGANIZATION, requested) is False
        )

    def test_location_grant_does_not_satisfy_organization_level_check(self) -> None:
        grant = GrantScope(scope_type=ScopeType.LOCATION, location_id=uuid.uuid4())
        requested = ScopeContext(organization_id=uuid.uuid4())

        assert (
            ScopeResolver.satisfies(grant, ScopeType.ORGANIZATION, requested) is False
        )


# ============================================================================
# AccessValidator (authorization engine end-to-end)
# ============================================================================


class TestAccessValidator:
    async def test_has_permission_true_for_matching_grant(self) -> None:
        repo = FakeRBACRepository()
        validator = AccessValidator(repo)
        permission = await make_permission(repo, "routers", "read")
        role = await make_role(repo, "Network Admin", scope_type=ScopeType.LOCATION)
        await repo.add_role_permission(role.id, permission.id, granted_by=None)
        user_id = uuid.uuid4()
        location_id = uuid.uuid4()
        await assign_role(
            repo,
            user_id=user_id,
            role=role,
            scope_type=ScopeType.LOCATION,
            location_id=location_id,
        )

        allowed = await validator.has_permission(
            user_id,
            "routers.read",
            scope_type=ScopeType.LOCATION,
            scope_context=ScopeContext(location_id=location_id),
        )

        assert allowed is True

    async def test_deny_override_wins_over_role_allow(self) -> None:
        repo = FakeRBACRepository()
        validator = AccessValidator(repo)
        permission = await make_permission(repo, "users", "delete")
        role = await make_role(repo, "Org Admin", scope_type=ScopeType.ORGANIZATION)
        await repo.add_role_permission(role.id, permission.id, granted_by=None)
        user_id = uuid.uuid4()
        org_id = uuid.uuid4()
        await assign_role(
            repo,
            user_id=user_id,
            role=role,
            scope_type=ScopeType.ORGANIZATION,
            organization_id=org_id,
        )
        await repo.create_permission_override(
            user_id=user_id,
            permission_id=permission.id,
            effect=OverrideEffect.DENY.value,
            scope_type=ScopeType.ORGANIZATION.value,
            organization_id=org_id,
            granted_at=_now(),
            granted_by=None,
        )

        allowed = await validator.has_permission(
            user_id,
            "users.delete",
            scope_type=ScopeType.ORGANIZATION,
            scope_context=ScopeContext(organization_id=org_id),
        )

        assert allowed is False

    async def test_allow_override_grants_permission_not_held_via_role(self) -> None:
        repo = FakeRBACRepository()
        validator = AccessValidator(repo)
        permission = await make_permission(repo, "reports", "export")
        user_id = uuid.uuid4()
        await repo.create_permission_override(
            user_id=user_id,
            permission_id=permission.id,
            effect=OverrideEffect.ALLOW.value,
            scope_type=ScopeType.GLOBAL.value,
            granted_at=_now(),
            granted_by=None,
        )

        allowed = await validator.has_permission(user_id, "reports.export")

        assert allowed is True

    async def test_check_raises_and_logs_permission_denied(self) -> None:
        repo = FakeRBACRepository()
        validator = AccessValidator(repo)
        user_id = uuid.uuid4()

        with pytest.raises(PermissionDeniedError):
            await validator.check(user_id, "routers.delete")

        assert any(entry.action == "permission_denied" for entry in repo.audit_log_rows)


# ============================================================================
# Role assignment: scope/hierarchy validation and escalation prevention
# ============================================================================


class TestRoleAssignment:
    async def test_assign_role_success_when_assigner_holds_superset(self) -> None:
        service, repo, _cache = make_service()
        assign_permission = await make_permission(repo, "roles", "assign")
        guest_permission = await make_permission(repo, "guest_users", "create")
        role = await make_role(repo, "Reception Staff", scope_type=ScopeType.LOCATION)
        await repo.add_role_permission(role.id, guest_permission.id, granted_by=None)

        assigner_role = await make_role(
            repo, "Location Manager", scope_type=ScopeType.LOCATION
        )
        await repo.add_role_permission(
            assigner_role.id, assign_permission.id, granted_by=None
        )
        await repo.add_role_permission(
            assigner_role.id, guest_permission.id, granted_by=None
        )
        assigner_id = uuid.uuid4()
        location_id = uuid.uuid4()
        await assign_role(
            repo,
            user_id=assigner_id,
            role=assigner_role,
            scope_type=ScopeType.LOCATION,
            location_id=location_id,
        )

        target_id = uuid.uuid4()
        assignment = await service.assign_role_to_user(
            actor_user_id=assigner_id,
            target_user_id=target_id,
            role_id=role.id,
            scope_type=ScopeType.LOCATION,
            requesting_organization_id=None,
            location_id=location_id,
        )

        assert assignment.user_id == target_id
        assert assignment.role_id == role.id

    async def test_assign_role_rejects_invalid_scope(self) -> None:
        service, repo, _cache = make_service()
        role = await make_role(repo, "Org Admin", scope_type=ScopeType.ORGANIZATION)
        assign_permission = await make_permission(repo, "roles", "assign")
        assigner_role = await make_role(
            repo, "Global Admin", scope_type=ScopeType.GLOBAL
        )
        await repo.add_role_permission(
            assigner_role.id, assign_permission.id, granted_by=None
        )
        assigner_id = uuid.uuid4()
        await assign_role(
            repo, user_id=assigner_id, role=assigner_role, scope_type=ScopeType.GLOBAL
        )

        with pytest.raises(InvalidScopeAssignmentError):
            await service.assign_role_to_user(
                actor_user_id=assigner_id,
                target_user_id=uuid.uuid4(),
                role_id=role.id,
                scope_type=ScopeType.ROUTER,  # not permitted for an ORG-scoped role
                requesting_organization_id=None,
                router_id=uuid.uuid4(),
            )

    async def test_assign_role_prevents_escalation_beyond_assigner_permissions(
        self,
    ) -> None:
        service, repo, _cache = make_service()
        assign_permission = await make_permission(repo, "roles", "assign")
        powerful_permission = await make_permission(repo, "system_settings", "manage")
        role = await make_role(repo, "Powerful Role", scope_type=ScopeType.GLOBAL)
        await repo.add_role_permission(role.id, powerful_permission.id, granted_by=None)

        # Assigner can assign roles, but does not themselves hold
        # 'system_settings.manage' -- so granting `role` would be escalation.
        weak_assigner_role = await make_role(
            repo, "Weak Assigner", scope_type=ScopeType.GLOBAL
        )
        await repo.add_role_permission(
            weak_assigner_role.id, assign_permission.id, granted_by=None
        )
        assigner_id = uuid.uuid4()
        await assign_role(
            repo,
            user_id=assigner_id,
            role=weak_assigner_role,
            scope_type=ScopeType.GLOBAL,
        )

        with pytest.raises(RoleEscalationError):
            await service.assign_role_to_user(
                actor_user_id=assigner_id,
                target_user_id=uuid.uuid4(),
                role_id=role.id,
                scope_type=ScopeType.GLOBAL,
                requesting_organization_id=None,
            )

    async def test_assign_role_denied_without_assign_permission(self) -> None:
        service, repo, _cache = make_service()
        role = await make_role(repo, "Some Role", scope_type=ScopeType.GLOBAL)
        assigner_id = uuid.uuid4()  # holds no permissions/roles at all

        with pytest.raises(PermissionDeniedError):
            await service.assign_role_to_user(
                actor_user_id=assigner_id,
                target_user_id=uuid.uuid4(),
                role_id=role.id,
                scope_type=ScopeType.GLOBAL,
                requesting_organization_id=None,
            )

    async def test_revoke_role_deactivates_assignment(self) -> None:
        service, repo, _cache = make_service()
        role = await make_role(repo, "Some Role", scope_type=ScopeType.GLOBAL)
        user_id = uuid.uuid4()
        assignment = await assign_role(
            repo, user_id=user_id, role=role, scope_type=ScopeType.GLOBAL
        )

        await service.revoke_role_from_user(
            actor_user_id=uuid.uuid4(),
            assignment_id=assignment.id,
            requesting_organization_id=None,
        )

        assert assignment.is_active is False
        assert any(entry.action == "role_revoked" for entry in repo.audit_log_rows)


# ============================================================================
# Cross-tenant isolation
# ============================================================================


class TestCrossTenantIsolation:
    async def test_get_role_from_other_organization_raises(self) -> None:
        service, repo, _cache = make_service()
        org_a = uuid.uuid4()
        org_b = uuid.uuid4()
        role = await make_role(
            repo,
            "Org A Custom Role",
            scope_type=ScopeType.ORGANIZATION,
            organization_id=org_a,
        )

        with pytest.raises(CrossTenantAccessError):
            await service.get_role(role.id, requesting_organization_id=org_b)

    async def test_list_roles_excludes_other_organizations_custom_roles(self) -> None:
        service, repo, _cache = make_service()
        org_a = uuid.uuid4()
        org_b = uuid.uuid4()
        await make_role(
            repo, "Org A Role", scope_type=ScopeType.ORGANIZATION, organization_id=org_a
        )
        await make_role(
            repo, "Org B Role", scope_type=ScopeType.ORGANIZATION, organization_id=org_b
        )
        await make_role(repo, "Global Role", scope_type=ScopeType.GLOBAL)

        roles = await service.list_roles(requesting_organization_id=org_a)

        names = {r.name for r in roles}
        assert "Org A Role" in names
        assert "Global Role" in names
        assert "Org B Role" not in names

    async def test_global_role_is_visible_to_every_organization(self) -> None:
        service, repo, _cache = make_service()
        await make_role(repo, "Global Role", scope_type=ScopeType.GLOBAL)

        role = await service.get_role(
            (await repo.get_role_by_slug("global-role", None)).id,
            requesting_organization_id=uuid.uuid4(),
        )

        assert role.name == "Global Role"


# ============================================================================
# Permission override escalation prevention
# ============================================================================


class TestPermissionOverrideEscalation:
    async def test_cannot_grant_allow_override_for_permission_not_held(self) -> None:
        service, repo, _cache = make_service()
        assign_permission = await make_permission(repo, "permissions", "assign")
        await make_permission(repo, "system_settings", "manage")
        assigner_role = await make_role(
            repo, "Limited Admin", scope_type=ScopeType.GLOBAL
        )
        await repo.add_role_permission(
            assigner_role.id, assign_permission.id, granted_by=None
        )
        assigner_id = uuid.uuid4()
        await assign_role(
            repo, user_id=assigner_id, role=assigner_role, scope_type=ScopeType.GLOBAL
        )

        with pytest.raises(OverrideEscalationError):
            await service.grant_permission_override(
                actor_user_id=assigner_id,
                target_user_id=uuid.uuid4(),
                permission_key="system_settings.manage",
                effect=OverrideEffect.ALLOW,
            )

    async def test_permissions_manage_bypass_allows_granting_override(self) -> None:
        service, repo, _cache = make_service()
        assign_permission = await make_permission(repo, "permissions", "assign")
        manage_permission = await make_permission(repo, "permissions", "manage")
        target_permission = await make_permission(repo, "system_settings", "manage")
        assigner_role = await make_role(
            repo, "Bypass Admin", scope_type=ScopeType.GLOBAL
        )
        await repo.add_role_permission(
            assigner_role.id, assign_permission.id, granted_by=None
        )
        await repo.add_role_permission(
            assigner_role.id, manage_permission.id, granted_by=None
        )
        assigner_id = uuid.uuid4()
        await assign_role(
            repo, user_id=assigner_id, role=assigner_role, scope_type=ScopeType.GLOBAL
        )

        override = await service.grant_permission_override(
            actor_user_id=assigner_id,
            target_user_id=uuid.uuid4(),
            permission_key="system_settings.manage",
            effect=OverrideEffect.ALLOW,
        )

        assert override.permission_id == target_permission.id


# ============================================================================
# Cache behavior
# ============================================================================


class TestPermissionCacheBehavior:
    async def test_cache_miss_then_hit_avoids_second_repository_resolution(
        self,
    ) -> None:
        repo = CountingRepository()
        cache = PermissionCache(FakeRedis(), ttl_seconds=300)
        validator = AccessValidator(repo, cache=cache)
        permission = await make_permission(repo, "dashboard", "view")
        role = await make_role(repo, "Viewer", scope_type=ScopeType.GLOBAL)
        await repo.add_role_permission(role.id, permission.id, granted_by=None)
        user_id = uuid.uuid4()
        await assign_role(repo, user_id=user_id, role=role, scope_type=ScopeType.GLOBAL)

        await validator.get_effective_grants(user_id)
        assert repo.resolve_calls == 1

        await validator.get_effective_grants(user_id)
        assert repo.resolve_calls == 1  # second call served from cache

    async def test_cache_invalidated_on_role_assignment(self) -> None:
        repo = CountingRepository()
        service, _repo, cache = make_service(repo)
        permission = await make_permission(repo, "dashboard", "view")
        role = await make_role(repo, "Viewer", scope_type=ScopeType.GLOBAL)
        await repo.add_role_permission(role.id, permission.id, granted_by=None)
        user_id = uuid.uuid4()

        await service.access_validator.get_effective_grants(user_id)
        assert repo.resolve_calls == 1
        await service.access_validator.get_effective_grants(user_id)
        assert repo.resolve_calls == 1  # cached (no assignment yet, but still cached)

        await repo.create_user_role(
            user_id=user_id,
            role_id=role.id,
            scope_type=ScopeType.GLOBAL.value,
            granted_at=_now(),
            granted_by=None,
        )
        await service._invalidate_users([user_id])

        await service.access_validator.get_effective_grants(user_id)
        assert repo.resolve_calls == 2  # cache invalidated -> recomputed

    async def test_cache_invalidated_when_role_permissions_change(self) -> None:
        repo = CountingRepository()
        service, _repo, _cache = make_service(repo)
        permission = await make_permission(repo, "dashboard", "view")
        await make_permission(repo, "reports", "read")
        role = await make_role(repo, "Viewer", scope_type=ScopeType.GLOBAL)
        await repo.add_role_permission(role.id, permission.id, granted_by=None)
        user_id = uuid.uuid4()
        await assign_role(repo, user_id=user_id, role=role, scope_type=ScopeType.GLOBAL)

        grants = await service.access_validator.get_effective_grants(user_id)
        assert grants.permission_keys() == {"dashboard.view"}

        await service.assign_permission_to_role(
            actor_user_id=uuid.uuid4(),
            role_id=role.id,
            permission_key="reports.read",
            requesting_organization_id=None,
        )

        refreshed = await service.access_validator.get_effective_grants(user_id)
        assert refreshed.permission_keys() == {"dashboard.view", "reports.read"}


# ============================================================================
# Seed data consistency (no DB required -- pure data-structure checks)
# ============================================================================


class TestSeedDataConsistency:
    """Guards the invariants ``seed.py`` relies on to seed without ever
    hitting ``InvalidScopeAssignmentError`` -- most importantly, that
    ``GLOBAL`` is always in a module's allowed permission_scopes (since
    Super Admin, a GLOBAL-scoped role, is granted every module at FULL)."""

    def test_every_permission_module_is_mapped(self) -> None:
        assert set(MODULE_ACTIONS) == set(PermissionModule)
        assert set(MODULE_DISPLAY_NAMES) == set(PermissionModule)
        assert set(MODULE_NARROWEST_SCOPE) == set(PermissionModule)

    def test_role_grants_are_subsets_of_module_actions(self) -> None:
        for role_def in SYSTEM_ROLES:
            for module, actions in role_def.grants().items():
                assert set(actions) <= set(MODULE_ACTIONS[module])

    def test_global_scope_always_allowed_for_every_module(self) -> None:
        for module in PermissionModule:
            assert ScopeType.GLOBAL in allowed_scope_types_for_module(module)

    def test_every_role_scope_type_is_compatible_with_every_module_it_is_granted(
        self,
    ) -> None:
        """The exact bug class this guards: an ORGANIZATION-scoped role
        (e.g. Read Only) being granted a GLOBAL-only permission (e.g.
        anything under System Settings) would make seeding raise
        InvalidScopeAssignmentError."""
        for role_def in SYSTEM_ROLES:
            for module in role_def.grants():
                allowed = allowed_scope_types_for_module(module)
                assert role_def.scope_type in allowed, (
                    role_def.slug,
                    module,
                    role_def.scope_type,
                )

    def test_permission_matrix_markdown_mentions_every_role(self) -> None:
        matrix = generate_permission_matrix_markdown()
        for role_def in SYSTEM_ROLES:
            assert role_def.name in matrix

    def test_network_engineer_and_office_admin_are_seeded(self) -> None:
        """Enterprise SaaS Phase D: the two suggested-role gaps identified
        against the objective's "Network Engineer, Office Admin, Reception,
        Helpdesk, Read Only" list (the other three already existed)."""
        slugs = {role_def.slug for role_def in SYSTEM_ROLES}
        assert "network-engineer" in slugs
        assert "office-admin" in slugs
