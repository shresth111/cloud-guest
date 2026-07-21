"""Data access layer for the RBAC domain.

Mirrors ``app.domains.auth.repository``'s shape: a ``Protocol`` describing
the operations the service/authorization layers need
(``RBACRepositoryProtocol``), and a concrete, ``GenericRepository``-backed
implementation (``RBACRepository``). ``GenericRepository`` covers plain
CRUD for every model; hand-written queries are used only for the
RBAC-specific relationship traversals (recursive parent-role permission
resolution, "all users holding this role" for cache invalidation, etc.)
that ``GenericRepository``'s equality/IN filters can't express.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Protocol

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database.constants import SortOrder
from app.database.repositories.generic import GenericRepository
from app.database.utils.pagination import PageParams, PaginationMeta, paginate

from .enums import ScopeType
from .models import (
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


class RBACRepositoryProtocol(Protocol):
    # -- permission groups -------------------------------------------------
    async def list_permission_groups(self) -> list[PermissionGroup]: ...

    async def get_permission_group_by_key(self, key: str) -> PermissionGroup | None: ...

    async def get_permission_group_by_id(
        self, group_id: uuid.UUID
    ) -> PermissionGroup | None: ...

    async def create_permission_group(self, **fields: object) -> PermissionGroup: ...

    # -- permissions ---------------------------------------------------------
    async def list_permissions(
        self, *, permission_group_id: uuid.UUID | None = None
    ) -> list[Permission]: ...

    async def get_permission_by_key(self, key: str) -> Permission | None: ...

    async def get_permission_by_id(
        self, permission_id: uuid.UUID
    ) -> Permission | None: ...

    async def create_permission(self, **fields: object) -> Permission: ...

    async def get_permission_scope_types(
        self, permission_id: uuid.UUID
    ) -> list[str]: ...

    async def add_permission_scope(
        self, permission_id: uuid.UUID, scope_type: ScopeType
    ) -> PermissionScope: ...

    # -- roles -----------------------------------------------------------------
    async def get_role_by_id(
        self, role_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Role | None: ...

    async def get_role_by_slug(
        self, slug: str, organization_id: uuid.UUID | None
    ) -> Role | None: ...

    async def list_roles(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        include_global: bool = True,
        scope_type: ScopeType | None = None,
        is_active: bool | None = None,
    ) -> list[Role]: ...

    async def create_role(self, **fields: object) -> Role: ...

    async def update_role(self, role: Role, data: dict[str, object]) -> Role: ...

    async def soft_delete_role(self, role: Role) -> Role: ...

    async def get_role_scope_types(self, role_id: uuid.UUID) -> list[str]: ...

    async def add_role_scope(
        self, role_id: uuid.UUID, scope_type: ScopeType, *, is_default: bool = False
    ) -> RoleScope: ...

    async def get_role_permissions(
        self, role_id: uuid.UUID
    ) -> list[RolePermission]: ...

    async def add_role_permission(
        self,
        role_id: uuid.UUID,
        permission_id: uuid.UUID,
        *,
        granted_by: uuid.UUID | None,
    ) -> RolePermission: ...

    async def remove_role_permission(
        self, role_id: uuid.UUID, permission_id: uuid.UUID
    ) -> bool: ...

    async def get_parent_chain(
        self, role_id: uuid.UUID, *, max_depth: int
    ) -> list[Role]: ...

    # -- user roles --------------------------------------------------------------
    async def get_active_user_roles(
        self, user_id: uuid.UUID, *, now: datetime | None = None
    ) -> list[UserRole]: ...

    async def get_user_role_assignment(
        self, assignment_id: uuid.UUID
    ) -> UserRole | None: ...

    async def create_user_role(self, **fields: object) -> UserRole: ...

    async def deactivate_user_role(self, user_role: UserRole) -> UserRole: ...

    async def get_user_ids_with_role(self, role_id: uuid.UUID) -> list[uuid.UUID]: ...

    # -- permission overrides ------------------------------------------------
    async def get_active_overrides_for_user(
        self, user_id: uuid.UUID, *, now: datetime | None = None
    ) -> list[PermissionOverride]: ...

    async def get_permission_override_by_id(
        self, override_id: uuid.UUID
    ) -> PermissionOverride | None: ...

    async def create_permission_override(
        self, **fields: object
    ) -> PermissionOverride: ...

    async def deactivate_permission_override(
        self, override: PermissionOverride
    ) -> PermissionOverride: ...

    # -- organization / location role configuration --------------------------
    async def get_organization_role(
        self, organization_id: uuid.UUID, role_id: uuid.UUID
    ) -> OrganizationRole | None: ...

    async def list_organization_roles(
        self, organization_id: uuid.UUID
    ) -> list[OrganizationRole]: ...

    async def upsert_organization_role(self, **fields: object) -> OrganizationRole: ...

    async def get_location_role(
        self, location_id: uuid.UUID, role_id: uuid.UUID
    ) -> LocationRole | None: ...

    async def list_location_roles(
        self, location_id: uuid.UUID
    ) -> list[LocationRole]: ...

    async def upsert_location_role(self, **fields: object) -> LocationRole: ...

    # -- audit log -------------------------------------------------------------
    async def create_audit_log_entry(self, **fields: object) -> AuditLogEntry: ...

    async def list_audit_log_entries(
        self, *, entity_type: str | None = None, entity_id: uuid.UUID | None = None
    ) -> list[AuditLogEntry]: ...

    async def search_audit_log_entries(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        actor_user_id: uuid.UUID | None = None,
        action: str | None = None,
        entity_type: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        page: int,
        page_size: int,
    ) -> tuple[list[AuditLogEntry], PaginationMeta]: ...


class RBACRepository:
    """Concrete, SQLAlchemy-backed implementation of ``RBACRepositoryProtocol``."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.permission_groups = GenericRepository(PermissionGroup, session)
        self.permissions = GenericRepository(Permission, session)
        self.permission_scopes = GenericRepository(PermissionScope, session)
        self.roles = GenericRepository(Role, session)
        self.role_scopes = GenericRepository(RoleScope, session)
        self.role_permissions = GenericRepository(RolePermission, session)
        self.user_roles = GenericRepository(UserRole, session)
        self.permission_overrides = GenericRepository(PermissionOverride, session)
        self.organization_roles = GenericRepository(OrganizationRole, session)
        self.location_roles = GenericRepository(LocationRole, session)
        self.audit_log_entries = GenericRepository(AuditLogEntry, session)

    # -- permission groups -------------------------------------------------

    async def list_permission_groups(self) -> list[PermissionGroup]:
        return await self.permission_groups.get_all(
            sort_by="sort_order", sort_order=SortOrder.ASC
        )

    async def get_permission_group_by_key(self, key: str) -> PermissionGroup | None:
        results = await self.permission_groups.get_all(filters={"key": key}, limit=1)
        return results[0] if results else None

    async def get_permission_group_by_id(
        self, group_id: uuid.UUID
    ) -> PermissionGroup | None:
        return await self.permission_groups.get_by_id(group_id)

    async def create_permission_group(self, **fields: object) -> PermissionGroup:
        return await self.permission_groups.create(fields)

    # -- permissions ---------------------------------------------------------

    async def list_permissions(
        self, *, permission_group_id: uuid.UUID | None = None
    ) -> list[Permission]:
        filters = (
            {"permission_group_id": permission_group_id}
            if permission_group_id
            else None
        )
        return await self.permissions.get_all(
            filters=filters, sort_by="key", sort_order=SortOrder.ASC
        )

    async def get_permission_by_key(self, key: str) -> Permission | None:
        results = await self.permissions.get_all(filters={"key": key}, limit=1)
        return results[0] if results else None

    async def get_permission_by_id(self, permission_id: uuid.UUID) -> Permission | None:
        return await self.permissions.get_by_id(permission_id)

    async def create_permission(self, **fields: object) -> Permission:
        return await self.permissions.create(fields)

    async def get_permission_scope_types(self, permission_id: uuid.UUID) -> list[str]:
        rows = await self.permission_scopes.get_all(
            filters={"permission_id": permission_id}
        )
        return [row.scope_type for row in rows]

    async def add_permission_scope(
        self, permission_id: uuid.UUID, scope_type: ScopeType
    ) -> PermissionScope:
        return await self.permission_scopes.create(
            {"permission_id": permission_id, "scope_type": scope_type.value}
        )

    # -- roles -----------------------------------------------------------------

    async def get_role_by_id(
        self, role_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Role | None:
        return await self.roles.get_by_id(role_id, include_deleted=include_deleted)

    async def get_role_by_slug(
        self, slug: str, organization_id: uuid.UUID | None
    ) -> Role | None:
        results = await self.roles.get_all(
            filters={"slug": slug, "organization_id": organization_id}, limit=1
        )
        if results:
            return results[0]
        if organization_id is None:
            # GenericRepository's equality filter can't express "IS NULL" via
            # the None-means-skip convention (see apply_filters), so global
            # (organization_id IS NULL) roles need an explicit statement.
            statement = select(Role).where(
                Role.slug == slug,
                Role.organization_id.is_(None),
                Role.is_deleted.is_(False),
            )
            result = await self.session.execute(statement)
            return result.scalar_one_or_none()
        return None

    async def list_roles(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        include_global: bool = True,
        scope_type: ScopeType | None = None,
        is_active: bool | None = None,
    ) -> list[Role]:
        statement = select(Role).where(Role.is_deleted.is_(False))
        if organization_id is not None and include_global:
            statement = statement.where(
                (Role.organization_id == organization_id)
                | (Role.organization_id.is_(None))
            )
        elif organization_id is not None:
            statement = statement.where(Role.organization_id == organization_id)
        elif not include_global:
            statement = statement.where(Role.organization_id.isnot(None))
        if scope_type is not None:
            statement = statement.where(Role.scope_type == scope_type.value)
        if is_active is not None:
            statement = statement.where(Role.is_active.is_(is_active))
        statement = statement.order_by(Role.name.asc())
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    async def create_role(self, **fields: object) -> Role:
        return await self.roles.create(fields)

    async def update_role(self, role: Role, data: dict[str, object]) -> Role:
        return await self.roles.update(role, data)

    async def soft_delete_role(self, role: Role) -> Role:
        return await self.roles.soft_delete(role)

    async def get_role_scope_types(self, role_id: uuid.UUID) -> list[str]:
        rows = await self.role_scopes.get_all(filters={"role_id": role_id})
        return [row.scope_type for row in rows]

    async def add_role_scope(
        self, role_id: uuid.UUID, scope_type: ScopeType, *, is_default: bool = False
    ) -> RoleScope:
        return await self.role_scopes.create(
            {
                "role_id": role_id,
                "scope_type": scope_type.value,
                "is_default": is_default,
            }
        )

    async def get_role_permissions(self, role_id: uuid.UUID) -> list[RolePermission]:
        statement = (
            select(RolePermission)
            .where(
                RolePermission.role_id == role_id, RolePermission.is_deleted.is_(False)
            )
            .options(selectinload(RolePermission.permission))
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    async def add_role_permission(
        self,
        role_id: uuid.UUID,
        permission_id: uuid.UUID,
        *,
        granted_by: uuid.UUID | None,
    ) -> RolePermission:
        return await self.role_permissions.create(
            {
                "role_id": role_id,
                "permission_id": permission_id,
                "granted_at": datetime.now(UTC),
                "granted_by": granted_by,
            }
        )

    async def remove_role_permission(
        self, role_id: uuid.UUID, permission_id: uuid.UUID
    ) -> bool:
        results = await self.role_permissions.get_all(
            filters={"role_id": role_id, "permission_id": permission_id}
        )
        if not results:
            return False
        for row in results:
            await self.role_permissions.delete(row)
        return True

    async def get_parent_chain(
        self, role_id: uuid.UUID, *, max_depth: int
    ) -> list[Role]:
        """Walk ``parent_role_id`` upward, stopping at ``max_depth`` as a
        defensive backstop (cycles are rejected at write time by the service
        layer, but this guards against any that slip through)."""
        chain: list[Role] = []
        seen: set[uuid.UUID] = {role_id}
        current = await self.get_role_by_id(role_id)
        depth = 0
        while current is not None and current.parent_role_id and depth < max_depth:
            parent = await self.get_role_by_id(current.parent_role_id)
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
        moment = now or datetime.now(UTC)
        statement = (
            select(UserRole)
            .where(
                UserRole.user_id == user_id,
                UserRole.is_active.is_(True),
                UserRole.is_deleted.is_(False),
                (UserRole.expires_at.is_(None)) | (UserRole.expires_at > moment),
            )
            .options(selectinload(UserRole.role))
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    async def get_user_role_assignment(
        self, assignment_id: uuid.UUID
    ) -> UserRole | None:
        return await self.user_roles.get_by_id(assignment_id)

    async def create_user_role(self, **fields: object) -> UserRole:
        return await self.user_roles.create(fields)

    async def deactivate_user_role(self, user_role: UserRole) -> UserRole:
        return await self.user_roles.update(user_role, {"is_active": False})

    async def get_user_ids_with_role(self, role_id: uuid.UUID) -> list[uuid.UUID]:
        statement = select(UserRole.user_id).where(
            UserRole.role_id == role_id,
            UserRole.is_active.is_(True),
            UserRole.is_deleted.is_(False),
        )
        result = await self.session.execute(statement)
        return list({row for row in result.scalars().all()})

    # -- permission overrides ------------------------------------------------

    async def get_active_overrides_for_user(
        self, user_id: uuid.UUID, *, now: datetime | None = None
    ) -> list[PermissionOverride]:
        moment = now or datetime.now(UTC)
        statement = (
            select(PermissionOverride)
            .where(
                PermissionOverride.user_id == user_id,
                PermissionOverride.is_active.is_(True),
                PermissionOverride.is_deleted.is_(False),
                (PermissionOverride.expires_at.is_(None))
                | (PermissionOverride.expires_at > moment),
            )
            .options(selectinload(PermissionOverride.permission))
        )
        result = await self.session.execute(statement)
        return list(result.scalars().all())

    async def get_permission_override_by_id(
        self, override_id: uuid.UUID
    ) -> PermissionOverride | None:
        return await self.permission_overrides.get_by_id(override_id)

    async def create_permission_override(self, **fields: object) -> PermissionOverride:
        return await self.permission_overrides.create(fields)

    async def deactivate_permission_override(
        self, override: PermissionOverride
    ) -> PermissionOverride:
        return await self.permission_overrides.update(override, {"is_active": False})

    # -- organization / location role configuration --------------------------

    async def get_organization_role(
        self, organization_id: uuid.UUID, role_id: uuid.UUID
    ) -> OrganizationRole | None:
        results = await self.organization_roles.get_all(
            filters={"organization_id": organization_id, "role_id": role_id}, limit=1
        )
        return results[0] if results else None

    async def list_organization_roles(
        self, organization_id: uuid.UUID
    ) -> list[OrganizationRole]:
        return await self.organization_roles.get_all(
            filters={"organization_id": organization_id}
        )

    async def upsert_organization_role(self, **fields: object) -> OrganizationRole:
        existing = await self.get_organization_role(
            fields["organization_id"],
            fields["role_id"],  # type: ignore[arg-type]
        )
        if existing:
            return await self.organization_roles.update(existing, fields)
        return await self.organization_roles.create(fields)

    async def get_location_role(
        self, location_id: uuid.UUID, role_id: uuid.UUID
    ) -> LocationRole | None:
        results = await self.location_roles.get_all(
            filters={"location_id": location_id, "role_id": role_id}, limit=1
        )
        return results[0] if results else None

    async def list_location_roles(self, location_id: uuid.UUID) -> list[LocationRole]:
        return await self.location_roles.get_all(filters={"location_id": location_id})

    async def upsert_location_role(self, **fields: object) -> LocationRole:
        existing = await self.get_location_role(
            fields["location_id"],
            fields["role_id"],  # type: ignore[arg-type]
        )
        if existing:
            return await self.location_roles.update(existing, fields)
        return await self.location_roles.create(fields)

    # -- audit log -------------------------------------------------------------

    async def create_audit_log_entry(self, **fields: object) -> AuditLogEntry:
        return await self.audit_log_entries.create(fields)

    async def list_audit_log_entries(
        self, *, entity_type: str | None = None, entity_id: uuid.UUID | None = None
    ) -> list[AuditLogEntry]:
        filters: dict[str, object] = {}
        if entity_type is not None:
            filters["entity_type"] = entity_type
        if entity_id is not None:
            filters["entity_id"] = entity_id
        return await self.audit_log_entries.get_all(
            filters=filters or None, sort_by="created_at", sort_order=SortOrder.DESC
        )

    async def search_audit_log_entries(
        self,
        *,
        organization_id: uuid.UUID | None = None,
        actor_user_id: uuid.UUID | None = None,
        action: str | None = None,
        entity_type: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        page: int,
        page_size: int,
    ) -> tuple[list[AuditLogEntry], PaginationMeta]:
        """Extension of :meth:`list_audit_log_entries` for
        ``app.domains.audit``'s query/export surface -- hand-written SQL,
        not ``GenericRepository.paginate``'s equality/IN-only filters,
        since a ``start``/``end`` date range needs a real ``>=``/``<=``
        comparison (same precedent as
        ``app.domains.billing.repository.BillingRepository
        .list_issued_past_due``). No schema change -- reads the exact same
        ``audit_log_entries`` table ``create_audit_log_entry`` already
        writes."""
        conditions = [AuditLogEntry.is_deleted.is_(False)]
        if organization_id is not None:
            conditions.append(AuditLogEntry.organization_id == organization_id)
        if actor_user_id is not None:
            conditions.append(AuditLogEntry.actor_user_id == actor_user_id)
        if action is not None:
            conditions.append(AuditLogEntry.action == action)
        if entity_type is not None:
            conditions.append(AuditLogEntry.entity_type == entity_type)
        if start is not None:
            conditions.append(AuditLogEntry.created_at >= start)
        if end is not None:
            conditions.append(AuditLogEntry.created_at <= end)

        params = PageParams(page=page, page_size=page_size)
        count_statement = (
            select(func.count()).select_from(AuditLogEntry).where(*conditions)
        )
        total_items = (await self.session.execute(count_statement)).scalar_one()

        statement = (
            select(AuditLogEntry)
            .where(*conditions)
            .order_by(AuditLogEntry.created_at.desc())
        )
        result = await self.session.execute(paginate(statement, params))
        rows = list(result.scalars().all())
        return rows, PaginationMeta.from_total(params, total_items)
