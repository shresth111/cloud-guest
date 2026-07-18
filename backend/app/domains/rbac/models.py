"""SQLAlchemy ORM models for the RBAC domain.

All tables extend ``app.database.base.BaseModel`` (the shared UUID /
timestamp / soft-delete / audit / version mixin stack -- see
``app/database/base.py``) for the same reason every other domain does: so
Alembic autogenerate, the generic repository, and cross-domain FKs all work
uniformly. No model here has a documented reason to diverge from that.

Scope columns: ``organization_id`` carries a real ``ForeignKey`` to
``organizations.id`` (added in migration ``0004``, once
``app.domains.organization`` landed -- Module 005) on every model that has
one (``Role``, ``UserRole``, ``OrganizationRole``, ``PermissionOverride``,
``AuditLogEntry``). ``location_id`` likewise carries a real ``ForeignKey``
to ``locations.id`` (added in migration ``0006``, once
``app.domains.location`` landed --
Module 006) on every model that has one (``UserRole``, ``PermissionOverride``,
``LocationRole``, ``AuditLogEntry``). ``router_id`` now likewise carries a
real ``ForeignKey`` to ``routers.id`` (added in migration ``0008``, once
``app.domains.router`` landed -- Module 008) on the two models that have one
(``UserRole``, ``PermissionOverride`` -- ``AuditLogEntry`` has no
``router_id`` column at all, only ``organization_id``/``location_id``, and
there is no dedicated ``RouterRole`` table, see below). The future ``msp_id``
remains a plain nullable ``UUID`` column *without* a SQL ``ForeignKey``
constraint, because the MSP domain still does not exist yet in this codebase
(see the module scope boundary). A real FK constraint for ``msp_id`` gets
added in a follow-up migration once that domain lands, the same way
``organization_id``/``location_id``/``router_id`` just were.
``PermissionScope`` carries no scope columns at all (only
``permission_id``/``scope_type``) and is unaffected.

**No ``RouterRole`` table.** ``OrganizationRole``/``LocationRole`` exist to
let an organization/location curate which roles are enabled and pick a
default role for new members at that scope. Module 008 deliberately did not
add a ``RouterRole`` equivalent: no gap was found that would require one --
a router has no "which roles are usable here" curation need distinct from
what ``LocationRole`` (one level up) already provides, and no router-level
"default role for new members" concept exists in the RBAC/Router briefs.
``ScopeType.ROUTER`` and ``router_id``-scoped ``UserRole``/
``PermissionOverride`` rows remain the only router-scoped RBAC surface --
this was an intentional scope decision, not an oversight; see
``docs/router/ROUTER_ARCHITECTURE.md`` §7 for the full reasoning, and
revisit only if a genuine per-router role-curation need emerges.

Design decisions worth calling out (see ``docs/rbac/RBAC_ARCHITECTURE.md``
for the full write-up):

* ``role_permissions`` is allow-only. Explicit deny at the *role* level is
  not modeled -- only additive grants. Deny semantics exist exclusively at
  the user level via ``permission_overrides``, which is simpler to reason
  about (a role can never make a user's access worse) and keeps the
  resolver's precedence rules easy to audit: role grants union together,
  then user overrides (allow or deny) apply on top.
* ``parent_role_id`` supports both role cloning (recording provenance) and
  permission inheritance. Inheritance is resolved recursively up the parent
  chain (not just one level) by ``PermissionResolver``, with a depth guard
  (``Settings.rbac_max_parent_role_depth``) as a defensive backstop against
  any cycle that might slip past the service-layer cycle check.
* ``permission_overrides`` carries the same scope columns as ``user_roles``
  so an override can be as broad (global) or as narrow (a single router) as
  the role assignment it's layered on top of.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import BaseModel


class PermissionGroup(BaseModel):
    """A logical grouping of permissions, one per ``PermissionModule`` value."""

    __tablename__ = "permission_groups"

    key: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    sort_order: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    permissions: Mapped[list[Permission]] = relationship(
        "Permission", back_populates="permission_group", cascade="all, delete-orphan"
    )

    __table_args__ = (Index("ix_permission_groups_key", "key"),)

    def __repr__(self) -> str:
        return f"<PermissionGroup(id={self.id}, key={self.key})>"


class Permission(BaseModel):
    """A single, machine-checkable permission, e.g. ``users.create``.

    Permissions are never hardcoded into authorization logic -- they are
    seeded rows (see ``app/domains/rbac/seed.py``) resolved dynamically at
    request time by ``PermissionResolver``.
    """

    __tablename__ = "permissions"

    permission_group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("permission_groups.id", ondelete="CASCADE"),
        nullable=False,
    )
    key: Mapped[str] = mapped_column(String(150), nullable=False, unique=True)
    action: Mapped[str] = mapped_column(String(30), nullable=False)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    permission_group: Mapped[PermissionGroup] = relationship(
        "PermissionGroup", back_populates="permissions"
    )

    __table_args__ = (
        Index("ix_permissions_permission_group_id", "permission_group_id"),
        Index("ix_permissions_key", "key"),
        Index("ix_permissions_action", "action"),
    )

    def __repr__(self) -> str:
        return f"<Permission(id={self.id}, key={self.key})>"


class PermissionScope(BaseModel):
    """The scope levels at which a permission is meaningfully applicable.

    E.g. ``organizations.create`` only makes sense at ``GLOBAL`` scope;
    ``guest_users.create`` makes sense at ``LOCATION`` (and narrower). This
    is used by the service layer to reject nonsensical scope assignments
    for a role that grants a given permission (see
    ``RBACService._validate_scope_assignment``). A permission with no rows
    here is treated as unconstrained (valid at any scope).
    """

    __tablename__ = "permission_scopes"

    permission_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("permissions.id", ondelete="CASCADE"),
        nullable=False,
    )
    scope_type: Mapped[str] = mapped_column(String(20), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "permission_id", "scope_type", name="uq_permission_scopes_permission_scope"
        ),
        Index("ix_permission_scopes_permission_id", "permission_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<PermissionScope(permission_id={self.permission_id}, "
            f"scope={self.scope_type})>"
        )


class Role(BaseModel):
    """A named bundle of permissions, assignable to users at a given scope."""

    __tablename__ = "roles"

    name: Mapped[str] = mapped_column(String(150), nullable=False)
    slug: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    is_system_role: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_template: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    scope_type: Mapped[str] = mapped_column(String(20), nullable=False)

    # Populated for org-scoped custom roles; NULL for global roles. See
    # module docstring for the FK follow-up added in migration 0004.
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
    )

    parent_role_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("roles.id", ondelete="SET NULL"), nullable=True
    )

    role_permissions: Mapped[list[RolePermission]] = relationship(
        "RolePermission", back_populates="role", cascade="all, delete-orphan"
    )
    parent_role: Mapped[Role | None] = relationship(
        "Role", remote_side="Role.id", back_populates="child_roles"
    )
    child_roles: Mapped[list[Role]] = relationship("Role", back_populates="parent_role")

    __table_args__ = (
        UniqueConstraint(
            "slug", "organization_id", name="uq_roles_slug_organization_id"
        ),
        Index("ix_roles_slug", "slug"),
        Index("ix_roles_scope_type", "scope_type"),
        Index("ix_roles_organization_id", "organization_id"),
        Index("ix_roles_parent_role_id", "parent_role_id"),
        Index("ix_roles_is_active", "is_active"),
        Index("ix_roles_is_system_role", "is_system_role"),
    )

    def __repr__(self) -> str:
        return f"<Role(id={self.id}, slug={self.slug}, scope={self.scope_type})>"


class RoleScope(BaseModel):
    """The scope types a role may legally be *assigned at* (via ``user_roles``).

    A role with no rows here may only be assigned at its own natural
    ``scope_type``. A role with rows here may be assigned at any of the
    listed scope types in addition to its own natural scope -- this is what
    lets e.g. a location-templated role also be cloned/assigned at
    organization scope for an org that wants it applied org-wide.
    """

    __tablename__ = "role_scopes"

    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), nullable=False
    )
    scope_type: Mapped[str] = mapped_column(String(20), nullable=False)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    __table_args__ = (
        UniqueConstraint("role_id", "scope_type", name="uq_role_scopes_role_scope"),
        Index("ix_role_scopes_role_id", "role_id"),
    )

    def __repr__(self) -> str:
        return f"<RoleScope(role_id={self.role_id}, scope={self.scope_type})>"


class RolePermission(BaseModel):
    """Join table: a permission granted to a role (allow-only, see module docstring)."""

    __tablename__ = "role_permissions"

    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), nullable=False
    )
    permission_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("permissions.id", ondelete="CASCADE"),
        nullable=False,
    )
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    granted_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    role: Mapped[Role] = relationship("Role", back_populates="role_permissions")
    permission: Mapped[Permission] = relationship("Permission")

    __table_args__ = (
        UniqueConstraint(
            "role_id", "permission_id", name="uq_role_permissions_role_permission"
        ),
        Index("ix_role_permissions_role_id", "role_id"),
        Index("ix_role_permissions_permission_id", "permission_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<RolePermission(role_id={self.role_id}, "
            f"permission_id={self.permission_id})>"
        )


class UserRole(BaseModel):
    """Join table: a role assigned to a user, at a specific scope context.

    A user may hold the same role at multiple, distinct scopes (e.g.
    "Location Manager" at Location A and Location B) -- each is a separate
    row -- and may hold multiple distinct roles at the same scope.
    """

    __tablename__ = "user_roles"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), nullable=False
    )

    scope_type: Mapped[str] = mapped_column(String(20), nullable=False)
    # msp_id/router_id remain FK-less -- see module docstring.
    msp_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
    )
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="SET NULL"),
        nullable=True,
    )
    router_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("routers.id", ondelete="SET NULL"),
        nullable=True,
    )

    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    granted_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    role: Mapped[Role] = relationship("Role")

    __table_args__ = (
        Index("ix_user_roles_user_id", "user_id"),
        Index("ix_user_roles_role_id", "role_id"),
        Index("ix_user_roles_organization_id", "organization_id"),
        Index("ix_user_roles_location_id", "location_id"),
        Index("ix_user_roles_router_id", "router_id"),
        Index("ix_user_roles_is_active", "is_active"),
        Index("ix_user_roles_expires_at", "expires_at"),
    )

    def is_expired(self, *, now: datetime) -> bool:
        return self.expires_at is not None and now > self.expires_at

    def __repr__(self) -> str:
        return (
            f"<UserRole(user_id={self.user_id}, role_id={self.role_id}, "
            f"scope={self.scope_type})>"
        )


class PermissionOverride(BaseModel):
    """Per-user allow/deny permission override, layered on top of role grants.

    When present and in scope for a check, an override always wins over
    role-derived grants for that exact permission (see
    ``PermissionResolver`` / ``AccessValidator``).
    """

    __tablename__ = "permission_overrides"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    permission_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("permissions.id", ondelete="CASCADE"),
        nullable=False,
    )
    effect: Mapped[str] = mapped_column(String(10), nullable=False)

    scope_type: Mapped[str] = mapped_column(String(20), nullable=False)
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
    )
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="SET NULL"),
        nullable=True,
    )
    router_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("routers.id", ondelete="SET NULL"),
        nullable=True,
    )

    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    granted_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    permission: Mapped[Permission] = relationship("Permission")

    __table_args__ = (
        Index("ix_permission_overrides_user_id", "user_id"),
        Index("ix_permission_overrides_permission_id", "permission_id"),
        Index("ix_permission_overrides_is_active", "is_active"),
    )

    def is_expired(self, *, now: datetime) -> bool:
        return self.expires_at is not None and now > self.expires_at

    def __repr__(self) -> str:
        return (
            f"<PermissionOverride(user_id={self.user_id}, "
            f"permission_id={self.permission_id}, effect={self.effect})>"
        )


class OrganizationRole(BaseModel):
    """Per-organization role configuration.

    Purpose: lets an organization opt in/out of which (system or custom)
    roles are actually usable within it, and designate one role as the
    default granted to new members on signup/invite acceptance. Without
    this table, every system role would be implicitly available to every
    organization with no way to curate or default it -- this table is what
    "which roles are enabled for this org" and "what does a brand-new
    member get" actually mean operationally.
    """

    __tablename__ = "organization_roles"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), nullable=False
    )
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_default_for_new_members: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    __table_args__ = (
        UniqueConstraint(
            "organization_id", "role_id", name="uq_organization_roles_org_role"
        ),
        Index("ix_organization_roles_organization_id", "organization_id"),
        Index("ix_organization_roles_role_id", "role_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<OrganizationRole(organization_id={self.organization_id}, "
            f"role_id={self.role_id})>"
        )


class LocationRole(BaseModel):
    """Per-location role configuration, analogous to ``OrganizationRole``.

    Lets a location curate which roles are usable at that specific location
    (narrower than its organization's set) and designate a default role for
    staff assigned to that location.
    """

    __tablename__ = "location_roles"

    location_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="CASCADE"),
        nullable=False,
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), nullable=False
    )
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_default_for_new_members: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    __table_args__ = (
        UniqueConstraint(
            "location_id", "role_id", name="uq_location_roles_location_role"
        ),
        Index("ix_location_roles_location_id", "location_id"),
        Index("ix_location_roles_role_id", "role_id"),
    )

    def __repr__(self) -> str:
        return f"<LocationRole(location_id={self.location_id}, role_id={self.role_id})>"


class AuditLogEntry(BaseModel):
    """Audit trail row for RBAC (and, generically, future-domain) events.

    Column names are kept generic (``actor_user_id``, ``action``,
    ``entity_type``, ``entity_id``, ``metadata``, ``organization_id``,
    ``location_id``) so other domains could plausibly log into this same
    table later rather than each domain growing its own bespoke audit
    table. Scoped deliberately to what RBAC needs today, not a full
    system-wide audit framework.

    The Python attribute is named ``event_metadata`` (not ``metadata``)
    because ``metadata`` is reserved by SQLAlchemy's ``DeclarativeBase``;
    the underlying column name is still ``metadata``.
    """

    __tablename__ = "audit_log_entries"

    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(50), nullable=False)
    entity_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    event_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict, nullable=False
    )
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
    )
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="SET NULL"),
        nullable=True,
    )

    __table_args__ = (
        Index("ix_audit_log_entries_actor_user_id", "actor_user_id"),
        Index("ix_audit_log_entries_action", "action"),
        Index("ix_audit_log_entries_entity_type", "entity_type"),
        Index("ix_audit_log_entries_entity_id", "entity_id"),
        Index("ix_audit_log_entries_organization_id", "organization_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<AuditLogEntry(id={self.id}, action={self.action}, "
            f"entity_type={self.entity_type})>"
        )
