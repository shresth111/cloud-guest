"""The RBAC authorization engine.

Four focused components, composed top-down:

* :class:`RoleResolver` -- which roles does a user actively hold, optionally
  narrowed to a scope context.
* :class:`PermissionResolver` -- the user's effective permission grants
  (allow *and* deny), derived fresh from role assignments (with recursive
  parent-role inheritance) plus user-level overrides.
* :class:`ScopeResolver` -- does a given grant's scope satisfy a requested
  scope, respecting the CloudGuest -> Organization -> Location -> Router
  hierarchy.
* :class:`AccessValidator` -- ties the above together into the actual
  "can this user do this" check, backed by :class:`PermissionCache` and
  emitting a ``Permission Denied`` audit log entry on denial.

Nothing here ever branches on a role's *name* or *slug* -- every decision is
driven by permission keys and scope data read from the database (or the
cache warmed from it). That is the "Dynamic Permission Evaluation"
requirement: roles and permissions are 100% data-driven.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from app.core.config import get_settings

from .cache import PermissionCache
from .context import GrantScope, ScopeContext
from .enums import SCOPE_HIERARCHY_ORDER, AuditAction, OverrideEffect, ScopeType
from .exceptions import PermissionDeniedError
from .models import Role, UserRole
from .repository import RBACRepositoryProtocol

logger = logging.getLogger(__name__)

Effect = Literal["allow", "deny"]


@dataclass(frozen=True, slots=True)
class ActiveRoleAssignment:
    """An active, non-expired ``UserRole`` paired with its (active) ``Role``."""

    assignment: UserRole
    role: Role

    @property
    def grant_scope(self) -> GrantScope:
        return GrantScope(
            scope_type=ScopeType(self.assignment.scope_type),
            organization_id=self.assignment.organization_id,
            location_id=self.assignment.location_id,
            router_id=self.assignment.router_id,
            msp_id=self.assignment.msp_id,
        )


@dataclass(frozen=True, slots=True)
class EffectiveGrant:
    """A single (permission, scope, effect) grant contributing to a user's access."""

    permission_key: str
    effect: Effect
    scope: GrantScope
    source: str

    def to_json(self) -> dict[str, Any]:
        return {
            "permission_key": self.permission_key,
            "effect": self.effect,
            "scope_type": self.scope.scope_type.value,
            "organization_id": str(self.scope.organization_id)
            if self.scope.organization_id
            else None,
            "location_id": str(self.scope.location_id)
            if self.scope.location_id
            else None,
            "router_id": str(self.scope.router_id) if self.scope.router_id else None,
            "msp_id": str(self.scope.msp_id) if self.scope.msp_id else None,
            "source": self.source,
        }

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> EffectiveGrant:
        return cls(
            permission_key=payload["permission_key"],
            effect=payload["effect"],
            scope=GrantScope(
                scope_type=ScopeType(payload["scope_type"]),
                organization_id=_maybe_uuid(payload.get("organization_id")),
                location_id=_maybe_uuid(payload.get("location_id")),
                router_id=_maybe_uuid(payload.get("router_id")),
                msp_id=_maybe_uuid(payload.get("msp_id")),
            ),
            source=payload["source"],
        )


def _maybe_uuid(value: str | None) -> uuid.UUID | None:
    return uuid.UUID(value) if value else None


@dataclass(frozen=True, slots=True)
class EffectiveGrants:
    """The complete set of allow/deny grants driving one user's access."""

    allow: tuple[EffectiveGrant, ...]
    deny: tuple[EffectiveGrant, ...]

    def permission_keys(self) -> set[str]:
        return {grant.permission_key for grant in self.allow}

    def to_json(self) -> dict[str, Any]:
        return {
            "allow": [grant.to_json() for grant in self.allow],
            "deny": [grant.to_json() for grant in self.deny],
        }

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> EffectiveGrants:
        return cls(
            allow=tuple(
                EffectiveGrant.from_json(item) for item in payload.get("allow", [])
            ),
            deny=tuple(
                EffectiveGrant.from_json(item) for item in payload.get("deny", [])
            ),
        )


class RoleResolver:
    """Resolves which roles a user actively holds."""

    def __init__(self, repository: RBACRepositoryProtocol) -> None:
        self.repository = repository

    async def get_active_assignments(
        self, user_id: uuid.UUID, *, now: datetime | None = None
    ) -> list[ActiveRoleAssignment]:
        """Active, non-expired ``user_roles`` rows whose role is itself active.

        A deactivated role (``Role.is_active is False``) grants nothing even
        if the assignment row itself is still marked active -- this is the
        "deactivated roles' assignments should not grant access" requirement.
        """
        moment = now or datetime.now(UTC)
        rows = await self.repository.get_active_user_roles(user_id, now=moment)
        return [
            ActiveRoleAssignment(assignment=row, role=row.role)
            for row in rows
            if row.role is not None and row.role.is_active and not row.role.is_deleted
        ]

    async def get_active_roles(
        self,
        user_id: uuid.UUID,
        *,
        scope_context: ScopeContext | None = None,
        now: datetime | None = None,
    ) -> list[Role]:
        """Distinct active roles, optionally narrowed to a scope context.

        Narrowing here is a simple containment check (does this assignment
        apply to the requested organization/location/router, or is it
        global) -- it is intentionally simpler than
        :meth:`ScopeResolver.satisfies`, which additionally reasons about
        *which permission-scope levels* a grant covers.
        """
        assignments = await self.get_active_assignments(user_id, now=now)
        if scope_context is not None:
            assignments = [
                item
                for item in assignments
                if _assignment_matches_context(item.assignment, scope_context)
            ]
        seen: set[uuid.UUID] = set()
        roles: list[Role] = []
        for item in assignments:
            if item.role.id not in seen:
                seen.add(item.role.id)
                roles.append(item.role)
        return roles


def _assignment_matches_context(assignment: UserRole, context: ScopeContext) -> bool:
    scope_type = ScopeType(assignment.scope_type)
    if scope_type == ScopeType.GLOBAL:
        return True
    if scope_type == ScopeType.ORGANIZATION:
        return (
            context.organization_id is not None
            and assignment.organization_id == context.organization_id
        )
    if scope_type == ScopeType.LOCATION:
        return (
            context.location_id is not None
            and assignment.location_id == context.location_id
        )
    if scope_type == ScopeType.ROUTER:
        return (
            context.router_id is not None and assignment.router_id == context.router_id
        )
    return False


class ScopeResolver:
    """Answers "does this grant's scope satisfy this requested scope check?"."""

    @staticmethod
    def satisfies(
        grant_scope: GrantScope,
        requested_scope_type: ScopeType,
        requested: ScopeContext,
    ) -> bool:
        """A grant satisfies a request when it is at least as broad and, at
        its own level, identifies the same entity as the request.

        ``GLOBAL`` grants satisfy everything. An ``ORGANIZATION`` grant
        satisfies an organization-level *or narrower* (location/router)
        check as long as the requested context's ``organization_id``
        matches -- this is the "broader scope covers narrower checks"
        hierarchy rule. A grant can never satisfy a check at a *broader*
        level than itself (a location-scoped grant cannot authorize an
        organization-level action).

        Note: because the Location/Router domains don't exist yet, this
        cannot look up "which organization does this location belong to" --
        it relies entirely on the caller (``CurrentOrganization`` /
        ``CurrentLocation`` dependencies) supplying ``organization_id``
        alongside ``location_id``/``router_id`` in the requested
        :class:`ScopeContext`. See RBAC_ARCHITECTURE.md.
        """
        if grant_scope.scope_type == ScopeType.GLOBAL:
            return True

        if (
            SCOPE_HIERARCHY_ORDER[grant_scope.scope_type]
            > SCOPE_HIERARCHY_ORDER[requested_scope_type]
        ):
            # The grant is narrower than what's being asked (e.g. a
            # LOCATION-scoped grant cannot satisfy an ORGANIZATION-level
            # check).
            return False

        if grant_scope.scope_type == ScopeType.ORGANIZATION:
            return (
                grant_scope.organization_id is not None
                and requested.organization_id is not None
                and grant_scope.organization_id == requested.organization_id
            )
        if grant_scope.scope_type == ScopeType.LOCATION:
            return (
                grant_scope.location_id is not None
                and requested.location_id is not None
                and grant_scope.location_id == requested.location_id
            )
        if grant_scope.scope_type == ScopeType.ROUTER:
            return (
                grant_scope.router_id is not None
                and requested.router_id is not None
                and grant_scope.router_id == requested.router_id
            )
        # DEVICE: reserved for future use, never satisfiable today.
        return False


class PermissionResolver:
    """Computes a user's complete effective permission grant set."""

    def __init__(self, repository: RBACRepositoryProtocol) -> None:
        self.repository = repository
        self.role_resolver = RoleResolver(repository)

    async def resolve(
        self, user_id: uuid.UUID, *, now: datetime | None = None
    ) -> EffectiveGrants:
        moment = now or datetime.now(UTC)
        assignments = await self.role_resolver.get_active_assignments(
            user_id, now=moment
        )

        allow: list[EffectiveGrant] = []
        for item in assignments:
            permission_keys = await self.resolve_role_permission_keys(item.role.id)
            grant_scope = item.grant_scope
            allow.extend(
                EffectiveGrant(
                    permission_key=key,
                    effect="allow",
                    scope=grant_scope,
                    source=f"role:{item.role.id}",
                )
                for key in permission_keys
            )

        overrides = await self.repository.get_active_overrides_for_user(
            user_id, now=moment
        )
        deny: list[EffectiveGrant] = []
        for override in overrides:
            if override.permission is None or override.permission.is_deleted:
                continue
            scope = GrantScope(
                scope_type=ScopeType(override.scope_type),
                organization_id=override.organization_id,
                location_id=override.location_id,
                router_id=override.router_id,
            )
            grant = EffectiveGrant(
                permission_key=override.permission.key,
                effect=OverrideEffect(override.effect).value,  # type: ignore[arg-type]
                scope=scope,
                source="override",
            )
            if grant.effect == "deny":
                deny.append(grant)
            else:
                allow.append(grant)

        return EffectiveGrants(allow=tuple(allow), deny=tuple(deny))

    async def resolve_role_permission_keys(self, role_id: uuid.UUID) -> set[str]:
        """Own + inherited permission keys for a role.

        Inheritance is recursive (not single-level): a role's effective
        permissions include its parent's, its grandparent's, and so on, up
        to ``Settings.rbac_max_parent_role_depth`` hops. Recursive was
        chosen over single-level because role cloning is expected to chain
        (a cloned-from-a-clone role should still see the whole lineage's
        grants) -- see RBAC_ARCHITECTURE.md for the full rationale.
        """
        keys: set[str] = set()
        own_permissions = await self.repository.get_role_permissions(role_id)
        keys.update(
            row.permission.key
            for row in own_permissions
            if row.permission is not None
            and row.permission.is_active
            and not row.permission.is_deleted
        )

        max_depth = get_settings().rbac_max_parent_role_depth
        for parent in await self.repository.get_parent_chain(
            role_id, max_depth=max_depth
        ):
            parent_permissions = await self.repository.get_role_permissions(parent.id)
            keys.update(
                row.permission.key
                for row in parent_permissions
                if row.permission is not None
                and row.permission.is_active
                and not row.permission.is_deleted
            )
        return keys


class AccessValidator:
    """The "can this user do this" check: resolver + scope + cache + audit."""

    def __init__(
        self,
        repository: RBACRepositoryProtocol,
        *,
        cache: PermissionCache | None = None,
    ) -> None:
        self.repository = repository
        self.cache = cache
        self.resolver = PermissionResolver(repository)
        self.scope_resolver = ScopeResolver()

    async def get_effective_grants(self, user_id: uuid.UUID) -> EffectiveGrants:
        if self.cache is not None:
            cached = await self.cache.get(user_id)
            if cached is not None:
                return EffectiveGrants.from_json(cached)

        grants = await self.resolver.resolve(user_id)

        if self.cache is not None:
            await self.cache.set(user_id, grants.to_json())
        return grants

    async def has_permission(
        self,
        user_id: uuid.UUID,
        permission_key: str,
        *,
        scope_type: ScopeType = ScopeType.GLOBAL,
        scope_context: ScopeContext | None = None,
    ) -> bool:
        context = scope_context or ScopeContext.global_scope()
        grants = await self.get_effective_grants(user_id)

        denied = any(
            grant.permission_key == permission_key
            and self.scope_resolver.satisfies(grant.scope, scope_type, context)
            for grant in grants.deny
        )
        if denied:
            return False

        return any(
            grant.permission_key == permission_key
            and self.scope_resolver.satisfies(grant.scope, scope_type, context)
            for grant in grants.allow
        )

    async def check(
        self,
        user_id: uuid.UUID,
        permission_key: str,
        *,
        scope_type: ScopeType = ScopeType.GLOBAL,
        scope_context: ScopeContext | None = None,
    ) -> None:
        """Raise :class:`PermissionDeniedError` (and log the denial) if
        ``user_id`` lacks ``permission_key`` at the requested scope."""
        context = scope_context or ScopeContext.global_scope()
        allowed = await self.has_permission(
            user_id, permission_key, scope_type=scope_type, scope_context=context
        )
        if allowed:
            return

        scope_description = _describe_scope(scope_type, context)
        logger.warning(
            "rbac_permission_denied",
            extra={
                "user_id": str(user_id),
                "permission_key": permission_key,
                "scope": scope_description,
            },
        )
        await self.repository.create_audit_log_entry(
            actor_user_id=user_id,
            action=AuditAction.PERMISSION_DENIED.value,
            entity_type="permission",
            entity_id=None,
            description=f"Permission '{permission_key}' denied at {scope_description}",
            event_metadata={
                "permission_key": permission_key,
                "scope": scope_description,
            },
            organization_id=context.organization_id,
            location_id=context.location_id,
        )
        raise PermissionDeniedError(permission_key, scope_description)


def _describe_scope(scope_type: ScopeType, context: ScopeContext) -> str:
    identifier = context.organization_id or context.location_id or context.router_id
    if scope_type == ScopeType.GLOBAL or identifier is None:
        return "global scope"
    return f"{scope_type.value} scope ({identifier})"
