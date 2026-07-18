"""Lightweight, non-persisted scope value objects shared across the RBAC domain.

Kept in their own module (rather than ``schemas.py`` or ``authorization.py``)
because ``repository.py``, ``authorization.py``, ``cache.py``, ``service.py``
and ``dependencies.py`` all need them and none of those modules should have
to import from each other just to get a shared value type.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from .enums import ScopeType


@dataclass(frozen=True, slots=True)
class ScopeContext:
    """The scope a permission/role check is being evaluated against.

    Represents "the thing the caller is trying to act on" -- e.g. "organization
    X" or "location Y within organization X". Compared against a grant's own
    ``ScopeContext`` by :class:`app.domains.rbac.authorization.ScopeResolver`.
    """

    organization_id: uuid.UUID | None = None
    location_id: uuid.UUID | None = None
    router_id: uuid.UUID | None = None
    msp_id: uuid.UUID | None = None

    @classmethod
    def global_scope(cls) -> ScopeContext:
        return cls()

    @classmethod
    def for_organization(cls, organization_id: uuid.UUID) -> ScopeContext:
        return cls(organization_id=organization_id)

    @classmethod
    def for_location(
        cls, location_id: uuid.UUID, *, organization_id: uuid.UUID | None = None
    ) -> ScopeContext:
        return cls(location_id=location_id, organization_id=organization_id)

    @classmethod
    def for_router(
        cls,
        router_id: uuid.UUID,
        *,
        organization_id: uuid.UUID | None = None,
        location_id: uuid.UUID | None = None,
    ) -> ScopeContext:
        return cls(
            router_id=router_id,
            organization_id=organization_id,
            location_id=location_id,
        )


@dataclass(frozen=True, slots=True)
class GrantScope:
    """The scope at which a role assignment or permission override was granted."""

    scope_type: ScopeType
    organization_id: uuid.UUID | None = None
    location_id: uuid.UUID | None = None
    router_id: uuid.UUID | None = None
    msp_id: uuid.UUID | None = None

    def describe(self) -> str:
        if self.scope_type == ScopeType.GLOBAL:
            return "global scope"
        identifier = self.organization_id or self.location_id or self.router_id
        return f"{self.scope_type.value} scope ({identifier})"
