"""Tenant scoping for handlers that name their target organization in the path.

``RequirePermission`` resolves the scope it checks from
``_current_scope_context`` (``app.domains.rbac.dependencies``), which prefers
the ``X-Organization-Id`` **header** over a path parameter. A handler that
takes ``organization_id`` from the **path** and does not compare it against
the caller's own organization therefore runs its permission check against one
organization and its read against another: any tenant holding the permission
on its own organization can reach every other tenant's copy of that resource
by putting a foreign UUID in the URL.

``GET /billing/dashboard/{organization_id}`` had exactly this shape and was
fixed inline; a subsequent audit found the same pattern across the billing,
organization, monitoring and rbac domains. This is that guard, extracted so
the next handler gets it by importing rather than by remembering.

Semantics match ``OrganizationService._enforce_tenant_access``:

- a platform-level caller (``requesting_organization_id is None``) may target
  any organization;
- a caller may target its own organization;
- an MSP parent may target its direct children;
- anything else raises ``CrossOrganizationAccessError`` (403).
"""

from __future__ import annotations

import uuid
from typing import Protocol

from .exceptions import CrossOrganizationAccessError


class _OrganizationParentLookup(Protocol):
    """The one thing this guard needs from ``OrganizationService``."""

    async def get_organization(self, organization_id: uuid.UUID): ...


async def enforce_target_organization(
    *,
    target_organization_id: uuid.UUID,
    requesting_organization_id: uuid.UUID | None,
    organization_service: _OrganizationParentLookup,
) -> None:
    """Raise ``CrossOrganizationAccessError`` unless the caller may act on
    ``target_organization_id``. See the module docstring for the rules."""
    if requesting_organization_id is None:
        return
    if target_organization_id == requesting_organization_id:
        return
    target = await organization_service.get_organization(target_organization_id)
    if target.parent_organization_id == requesting_organization_id:
        return
    raise CrossOrganizationAccessError()
