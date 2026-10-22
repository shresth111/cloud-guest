"""The ``/isp`` guard stack (API_CONTRACT §0).

Every ``/isp`` route declares, in this order::

    dependencies=[
        Depends(RejectLocationRouterHeaders),   # 400 on X-Location-Id / X-Router-Id
        Depends(RequireOrganization),           # existing; never None, refuses "all"
        Depends(RequirePermission(key, scope=ScopeType.ORGANIZATION)),  # pinned
        Depends(RequireIspPartner),
    ]

``isp_guards(key)`` builds exactly that list so no route spells it by hand,
and ``tests/unit/test_isp_partner_guards.py`` asserts it over the mounted
route table.

``RequireIspPartner`` turns the header organization into an
:class:`IspContext`. It refuses, in this order:

1. any caller holding an active GLOBAL-scoped role (Super Admin et al.):
   ``ISP_ROLE_REQUIRED``. Master support uses ``/platform/isp-partners``.
   This keeps "``None`` means every organization" and platform bypasses out
   of the ISP code path entirely;
2. a caller with no ``isp-*`` role on the header organization:
   ``ISP_ROLE_REQUIRED`` (this is what refuses an Organization Owner of a
   customer org naming their own org);
3. an organization with no ``isp_partner_profiles`` row:
   ``ISP_PARTNER_REQUIRED``;
4. a suspended profile, or an organization that is not an active MSP:
   ``ISP_PARTNER_SUSPENDED``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.auth.models import AuthUser
from app.domains.organization.enums import OrganizationStatus, OrganizationType
from app.domains.rbac.authorization import RoleResolver
from app.domains.rbac.dependencies import (
    CurrentUser,
    RequireOrganization,
    RequirePermission,
    get_rbac_repository,
)
from app.domains.rbac.enums import ScopeType
from app.domains.rbac.repository import RBACRepositoryProtocol

from .constants import ISP_ROLE_SLUGS, UNCONFINABLE_ROLES, IspProfileStatus
from .exceptions import (
    IspPartnerRequiredError,
    IspPartnerSuspendedError,
    IspRoleRequiredError,
    IspScopeHeadersNotAllowedError,
)
from .repository import IspRepository

_REFUSED_HEADERS = ("X-Location-Id", "X-Router-Id")


async def RejectLocationRouterHeaders(request: Request) -> None:
    """``_current_scope_context`` would otherwise derive the organization from
    a location or router the caller names, moving the RBAC check onto a
    customer org. ``/isp`` never accepts either header."""
    for header in _REFUSED_HEADERS:
        if request.headers.get(header):
            raise IspScopeHeadersNotAllowedError()


def get_isp_repository(db: AsyncSession = Depends(get_db_session)) -> IspRepository:
    return IspRepository(db)


@dataclass
class IspContext:
    isp_org_id: uuid.UUID
    user_id: uuid.UUID
    role_slug: str
    role_id: uuid.UUID
    #: None = every customer of this ISP.
    confined_customer_ids: frozenset[uuid.UUID] | None
    organization: Any
    profile: Any
    repository: Any
    _child_ids: list[uuid.UUID] | None = field(default=None, repr=False)

    async def child_ids(self) -> list[uuid.UUID]:
        """Non-archived STANDARD children of this ISP, intersected with the
        caller's confinement. May be empty; an empty list means "no
        results", never "all"."""
        if self._child_ids is None:
            children = await self.repository.child_ids(self.isp_org_id)
            if self.confined_customer_ids is not None:
                children = [c for c in children if c in self.confined_customer_ids]
            self._child_ids = list(children)
        return list(self._child_ids)


async def RequireIspPartner(
    isp_org_id: uuid.UUID = Depends(RequireOrganization),
    user: AuthUser = Depends(CurrentUser),
    rbac_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    repository: IspRepository = Depends(get_isp_repository),
) -> IspContext:
    user_id = uuid.UUID(str(user.id))
    assignments = await RoleResolver(rbac_repository).get_active_assignments(user_id)

    if any(a.role.scope_type == ScopeType.GLOBAL.value for a in assignments) or any(
        a.assignment.scope_type == ScopeType.GLOBAL.value for a in assignments
    ):
        raise IspRoleRequiredError()

    isp_roles = [
        a
        for a in assignments
        if a.role.slug in ISP_ROLE_SLUGS
        and a.role.organization_id is None
        and a.assignment.organization_id == isp_org_id
        and a.assignment.scope_type == ScopeType.ORGANIZATION.value
    ]
    if not isp_roles:
        raise IspRoleRequiredError()
    # One isp-* role per user per ISP is what this API writes; if more exist
    # (hand-edited data) take the most privileged deterministically.
    order = ["isp-owner", "isp-admin", "isp-noc", "isp-technician", "isp-viewer"]
    chosen = min(isp_roles, key=lambda a: order.index(a.role.slug))

    profile = await repository.get_profile(isp_org_id)
    if profile is None:
        raise IspPartnerRequiredError()
    organization = await repository.get_organization(isp_org_id)
    if (
        profile.status != IspProfileStatus.ACTIVE.value
        or organization is None
        or organization.org_type != OrganizationType.MSP.value
        or organization.status != OrganizationStatus.ACTIVE.value
    ):
        raise IspPartnerSuspendedError(support_phone=None)

    confined: frozenset[uuid.UUID] | None = None
    if chosen.role.slug not in UNCONFINABLE_ROLES:
        scope_ids = await repository.confined_customer_ids(isp_org_id, user_id)
        confined = frozenset(scope_ids) if scope_ids else None

    return IspContext(
        isp_org_id=isp_org_id,
        user_id=user_id,
        role_slug=chosen.role.slug,
        role_id=chosen.role.id,
        confined_customer_ids=confined,
        organization=organization,
        profile=profile,
        repository=repository,
    )


def isp_guards(permission_key: str) -> list[Any]:
    """The four guards, in contract order, for one ``/isp`` route."""
    return [
        Depends(RejectLocationRouterHeaders),
        Depends(RequireOrganization),
        Depends(RequirePermission(permission_key, scope=ScopeType.ORGANIZATION)),
        Depends(RequireIspPartner),
    ]


__all__ = [
    "IspContext",
    "RejectLocationRouterHeaders",
    "RequireIspPartner",
    "get_isp_repository",
    "isp_guards",
]
