"""FastAPI dependencies for the User management domain.

Authorization for admin endpoints is provided entirely by RBAC's existing
``RequirePermission`` dependency (``app.domains.rbac.dependencies``) against
the already-seeded ``users.*`` permission keys -- nothing here re-implements
authorization. ``/me``/``/me`` (self-service) endpoints require only
``CurrentUser`` (i.e. any authenticated user may read/edit their own
profile).

This module only wires the service layer, composing with
``app.domains.auth`` (identity), ``app.domains.organization`` (membership),
and ``app.domains.rbac`` (role assignment convenience + role lookup)
rather than duplicating any of them -- see ``app.domains.user.service`` for
the narrow protocols each dependency satisfies.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.auth.repository import AuthRepository, AuthRepositoryProtocol
from app.domains.organization.dependencies import get_organization_service
from app.domains.organization.service import OrganizationService
from app.domains.rbac.authorization import RoleResolver
from app.domains.rbac.dependencies import get_rbac_repository, get_rbac_service
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.rbac.service import RBACService

from .service import UserService


def get_identity_repository(
    db: AsyncSession = Depends(get_db_session),
) -> AuthRepositoryProtocol:
    return AuthRepository(db)


def get_role_resolver(
    repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> RoleResolver:
    return RoleResolver(repository)


def get_user_service(
    identity_repository: AuthRepositoryProtocol = Depends(get_identity_repository),
    organization_service: OrganizationService = Depends(get_organization_service),
    rbac_service: RBACService = Depends(get_rbac_service),
    role_resolver: RoleResolver = Depends(get_role_resolver),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> UserService:
    return UserService(
        identity_repository,
        organization_service,
        rbac_service,
        role_resolver,
        audit_writer=audit_repository,
    )
