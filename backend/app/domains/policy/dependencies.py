"""FastAPI dependencies for the Policy domain.

Wires the repository/service layer, composing with
``app.domains.organization``/``app.domains.location`` (tenant/hierarchy
validation, via the narrow ``OrganizationLookupProtocol``/
``LocationLookupProtocol`` shapes ``service.py`` defines), RBAC (audit
logging, role lookup for Phase F's WHO-targeting, and role resolution for
``GET /policies/resolve``), and ``app.domains.auth`` (user lookup for
Phase F's WHO-targeting) -- the exact same dependency shape
``app.domains.guest_teams.dependencies`` already establishes for its own
narrow cross-domain composition. ``policy`` still composes no *feature*
domain (auth/rbac are foundational Identity & Access modules, not
feature domains -- see ``service.py``'s module docstring).
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.auth.dependencies import get_auth_repository
from app.domains.auth.repository import AuthRepositoryProtocol
from app.domains.location.dependencies import get_location_service
from app.domains.location.service import LocationService
from app.domains.organization.dependencies import get_organization_service
from app.domains.organization.service import OrganizationService
from app.domains.rbac.authorization import RoleResolver
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .repository import PolicyRepository, PolicyRepositoryProtocol
from .service import PolicyService


def get_policy_repository(
    db: AsyncSession = Depends(get_db_session),
) -> PolicyRepositoryProtocol:
    return PolicyRepository(db)


def get_policy_service(
    repository: PolicyRepositoryProtocol = Depends(get_policy_repository),
    organization_service: OrganizationService = Depends(get_organization_service),
    location_service: LocationService = Depends(get_location_service),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    user_repository: AuthRepositoryProtocol = Depends(get_auth_repository),
) -> PolicyService:
    return PolicyService(
        repository,
        organization_service,
        location_service,
        audit_writer=audit_repository,
        user_lookup=user_repository,
        # RBACRepository already exposes get_role_by_id -- the same object
        # already composed above as audit_writer, reused structurally here
        # as PolicyService's RoleLookupProtocol rather than a second
        # dependency.
        role_lookup=audit_repository,
    )


def get_role_resolver(
    repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> RoleResolver:
    """Backs ``GET /policies/resolve``'s optional per-user resolution
    (Enterprise SaaS Phase F) -- resolves the target user's active role
    ids so a ``role``-targeted assignment can be matched."""
    return RoleResolver(repository)


__all__ = ["get_policy_repository", "get_policy_service", "get_role_resolver"]
