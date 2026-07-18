"""FastAPI dependencies for the Router domain.

Authorization for router endpoints is provided entirely by RBAC's existing
``RequirePermission`` dependency (``app.domains.rbac.dependencies``) against
the already-seeded ``routers.*``/``router_provisioning.*`` permission keys --
nothing here re-implements authorization. This module only wires the
repository/service layer, composing with ``app.domains.location`` (for
hierarchy validation), ``app.domains.organization`` (for MSP-child tenant
scoping), and RBAC (for audit logging) rather than duplicating any of them.

The device check-in endpoint (``POST /routers/provisioning/check-in``) is
deliberately excluded from any ``RequirePermission``/``CurrentUser``
dependency -- see ``app.domains.router.router`` and
``docs/router/ROUTER_ARCHITECTURE.md`` §5.
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.database.session import get_db_session
from app.domains.location.dependencies import get_location_service
from app.domains.location.service import LocationService
from app.domains.organization.dependencies import get_organization_service
from app.domains.organization.service import OrganizationService
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .repository import RouterRepository, RouterRepositoryProtocol
from .service import RouterService


def get_router_repository(
    db: AsyncSession = Depends(get_db_session),
) -> RouterRepositoryProtocol:
    return RouterRepository(db)


def get_router_service(
    repository: RouterRepositoryProtocol = Depends(get_router_repository),
    location_service: LocationService = Depends(get_location_service),
    organization_service: OrganizationService = Depends(get_organization_service),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    settings: Settings = Depends(get_settings),
) -> RouterService:
    return RouterService(
        repository,
        location_service,
        organization_service,
        audit_writer=audit_repository,
        provisioning_token_ttl_hours=settings.router_provisioning_token_expire_hours,
    )
