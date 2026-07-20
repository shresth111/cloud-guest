"""FastAPI dependencies for the Location domain.

Authorization for location endpoints is provided entirely by RBAC's
existing ``RequirePermission`` dependency (``app.domains.rbac.dependencies``)
against the already-seeded ``locations.*`` permission keys -- nothing here
re-implements authorization. This module only wires the repository/service
layer, composing with ``app.domains.organization`` (for hierarchy
validation) and RBAC (for audit logging) rather than duplicating either.

See ``app.domains.rbac.dependencies.CurrentLocation`` for the real
location-validation + org-consistency check added alongside this module
(documented there and in ``docs/location/LOCATION_ARCHITECTURE.md``).
"""

from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db_session
from app.domains.organization.dependencies import get_organization_service
from app.domains.organization.service import OrganizationService
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .number_generator import LocationCodeCounterRepositoryProtocol
from .repository import (
    LocationCodeCounterRepository,
    LocationRepository,
    LocationRepositoryProtocol,
)
from .service import LocationService


def get_location_repository(
    db: AsyncSession = Depends(get_db_session),
) -> LocationRepositoryProtocol:
    return LocationRepository(db)


def get_location_code_counter_repository(
    db: AsyncSession = Depends(get_db_session),
) -> LocationCodeCounterRepositoryProtocol:
    return LocationCodeCounterRepository(db)


def get_location_service(
    repository: LocationRepositoryProtocol = Depends(get_location_repository),
    organization_service: OrganizationService = Depends(get_organization_service),
    location_code_counter: LocationCodeCounterRepositoryProtocol = Depends(
        get_location_code_counter_repository
    ),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> LocationService:
    return LocationService(
        repository,
        organization_service,
        location_code_counter=location_code_counter,
        audit_writer=audit_repository,
    )
