"""FastAPI dependencies for the Analytics domain.

Wires the repository/service layer, composing with
``app.domains.guest``'s existing ``GuestAnalyticsService`` (reused directly
for guest/session aggregate queries, never reimplemented) rather than
duplicating it -- the same narrow, duck-typed ``Protocol`` composition
pattern every prior domain in this codebase establishes (see
``app.domains.monitoring.dependencies.get_platform_dashboard_service`` for
the closest existing precedent of a service composing another domain's
analytics service this same way).
"""

from __future__ import annotations

from fastapi import Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.redis import get_redis_client
from app.database.session import get_db_session
from app.domains.guest.dependencies import get_guest_analytics_service
from app.domains.guest.service import GuestAnalyticsService
from app.domains.location.dependencies import get_location_service
from app.domains.location.service import LocationService
from app.domains.organization.dependencies import get_organization_service
from app.domains.organization.service import OrganizationService
from app.domains.rbac.authorization import RoleResolver
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.wireguard.dependencies import get_wireguard_service
from app.domains.wireguard.service import WireGuardService

from .dashboard_scope import DashboardScopeResolver
from .dashboard_service import DashboardService
from .domain_analytics_service import DomainAnalyticsService
from .repository import AnalyticsRepository, AnalyticsRepositoryProtocol
from .service import AnalyticsService


def get_analytics_repository(
    db: AsyncSession = Depends(get_db_session),
) -> AnalyticsRepositoryProtocol:
    return AnalyticsRepository(db)


def get_analytics_service(
    repository: AnalyticsRepositoryProtocol = Depends(get_analytics_repository),
    guest_analytics_service: GuestAnalyticsService = Depends(
        get_guest_analytics_service
    ),
) -> AnalyticsService:
    return AnalyticsService(repository, guest_analytics_service)


def get_dashboard_scope_resolver(
    rbac_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    organization_service: OrganizationService = Depends(get_organization_service),
    location_service: LocationService = Depends(get_location_service),
) -> DashboardScopeResolver:
    """Composes ``app.domains.rbac.authorization.RoleResolver`` (real, active
    role assignments) with ``OrganizationService``/``LocationService`` (MSP-
    children expansion, location-to-organization lookup) -- see
    ``dashboard_scope.py``'s own module docstring for the full write-up.
    None of ``rbac``/``organization``/``location``'s own files are edited to
    wire this; every dependency here is that domain's own existing,
    already-public factory."""
    role_resolver = RoleResolver(rbac_repository)
    return DashboardScopeResolver(role_resolver, organization_service, location_service)


def get_dashboard_service(
    repository: AnalyticsRepositoryProtocol = Depends(get_analytics_repository),
    guest_analytics_service: GuestAnalyticsService = Depends(
        get_guest_analytics_service
    ),
    scope_resolver: DashboardScopeResolver = Depends(get_dashboard_scope_resolver),
    organization_service: OrganizationService = Depends(get_organization_service),
    location_service: LocationService = Depends(get_location_service),
    redis: Redis = Depends(get_redis_client),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> DashboardService:
    return DashboardService(
        repository,
        guest_analytics_service,
        scope_resolver,
        organization_service,
        location_service,
        redis,
        audit_writer=audit_repository,
    )


def get_domain_analytics_service(
    repository: AnalyticsRepositoryProtocol = Depends(get_analytics_repository),
    guest_analytics_service: GuestAnalyticsService = Depends(
        get_guest_analytics_service
    ),
    scope_resolver: DashboardScopeResolver = Depends(get_dashboard_scope_resolver),
    wireguard_service: WireGuardService = Depends(get_wireguard_service),
    redis: Redis = Depends(get_redis_client),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> DomainAnalyticsService:
    """Wires BE-012 Part 3's ``DomainAnalyticsService`` -- composes the same
    ``AnalyticsRepository``/``GuestAnalyticsService``/``DashboardScopeResolver``/
    Redis/audit-writer Part 2's own ``get_dashboard_service`` already wires,
    plus one new composition point: the real
    ``app.domains.wireguard.service.WireGuardService`` (via that domain's own
    already-public ``get_wireguard_service`` dependency factory, reused
    directly -- no file inside ``app.domains.wireguard`` is edited to make
    this work), satisfying ``WireGuardHealthProtocol``'s single
    ``compute_health_status`` method."""
    return DomainAnalyticsService(
        repository,
        guest_analytics_service,
        scope_resolver,
        wireguard_service,
        redis,
        audit_writer=audit_repository,
    )


__all__ = [
    "get_analytics_repository",
    "get_analytics_service",
    "get_dashboard_scope_resolver",
    "get_dashboard_service",
    "get_domain_analytics_service",
]
