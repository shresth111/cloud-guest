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

from app.core.config import Settings, get_settings
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
from app.domains.voucher.dependencies import get_voucher_repository
from app.domains.voucher.repository import VoucherRepositoryProtocol
from app.domains.wireguard.dependencies import get_wireguard_service
from app.domains.wireguard.service import WireGuardService

from .business_service import BusinessAnalyticsService
from .dashboard_scope import DashboardScopeResolver
from .dashboard_service import DashboardService
from .domain_analytics_service import DomainAnalyticsService
from .forecast_service import ForecastService
from .insight_service import InsightService
from .report_repository import ReportRepository, ReportRepositoryProtocol
from .report_service import (
    ReportGenerationService,
    ReportTemplateService,
    ScheduledReportService,
)
from .repository import AnalyticsRepository, AnalyticsRepositoryProtocol
from .service import AnalyticsService
from .voucher_analytics_service import VoucherAnalyticsService


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


def get_business_analytics_service(
    repository: AnalyticsRepositoryProtocol = Depends(get_analytics_repository),
    scope_resolver: DashboardScopeResolver = Depends(get_dashboard_scope_resolver),
    redis: Redis = Depends(get_redis_client),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> BusinessAnalyticsService:
    """Wires BE-012 Part 4's ``BusinessAnalyticsService`` -- reuses the exact
    same ``AnalyticsRepository``/``DashboardScopeResolver``/Redis/audit-writer
    composition every other analytics service in this domain already wires."""
    return BusinessAnalyticsService(
        repository, scope_resolver, redis, audit_writer=audit_repository
    )


def get_forecast_service(
    repository: AnalyticsRepositoryProtocol = Depends(get_analytics_repository),
    scope_resolver: DashboardScopeResolver = Depends(get_dashboard_scope_resolver),
    redis: Redis = Depends(get_redis_client),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    settings: Settings = Depends(get_settings),
) -> ForecastService:
    """Wires BE-012 Part 4's ``ForecastService`` -- same composition as
    above, plus the real ``Settings`` object every forecast threshold
    (history window, minimum fit points, capacity ceiling, router-risk
    signal thresholds) is read from."""
    return ForecastService(
        repository, scope_resolver, redis, settings, audit_writer=audit_repository
    )


def get_insight_service(
    repository: AnalyticsRepositoryProtocol = Depends(get_analytics_repository),
    scope_resolver: DashboardScopeResolver = Depends(get_dashboard_scope_resolver),
    redis: Redis = Depends(get_redis_client),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    settings: Settings = Depends(get_settings),
) -> InsightService:
    """Wires BE-012 Part 4's ``InsightService`` -- same composition as
    ``get_forecast_service``, for the Insight Engine's own rule thresholds."""
    return InsightService(
        repository, scope_resolver, redis, settings, audit_writer=audit_repository
    )


def get_report_repository(
    db: AsyncSession = Depends(get_db_session),
) -> ReportRepositoryProtocol:
    return ReportRepository(db)


def get_report_generation_service(
    dashboard_service: DashboardService = Depends(get_dashboard_service),
    domain_analytics_service: DomainAnalyticsService = Depends(
        get_domain_analytics_service
    ),
    business_analytics_service: BusinessAnalyticsService = Depends(
        get_business_analytics_service
    ),
    forecast_service: ForecastService = Depends(get_forecast_service),
    insight_service: InsightService = Depends(get_insight_service),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> ReportGenerationService:
    """Wires BE-012 Part 5's ``ReportGenerationService`` -- reuses every one
    of Parts 2-4's own already-wired services (via their own existing
    ``Depends`` factories above) rather than rebuilding their own
    repository/scope-resolver/Redis composition a second time; see
    ``report_service.py``'s own module docstring for why this service
    itself contains no metric computation."""
    return ReportGenerationService(
        dashboard_service,
        domain_analytics_service,
        business_analytics_service,
        forecast_service,
        insight_service,
        audit_writer=audit_repository,
    )


def get_report_template_service(
    repository: ReportRepositoryProtocol = Depends(get_report_repository),
    scope_resolver: DashboardScopeResolver = Depends(get_dashboard_scope_resolver),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> ReportTemplateService:
    return ReportTemplateService(
        repository, scope_resolver, audit_writer=audit_repository
    )


def get_scheduled_report_service(
    repository: ReportRepositoryProtocol = Depends(get_report_repository),
    scope_resolver: DashboardScopeResolver = Depends(get_dashboard_scope_resolver),
    template_service: ReportTemplateService = Depends(get_report_template_service),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> ScheduledReportService:
    return ScheduledReportService(
        repository,
        scope_resolver,
        template_service,
        audit_writer=audit_repository,
    )


def get_voucher_analytics_service(
    voucher_repository: VoucherRepositoryProtocol = Depends(get_voucher_repository),
) -> VoucherAnalyticsService:
    """Phase 1 BhaiFi-parity: composes the real ``VoucherRepository``
    directly (via ``app.domains.voucher``'s own already-public
    ``get_voucher_repository`` factory -- no file inside that domain is
    edited to make this work), satisfying
    ``voucher_analytics.VoucherRedemptionLookupProtocol``'s three
    read-only aggregate methods. See that module's own docstring for why
    this composes the voucher *repository* directly rather than
    ``VoucherService`` -- the one deliberate exception to every other
    factory in this file's "compose a domain's own service" convention."""
    return VoucherAnalyticsService(voucher_repository)


__all__ = [
    "get_analytics_repository",
    "get_analytics_service",
    "get_dashboard_scope_resolver",
    "get_dashboard_service",
    "get_domain_analytics_service",
    "get_business_analytics_service",
    "get_forecast_service",
    "get_insight_service",
    "get_report_repository",
    "get_report_generation_service",
    "get_report_template_service",
    "get_scheduled_report_service",
    "get_voucher_analytics_service",
]
