"""FastAPI dependency wiring for Smart Location Provisioning.

Deliberately a **separate module** from ``dependencies.py`` -- not a
stylistic choice, but a real import-cycle constraint: ``dependencies.py``
(this domain's own plain CRUD wiring) is imported at module level by
``app.domains.captive_portal.dependencies``, ``app.domains.router
.dependencies``, and ``app.domains.router_provisioning.dependencies`` (each
composes ``get_location_service`` for its own hierarchy validation). This
module needs to import *those same* dependency-provider modules to compose
``LocationProvisioningService`` -- if it did so from inside
``dependencies.py`` itself, that would be a genuine circular import
(``location.dependencies`` -> ``captive_portal.dependencies`` ->
``location.dependencies``). Splitting the provisioning-specific wiring into
its own module (which none of those other domains' ``dependencies.py``
files import) breaks the cycle with zero change to any of them.

## Why this *is* still "one shared AsyncSession, one transaction"

Every dependency-provider function composed below (``get_location_service``,
``get_organization_service``, ``get_user_service``, ``get_router_service``,
``get_router_provisioning_service``, ``get_wireguard_service``,
``get_plan_service``, ``get_subscription_service``,
``get_captive_portal_service``, ``get_rbac_repository``,
``get_identity_repository``) transitively depends on
``app.database.session.get_db_session`` -- and FastAPI's dependency
resolution invokes any given dependency callable **at most once per
request** (its default caching behavior, never overridden here), so every
one of the many repositories instantiated across this whole graph receives
the *same* ``AsyncSession`` object for a single request. This is the exact
same "compose already-existing ``Depends(get_xxx_service)`` providers"
pattern ``app.domains.router_agent.dependencies`` already uses to compose
``router.dependencies`` + ``router_provisioning.dependencies`` -- nothing
new was invented here.
"""

from __future__ import annotations

from fastapi import Depends

from app.core.config import Settings, get_settings
from app.domains.auth.repository import AuthRepositoryProtocol
from app.domains.billing.dependencies import get_plan_service, get_subscription_service
from app.domains.billing.service import PlanService, SubscriptionService
from app.domains.captive_portal.dependencies import get_captive_portal_service
from app.domains.captive_portal.service import CaptivePortalService
from app.domains.organization.dependencies import get_organization_service
from app.domains.organization.service import OrganizationService
from app.domains.otp.service import LoggingEmailProvider, LoggingSmsProvider
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol
from app.domains.router.dependencies import get_router_service
from app.domains.router.service import RouterService
from app.domains.router_provisioning.dependencies import (
    get_router_provisioning_service,
)
from app.domains.router_provisioning.service import RouterProvisioningService
from app.domains.user.dependencies import get_identity_repository, get_user_service
from app.domains.user.service import UserService
from app.domains.wireguard.dependencies import get_wireguard_service
from app.domains.wireguard.service import WireGuardService

from .dependencies import get_location_service
from .provisioning_service import LocationProvisioningService
from .service import LocationService


def get_location_provisioning_service(
    location_service: LocationService = Depends(get_location_service),
    organization_service: OrganizationService = Depends(get_organization_service),
    user_service: UserService = Depends(get_user_service),
    identity_repository: AuthRepositoryProtocol = Depends(get_identity_repository),
    rbac_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    router_service: RouterService = Depends(get_router_service),
    router_provisioning_service: RouterProvisioningService = Depends(
        get_router_provisioning_service
    ),
    wireguard_service: WireGuardService = Depends(get_wireguard_service),
    plan_service: PlanService = Depends(get_plan_service),
    subscription_service: SubscriptionService = Depends(get_subscription_service),
    captive_portal_service: CaptivePortalService = Depends(get_captive_portal_service),
    settings: Settings = Depends(get_settings),
) -> LocationProvisioningService:
    return LocationProvisioningService(
        location_service,
        organization_service,
        user_service,
        identity_repository,
        rbac_repository,
        router_service,
        router_provisioning_service,
        wireguard_service,
        plan_service,
        subscription_service,
        captive_portal_service,
        LoggingEmailProvider(),
        LoggingSmsProvider(),
        login_url_base=settings.frontend_base_url,
    )


__all__ = ["get_location_provisioning_service"]
