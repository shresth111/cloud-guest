"""FastAPI dependencies for the Guest Marketing domain.

Three providers, deliberately separate:

* :func:`get_marketing_service` -- customer routes. Resolves the caller's
  grant-derived location confinement (strict ``CallerLocationScope``: every
  customer route is authenticated).
* :func:`get_public_marketing_service` -- the unauthenticated unsubscribe and
  guest consent routes. No caller, no confinement; those routes act on a
  token or on the guest's own session, never on a tenant's records.
* :func:`get_marketing_consent_offer_resolver` -- composed into the guest
  login routes to fill ``marketing_consent_offer``. It can never fail a
  login: any error resolves to "no offer".
"""

from __future__ import annotations

import logging
import uuid

from fastapi import Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.database.redis import get_redis_client
from app.database.session import get_db_session
from app.domains.auth.models import AuthUser
from app.domains.billing.cache import EntitlementCache
from app.domains.billing.constants import PlanFeatureKey
from app.domains.billing.repository import (
    FeatureOverrideRepository,
    LicenseRepository,
    PlanRepository,
)
from app.domains.billing.service import EntitlementChecker, LicenseService
from app.domains.rbac.dependencies import (
    CurrentLocation,
    CurrentUser,
    RequireOrganization,
    get_rbac_repository,
)
from app.domains.rbac.location_scope import CallerLocationScope, LocationScope
from app.domains.rbac.repository import RBACRepositoryProtocol

from .credits import build_campaign_credits
from .exceptions import CrossLocationError
from .provider_service import ProviderService
from .repository import MarketingRepository
from .senders import resolve_marketing_senders
from .service import CallerScope, MarketingService

logger = logging.getLogger(__name__)


def build_entitlement_check(
    session: AsyncSession,
    redis: Redis | None,
    feature: PlanFeatureKey = PlanFeatureKey.GUEST_MARKETING,
):
    """``organization_id -> bool`` for ``guest_marketing``, through the same
    ``EntitlementChecker`` (overrides merged, Redis-cached) ``RequireFeature``
    uses -- so the dispatcher and the portal offer agree with the API gate."""
    license_service = LicenseService(
        LicenseRepository(session),
        PlanRepository(session),
        feature_overrides=FeatureOverrideRepository(session),
    )

    class _NoCache:
        async def get(self, organization_id):  # noqa: ANN001
            return None

        async def set(self, organization_id, payload):  # noqa: ANN001
            return None

        async def invalidate(self, organization_id):  # noqa: ANN001
            return None

    checker = EntitlementChecker(
        license_service, EntitlementCache(redis) if redis is not None else _NoCache()
    )

    async def _check(organization_id: uuid.UUID) -> bool:
        snapshot = await checker.get_snapshot(organization_id)
        return snapshot.is_active and snapshot.has_feature(feature)

    return _check


def get_marketing_repository(
    db: AsyncSession = Depends(get_db_session),
) -> MarketingRepository:
    return MarketingRepository(db)


def _enqueue_batch(campaign_id: uuid.UUID, countdown: int) -> None:
    from .tasks import enqueue_send_batch

    enqueue_send_batch(campaign_id, countdown)


def get_marketing_service(
    repository: MarketingRepository = Depends(get_marketing_repository),
    settings: Settings = Depends(get_settings),
    redis: Redis = Depends(get_redis_client),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    caller_location_scope: LocationScope = Depends(CallerLocationScope),
) -> MarketingService:
    return MarketingService(
        repository,
        settings=settings,
        senders=resolve_marketing_senders(settings),
        redis=redis,
        audit_writer=audit_repository,
        entitlement_check=build_entitlement_check(repository.session, redis),
        byo_entitlement_check=build_entitlement_check(
            repository.session, redis, PlanFeatureKey.GUEST_MARKETING_BYO
        ),
        enqueue_batch=_enqueue_batch,
        caller_location_scope=caller_location_scope,
        credits=build_campaign_credits(
            repository.session, audit_writer=audit_repository
        ),
    )


def get_public_marketing_service(
    repository: MarketingRepository = Depends(get_marketing_repository),
    settings: Settings = Depends(get_settings),
    redis: Redis = Depends(get_redis_client),
) -> MarketingService:
    return MarketingService(
        repository,
        settings=settings,
        senders=resolve_marketing_senders(settings),
        redis=redis,
        entitlement_check=build_entitlement_check(repository.session, redis),
        byo_entitlement_check=build_entitlement_check(
            repository.session, redis, PlanFeatureKey.GUEST_MARKETING_BYO
        ),
    )


async def get_caller_scope(
    organization_id: uuid.UUID = Depends(RequireOrganization),
    header_location_id: uuid.UUID | None = Depends(CurrentLocation),
    confinement: LocationScope = Depends(CallerLocationScope),
    user: AuthUser = Depends(CurrentUser),
) -> CallerScope:
    """The caller's organization plus location confinement (contract §5.0).

    ``X-Location-Id`` makes the request location-scoped. A caller whose
    *grants* confine them to locations is location-scoped regardless of the
    header: with one location they are pinned to it, and a header naming a
    location outside their grants is refused. (``RequirePermission`` pinned
    at LOCATION already refuses that case; this is the service-layer
    backstop, because the header is UI context, not entitlement.)
    """
    location_id = header_location_id
    if confinement is not None:
        if location_id is None:
            if len(confinement) != 1:
                raise CrossLocationError(
                    "Select one of your locations (send X-Location-Id)."
                )
            location_id = next(iter(confinement))
        elif location_id not in confinement:
            raise CrossLocationError("You can only act on your own location.")
    return CallerScope(
        organization_id=organization_id,
        location_id=location_id,
        actor_user_id=uuid.UUID(user.id),
    )


def get_provider_service(
    repository: MarketingRepository = Depends(get_marketing_repository),
    settings: Settings = Depends(get_settings),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    marketing: MarketingService = Depends(get_marketing_service),
) -> ProviderService:
    return ProviderService(
        repository,
        settings=settings,
        marketing=marketing,
        audit_writer=audit_repository,
    )


def get_platform_provider_service(
    repository: MarketingRepository = Depends(get_marketing_repository),
    settings: Settings = Depends(get_settings),
    redis: Redis = Depends(get_redis_client),
) -> ProviderService:
    """Master read-only view: no caller confinement (the route is pinned
    GLOBAL), no audit (it reads nothing secret and writes nothing)."""
    marketing = MarketingService(
        repository,
        settings=settings,
        senders=resolve_marketing_senders(settings),
        redis=redis,
        byo_entitlement_check=build_entitlement_check(
            repository.session, redis, PlanFeatureKey.GUEST_MARKETING_BYO
        ),
    )

    async def _exists(organization_id: uuid.UUID) -> bool:
        return await repository.get_organization(organization_id) is not None

    return ProviderService(
        repository, settings=settings, marketing=marketing, organization_exists=_exists
    )


class MarketingConsentOfferResolver:
    def __init__(self, service: MarketingService) -> None:
        self.service = service

    async def offer_for(self, result) -> dict | None:  # noqa: ANN001
        """Runs inside a SAVEPOINT: a failing marketing query must not abort
        the login's own transaction (Postgres refuses every later statement
        in an aborted transaction, which would turn a marketing bug into a
        failed guest login at commit)."""
        session = self.service.repository.session
        try:
            async with session.begin_nested():
                return await self.service.consent_offer(
                    guest=getattr(result, "guest", None),
                    session=getattr(result, "session", None),
                )
        except Exception:  # noqa: BLE001 - never fail a guest login over marketing
            logger.warning("marketing_consent_offer_failed", exc_info=True)
            return None


def get_marketing_consent_offer_resolver(
    service: MarketingService = Depends(get_public_marketing_service),
) -> MarketingConsentOfferResolver:
    return MarketingConsentOfferResolver(service)


__all__ = [
    "MarketingConsentOfferResolver",
    "build_entitlement_check",
    "get_caller_scope",
    "get_marketing_consent_offer_resolver",
    "get_marketing_repository",
    "get_marketing_service",
    "get_public_marketing_service",
]
