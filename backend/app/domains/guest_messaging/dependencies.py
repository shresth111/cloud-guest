"""FastAPI wiring for login messaging.

The entitlement check is the same ``EntitlementChecker`` path ``RequireFeature``
uses (overrides merged), for ``guest_login_byo``.
"""

from __future__ import annotations

import logging

from fastapi import Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.database.redis import get_redis_client
from app.database.session import get_db_session
from app.domains.billing.constants import PlanFeatureKey
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .registry import AdapterContext
from .repository import LoginProviderRepository
from .service import LoginMessagingService, OrgOtpDispatcher

logger = logging.getLogger(__name__)


def build_login_messaging_service(
    session: AsyncSession,
    redis: Redis,
    settings: Settings,
    audit_writer: RBACRepositoryProtocol | None,
) -> LoginMessagingService:
    from app.domains.marketing.dependencies import build_entitlement_check

    return LoginMessagingService(
        LoginProviderRepository(session),
        settings=settings,
        redis=redis,
        audit_writer=audit_writer,
        byo_entitlement_check=build_entitlement_check(
            session, redis, PlanFeatureKey.GUEST_LOGIN_BYO
        ),
        adapter_context=AdapterContext(settings=settings),
    )


def get_login_messaging_service(
    db: AsyncSession = Depends(get_db_session),
    redis: Redis = Depends(get_redis_client),
    settings: Settings = Depends(get_settings),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> LoginMessagingService:
    return build_login_messaging_service(db, redis, settings, audit_repository)


def build_org_otp_dispatcher(
    session: AsyncSession,
    redis: Redis,
    settings: Settings,
    audit_writer: RBACRepositoryProtocol | None,
) -> OrgOtpDispatcher | None:
    """For ``OtpService``. Building it must not fail a login either: on any
    error there is simply no dispatcher and the platform default sends."""
    try:
        return OrgOtpDispatcher(
            build_login_messaging_service(session, redis, settings, audit_writer),
            session,
        )
    except Exception:  # noqa: BLE001
        logger.warning("guest_login_byo_dispatcher_unavailable", exc_info=True)
        return None


__all__ = [
    "build_login_messaging_service",
    "build_org_otp_dispatcher",
    "get_login_messaging_service",
]
