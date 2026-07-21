"""FastAPI dependencies for the OTP domain.

``POST /otp/request``/``POST /otp/verify`` are guest-facing, unauthenticated
endpoints (see ``router.py``'s module docstring for why they carry no
``RequirePermission``/``CurrentUser`` dependency) -- this module only wires
the repository/service layer, composing with RBAC (for audit logging) and
the shared Redis client (for request rate limiting) rather than duplicating
either. The admin-facing ``GET /otp/requests`` endpoint reuses the exact
same ``get_otp_service`` dependency; its own authorization is provided
entirely by RBAC's ``RequirePermission`` in ``router.py``.

``sms_provider``/``email_provider`` are resolved via ``service.py``'s
``get_configured_sms_provider``/``get_configured_email_provider`` --
``Settings.sms_delivery_provider``/``Settings.email_delivery_provider``
select a real provider, defaulting to the honest interim
``LoggingSmsProvider``/``LoggingEmailProvider`` (see ``service.py``'s
module docstring) when unset.
"""

from __future__ import annotations

from fastapi import Depends
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.database.redis import get_redis_client
from app.database.session import get_db_session
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .repository import OtpRepository, OtpRepositoryProtocol
from .service import (
    OtpService,
    get_configured_email_provider,
    get_configured_sms_provider,
)


def get_otp_repository(
    db: AsyncSession = Depends(get_db_session),
) -> OtpRepositoryProtocol:
    return OtpRepository(db)


def get_otp_service(
    repository: OtpRepositoryProtocol = Depends(get_otp_repository),
    redis: Redis = Depends(get_redis_client),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    settings: Settings = Depends(get_settings),
) -> OtpService:
    return OtpService(
        repository,
        redis,
        audit_writer=audit_repository,
        sms_provider=get_configured_sms_provider(settings),
        email_provider=get_configured_email_provider(settings),
        code_length=settings.otp_code_length,
        expiry_seconds=settings.otp_expiry_seconds,
        max_verification_attempts=settings.otp_max_verification_attempts,
        max_requests_per_window=settings.otp_max_requests_per_window,
        request_window_minutes=settings.otp_request_window_minutes,
    )


__all__ = ["get_otp_repository", "get_otp_service"]
