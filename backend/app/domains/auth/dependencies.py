"""FastAPI dependencies for the auth domain: current-user resolution and
service/repository wiring via dependency injection.
"""

from __future__ import annotations

import uuid

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.redis import get_redis_client
from app.database.session import get_db_session
from app.middleware.request_context import get_masking_context

from .jwt import InvalidTokenError, JWTManager, TokenExpiredError
from .models import AuthUser
from .repository import AuthRepository, AuthRepositoryProtocol
from .service import AuthService, DeviceInfo

bearer_scheme = HTTPBearer(auto_error=False)


def get_auth_repository(
    db: AsyncSession = Depends(get_db_session),
) -> AuthRepositoryProtocol:
    return AuthRepository(db)


def get_auth_service(
    repository: AuthRepositoryProtocol = Depends(get_auth_repository),
    redis: Redis = Depends(get_redis_client),
) -> AuthService:
    return AuthService(repository, redis)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    repository: AuthRepositoryProtocol = Depends(get_auth_repository),
) -> AuthUser:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authentication credentials",
        )

    try:
        payload = JWTManager.validate_token(
            credentials.credentials, expected_type="access"
        )
    except (InvalidTokenError, TokenExpiredError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        ) from exc

    user = await repository.get_user_by_id(uuid.UUID(str(payload["sub"])))
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is not active",
        )

    auth_user = AuthUser.from_model(user)
    # See app.common.masking's own module docstring / MaskingContext's
    # docstring: this is the one place a real, authenticated user's
    # data_masking_enabled flag becomes visible to the rest of the
    # request (Masked* field serializers, and the audit flush at the end
    # of RequestContextMiddleware.dispatch).
    masking_ctx = get_masking_context()
    masking_ctx.masking_enabled = auth_user.data_masking_enabled
    masking_ctx.user_id = auth_user.id
    return auth_user


def get_device_info(request: Request) -> DeviceInfo:
    client_host = request.client.host if request.client else "unknown"
    return DeviceInfo(
        ip_address=client_host,
        user_agent=request.headers.get("user-agent", "unknown"),
        device_name=request.headers.get("x-device-name"),
    )
