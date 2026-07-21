"""FastAPI dependencies for the auth domain: current-user resolution and
service/repository wiring via dependency injection.

``get_current_user`` -- the sole function ``app.domains.rbac.dependencies
.CurrentUser``/``RequirePermission`` build on -- accepts *either* a JWT
``Authorization: Bearer`` token (the original mechanism) *or* an
``X-API-Key`` header (see ``app.domains.api_keys``). Teaching this one
function to accept both means every existing ``RequirePermission``-gated
endpoint in the app supports API-key auth automatically, with zero
per-domain changes -- an API key is not a second, parallel authorization
mechanism, only an alternative way to establish the same identity RBAC's
normal permission resolution already runs against.
"""

from __future__ import annotations

import uuid

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.redis import get_redis_client
from app.database.session import get_db_session
from app.domains.api_keys.dependencies import get_api_key_service
from app.domains.api_keys.exceptions import ApiKeyAuthenticationError
from app.domains.api_keys.service import ApiKeyService
from app.domains.notification.dependencies import get_notification_service
from app.domains.notification.service import NotificationService
from app.domains.rbac.authorization import RoleResolver
from app.domains.rbac.repository import RBACRepository
from app.middleware.request_context import get_masking_context

from .jwt import InvalidTokenError, JWTManager, TokenExpiredError
from .models import AuthUser, User
from .repository import AuthRepository, AuthRepositoryProtocol
from .service import AuthService, DeviceInfo

bearer_scheme = HTTPBearer(auto_error=False)
_API_KEY_HEADER = "X-API-Key"
_ORG_HEADER = "X-Organization-Id"


def get_auth_repository(
    db: AsyncSession = Depends(get_db_session),
) -> AuthRepositoryProtocol:
    return AuthRepository(db)


def get_auth_service(
    repository: AuthRepositoryProtocol = Depends(get_auth_repository),
    redis: Redis = Depends(get_redis_client),
    notification_service: NotificationService = Depends(get_notification_service),
) -> AuthService:
    return AuthService(repository, redis, notification_service=notification_service)


def get_role_resolver(db: AsyncSession = Depends(get_db_session)) -> RoleResolver:
    """Builds directly against ``rbac.repository``/``rbac.authorization``
    -- deliberately NOT ``app.domains.rbac.dependencies.get_rbac_repository``,
    which itself imports ``get_current_user`` from *this* module and would
    create a circular import. Used only by ``login``'s role-aware response
    (Enterprise SaaS Phase E)."""
    return RoleResolver(RBACRepository(db))


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    repository: AuthRepositoryProtocol = Depends(get_auth_repository),
    api_key_service: ApiKeyService = Depends(get_api_key_service),
) -> AuthUser:
    x_api_key = request.headers.get(_API_KEY_HEADER)
    if x_api_key:
        user = await _resolve_user_from_api_key(
            x_api_key, request=request, repository=repository, service=api_key_service
        )
    elif credentials is not None:
        user = await _resolve_user_from_jwt(credentials, repository=repository)
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authentication credentials",
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


async def _resolve_user_from_jwt(
    credentials: HTTPAuthorizationCredentials,
    *,
    repository: AuthRepositoryProtocol,
) -> User:
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
    return user


async def _resolve_user_from_api_key(
    plaintext_key: str,
    *,
    request: Request,
    repository: AuthRepositoryProtocol,
    service: ApiKeyService,
) -> User:
    try:
        api_key = await service.resolve_active_key(plaintext_key)
    except ApiKeyAuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key",
        ) from exc

    # An API key is scoped to exactly one organization at creation (see
    # models.ApiKey's own docstring) -- a caller naming a different one via
    # X-Organization-Id is a real scope-escalation attempt, not a header to
    # silently trust. Absent, CurrentOrganization resolves None exactly as
    # it would for a JWT caller with no header -- no new gap introduced.
    org_header = request.headers.get(_ORG_HEADER)
    if org_header and uuid.UUID(org_header) != api_key.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="X-Organization-Id does not match this API key's organization",
        )

    user = await repository.get_user_by_id(api_key.user_id)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is not active",
        )
    return user


def get_device_info(request: Request) -> DeviceInfo:
    client_host = request.client.host if request.client else "unknown"
    return DeviceInfo(
        ip_address=client_host,
        user_agent=request.headers.get("user-agent", "unknown"),
        device_name=request.headers.get("x-device-name"),
    )
