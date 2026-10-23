"""Self-service "forgot password" for the ISP partner console (founder ask
2026-10-23: "forgot password wala option bhi add kar do").

``POST /isp/auth/forgot-password`` -- public, unauthenticated, behind the
``ISP_PARTNER_ENABLED`` flag like every ``/isp`` route.

Why a wrapper and not ``POST /auth/forgot-password``: the existing
``AuthService.initiate_password_reset`` builds its link from
``frontend_base_url`` (the customer app), so an ISP user would land on the
customer ``/reset-password`` page on the wrong host. That code is not edited.
This endpoint issues the token through the SAME service
(``AuthService._issue_cache_token`` with the same ``auth:password_reset``
key and the same one-hour TTL), so the token is consumed by the existing,
unchanged ``POST /auth/reset-password`` -- single use, strength + reuse
checks, ``revoke_all_sessions`` -- exactly as for a customer. Only the link
differs: ``ISP_PARTNER_LOGIN_URL`` + ``/partner/reset-password?token=``.

Security properties (pinned by ``tests/unit/test_isp_partner_password_reset.py``):

- One response for every outcome: unknown email, a non-ISP account, a
  GLOBAL (platform) account, an inactive account, a per-email cap hit, and a
  backend failure all answer the same 200 body as a real send. Nothing in the
  body, the status or the headers depends on the account.
- Only an active account holding a system ``isp-*`` role at ORGANIZATION
  scope, and no GLOBAL role, is sent a partner link. Platform staff use the
  Master flow; customers use the customer flow.
- Rate limited twice, because the global ``RateLimitMiddleware`` path list
  (``app/middleware/rate_limit.py``) does not include this path and is not
  edited: per client IP (429 with ``Retry-After``; independent of the email,
  so it reveals nothing) and per email (silently skips the send, so it cannot
  be used to probe either).
- The token is never logged; only the user id is.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse
from redis.asyncio import Redis

from app.common.responses import build_response
from app.core.email_layout import (
    button,
    callout,
    esc,
    heading,
    link_fallback,
    paragraph,
    render_email,
)
from app.database.redis import get_redis_client
from app.domains.auth.dependencies import get_auth_service
from app.domains.auth.schemas import ForgotPasswordRequest
from app.domains.auth.service import _RESET_TOKEN_KEY, AuthService
from app.domains.notification.constants import (
    NotificationChannelType,
    NotificationEventType,
)
from app.domains.rbac.authorization import RoleResolver
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.enums import ScopeType
from app.domains.rbac.repository import RBACRepositoryProtocol

from .config import get_isp_partner_settings
from .constants import ISP_ROLE_SLUGS
from .http import ok, request_id

__all__ = [
    "GENERIC_MESSAGE",
    "IP_LIMIT",
    "EMAIL_LIMIT",
    "IspPasswordReset",
    "is_isp_reset_eligible",
    "partner_reset_url",
    "password_reset_router",
]

logger = logging.getLogger(__name__)

password_reset_router = APIRouter(prefix="/auth", tags=["ISP Partner: auth"])

GENERIC_MESSAGE = (
    "If an ISP partner account exists with that email, a password reset link "
    "has been sent."
)
#: Same lifetime as the customer flow's token (AuthService.initiate_password_reset).
RESET_TTL = timedelta(hours=1)
#: (max requests, window seconds)
IP_LIMIT = (10, 15 * 60)
EMAIL_LIMIT = (3, 60 * 60)

_IP_KEY = "isp_partner:pwreset:ip:{ip}"
_EMAIL_KEY = "isp_partner:pwreset:email:{digest}"


def partner_reset_url(token: str) -> str:
    base = get_isp_partner_settings().login_url.rstrip("/")
    return f"{base}/partner/reset-password?token={token}"


def is_isp_reset_eligible(user: Any, assignments: list[Any]) -> bool:
    """The same role test ``RequireIspPartner`` applies, minus the org header:
    an active user with a system ``isp-*`` role at ORGANIZATION scope and no
    GLOBAL role anywhere."""
    if user is None or not getattr(user, "is_active", False):
        return False
    if (getattr(user, "status", "active") or "active") != "active":
        return False
    if any(
        a.role.scope_type == ScopeType.GLOBAL.value
        or a.assignment.scope_type == ScopeType.GLOBAL.value
        for a in assignments
    ):
        return False
    return any(
        a.role.slug in ISP_ROLE_SLUGS
        and a.role.organization_id is None
        and a.assignment.scope_type == ScopeType.ORGANIZATION.value
        for a in assignments
    )


def _render_email(*, first_name: str, reset_url: str) -> str:
    content = (
        heading("Reset your ISP Partner Console password")
        + paragraph(
            f"Hi {esc(first_name)}, we received a request to reset the password "
            "for your Wyfy Guest ISP Partner Console account. Click the button "
            "below to choose a new one."
        )
        + button("Reset Password", reset_url)
        + link_fallback(reset_url)
        + callout(
            "This link expires in 1 hour and can only be used once. If you "
            "didn't request this, you can safely ignore this email &mdash; "
            "your password will not be changed.",
            tone="warning",
        )
    )
    return render_email(
        preheader=(
            "Reset your ISP Partner Console password. This link expires in 1 hour."
        ),
        content_html=content,
    )


async def _hit(redis: Redis, key: str, window: int) -> int:
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, window)
    return int(count)


class IspPasswordReset:
    """The flow, with its collaborators injected (unit-testable without a DB)."""

    def __init__(
        self,
        *,
        auth_service: AuthService,
        rbac_repository: RBACRepositoryProtocol,
        redis: Redis,
        role_resolver_cls: Any = None,
    ) -> None:
        self.auth_service = auth_service
        self.rbac_repository = rbac_repository
        self.redis = redis
        self.role_resolver_cls = role_resolver_cls or RoleResolver

    async def ip_allowed(self, client_ip: str) -> tuple[bool, int]:
        """(allowed, retry_after_seconds). Fails open on a Redis error, like
        the global middleware: the per-email cap and the token store still
        need Redis, so nothing is sent while it is down anyway."""
        cap, window = IP_LIMIT
        key = _IP_KEY.format(ip=client_ip)
        try:
            if await _hit(self.redis, key, window) <= cap:
                return True, 0
            ttl = await self.redis.ttl(key)
            return False, int(ttl) if ttl and ttl > 0 else window
        except Exception:  # noqa: BLE001
            logger.warning("isp_password_reset_ip_limit_unavailable")
            return True, 0

    async def request(self, email: str) -> None:
        """Never raises and never returns anything account-dependent."""
        try:
            await self._request(email)
        except Exception:  # noqa: BLE001 -- the reply must not differ
            logger.exception("isp_password_reset_failed")

    async def _request(self, email: str) -> None:
        normalized = email.strip().lower()
        digest = hashlib.sha256(normalized.encode()).hexdigest()
        cap, window = EMAIL_LIMIT
        if await _hit(self.redis, _EMAIL_KEY.format(digest=digest), window) > cap:
            logger.info("isp_password_reset_email_capped")
            return

        user = await self.auth_service.repository.get_user_by_email(normalized)
        if user is None:
            logger.info("isp_password_reset_unknown_email")
            return
        user_id = uuid.UUID(str(user.id))
        assignments = await self.role_resolver_cls(
            self.rbac_repository
        ).get_active_assignments(user_id)
        if not is_isp_reset_eligible(user, assignments):
            logger.info(
                "isp_password_reset_not_eligible", extra={"user_id": str(user_id)}
            )
            return

        token = await self.auth_service._issue_cache_token(
            _RESET_TOKEN_KEY, user_id, ttl=RESET_TTL
        )
        await self.auth_service.notification_service.enqueue(
            event_type=NotificationEventType.PASSWORD_RESET,
            channel=NotificationChannelType.EMAIL,
            recipient=user.email,
            subject="Reset your Wyfy Guest ISP Partner Console password",
            body=_render_email(
                first_name=user.first_name or "there",
                reset_url=partner_reset_url(token),
            ),
            organization_id=None,
        )
        logger.info("isp_password_reset_initiated", extra={"user_id": str(user_id)})


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@password_reset_router.post("/forgot-password", status_code=status.HTTP_200_OK)
async def isp_forgot_password(
    request: Request,
    payload: ForgotPasswordRequest,
    auth_service: AuthService = Depends(get_auth_service),
    rbac_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
    redis: Redis = Depends(get_redis_client),
):
    flow = IspPasswordReset(
        auth_service=auth_service, rbac_repository=rbac_repository, redis=redis
    )
    allowed, retry_after = await flow.ip_allowed(_client_ip(request))
    if not allowed:
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content=build_response(
                success=False,
                message="Too many requests -- please try again later",
                data=None,
                request_id=request_id(request),
            ),
            headers={"Retry-After": str(retry_after)},
        )
    await flow.request(str(payload.email))
    return ok(request, {"message": GENERIC_MESSAGE}, GENERIC_MESSAGE)
