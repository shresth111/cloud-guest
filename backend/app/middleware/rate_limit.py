"""Global, Redis-backed rate-limit middleware for auth and public/guest-
facing routes.

Mirrors ``app.domains.otp.service.OtpRateLimiter``'s identical
INCR+EXPIRE+TTL Redis pattern (and ``app.domains.auth.security.AuthSecurity
.check_rate_limit``'s own sibling precedent) -- reused here at the
middleware layer rather than reimplemented, just keyed by ``(client IP,
path)`` instead of an OTP identifier/login email.

## Why this, when OTP/voucher redemption already have their own limiters

``OtpRateLimiter``/``app.domains.voucher.service.VoucherRedemptionRateLimiter``
are scoped to one *identifier* (a phone/email, a voucher code) -- they
protect the delivery channel/a specific code from being spammed regardless
of which IP is asking. This middleware is scoped to one *client IP*
instead -- it protects against a single source hammering any of these
endpoints while rotating identifiers/codes, a genuinely different attack
dimension. Applying both is defense in depth, not duplication.

## Why only a curated path list, not every route

``register``/``forgot-password``/``resend-verification``/``verify-email``
had **no** request-level rate limiting at all before this (``AuthSecurity
.check_rate_limit`` only covers ``/login``'s email+IP failed-attempt
brute-force case) -- that is the real gap this middleware closes. Every
other route in the app is already RBAC-gated (``RequirePermission``),
which is a much stronger control than a per-IP request count; adding a
blunt IP-based limiter on top of every authenticated admin endpoint would
mostly just risk false positives against legitimate, bursty admin/API
traffic for no real security benefit.
"""

from __future__ import annotations

from redis.asyncio import Redis
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.common.responses import build_response

# Path prefixes this middleware applies to -- every auth endpoint that
# lacks its own identifier-scoped limiter, plus every genuinely public/
# guest-facing endpoint (see module docstring). Prefixes, not exact
# matches, so e.g. "/api/v1/auth/login" also covers any trailing slash
# variant.
RATE_LIMITED_PATH_PREFIXES: tuple[str, ...] = (
    "/api/v1/auth/login",
    "/api/v1/auth/register",
    "/api/v1/auth/forgot-password",
    "/api/v1/auth/reset-password",
    "/api/v1/auth/resend-verification",
    "/api/v1/auth/verify-email",
    "/api/v1/otp/request",
    "/api/v1/otp/verify",
    "/api/v1/vouchers/validate",
    "/api/v1/vouchers/redeem",
    "/api/v1/captive-portal/resolve",
    "/api/v1/guest/",
)

_RATE_LIMIT_KEY_TEMPLATE = "rate_limit:{client_ip}:{path}"


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        *,
        redis: Redis,
        max_requests: int,
        window_seconds: int,
        path_prefixes: tuple[str, ...] = RATE_LIMITED_PATH_PREFIXES,
    ) -> None:
        super().__init__(app)
        self.redis = redis
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.path_prefixes = path_prefixes

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        if not any(path.startswith(prefix) for prefix in self.path_prefixes):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        key = _RATE_LIMIT_KEY_TEMPLATE.format(client_ip=client_ip, path=path)
        current = await self.redis.incr(key)
        if current == 1:
            await self.redis.expire(key, self.window_seconds)

        if current > self.max_requests:
            ttl = await self.redis.ttl(key)
            retry_after = ttl if ttl and ttl > 0 else self.window_seconds
            return JSONResponse(
                status_code=429,
                content=build_response(
                    success=False,
                    message="Too many requests -- please try again later",
                    data=None,
                    request_id=str(getattr(request.state, "request_id", "")),
                ),
                headers={"Retry-After": str(retry_after)},
            )

        return await call_next(request)


__all__ = ["RateLimitMiddleware", "RATE_LIMITED_PATH_PREFIXES"]
