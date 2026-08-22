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

## Why ``/captive-portal/resolve`` is keyed differently

Design spec §5 S8. That endpoint is the *first* request a guest's device
makes on a WiFi join, and every device in a venue leaves through the
venue's single NAT egress IP -- so a per-IP bucket is, for the common
deployment, a per-*venue* bucket that happens to be sized for one device.
Twenty guests arriving together could 429 each other out of the internet
they were trying to join. See ``_resolve_buckets`` for the replacement and
for the attack analysis behind it.

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

import logging
import uuid

from redis.asyncio import Redis
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.common.responses import build_response

logger = logging.getLogger(__name__)

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
    # Public "Book a Demo" lead-capture form -- no auth, so nothing but this
    # per-IP throttle stops it being trivially spammed. Only POST is
    # unauthenticated (see app.domains.demo_request.router's own module
    # docstring), but the prefix also covers the RBAC-gated GET/PATCH
    # endpoints, matching every other prefix entry above's own
    # "whole-domain prefix, not method-specific" grain.
    "/api/v1/demo-requests",
    # Public demo-booking calendar -- availability, book, cancel,
    # reschedule. Unauthenticated for the same reason the form above is
    # (see app.domains.demo_booking.router's module docstring), and this
    # per-IP throttle is the first of the three layers that keep a script
    # from filling the sales team's calendar; the other two (per-email
    # attempts, and a hard cap on slots one address may hold) live in that
    # domain. The prefix also covers the RBAC-gated console GET/PATCH,
    # matching every other entry above's whole-domain grain.
    "/api/v1/demo-bookings",
)

_RATE_LIMIT_KEY_TEMPLATE = "rate_limit:{client_ip}:{path}"

# The one path whose bucket is not keyed on the client IP alone -- see
# module docstring and ``_resolve_buckets``.
CAPTIVE_PORTAL_RESOLVE_PATH = "/api/v1/captive-portal/resolve"

_RESOLVE_VENUE_KEY_TEMPLATE = "rate_limit:portal_resolve:venue:{scope}"
_RESOLVE_IP_KEY_TEMPLATE = "rate_limit:portal_resolve:ip:{client_ip}"

# How much higher the per-IP ceiling sits than the per-venue cap.
#
# It cannot be equal. Behind a venue's NAT, one IP *is* one venue, so an
# equal per-IP bucket would always bind first and the venue keying would
# be decorative -- the change would amount to "the old bucket, with a
# bigger number". Setting it higher makes the venue bucket the control
# that actually governs legitimate traffic, and leaves the IP bucket
# doing the one job the venue bucket cannot: bounding an attacker who
# rotates the (client-controlled) venue id to mint a fresh bucket per
# request.
#
# It also cannot be unbounded, which is what omitting it entirely would
# mean. 4x is the compromise: a legitimate venue never approaches it
# (reaching it requires exceeding that venue's own cap fourfold, which
# the venue bucket already refused), while rotation buys a bounded 4x
# rather than infinity. Derived from the venue cap rather than configured
# separately -- one number to reason about, not two that can drift.
_RESOLVE_IP_CEILING_MULTIPLIER = 4


def _venue_scope(request: Request) -> str | None:
    """Derives the venue this resolve call is *for*, from the same
    ``location_id``/``organization_id`` query params the endpoint itself
    resolves by. ``None`` when neither is present or parseable (the
    endpoint will reject such a call anyway).

    ``location_id`` wins when both are given, matching the endpoint's own
    most-specific-wins resolution, so the two agree on what "one venue"
    means.

    **Every value is normalized through ``uuid.UUID`` before it reaches a
    Redis key.** The raw query string is attacker-controlled, and
    interpolating it unparsed would let a crafted value inject ``:``
    separators and collide with -- or forge -- keys in other namespaces
    (including the per-IP buckets above). Parsing to a UUID and
    re-rendering it yields a fixed-format, injection-proof component; an
    unparseable value is simply not used as a key at all.
    """
    params = request.query_params
    for prefix, name in (("loc", "location_id"), ("org", "organization_id")):
        raw = params.get(name)
        if not raw:
            continue
        try:
            return f"{prefix}:{uuid.UUID(raw)}"
        except ValueError:
            continue
    return None


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        *,
        redis: Redis,
        max_requests: int,
        window_seconds: int,
        path_prefixes: tuple[str, ...] = RATE_LIMITED_PATH_PREFIXES,
        resolve_max_requests: int | None = None,
    ) -> None:
        super().__init__(app)
        self.redis = redis
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.path_prefixes = path_prefixes
        self.resolve_max_requests = resolve_max_requests or max_requests

    def _resolve_buckets(self, request: Request) -> list[tuple[str, int]]:
        """The ``(key, cap)`` buckets a ``/captive-portal/resolve`` call
        must pass. **All** of them are checked; any one over its cap
        yields a 429.

        Design spec §5 S8. The old ``(client_ip, path)`` bucket is
        replaced by two:

        ``venue`` -- keyed on the organization/location the call names.
        This is the fairness control. It makes the limit's unit the thing
        actually being protected (one tenant's portal config) rather than
        an accident of network topology, and it is the half that stays
        correct when guests are *not* behind a shared NAT at all: on
        mobile data, IPv6, or per-device public addressing, a per-IP
        bucket silently becomes per-device and the venue is the only
        stable unit left.

        ``ip`` -- retained, and this is the deliberate part. The venue
        component is derived from a query parameter, i.e. it is
        **client-controlled**, and a key an attacker chooses is a key an
        attacker can rotate: fresh ``location_id`` per request means a
        fresh bucket per request, which escapes the venue limit entirely
        and inflates Redis key count while doing it. The per-IP bucket
        does not move when the query string does, so it is what bounds
        rotation. It sits at ``_RESOLVE_IP_CEILING_MULTIPLIER`` times the
        venue cap -- see that constant for why it must be neither equal
        nor absent. (Key *injection* is handled separately, by
        normalizing the parameter through ``uuid.UUID``; see
        ``_venue_scope``.)

        Both are sized for a venue, not a device, which is what actually
        fixes the reported bug -- the old cap was one device's worth of
        traffic applied to an entire venue's NAT address.

        The residual exposure is that a single attacker who knows a real
        ``location_id`` can burn that venue's bucket. That is strictly
        better than the status quo, where any one device behind the NAT
        could do the same by accident, and it is bounded: resolve is a
        single Redis GET on a warm cache, and the endpoint fails open
        (see ``dispatch``) rather than locking a lobby out when Redis
        itself is unhealthy.
        """
        client_ip = request.client.host if request.client else "unknown"
        buckets = [
            (
                _RESOLVE_IP_KEY_TEMPLATE.format(client_ip=client_ip),
                self.resolve_max_requests * _RESOLVE_IP_CEILING_MULTIPLIER,
            )
        ]
        scope = _venue_scope(request)
        if scope is not None:
            buckets.insert(
                0,
                (
                    _RESOLVE_VENUE_KEY_TEMPLATE.format(scope=scope),
                    self.resolve_max_requests,
                ),
            )
        return buckets

    def _buckets_for(self, request: Request, path: str) -> list[tuple[str, int]]:
        if path.startswith(CAPTIVE_PORTAL_RESOLVE_PATH):
            return self._resolve_buckets(request)
        client_ip = request.client.host if request.client else "unknown"
        return [
            (
                _RATE_LIMIT_KEY_TEMPLATE.format(client_ip=client_ip, path=path),
                self.max_requests,
            )
        ]

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        if not any(path.startswith(prefix) for prefix in self.path_prefixes):
            return await call_next(request)

        try:
            exceeded_key = await self._first_exceeded(
                self._buckets_for(request, path)
            )
        except Exception as exc:  # noqa: BLE001 -- fail open, see below
            # A rate limiter that 500s when Redis blinks is worse than no
            # rate limiter. This middleware sits in front of
            # ``/captive-portal/resolve``, which is unauthenticated and is
            # the first request a guest makes standing in a lobby with no
            # internet -- failing closed there turns a Redis hiccup into
            # "the WiFi is broken" for every guest at every venue at once.
            logger.warning(
                "rate_limit_backend_unavailable_failing_open",
                extra={"path": path, "error": str(exc)},
            )
            return await call_next(request)

        if exceeded_key is not None:
            retry_after = await self._retry_after(exceeded_key)
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

    async def _first_exceeded(self, buckets: list[tuple[str, int]]) -> str | None:
        """Increments every bucket and returns the first one over its cap.

        Every bucket is incremented even once one is known to be over, so
        a request that trips one limit still counts against the others --
        otherwise an attacker could shield a bucket from ever counting by
        keeping a cheaper one permanently tripped.
        """
        exceeded: str | None = None
        for key, cap in buckets:
            current = await self.redis.incr(key)
            if current == 1:
                await self.redis.expire(key, self.window_seconds)
            if current > cap and exceeded is None:
                exceeded = key
        return exceeded

    async def _retry_after(self, key: str) -> int:
        try:
            ttl = await self.redis.ttl(key)
        except Exception:  # noqa: BLE001 -- the 429 stands; only the hint is lost
            return self.window_seconds
        return ttl if ttl and ttl > 0 else self.window_seconds


__all__ = [
    "CAPTIVE_PORTAL_RESOLVE_PATH",
    "RATE_LIMITED_PATH_PREFIXES",
    "RateLimitMiddleware",
]
