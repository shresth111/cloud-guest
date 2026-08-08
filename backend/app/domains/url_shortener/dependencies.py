"""FastAPI dependencies for the URL Shortener domain.

Wires the repository/service layer, composing with RBAC (for audit logging
on the Master-console moderation path) and the shared Redis client (for the
guest-facing create/redirect rate limiters) rather than duplicating either.

Rate-limit thresholds (``create_max_attempts_per_window``/
``redirect_max_attempts_per_window``/...) are plain module constants in
``constants.py``, not ``Settings`` fields -- mirrors
``app.domains.voucher``'s own documented choice (see that module's
``constants.py`` docstring) for the identical reason: no per-environment
tuning need justifies the ``app/core/config.py`` boundary exception for
this module's own internal knobs. ``short_link_base_url`` (used to compose
``short_url`` in ``router.py``) *is* a genuine ``Settings`` field, alongside
``frontend_base_url`` -- a real, deployment-specific public origin, not an
internal tuning knob.
"""

from __future__ import annotations

from fastapi import Depends, Request
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.database.redis import get_redis_client
from app.database.session import get_db_session
from app.domains.rbac.dependencies import get_rbac_repository
from app.domains.rbac.repository import RBACRepositoryProtocol

from .constants import (
    DEFAULT_CREATE_MAX_ATTEMPTS_PER_WINDOW,
    DEFAULT_CREATE_WINDOW_MINUTES,
    DEFAULT_REDIRECT_MAX_ATTEMPTS_PER_WINDOW,
    DEFAULT_REDIRECT_WINDOW_MINUTES,
)
from .repository import ShortLinkRepository, ShortLinkRepositoryProtocol
from .service import ShortLinkService


def get_short_link_repository(
    db: AsyncSession = Depends(get_db_session),
) -> ShortLinkRepositoryProtocol:
    return ShortLinkRepository(db)


def get_short_link_service(
    repository: ShortLinkRepositoryProtocol = Depends(get_short_link_repository),
    redis: Redis = Depends(get_redis_client),
    audit_repository: RBACRepositoryProtocol = Depends(get_rbac_repository),
) -> ShortLinkService:
    return ShortLinkService(
        repository,
        redis,
        audit_writer=audit_repository,
        create_max_attempts_per_window=DEFAULT_CREATE_MAX_ATTEMPTS_PER_WINDOW,
        create_window_minutes=DEFAULT_CREATE_WINDOW_MINUTES,
        redirect_max_attempts_per_window=DEFAULT_REDIRECT_MAX_ATTEMPTS_PER_WINDOW,
        redirect_window_minutes=DEFAULT_REDIRECT_WINDOW_MINUTES,
    )


def get_short_link_source_ip(request: Request) -> str:
    """The presumed caller IP address for guest-facing rate limiting --
    mirrors ``app.domains.voucher.dependencies.get_redemption_source``'s
    identical "fall back to a fixed string, never None" posture, so a test
    client/proxy with no visible client host still gets a single,
    consistent bucket rather than bypassing the limiter entirely."""
    if request.client is not None and request.client.host:
        return request.client.host
    return "unknown"


def build_short_url(code: str, *, settings: Settings) -> str:
    """Composes the public, clickable short URL for ``code`` -- see
    ``schemas.py``'s module docstring for why this is
    ``Settings.short_link_base_url`` plus this module's own
    ``GET /s/{code}`` route, not ``frontend_base_url`` (that setting names
    the *frontend's* origin, not this backend's own public redirect
    route)."""
    base = settings.short_link_base_url.rstrip("/")
    return f"{base}{settings.api_v1_prefix}/s/{code}"


__all__ = [
    "get_short_link_repository",
    "get_short_link_service",
    "get_short_link_source_ip",
    "build_short_url",
]
