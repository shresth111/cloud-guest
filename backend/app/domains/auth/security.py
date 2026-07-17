"""Security facade: password + token primitives, plus brute-force protection.

``AuthSecurity`` keeps the stub's original four methods
(``hash_password``, ``verify_password``, ``create_token``, ``decode_token``)
as thin delegations to :mod:`.password` and :mod:`.jwt`, and extends the
class with the rate-limiting / account-lockout / device-fingerprinting
behaviour that used to live in the old, separate ``security_service.py``.
That functionality is genuinely part of "security" even though it isn't
literally password or token handling, and this module is the natural home
for it since there is no separate stub for it in this domain.

Rate limiting and lockout use the existing Redis client
(``app.database.redis``) rather than introducing a new cache abstraction.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import status
from redis.asyncio import Redis

from app.common.exceptions import CloudGuestError
from app.core.config import get_settings

from .jwt import JWTManager
from .password import PasswordManager

_RATE_LIMIT_KEY = "auth:login_attempts:{email}:{ip_address}"


class AccountLockedError(CloudGuestError):
    """Raised when a user account is temporarily locked after repeated failures."""

    def __init__(
        self, locked_until: datetime, message: str = "Account is locked"
    ) -> None:
        self.locked_until = locked_until
        super().__init__(message, status_code=status.HTTP_423_LOCKED)


class RateLimitError(CloudGuestError):
    """Raised when login attempts for an email/IP pair exceed the allowed rate."""

    def __init__(self, retry_after_seconds: int) -> None:
        self.retry_after_seconds = retry_after_seconds
        super().__init__(
            f"Too many login attempts. Try again in {retry_after_seconds} seconds.",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            data={"retry_after_seconds": retry_after_seconds},
        )


class AuthSecurity:
    """Static facade over password hashing, token handling, and login defenses."""

    # -- password + token primitives (preserved stub interface) -----------

    @staticmethod
    def hash_password(password: str) -> str:
        return PasswordManager.hash(password)

    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        return PasswordManager.verify(password, hashed_password)

    @staticmethod
    def create_token(subject: str, **claims: Any) -> str:
        settings = get_settings()
        now = datetime.now(UTC)
        expires_at = now + timedelta(minutes=settings.access_token_expire_minutes)
        payload: dict[str, Any] = {
            "sub": subject,
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            **claims,
        }
        return JWTManager.encode(payload)

    @staticmethod
    def decode_token(token: str) -> dict[str, Any]:
        return JWTManager.decode(token)

    # -- device fingerprinting ---------------------------------------------

    @staticmethod
    def generate_device_id(
        ip_address: str, user_agent: str, fingerprint_seed: str | None = None
    ) -> str:
        components = [ip_address, user_agent]
        if fingerprint_seed:
            components.append(fingerprint_seed)
        fingerprint = "|".join(components)
        return hashlib.sha256(fingerprint.encode()).hexdigest()[:16]

    # -- rate limiting / account lockout ------------------------------------

    @staticmethod
    async def check_rate_limit(redis: Redis, email: str, ip_address: str) -> None:
        """Raise ``RateLimitError`` if this email/IP pair has too many failures."""
        settings = get_settings()
        key = _RATE_LIMIT_KEY.format(email=email, ip_address=ip_address)
        attempts = await redis.get(key)
        if attempts and int(attempts) >= settings.max_login_attempts:
            ttl = await redis.ttl(key)
            raise RateLimitError(
                ttl if ttl and ttl > 0 else settings.account_lockout_minutes * 60
            )

    @staticmethod
    async def record_login_attempt(
        redis: Redis, email: str, ip_address: str, *, success: bool
    ) -> None:
        """Track failed attempts for rate limiting; clear the counter on success."""
        settings = get_settings()
        key = _RATE_LIMIT_KEY.format(email=email, ip_address=ip_address)
        if success:
            await redis.delete(key)
            return
        current = await redis.incr(key)
        if current == 1:
            await redis.expire(key, settings.account_lockout_minutes * 60)

    @staticmethod
    def check_account_lock(locked_until: datetime | None) -> None:
        """Raise ``AccountLockedError`` if ``locked_until`` is still in the future."""
        if locked_until and datetime.now(UTC) < locked_until:
            raise AccountLockedError(locked_until)
