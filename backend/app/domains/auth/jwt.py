"""JWT access/refresh token handling.

Ported from the old ``jwt_handler.py``. Configuration (secret key, algorithm,
token lifetimes) is pulled from ``app.core.config.Settings`` instead of being
passed in / hardcoded, per this project's convention of centralizing config.

The stub's ``encode``/``decode`` static methods are kept as the low-level
primitives; the richer token-pair / validation behaviour from the old
handler is added alongside them as additional static methods.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import jwt as pyjwt

from app.core.config import get_settings


class JWTError(Exception):
    """Base exception for JWT handling errors."""


class TokenExpiredError(JWTError):
    """Raised when a token has expired."""


class InvalidTokenError(JWTError):
    """Raised when a token is malformed, has a bad signature, or fails validation."""


class JWTManager:
    """Static facade over PyJWT, configured from application settings."""

    @staticmethod
    def encode(payload: dict[str, Any]) -> str:
        """Low-level: sign an arbitrary claims dict with the configured secret/alg."""
        settings = get_settings()
        return pyjwt.encode(
            payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm
        )

    @staticmethod
    def decode(token: str, *, verify_expiry: bool = True) -> dict[str, Any]:
        """Low-level: decode and verify the signature (and, by default, expiry)."""
        settings = get_settings()
        try:
            return pyjwt.decode(
                token,
                settings.jwt_secret_key,
                algorithms=[settings.jwt_algorithm],
                options={"verify_exp": verify_expiry},
            )
        except pyjwt.ExpiredSignatureError as exc:
            raise TokenExpiredError("Token has expired") from exc
        except pyjwt.InvalidTokenError as exc:
            raise InvalidTokenError(f"Invalid token: {exc}") from exc

    @staticmethod
    def create_access_token(
        user_id: str,
        email: str,
        additional_claims: dict[str, Any] | None = None,
    ) -> tuple[str, str]:
        """Create an access token. Returns ``(token, jti)``."""
        settings = get_settings()
        now = datetime.now(UTC)
        expires_at = now + timedelta(minutes=settings.access_token_expire_minutes)
        jti = str(uuid4())

        payload: dict[str, Any] = {
            "sub": user_id,
            "email": email,
            "jti": jti,
            "type": "access",
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
        }
        if additional_claims:
            payload.update(additional_claims)

        return JWTManager.encode(payload), jti

    @staticmethod
    def create_refresh_token(user_id: str, email: str) -> tuple[str, str]:
        """Create a refresh token. Returns ``(token, jti)``."""
        settings = get_settings()
        now = datetime.now(UTC)
        expires_at = now + timedelta(days=settings.refresh_token_expire_days)
        jti = str(uuid4())

        payload: dict[str, Any] = {
            "sub": user_id,
            "email": email,
            "jti": jti,
            "type": "refresh",
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
        }
        return JWTManager.encode(payload), jti

    @staticmethod
    def create_token_pair(
        user_id: str,
        email: str,
        additional_claims: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create an access + refresh token pair with expiry metadata."""
        settings = get_settings()
        access_token, access_jti = JWTManager.create_access_token(
            user_id, email, additional_claims
        )
        refresh_token, refresh_jti = JWTManager.create_refresh_token(user_id, email)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "access_jti": access_jti,
            "refresh_jti": refresh_jti,
            "expires_in": settings.access_token_expire_minutes * 60,
            "refresh_expires_in": settings.refresh_token_expire_days * 86400,
        }

    @staticmethod
    def validate_token(
        token: str,
        *,
        expected_type: str | None = None,
        user_id: str | None = None,
    ) -> dict[str, Any]:
        """Decode ``token`` and optionally assert its ``type``/``sub`` claims."""
        payload = JWTManager.decode(token)

        if expected_type and payload.get("type") != expected_type:
            raise InvalidTokenError(f"Invalid token type. Expected {expected_type}")
        if user_id and payload.get("sub") != user_id:
            raise InvalidTokenError("Token subject does not match")

        return payload

    @staticmethod
    def get_token_info(token: str) -> dict[str, Any]:
        """Decode ``token`` without verifying expiry (for inspecting expired tokens)."""
        try:
            return JWTManager.decode(token, verify_expiry=False)
        except InvalidTokenError:
            raise
        except JWTError as exc:
            raise InvalidTokenError(f"Failed to extract token info: {exc}") from exc

    @staticmethod
    def is_token_expired(token: str) -> bool:
        try:
            payload = JWTManager.get_token_info(token)
        except JWTError:
            return True
        return datetime.now(UTC).timestamp() > payload.get("exp", 0)
