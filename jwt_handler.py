"""
JWT token handling for access and refresh tokens.

Implements secure JWT generation, validation, and rotation.
Supports token blacklisting via Redis.

Architecture: Infrastructure Layer - Security
"""

from datetime import datetime, timedelta
from typing import Any, Dict, Optional
from uuid import uuid4

import jwt
from pydantic import BaseModel, Field


class TokenPayload(BaseModel):
    """JWT token payload structure."""

    sub: str = Field(..., description="Subject (user_id)")
    email: str = Field(..., description="User email")
    jti: str = Field(..., description="JWT ID (unique token identifier)")
    iat: int = Field(..., description="Issued at (timestamp)")
    exp: int = Field(..., description="Expiration (timestamp)")
    type: str = Field(..., description="Token type (access or refresh)")


class JWTError(Exception):
    """Base exception for JWT errors."""

    pass


class TokenExpiredError(JWTError):
    """Exception raised when token is expired."""

    pass


class InvalidTokenError(JWTError):
    """Exception raised when token is invalid."""

    pass


class JWTHandler:
    """
    JWT token handler for encoding and decoding tokens.

    Configuration:
        - Algorithm: HS256 (HMAC with SHA-256)
        - Access token expiry: 15 minutes
        - Refresh token expiry: 7 days
        - Includes JTI (JWT ID) for token tracking and revocation

    Security Features:
        - Token rotation on refresh
        - JTI tracking for revocation
        - Standard claims validation (iat, exp, sub)
        - Signature verification
    """

    def __init__(
        self,
        secret_key: str,
        algorithm: str = "HS256",
        access_token_expire_minutes: int = 15,
        refresh_token_expire_days: int = 7,
    ) -> None:
        """
        Initialize JWT handler.

        Args:
            secret_key: Secret key for signing tokens
            algorithm: JWT algorithm (default: HS256)
            access_token_expire_minutes: Access token expiry duration
            refresh_token_expire_days: Refresh token expiry duration
        """
        if not secret_key or len(secret_key) < 32:
            raise ValueError(
                "Secret key must be provided and at least 32 characters long"
            )

        self.secret_key = secret_key
        self.algorithm = algorithm
        self.access_token_expire_minutes = access_token_expire_minutes
        self.refresh_token_expire_days = refresh_token_expire_days

    def create_access_token(
        self, user_id: str, email: str, additional_claims: Optional[Dict[str, Any]] = None
    ) -> tuple[str, str]:
        """
        Create a new access token.

        Args:
            user_id: User ID
            email: User email
            additional_claims: Additional claims to include in token

        Returns:
            Tuple of (access_token, jti)
        """
        now = datetime.utcnow()
        expires_at = now + timedelta(minutes=self.access_token_expire_minutes)
        jti = str(uuid4())

        payload: Dict[str, Any] = {
            "sub": user_id,
            "email": email,
            "jti": jti,
            "type": "access",
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
        }

        if additional_claims:
            payload.update(additional_claims)

        encoded_token = jwt.encode(
            payload, self.secret_key, algorithm=self.algorithm
        )

        return encoded_token, jti

    def create_refresh_token(self, user_id: str, email: str) -> tuple[str, str]:
        """
        Create a new refresh token.

        Args:
            user_id: User ID
            email: User email

        Returns:
            Tuple of (refresh_token, jti)
        """
        now = datetime.utcnow()
        expires_at = now + timedelta(days=self.refresh_token_expire_days)
        jti = str(uuid4())

        payload: Dict[str, Any] = {
            "sub": user_id,
            "email": email,
            "jti": jti,
            "type": "refresh",
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
        }

        encoded_token = jwt.encode(
            payload, self.secret_key, algorithm=self.algorithm
        )

        return encoded_token, jti

    def create_token_pair(
        self,
        user_id: str,
        email: str,
        additional_claims: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create both access and refresh tokens.

        Args:
            user_id: User ID
            email: User email
            additional_claims: Additional claims for access token

        Returns:
            Dictionary with access_token, refresh_token, and expiry info
        """
        access_token, access_jti = self.create_access_token(
            user_id, email, additional_claims
        )
        refresh_token, refresh_jti = self.create_refresh_token(user_id, email)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "access_jti": access_jti,
            "refresh_jti": refresh_jti,
            "expires_in": self.access_token_expire_minutes * 60,  # seconds
            "refresh_expires_in": self.refresh_token_expire_days * 86400,  # seconds
        }

    def decode_token(
        self,
        token: str,
        verify_expiry: bool = True,
        verify_signature: bool = True,
    ) -> Dict[str, Any]:
        """
        Decode and validate a JWT token.

        Args:
            token: JWT token to decode
            verify_expiry: Whether to verify token expiration
            verify_signature: Whether to verify token signature

        Returns:
            Decoded token payload

        Raises:
            TokenExpiredError: If token is expired
            InvalidTokenError: If token is invalid
        """
        try:
            options = {
                "verify_signature": verify_signature,
                "verify_exp": verify_expiry,
            }

            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options=options,
            )

            return payload
        except jwt.ExpiredSignatureError as e:
            raise TokenExpiredError("Token has expired") from e
        except jwt.InvalidTokenError as e:
            raise InvalidTokenError(f"Invalid token: {str(e)}") from e
        except Exception as e:
            raise InvalidTokenError(f"Token validation failed: {str(e)}") from e

    def validate_token(
        self,
        token: str,
        expected_type: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validate token and optionally check type and user_id.

        Args:
            token: JWT token to validate
            expected_type: Expected token type ('access' or 'refresh')
            user_id: Expected user_id (optional)

        Returns:
            Decoded payload if valid

        Raises:
            InvalidTokenError: If token is invalid or doesn't match expectations
        """
        payload = self.decode_token(token)

        # Validate token type
        if expected_type and payload.get("type") != expected_type:
            raise InvalidTokenError(f"Invalid token type. Expected {expected_type}")

        # Validate user_id
        if user_id and payload.get("sub") != user_id:
            raise InvalidTokenError("Token user_id does not match")

        return payload

    def get_token_info(self, token: str) -> Dict[str, Any]:
        """
        Extract token information without full validation.

        Useful for getting info from expired tokens.

        Args:
            token: JWT token

        Returns:
            Token payload (without expiry validation)
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"verify_signature": True, "verify_exp": False},
            )
            return payload
        except Exception as e:
            raise InvalidTokenError(f"Failed to extract token info: {str(e)}") from e

    def is_token_expired(self, token: str) -> bool:
        """
        Check if token is expired.

        Args:
            token: JWT token to check

        Returns:
            True if expired, False otherwise
        """
        try:
            payload = self.get_token_info(token)
            exp_timestamp = payload.get("exp", 0)
            return datetime.utcnow().timestamp() > exp_timestamp
        except Exception:
            return True

    def get_expiry_time(self, token: str) -> Optional[datetime]:
        """
        Get token expiration time.

        Args:
            token: JWT token

        Returns:
            Expiration datetime or None if invalid token
        """
        try:
            payload = self.get_token_info(token)
            exp_timestamp = payload.get("exp")
            if exp_timestamp:
                return datetime.utcfromtimestamp(exp_timestamp)
            return None
        except Exception:
            return None

    @property
    def access_token_lifetime(self) -> timedelta:
        """Get access token lifetime as timedelta."""
        return timedelta(minutes=self.access_token_expire_minutes)

    @property
    def refresh_token_lifetime(self) -> timedelta:
        """Get refresh token lifetime as timedelta."""
        return timedelta(days=self.refresh_token_expire_days)
