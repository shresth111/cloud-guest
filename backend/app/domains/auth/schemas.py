"""Pydantic request/response schemas for the auth API.

Preserves the original stub's simple names (``LoginRequest``,
``RefreshTokenRequest``, ``TokenResponse``, ``UserResponse``) but fills in
the fields the real auth flows need (registration, password reset/change,
email verification, session management) using pydantic v2 conventions
(``ConfigDict`` / ``field_validator`` / ``json_schema_extra``) to match the
rest of this codebase (see ``app/database/schemas/base.py``).
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

# ============================================================================
# Request schemas
# ============================================================================


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=1, description="User password")
    device_name: str | None = Field(
        default=None,
        max_length=255,
        description="Device name, e.g. 'Chrome on Windows'",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "user@example.com",
                "password": "SecurePass123!",
                "device_name": "Chrome on Windows 10",
            }
        }
    )


class RegisterRequest(BaseModel):
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    email: EmailStr = Field(..., description="Email address")
    username: str = Field(
        ..., min_length=3, max_length=100, description="Unique username"
    )
    password: str = Field(
        ...,
        min_length=12,
        description="Password (min 12 chars incl. upper, lower, digit, special char)",
    )
    phone: str | None = Field(default=None, max_length=20)
    timezone: str = Field(default="UTC", max_length=50)
    language: str = Field(default="en", max_length=10)

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        if not all(char.isalnum() or char in "_-" for char in value):
            raise ValueError(
                "Username can only contain letters, numbers, underscores, and hyphens"
            )
        return value.lower()

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "first_name": "Shresth",
                "last_name": "Pathak",
                "email": "shresth@example.com",
                "username": "shresth_p",
                "password": "SecurePass123!@#",
                "phone": "+91-9876543210",
                "timezone": "Asia/Kolkata",
                "language": "en",
            }
        }
    )


class RefreshTokenRequest(BaseModel):
    refresh_token: str = Field(..., description="Refresh token")


class ForgotPasswordRequest(BaseModel):
    email: EmailStr = Field(..., description="Email address")


class ResetPasswordRequest(BaseModel):
    token: str = Field(..., description="Reset token from email")
    new_password: str = Field(
        ..., min_length=12, description="New password (min 12 chars)"
    )


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., description="Current password")
    new_password: str = Field(
        ..., min_length=12, description="New password (min 12 chars)"
    )


class VerifyEmailRequest(BaseModel):
    token: str = Field(..., description="Verification token from email")


class ResendVerificationRequest(BaseModel):
    email: EmailStr = Field(..., description="Email address")


class LogoutRequest(BaseModel):
    refresh_token: str | None = Field(
        default=None,
        description="Refresh token to revoke; omit to only end the current session",
    )


# ============================================================================
# Response schemas
# ============================================================================


class UserResponse(BaseModel):
    id: str = Field(..., description="User ID")
    first_name: str
    last_name: str
    email: EmailStr
    username: str
    phone: str | None = None
    profile_photo: str | None = None
    designation: str | None = None
    department: str | None = None
    timezone: str
    language: str
    status: str
    is_active: bool = True
    is_superuser: bool = False
    is_verified: bool = False
    email_verified_at: datetime | None = None
    last_login_at: datetime | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(..., description="Access token expiry in seconds")
    refresh_expires_in: int = Field(..., description="Refresh token expiry in seconds")


class LoginResponse(BaseModel):
    user: UserResponse
    tokens: TokenResponse
    session_id: str


class RegisterResponse(BaseModel):
    message: str
    user: UserResponse
    verification_email_sent: bool = Field(
        ..., description="Whether a verification token was issued for the new account"
    )


class SessionResponse(BaseModel):
    id: str
    device_id: str
    device_name: str | None = None
    ip_address: str
    user_agent: str
    location: str | None = None
    is_current: bool = False
    created_at: datetime
    expires_at: datetime
    last_activity_at: datetime
    is_active: bool

    model_config = ConfigDict(from_attributes=True)


class SessionListResponse(BaseModel):
    sessions: list[SessionResponse]
    total: int


class MessageResponse(BaseModel):
    message: str
    success: bool = True
