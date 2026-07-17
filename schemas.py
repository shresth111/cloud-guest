"""
Pydantic schemas for authentication API requests and responses.

Includes validation, serialization, and documentation.

Architecture: Presentation Layer - Schemas
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, validator


# ============================================================================
# REQUEST SCHEMAS
# ============================================================================


class LoginRequest(BaseModel):
    """User login request."""

    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=1, description="User password")
    device_name: Optional[str] = Field(
        None, max_length=255, description="Device name (e.g., 'Chrome on Windows')"
    )

    class Config:
        schema_extra = {
            "example": {
                "email": "user@example.com",
                "password": "SecurePass123!",
                "device_name": "Chrome on Windows 10",
            }
        }


class RegisterRequest(BaseModel):
    """User registration request."""

    first_name: str = Field(..., min_length=1, max_length=100, description="First name")
    last_name: str = Field(..., min_length=1, max_length=100, description="Last name")
    email: EmailStr = Field(..., description="Email address")
    username: str = Field(
        ..., min_length=3, max_length=100, description="Username (unique)"
    )
    password: str = Field(
        ..., min_length=12, description="Password (min 12 chars with uppercase, lowercase, digit, special char)"
    )
    phone: Optional[str] = Field(None, max_length=20, description="Phone number")
    timezone: str = Field("UTC", description="User timezone")
    language: str = Field("en", max_length=10, description="Preferred language")

    @validator("username")
    def validate_username(cls, v: str) -> str:
        """Username must be alphanumeric with underscores/hyphens."""
        if not all(c.isalnum() or c in "_-" for c in v):
            raise ValueError(
                "Username can only contain letters, numbers, underscores, and hyphens"
            )
        return v.lower()

    class Config:
        schema_extra = {
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


class ForgotPasswordRequest(BaseModel):
    """Forgot password request."""

    email: EmailStr = Field(..., description="Email address")

    class Config:
        schema_extra = {"example": {"email": "user@example.com"}}


class ResetPasswordRequest(BaseModel):
    """Password reset request."""

    token: str = Field(..., description="Reset token from email")
    new_password: str = Field(
        ..., min_length=12, description="New password (min 12 chars)"
    )

    class Config:
        schema_extra = {
            "example": {
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "new_password": "NewSecurePass123!@#",
            }
        }


class ChangePasswordRequest(BaseModel):
    """Change password request."""

    current_password: str = Field(..., description="Current password")
    new_password: str = Field(
        ..., min_length=12, description="New password (min 12 chars)"
    )

    class Config:
        schema_extra = {
            "example": {
                "current_password": "OldPass123!@#",
                "new_password": "NewPass123!@#",
            }
        }


class VerifyEmailRequest(BaseModel):
    """Email verification request."""

    token: str = Field(..., description="Verification token from email")

    class Config:
        schema_extra = {
            "example": {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}
        }


class ResendVerificationRequest(BaseModel):
    """Resend email verification request."""

    email: EmailStr = Field(..., description="Email address")

    class Config:
        schema_extra = {"example": {"email": "user@example.com"}}


class RefreshTokenRequest(BaseModel):
    """Refresh token request."""

    refresh_token: str = Field(..., description="Refresh token")

    class Config:
        schema_extra = {
            "example": {
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            }
        }


class RevokeSessionRequest(BaseModel):
    """Revoke session request."""

    session_id: str = Field(..., description="Session ID to revoke")

    class Config:
        schema_extra = {"example": {"session_id": "550e8400-e29b-41d4-a716-446655440000"}}


# ============================================================================
# RESPONSE SCHEMAS
# ============================================================================


class UserResponse(BaseModel):
    """User information response."""

    id: str = Field(..., description="User ID")
    first_name: str = Field(..., description="First name")
    last_name: str = Field(..., description="Last name")
    email: str = Field(..., description="Email address")
    username: str = Field(..., description="Username")
    phone: Optional[str] = Field(None, description="Phone number")
    profile_photo: Optional[str] = Field(None, description="Profile photo URL")
    designation: Optional[str] = Field(None, description="Job designation")
    department: Optional[str] = Field(None, description="Department")
    timezone: str = Field(..., description="Timezone")
    language: str = Field(..., description="Language")
    status: str = Field(..., description="Account status")
    is_active: bool = Field(..., description="Whether account is active")
    is_verified: bool = Field(..., description="Whether email is verified")
    email_verified_at: Optional[datetime] = Field(None, description="Email verification time")
    last_login_at: Optional[datetime] = Field(None, description="Last login time")
    created_at: datetime = Field(..., description="Account creation time")
    updated_at: datetime = Field(..., description="Last update time")

    class Config:
        from_attributes = True
        schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "first_name": "Shresth",
                "last_name": "Pathak",
                "email": "shresth@example.com",
                "username": "shresth_p",
                "phone": "+91-9876543210",
                "designation": "DevOps Engineer",
                "timezone": "Asia/Kolkata",
                "language": "en",
                "status": "active",
                "is_active": True,
                "is_verified": True,
                "email_verified_at": "2024-01-15T10:30:00Z",
                "last_login_at": "2024-01-20T14:22:30Z",
                "created_at": "2024-01-01T08:00:00Z",
                "updated_at": "2024-01-20T14:22:30Z",
            }
        }


class TokenResponse(BaseModel):
    """Token response containing access and refresh tokens."""

    access_token: str = Field(..., description="Access token (JWT)")
    refresh_token: str = Field(..., description="Refresh token (JWT)")
    token_type: str = Field("Bearer", description="Token type")
    expires_in: int = Field(..., description="Access token expiry (seconds)")
    refresh_expires_in: int = Field(..., description="Refresh token expiry (seconds)")

    class Config:
        schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "Bearer",
                "expires_in": 900,
                "refresh_expires_in": 604800,
            }
        }


class LoginResponse(BaseModel):
    """Successful login response."""

    user: UserResponse = Field(..., description="User information")
    tokens: TokenResponse = Field(..., description="Token pair")
    session_id: str = Field(..., description="Session ID")

    class Config:
        schema_extra = {
            "example": {
                "user": {
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "email": "user@example.com",
                    "username": "username",
                    "is_verified": True,
                    "status": "active",
                },
                "tokens": {
                    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                    "token_type": "Bearer",
                    "expires_in": 900,
                    "refresh_expires_in": 604800,
                },
                "session_id": "550e8400-e29b-41d4-a716-446655440000",
            }
        }


class RegisterResponse(BaseModel):
    """Registration response."""

    message: str = Field(..., description="Success message")
    user: UserResponse = Field(..., description="User information")
    verification_email_sent: bool = Field(
        ..., description="Whether verification email was sent"
    )

    class Config:
        schema_extra = {
            "example": {
                "message": "User registered successfully. "
                "Please check your email to verify your account.",
                "user": {
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "email": "user@example.com",
                    "is_verified": False,
                },
                "verification_email_sent": True,
            }
        }


class SessionResponse(BaseModel):
    """Active session information."""

    id: str = Field(..., description="Session ID")
    device_id: str = Field(..., description="Device ID")
    device_name: Optional[str] = Field(None, description="Device name")
    ip_address: str = Field(..., description="Client IP address")
    user_agent: str = Field(..., description="User agent string")
    location: Optional[str] = Field(None, description="Inferred location")
    is_current: bool = Field(..., description="Is this the current session")
    created_at: datetime = Field(..., description="Session creation time")
    expires_at: datetime = Field(..., description="Session expiration time")
    last_activity_at: datetime = Field(..., description="Last activity time")
    is_active: bool = Field(..., description="Is session still active")

    class Config:
        from_attributes = True
        schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "device_id": "abc123def456",
                "device_name": "Chrome on Windows 10",
                "ip_address": "192.168.1.1",
                "user_agent": "Mozilla/5.0...",
                "location": "Delhi, India",
                "is_current": True,
                "created_at": "2024-01-20T10:00:00Z",
                "expires_at": "2024-01-27T10:00:00Z",
                "last_activity_at": "2024-01-20T14:22:30Z",
                "is_active": True,
            }
        }


class SessionListResponse(BaseModel):
    """List of active sessions."""

    sessions: list[SessionResponse] = Field(..., description="List of sessions")
    total: int = Field(..., description="Total number of sessions")

    class Config:
        schema_extra = {
            "example": {
                "sessions": [
                    {
                        "id": "550e8400-e29b-41d4-a716-446655440000",
                        "device_name": "Chrome on Windows",
                        "is_current": True,
                    }
                ],
                "total": 1,
            }
        }


class MessageResponse(BaseModel):
    """Generic message response."""

    message: str = Field(..., description="Response message")
    success: bool = Field(True, description="Whether operation was successful")

    class Config:
        schema_extra = {
            "example": {
                "message": "Operation completed successfully",
                "success": True,
            }
        }


class ErrorResponse(BaseModel):
    """Error response."""

    error: str = Field(..., description="Error code")
    message: str = Field(..., description="Error message")
    details: Optional[dict] = Field(None, description="Additional error details")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Error timestamp")

    class Config:
        schema_extra = {
            "example": {
                "error": "invalid_credentials",
                "message": "Invalid email or password",
                "details": None,
                "timestamp": "2024-01-20T14:22:30Z",
            }
        }
