"""SQLAlchemy ORM models and lightweight DTOs for the auth domain.

The persistence models (``User``, ``Session``, ``PasswordHistory``,
``LoginAttempt``) build on the project's shared declarative base
(``app.database.base.Base`` / ``BaseModel``) so that Alembic autogenerate,
cross-domain foreign keys, and generic-repository based queries all keep
working the same way they do for every other domain. They intentionally do
**not** define their own ``DeclarativeBase`` (the old standalone auth module
did, which would have registered a second, disconnected metadata object).

``AuthUser`` and ``TokenPair`` remain as small, non-persisted DTOs used to
pass authenticated-user context and token results around the service/router
layers without leaking SQLAlchemy instances outside of the domain.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import BaseModel

if TYPE_CHECKING:
    pass


class User(BaseModel):
    """Platform user / identity record.

    ``id``, ``created_at``, ``updated_at``, soft-delete (``is_deleted`` /
    ``deleted_at``), audit (``created_by`` / ``updated_by``), and
    ``version`` columns all come from ``BaseModel`` -- they are not
    redeclared here.
    """

    __tablename__ = "users"

    # Personal information
    first_name: Mapped[str] = mapped_column(String(100), nullable=False)
    last_name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    username: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    phone: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # Authentication
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    # Profile
    profile_photo: Mapped[str | None] = mapped_column(String(500), nullable=True)
    designation: Mapped[str | None] = mapped_column(String(100), nullable=True)
    department: Mapped[str | None] = mapped_column(String(100), nullable=True)
    employee_id: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Preferences
    timezone: Mapped[str] = mapped_column(String(50), default="UTC", nullable=False)
    language: Mapped[str] = mapped_column(String(10), default="en", nullable=False)

    # Account status
    status: Mapped[str] = mapped_column(String(20), default="active", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Verification timestamps
    email_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    phone_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Login tracking / brute-force protection
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    failed_login_attempts: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    password_changed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Smart Location Provisioning addition (Module 006 extension) -- see
    # ``app.domains.auth.service.AuthService.login``'s ``must_change_password``
    # check and ``docs/location/FLOW.md``'s "must_change_password" section
    # for the full write-up of why this narrow, additive column was judged
    # necessary: a location-provisioning-created "Location Owner" account is
    # handed a real, randomly-generated temporary password (see
    # ``app.domains.location.provisioning_service``) that this codebase has
    # no other existing mechanism to force a change of before first ordinary
    # use. ``False`` by default (every pre-existing account, and every
    # self-registered/``register()``-created account, is unaffected).
    must_change_password: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    sessions: Mapped[list[Session]] = relationship(
        "Session", back_populates="user", cascade="all, delete-orphan"
    )
    password_history: Mapped[list[PasswordHistory]] = relationship(
        "PasswordHistory", back_populates="user", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_users_email", "email"),
        Index("ix_users_username", "username"),
        Index("ix_users_is_active", "is_active"),
        Index("ix_users_status", "status"),
    )

    def __repr__(self) -> str:
        return f"<User(id={self.id}, email={self.email}, username={self.username})>"

    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}".strip()

    def is_account_locked(self, *, now: datetime | None = None) -> bool:
        if self.locked_until is None:
            return False
        return (now or datetime.now(UTC)) < self.locked_until

    def is_email_verified(self) -> bool:
        return self.is_verified and self.email_verified_at is not None


class Session(BaseModel):
    """A login session tied to a device, used to track and revoke refresh tokens."""

    __tablename__ = "sessions"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    device_id: Mapped[str] = mapped_column(String(255), nullable=False)
    device_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    user_agent: Mapped[str] = mapped_column(Text, nullable=False)
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)

    refresh_token_jti: Mapped[str] = mapped_column(
        String(255), nullable=False, unique=True
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_activity_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    user: Mapped[User] = relationship("User", back_populates="sessions")

    __table_args__ = (
        Index("ix_sessions_user_id", "user_id"),
        Index("ix_sessions_device_id", "device_id"),
        Index("ix_sessions_refresh_token_jti", "refresh_token_jti"),
        Index("ix_sessions_is_active", "is_active"),
        Index("ix_sessions_expires_at", "expires_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<Session(id={self.id}, user_id={self.user_id}, device={self.device_id})>"
        )

    def is_expired(self, *, now: datetime | None = None) -> bool:
        return (now or datetime.now(UTC)) > self.expires_at

    def mark_activity(self) -> None:
        self.last_activity_at = datetime.now(UTC)


class PasswordHistory(BaseModel):
    """Previous password hashes, kept to prevent password reuse."""

    __tablename__ = "password_history"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    user: Mapped[User] = relationship("User", back_populates="password_history")

    __table_args__ = (Index("ix_password_history_user_id", "user_id"),)

    def __repr__(self) -> str:
        return f"<PasswordHistory(id={self.id}, user_id={self.user_id})>"


class LoginAttempt(BaseModel):
    """Audit log of login attempts, used for lockout and security analytics."""

    __tablename__ = "login_attempts"

    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    user_agent: Mapped[str] = mapped_column(Text, nullable=False)

    success: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    failure_reason: Mapped[str | None] = mapped_column(String(100), nullable=True)

    __table_args__ = (
        Index("ix_login_attempts_email", "email"),
        Index("ix_login_attempts_user_id", "user_id"),
        Index("ix_login_attempts_ip_address", "ip_address"),
    )

    def __repr__(self) -> str:
        return (
            f"<LoginAttempt(id={self.id}, email={self.email}, success={self.success})>"
        )


@dataclass
class AuthUser:
    """Lightweight, non-persisted representation of an authenticated user.

    Used by the router/dependency layer so route handlers don't need to
    depend on (or accidentally leak) the SQLAlchemy ``User`` instance.
    """

    id: str
    email: str
    username: str | None = None
    is_active: bool = True
    is_superuser: bool = False
    is_verified: bool = False

    @classmethod
    def from_model(cls, user: User) -> AuthUser:
        return cls(
            id=str(user.id),
            email=user.email,
            username=user.username,
            is_active=user.is_active,
            is_superuser=False,
            is_verified=user.is_verified,
        )


@dataclass
class TokenPair:
    """Result of an access/refresh token issuance."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 0
    refresh_expires_in: int = 0
