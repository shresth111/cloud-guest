"""
SQLAlchemy ORM models for Authentication & Identity module.

This module defines the database schema for users, sessions, password history,
and login attempts tracking.

Architecture: Infrastructure Layer - Persistence
"""

from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all ORM models."""

    pass


class User(Base):
    """
    User entity representing CloudGuest platform users.

    Attributes:
        id: Unique identifier (UUID)
        first_name: User's first name
        last_name: User's last name
        full_name: Computed full name
        email: Unique email address
        username: Unique username
        phone: Optional phone number
        password_hash: Argon2 hashed password
        profile_photo: URL to profile photo
        designation: Job title/designation
        department: Department name
        employee_id: Employee ID (if applicable)
        timezone: User's timezone (e.g., 'Asia/Kolkata')
        language: Preferred language (e.g., 'en', 'hi')
        status: Account status ('active', 'inactive', 'suspended')
        is_active: Whether account is active
        is_verified: Whether email is verified
        email_verified_at: Timestamp of email verification
        phone_verified_at: Timestamp of phone verification
        last_login_at: Last successful login timestamp
        failed_login_attempts: Current count of failed login attempts
        locked_until: Timestamp until which account is locked
        password_changed_at: Last password change timestamp
        created_at: Account creation timestamp
        updated_at: Last update timestamp

    Relationships:
        sessions: Multiple active/inactive sessions
        password_history: Previous password hashes for validation
    """

    __tablename__ = "users"

    # Primary Key
    id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4())
    )

    # Personal Information
    first_name: Mapped[str] = mapped_column(String(100), nullable=False)
    last_name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    username: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    phone: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    # Authentication
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    # Profile
    profile_photo: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    designation: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    department: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    employee_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Preferences
    timezone: Mapped[str] = mapped_column(String(50), default="UTC")
    language: Mapped[str] = mapped_column(String(10), default="en")

    # Account Status
    status: Mapped[str] = mapped_column(
        String(20), default="active", nullable=False
    )  # active, inactive, suspended
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Verification Timestamps
    email_verified_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    phone_verified_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Login Tracking
    last_login_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Security
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    password_changed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Relationships
    sessions: Mapped[list["Session"]] = relationship(
        "Session", back_populates="user", cascade="all, delete-orphan"
    )
    password_history: Mapped[list["PasswordHistory"]] = relationship(
        "PasswordHistory", back_populates="user", cascade="all, delete-orphan"
    )

    # Indexes for performance
    __table_args__ = (
        Index("ix_users_email", "email"),
        Index("ix_users_username", "username"),
        Index("ix_users_is_active", "is_active"),
        Index("ix_users_status", "status"),
        Index("ix_users_created_at", "created_at"),
        UniqueConstraint("email", name="uq_users_email"),
        UniqueConstraint("username", name="uq_users_username"),
    )

    def __repr__(self) -> str:
        return f"<User(id={self.id}, email={self.email}, username={self.username})>"

    @property
    def full_name(self) -> str:
        """Compute full name from first and last names."""
        return f"{self.first_name} {self.last_name}".strip()

    def is_account_locked(self) -> bool:
        """Check if account is currently locked."""
        if self.locked_until is None:
            return False
        return datetime.utcnow() < self.locked_until

    def is_email_verified(self) -> bool:
        """Check if email is verified."""
        return self.is_verified and self.email_verified_at is not None


class Session(Base):
    """
    User session representing a login instance on a device.

    Supports multi-device sessions with device/IP/user-agent tracking.

    Attributes:
        id: Unique session identifier
        user_id: Foreign key to User
        device_id: Unique device identifier
        device_name: Human-readable device name
        ip_address: Client IP address
        user_agent: HTTP User-Agent string
        location: Inferred location (city/country)
        refresh_token_jti: JWT ID for refresh token tracking
        expires_at: Session expiration timestamp
        created_at: Session creation timestamp
        updated_at: Last activity timestamp
        last_activity_at: Last activity timestamp
        is_active: Whether session is still active
    """

    __tablename__ = "sessions"

    # Primary Key
    id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4())
    )

    # Foreign Key
    user_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    # Device Information
    device_id: Mapped[str] = mapped_column(String(255), nullable=False)
    device_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Network Information
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)  # IPv4/IPv6
    user_agent: Mapped[str] = mapped_column(Text, nullable=False)
    location: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Token Management
    refresh_token_jti: Mapped[str] = mapped_column(
        String(255), nullable=False, unique=True
    )

    # Timestamps
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow
    )
    last_activity_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, nullable=False
    )

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationship
    user: Mapped["User"] = relationship("User", back_populates="sessions")

    # Indexes for performance
    __table_args__ = (
        Index("ix_sessions_user_id", "user_id"),
        Index("ix_sessions_device_id", "device_id"),
        Index("ix_sessions_refresh_token_jti", "refresh_token_jti"),
        Index("ix_sessions_is_active", "is_active"),
        Index("ix_sessions_expires_at", "expires_at"),
        UniqueConstraint("refresh_token_jti", name="uq_sessions_refresh_token_jti"),
    )

    def __repr__(self) -> str:
        return f"<Session(id={self.id}, user_id={self.user_id}, device_id={self.device_id})>"

    def is_expired(self) -> bool:
        """Check if session has expired."""
        return datetime.utcnow() > self.expires_at

    def mark_activity(self) -> None:
        """Update last activity timestamp."""
        self.last_activity_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()


class PasswordHistory(Base):
    """
    Password history for preventing password reuse.

    Tracks previous password hashes to ensure users cannot reuse old passwords
    within a configurable period (e.g., last 5 passwords).

    Attributes:
        id: Unique identifier
        user_id: Foreign key to User
        password_hash: Previous password hash
        created_at: When password was set
    """

    __tablename__ = "password_history"

    # Primary Key
    id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4())
    )

    # Foreign Key
    user_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    # Data
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, nullable=False
    )

    # Relationship
    user: Mapped["User"] = relationship("User", back_populates="password_history")

    # Indexes
    __table_args__ = (Index("ix_password_history_user_id", "user_id"),)

    def __repr__(self) -> str:
        return f"<PasswordHistory(id={self.id}, user_id={self.user_id})>"


class LoginAttempt(Base):
    """
    Track login attempts for security analytics and rate limiting.

    Helps identify brute force attacks and suspicious patterns.

    Attributes:
        id: Unique identifier
        user_id: Foreign key to User (nullable - might be unknown email)
        email: Email attempted
        ip_address: Source IP address
        user_agent: HTTP User-Agent
        success: Whether login was successful
        failure_reason: Reason for failure if unsuccessful
        created_at: Attempt timestamp
    """

    __tablename__ = "login_attempts"

    # Primary Key
    id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid4())
    )

    # Foreign Key (nullable - for unknown users)
    user_id: Mapped[Optional[str]] = mapped_column(
        UUID(as_uuid=False), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Data
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    user_agent: Mapped[str] = mapped_column(Text, nullable=False)

    # Outcome
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    failure_reason: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, nullable=False
    )

    # Indexes for security queries
    __table_args__ = (
        Index("ix_login_attempts_email", "email"),
        Index("ix_login_attempts_user_id", "user_id"),
        Index("ix_login_attempts_ip_address", "ip_address"),
        Index("ix_login_attempts_created_at", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<LoginAttempt(id={self.id}, email={self.email}, success={self.success})>"
