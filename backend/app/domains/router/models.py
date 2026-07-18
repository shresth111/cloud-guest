"""SQLAlchemy ORM models for the Router domain.

Both tables extend ``app.database.base.BaseModel`` (UUID PK, timestamps,
soft-delete, audit, version columns) for the same reason every other domain
does -- Alembic autogenerate, ``GenericRepository``, and cross-domain FKs all
keep working uniformly.

Two models:

* :class:`Router` -- a physical/virtual MikroTik RouterOS device deployed at
  exactly one :class:`app.domains.location.models.Location` (CloudGuest
  hierarchy: Organization -> Location -> Router -> Guest). Carries both
  ``location_id`` (its direct parent) and ``organization_id`` (denormalized
  from ``location.organization_id`` at creation time) -- see
  ``docs/router/ROUTER_ARCHITECTURE.md`` §1 for why this denormalization was
  chosen (mirrors how RBAC's own scope columns, e.g. ``UserRole``, already
  carry both ``organization_id`` and ``location_id`` rather than deriving one
  from the other via a join).
* :class:`RouterProvisioningToken` -- a single-use, hashed bearer credential
  the physical device presents at zero-touch-provisioning check-in. Only
  ``token_hash`` (a SHA-256 digest) is stored, never the plaintext -- see
  ``docs/router/ROUTER_ARCHITECTURE.md`` §5 for why a fast cryptographic hash
  is the right choice here (unlike Argon2id for user passwords) for a
  high-entropy, randomly-generated token.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .enums import RouterStatus


class Router(BaseModel):
    """A MikroTik RouterOS device record, belonging to exactly one location."""

    __tablename__ = "routers"

    location_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Denormalized from location.organization_id at creation time, and -- like
    # location_id -- immutable afterward (a router "moving" location/org is a
    # decommission-and-re-register operation, mirroring Location's own
    # organization_id-immutability decision). See module docstring.
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    serial_number: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    mac_address: Mapped[str] = mapped_column(String(17), nullable=False, unique=True)
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    routeros_version: Mapped[str | None] = mapped_column(String(50), nullable=True)

    management_ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    public_ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)

    status: Mapped[str] = mapped_column(
        String(30), default=RouterStatus.PENDING_PROVISIONING.value, nullable=False
    )

    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_health_check_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # None until the first health check ever runs ("unknown") -- see
    # RouterHealthStatus's module docstring.
    health_status: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # RouterOS API connection credentials. ``api_username`` is stored in the
    # clear (a connection identifier, not a secret on its own -- the same
    # posture this codebase already takes for e.g. Organization.contact_email);
    # the password/API key is Fernet-encrypted (app.domains.router.crypto)
    # before ever reaching this column. Both nullable: a freshly-registered
    # router in pending_provisioning has no connection credentials yet.
    api_username: Mapped[str | None] = mapped_column(String(100), nullable=True)
    api_credentials_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Extension point: per-router config that does not warrant its own column
    # (e.g. captive-portal branding overrides, vendor-specific quirks flags).
    # Deliberately not modeled as individual columns -- same boundary
    # philosophy as Organization.settings/Location.settings.
    settings: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, nullable=False
    )

    __table_args__ = (
        Index("ix_routers_location_id", "location_id"),
        Index("ix_routers_organization_id", "organization_id"),
        Index("ix_routers_serial_number", "serial_number"),
        Index("ix_routers_mac_address", "mac_address"),
        Index("ix_routers_status", "status"),
        Index("ix_routers_name", "name"),
    )

    def __repr__(self) -> str:
        return (
            f"<Router(id={self.id}, serial_number={self.serial_number}, "
            f"status={self.status})>"
        )

    def is_online(self) -> bool:
        return self.status == RouterStatus.ONLINE.value


class RouterProvisioningToken(BaseModel):
    """A single-use, hashed bearer credential for zero-touch provisioning.

    The plaintext token is generated once, returned to the requesting admin
    in the create-response, and never persisted or retrievable again -- only
    ``token_hash`` (a SHA-256 hex digest) is stored, following the same
    "shown once" UX as e.g. API keys elsewhere. ``used_at`` enforces
    single-use: once consumed at check-in, the same token can never be
    presented again.
    """

    __tablename__ = "router_provisioning_tokens"

    router_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("routers.id", ondelete="CASCADE"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    __table_args__ = (
        UniqueConstraint("token_hash", name="uq_router_provisioning_tokens_token_hash"),
        Index("ix_router_provisioning_tokens_router_id", "router_id"),
        Index("ix_router_provisioning_tokens_expires_at", "expires_at"),
    )

    def is_expired(self, *, now: datetime) -> bool:
        return now > self.expires_at

    def is_used(self) -> bool:
        return self.used_at is not None

    def __repr__(self) -> str:
        return (
            f"<RouterProvisioningToken(id={self.id}, router_id={self.router_id}, "
            f"used={self.is_used()})>"
        )
