"""SQLAlchemy model for the API Keys domain: :class:`ApiKey`."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel


class ApiKey(BaseModel):
    """A persistent, hashed bearer credential a caller presents via the
    ``X-API-Key`` header instead of a JWT (see
    ``app.domains.auth.dependencies.get_current_user``'s own docstring for
    the exact resolution flow).

    Only ``key_hash`` (a SHA-256 hex digest) is ever stored -- the same
    posture ``app.domains.router_agent.models.RouterAgentCredential
    .credential_hash`` already established for a high-entropy, randomly-
    generated bearer token (no need of a slow password hash like
    Argon2id; see that model's own docstring). The full plaintext key is
    shown exactly once, at creation, and never persisted or recoverable.

    A key acts *as* ``user_id`` (RBAC's normal permission resolution for
    that user still applies in full -- this is not a bypass of RBAC, only
    an alternative way to authenticate), scoped to one ``organization_id``.
    """

    __tablename__ = "api_keys"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    display_prefix: Mapped[str] = mapped_column(String(20), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index("ix_api_keys_organization_id", "organization_id"),
        Index("ix_api_keys_user_id", "user_id"),
        Index("ix_api_keys_key_hash", "key_hash"),
        Index("ix_api_keys_revoked_at", "revoked_at"),
    )

    def __repr__(self) -> str:
        return f"<ApiKey(name={self.name}, display_prefix={self.display_prefix})>"
