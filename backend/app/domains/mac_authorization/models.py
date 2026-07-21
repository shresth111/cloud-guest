"""SQLAlchemy ORM model for the MAC Authorization domain.

One table -- ``MacAuthorizationEntry``. A row's own state *is* its
current state; there is no history table (nothing about a whitelist
entry benefits from an append-only log the way e.g. a health check
does).

Extends ``app.database.base.BaseModel`` (UUID PK, timestamps, soft-delete,
audit, version columns) for the same reason every other domain does.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import MacAuthorizationType


class MacAuthorizationEntry(BaseModel):
    """One whitelisted MAC address, scoped to an organization (and
    optionally a location). An organization may not hold two non-deleted
    entries for the same ``mac_address`` -- enforced by the partial
    unique index below, mirroring
    ``app.domains.vlan.models.Vlan``'s own identical partial-unique-index
    precedent for "logically unique among non-deleted rows", scoped to
    ``organization_id`` here rather than ``router_id`` (this domain has
    no router concept -- see module docstring)."""

    __tablename__ = "mac_authorization_entries"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    # NULL = organization-wide. Informational/filterable only in this
    # pass -- not part of the uniqueness scope below (a Postgres unique
    # index treats every NULL as distinct from every other NULL, which
    # would silently allow unlimited org-wide duplicates for the same MAC
    # if location_id were included in the index).
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="CASCADE"),
        nullable=True,
    )
    # Canonical uppercase colon-separated form ("AA:BB:CC:DD:EE:FF"),
    # normalized by validators.normalize_mac_address before this row is
    # ever written -- never stored in whatever mixed case/separator the
    # caller happened to submit.
    mac_address: Mapped[str] = mapped_column(String(17), nullable=False)
    authorization_type: Mapped[str] = mapped_column(
        String(20), default=MacAuthorizationType.PERMANENT.value, nullable=False
    )
    # Required iff authorization_type == "temporary", forbidden iff
    # "permanent" -- enforced at the service layer
    # (validators.validate_expiry), not a database CHECK constraint.
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    __table_args__ = (
        Index("ix_mac_authorization_entries_organization_id", "organization_id"),
        Index("ix_mac_authorization_entries_location_id", "location_id"),
        Index("ix_mac_authorization_entries_mac_address", "mac_address"),
        Index("ix_mac_authorization_entries_is_enabled", "is_enabled"),
        Index(
            "uq_mac_authorization_entries_org_id_mac_address",
            "organization_id",
            "mac_address",
            unique=True,
            postgresql_where=text("is_deleted = false"),
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<MacAuthorizationEntry(id={self.id}, mac_address={self.mac_address}, "
            f"authorization_type={self.authorization_type})>"
        )


__all__ = ["MacAuthorizationEntry"]
