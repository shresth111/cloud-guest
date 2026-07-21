"""SQLAlchemy ORM model for the DNS Management domain.

One table -- ``DnsRecord``. A row's own state *is* its current state;
there is no live device push in this pass (see module docstring --
realized onto a device later by Network Configuration Management's own
provisioning pass, not this domain).

Extends ``app.database.base.BaseModel`` (UUID PK, timestamps, soft-delete,
audit, version columns) for the same reason every other domain does.

Unlike ``app.domains.dhcp.models.DhcpPool``'s range-overlap conflict
detection, two DNS records may legitimately share the same ``name`` on one
router (real-world round-robin DNS -- multiple ``A`` records for one
name) -- so no uniqueness/conflict check is enforced here at all, at
either the database or service layer.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import DEFAULT_TTL_SECONDS, DnsRecordType


class DnsRecord(BaseModel):
    """One static DNS entry a router serves -- see module docstring."""

    __tablename__ = "dns_records"

    router_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("routers.id", ondelete="CASCADE"), nullable=False
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    location_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    record_type: Mapped[str] = mapped_column(
        String(10), default=DnsRecordType.A.value, nullable=False
    )
    # The resolved value: an IP address for A/AAAA, a hostname for CNAME.
    # A single, plain string column regardless of record_type -- the exact
    # same "one column, not one per variant" judgment call
    # app.domains.guest_access.models's own module docstring documents for
    # AccessRuleType.
    address: Mapped[str] = mapped_column(String(255), nullable=False)
    ttl_seconds: Mapped[int] = mapped_column(
        Integer, default=DEFAULT_TTL_SECONDS, nullable=False
    )
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    __table_args__ = (
        Index("ix_dns_records_router_id", "router_id"),
        Index("ix_dns_records_organization_id", "organization_id"),
        Index("ix_dns_records_location_id", "location_id"),
        Index("ix_dns_records_name", "name"),
        Index("ix_dns_records_is_enabled", "is_enabled"),
    )

    def __repr__(self) -> str:
        return (
            f"<DnsRecord(id={self.id}, name={self.name}, "
            f"record_type={self.record_type})>"
        )


__all__ = ["DnsRecord"]
