"""SQLAlchemy ORM model for the Port Forwarding Management domain.

One table -- ``PortForwardingRule``. A row's own state *is* its current
state; there is no live device push in this pass to produce a history of
(see module docstring -- realized onto a device later by Network
Configuration Management's own provisioning pass, not this domain).

Extends ``app.database.base.BaseModel`` (UUID PK, timestamps, soft-delete,
audit, version columns) for the same reason every other domain does.

## Why conflict detection is not a database constraint

Mirrors ``app.domains.dhcp.models.DhcpPool``'s own identical reasoning:
"do these two rules both claim the same external destination_port/
protocol/destination_address" is not expressible as a simple
column-equality index (``protocol``/``destination_address`` both have a
wildcard/``BOTH`` value that must be treated as overlapping every other
value, not compared by plain equality). Conflict detection is therefore a
service-layer check only (``service.py``'s own ``_check_conflict``) -- a
real, honest gap documented here rather than silently assumed away.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import PortForwardingProtocol


class PortForwardingRule(BaseModel):
    """One port-forwarding (DSTNAT) rule a router carries -- see module
    docstring."""

    __tablename__ = "port_forwarding_rules"

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
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    protocol: Mapped[str] = mapped_column(
        String(10), default=PortForwardingProtocol.BOTH.value, nullable=False
    )
    # Restricts which originating source may use this rule -- an IP or
    # CIDR block. NULL means "any source" (no restriction).
    source_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # The router's own WAN-facing address this rule matches incoming
    # traffic against -- an IP or CIDR block. NULL means "any of this
    # router's own addresses/interfaces".
    destination_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    destination_port: Mapped[int] = mapped_column(Integer, nullable=False)
    # The internal target this rule forwards matched traffic to -- always
    # a single, real IP (never a CIDR/wildcard; a DSTNAT rule forwards to
    # exactly one destination).
    internal_address: Mapped[str] = mapped_column(String(45), nullable=False)
    internal_port: Mapped[int] = mapped_column(Integer, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    __table_args__ = (
        Index("ix_port_forwarding_rules_router_id", "router_id"),
        Index("ix_port_forwarding_rules_organization_id", "organization_id"),
        Index("ix_port_forwarding_rules_location_id", "location_id"),
        Index("ix_port_forwarding_rules_destination_port", "destination_port"),
        Index("ix_port_forwarding_rules_is_enabled", "is_enabled"),
    )

    def __repr__(self) -> str:
        return (
            f"<PortForwardingRule(id={self.id}, name={self.name}, "
            f"destination_port={self.destination_port})>"
        )


__all__ = ["PortForwardingRule"]
