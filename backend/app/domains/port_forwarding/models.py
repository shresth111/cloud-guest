"""SQLAlchemy ORM model for the Port Forwarding Management domain.

One table -- ``PortForwardingRule``. A row's own state *is* its current
state, plus the three ``device_push_*`` columns recording whether that
state has actually reached a router -- see
``constants.PortForwardingDevicePushStatus``. There is no per-push history
table, deliberately: what an operator needs is "is this rule live right
now, and why not", which the current row answers.

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
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import PortForwardingDevicePushStatus, PortForwardingProtocol


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
    #: Whether a real ``/ip firewall nat`` DSTNAT rule for this row exists on
    #: the router right now -- see ``constants.PortForwardingDevicePushStatus``.
    #: Deliberately independent of ``is_enabled``, which is intent: a rule can
    #: be enabled and never have reached a device. Before this existed,
    #: creating a rule wrote a row and contacted nothing, so the port the
    #: dashboard reported as published was never actually forwarded.
    device_push_status: Mapped[str] = mapped_column(
        String(20),
        default=PortForwardingDevicePushStatus.PENDING.value,
        nullable=False,
    )
    #: The raw ``str(exc)`` from the last failed push, shown to the operator
    #: verbatim -- a RouterOS error is more useful unedited than summarized.
    device_push_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    device_pushed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

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
