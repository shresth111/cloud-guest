"""SQLAlchemy ORM model for the Firewall Rule Management domain.

One table -- ``FirewallRule``. A row's own state *is* its current state;
there is no live device push in this pass (see module docstring --
realized onto a device later by Network Configuration Management's own
provisioning pass, not this domain).

Extends ``app.database.base.BaseModel`` (UUID PK, timestamps, soft-delete,
audit, version columns) for the same reason every other domain does.

Unlike ``app.domains.dhcp.models.DhcpPool``'s range-overlap conflict
detection or ``app.domains.port_forwarding.models.PortForwardingRule``'s
destination-port conflict detection, firewall rules are allowed --
expected -- to overlap: a real firewall filter is a first-match-wins,
ordered list where redundant/overlapping rules are normal, intentional
policy (e.g. a specific ``DROP`` ahead of a broader ``ACCEPT``). No
conflict/uniqueness check is enforced here at all.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import DEFAULT_PRIORITY, FirewallAction, FirewallChain, FirewallProtocol


class FirewallRule(BaseModel):
    """One packet-filter rule a router carries -- see module docstring."""

    __tablename__ = "firewall_rules"

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
    chain: Mapped[str] = mapped_column(
        String(20), default=FirewallChain.FORWARD.value, nullable=False
    )
    action: Mapped[str] = mapped_column(
        String(20), default=FirewallAction.ACCEPT.value, nullable=False
    )
    protocol: Mapped[str] = mapped_column(
        String(10), default=FirewallProtocol.ALL.value, nullable=False
    )
    source_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    destination_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    in_interface: Mapped[str | None] = mapped_column(String(100), nullable=True)
    # Lower evaluates first -- see module docstring's "rule order is
    # semantically significant" write-up.
    priority: Mapped[int] = mapped_column(
        Integer, default=DEFAULT_PRIORITY, nullable=False
    )
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    __table_args__ = (
        Index("ix_firewall_rules_router_id", "router_id"),
        Index("ix_firewall_rules_organization_id", "organization_id"),
        Index("ix_firewall_rules_location_id", "location_id"),
        Index("ix_firewall_rules_chain", "chain"),
        Index("ix_firewall_rules_priority", "priority"),
        Index("ix_firewall_rules_is_enabled", "is_enabled"),
    )

    def __repr__(self) -> str:
        return (
            f"<FirewallRule(id={self.id}, name={self.name}, "
            f"chain={self.chain}, action={self.action})>"
        )


__all__ = ["FirewallRule"]
