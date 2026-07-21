"""SQLAlchemy ORM model for the QoS & VOIP Priority domain.

One table -- ``QosTrafficRule``. A row's own state *is* its current
state; there is no live device push in this pass to produce a history of
-- realized onto a device later by ``app.domains.network_config``'s own
provisioning pass, not this domain (mirrors ``app.domains.dhcp``/
``app.domains.vlan``/``app.domains.port_forwarding``/``app.domains
.hotspot``'s own identical "config resource, realized onto a device
later" precedent).

Extends ``app.database.base.BaseModel`` (UUID PK, timestamps, soft-delete,
audit, version columns) for the same reason every other domain does.

## Scope: traffic classification, not bandwidth/priority itself

``app.domains.queue_management`` already *is* the real, complete
bandwidth/priority engine -- rate limits, RouterOS priority 1-8, and a
real device push (``/queue simple``/``/queue tree``). What is missing
anywhere in this codebase is traffic **classification**: matching
packets by protocol/port (e.g. SIP signaling on 5060, RTP media on a
port range) or DSCP value. ``QosTrafficRule`` models exactly that gap --
a match (port-range-or-DSCP) mapped to a ``priority`` -- and reuses
``app.domains.queue_management.constants.MIN_QUEUE_PRIORITY``/
``MAX_QUEUE_PRIORITY`` as this column's own valid range (the same real
RouterOS 1-8 constraint, not a second, independently-chosen bound).

This domain never creates a ``QueueProfile``/queues itself. See
``docs/qos/FLOW.md`` for why pairing the packet-mark this domain's own
``app.domains.network_config`` rendering produces with an actual
``/queue tree`` entry is a real, separate, currently-manual device-side
step, not automated in this pass.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import DEFAULT_PRIORITY


class QosTrafficRule(BaseModel):
    """One traffic-classification rule a router applies -- see module
    docstring. Matches either by ``protocol``/port-range (VOIP
    signaling/media, e.g. SIP/RTP) or by ``dscp_value`` -- see
    ``validators.py`` for why exactly one of the two match kinds must be
    present."""

    __tablename__ = "qos_traffic_rules"

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
    # NULL means "match every protocol" -- mirrors
    # app.domains.port_forwarding.models.PortForwardingRule.protocol's
    # own "BOTH"-as-wildcard precedent, but nullable here since a
    # DSCP-only rule has no protocol/port match at all.
    protocol: Mapped[str | None] = mapped_column(String(10), nullable=True)
    port_range_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    port_range_end: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # A real DSCP value (0-63, IETF RFC 2474's 6-bit field) -- see
    # validators.py. NULL when this rule matches by port instead.
    dscp_value: Mapped[int | None] = mapped_column(Integer, nullable=True)
    priority: Mapped[int] = mapped_column(
        Integer, default=DEFAULT_PRIORITY, nullable=False
    )
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    __table_args__ = (
        Index("ix_qos_traffic_rules_router_id", "router_id"),
        Index("ix_qos_traffic_rules_organization_id", "organization_id"),
        Index("ix_qos_traffic_rules_location_id", "location_id"),
        Index("ix_qos_traffic_rules_is_enabled", "is_enabled"),
    )

    def __repr__(self) -> str:
        return (
            f"<QosTrafficRule(id={self.id}, router_id={self.router_id}, "
            f"name={self.name})>"
        )


__all__ = ["QosTrafficRule"]
