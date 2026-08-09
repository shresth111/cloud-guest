"""SQLAlchemy ORM model for the QoS & VOIP Priority domain.

One table -- ``QosTrafficRule``. A row's own ``is_enabled``/match/priority
state *is* its current desired state, realized onto a device by two
independent, composed real device pushes (mirrors ``app.domains.dhcp``/
``app.domains.vlan``/``app.domains.port_forwarding``/``app.domains
.hotspot``'s own identical "config resource, realized onto a device
later" precedent for the DB-row-is-desired-state half of that story):

1. The mangle *mark* (``/ip firewall mangle ... action=mark-packet``),
   rendered by ``app.domains.network_config.renderers
   .render_qos_traffic_rule`` and pushed through that domain's own real
   ``ConfigVersion``/``ProvisioningJob`` pipeline
   (``POST /network-config/routers/{router_id}/push``).
2. The paired ``/queue tree`` entry that actually makes the mark do
   anything, pushed directly by this domain's own
   ``device_adapters.py``/``service.QosService.push_rule_to_device`` (see
   that method's own docstring). This row's own ``device_queue_id``/
   ``device_packet_mark``/``device_push_status``/``device_push_error``/
   ``device_pushed_at`` columns are that second push's real, current
   device state -- mirrors ``app.domains.queue_management.models
   .QueueAssignment``'s own ``device_queue_id``/``error_message``/
   ``applied_at`` columns exactly, just narrower (this domain never
   creates a ``/queue simple`` entry or a ``QueueProfile``).

Extends ``app.database.base.BaseModel`` (UUID PK, timestamps, soft-delete,
audit, version columns) for the same reason every other domain does.

## Scope: traffic classification, not bandwidth/priority itself

``app.domains.queue_management`` already *is* the real, complete
bandwidth/priority engine -- rate limits, RouterOS priority 1-8, and a
real device push (``/queue simple``/``/queue tree``). What this domain
adds is traffic **classification**: matching packets by protocol/port
(e.g. SIP signaling on 5060, RTP media on a port range) or DSCP value.
``QosTrafficRule`` models exactly that -- a match (port-range-or-DSCP)
mapped to a ``priority`` -- and reuses
``app.domains.queue_management.constants.MIN_QUEUE_PRIORITY``/
``MAX_QUEUE_PRIORITY`` as this column's own valid range (the same real
RouterOS 1-8 constraint, not a second, independently-chosen bound).

This domain still never creates a ``QueueProfile`` or a ``/queue
simple`` entry -- see ``docs/qos/FLOW.md`` Section 2 for the full
history of the packet-mark/queue-tree pairing gap this module's
``device_queue_id`` et al. now close, and why the fix lives here (a
direct push) rather than inside ``network_config``'s own renderer.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import DEFAULT_PRIORITY, QosDevicePushStatus


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

    # -- Real device push state for the paired /queue tree entry -- see
    # module docstring's numbered list above. Independent of the mangle
    # mark's own push state, which network_config's ConfigVersion already
    # tracks separately.
    device_queue_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # The qos_packet_mark_identifier(self) value in effect when
    # device_queue_id was created -- lets a later push detect a changed
    # identifier (e.g. this rule was renamed) and remove-then-recreate
    # rather than leaving a queue that references a stale mark. See
    # service.py::push_rule_to_device.
    device_packet_mark: Mapped[str | None] = mapped_column(String(64), nullable=True)
    device_push_status: Mapped[str] = mapped_column(
        String(20), default=QosDevicePushStatus.PENDING.value, nullable=False
    )
    device_push_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    device_pushed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

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
