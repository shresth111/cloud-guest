"""SQLAlchemy ORM model for the VLAN Management domain.

One table -- ``Vlan``. A row's own state *is* its current state; there is
no live device push in this pass to produce a history of (see module
docstring -- realized onto a device later by Network Configuration
Management's own provisioning pass, not this domain).

Extends ``app.database.base.BaseModel`` (UUID PK, timestamps, soft-delete,
audit, version columns) for the same reason every other domain does.
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
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import VlanDevicePushStatus


class Vlan(BaseModel):
    """One VLAN a router carries. A router may not hold two non-deleted
    ``Vlan`` rows with the same ``vlan_id`` -- enforced by the partial
    unique index below, mirroring
    ``app.domains.isp.models.IspLink``'s own identical partial-unique-
    index precedent for "logically unique among non-deleted rows"."""

    __tablename__ = "vlans"

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
    # The real IEEE 802.1Q VLAN tag (1-4094) -- see constants.py.
    vlan_id: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    gateway_ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    # A CIDR block, e.g. "192.168.10.0/24" -- validated at the service
    # layer (validators.validate_cidr), not a database-level constraint.
    cidr: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # The router's own parent interface this VLAN is tagged on (e.g.
    # "ether1") -- informational/provisioning-facing only, mirrors
    # app.domains.isp.models.IspLink.interface's identical scope.
    interface: Mapped[str | None] = mapped_column(String(100), nullable=True)
    # "trunk" (default): ``interface`` is the parent trunk carrying tagged
    # traffic -- renders as a standard ``/interface vlan`` sub-interface,
    # the existing, always-safe behavior. "access": ``interface`` is a
    # dedicated physical port (e.g. "ether3") that is pulled out of the
    # shared LAN bridge and given this VLAN's subnet directly, untagged --
    # deliberately implemented this way (a dedicated port/bridge) rather
    # than via bridge-wide vlan-filtering + PVID, so enabling "access" mode
    # never touches -- and can never break -- the shared production
    # bridge's already-live traffic. See renderers.render_vlan.
    port_mode: Mapped[str] = mapped_column(
        String(20), default="trunk", server_default="trunk", nullable=False
    )
    # When true, this VLAN's own interface gets its own captive-portal
    # hotspot (pool + dhcp-server + hotspot profile + hotspot server),
    # independent of the router's default "hotspot1" -- when false, the
    # VLAN is a plain routed/DHCP network with no portal challenge.
    enable_hotspot: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false", nullable=False
    )
    # NAT / Internet Access. When true, the device push also realizes a
    # source-NAT masquerade rule for this VLAN's own ``cidr`` on the
    # router's real WAN interface -- the difference between a working
    # local network and one whose guests reach the internet. Without it a
    # pushed VLAN hands out leases and routes nowhere, with no error
    # anywhere to say so. Defaults false: turning it on is a deliberate
    # decision, and inferring it would put a segment somebody built as
    # isolated onto the public internet on its next push.
    nat_enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false", nullable=False
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # -- device push ---------------------------------------------------------
    #
    # Whether this row has ever reached a real router, and what happened.
    # Deliberately independent of ``is_enabled`` (intent) and of
    # ``network_config``'s ``ConfigVersion`` status (a different, script-based
    # pipeline). A VLAN can be enabled and rendered into an "APPLIED" config
    # version and still never have been on a device -- which was the state of
    # every VLAN row before this domain had a push at all.
    device_push_status: Mapped[str] = mapped_column(
        String(20),
        default=VlanDevicePushStatus.PENDING.value,
        server_default=VlanDevicePushStatus.PENDING.value,
        nullable=False,
    )
    # The raw ``str(exc)`` from the last failed push. Shown to the operator
    # verbatim -- a device error is more useful unedited than summarized.
    device_push_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    device_pushed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index("ix_vlans_router_id", "router_id"),
        Index("ix_vlans_organization_id", "organization_id"),
        Index("ix_vlans_location_id", "location_id"),
        Index("ix_vlans_is_enabled", "is_enabled"),
        Index(
            "uq_vlans_router_id_vlan_id",
            "router_id",
            "vlan_id",
            unique=True,
            postgresql_where=text("is_deleted = false"),
        ),
    )

    def __repr__(self) -> str:
        return f"<Vlan(id={self.id}, vlan_id={self.vlan_id}, name={self.name})>"


__all__ = ["Vlan"]
