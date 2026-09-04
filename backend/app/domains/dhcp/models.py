"""SQLAlchemy ORM model for the DHCP Pool Management domain.

Two tables -- ``DhcpPool`` and ``RouterRogueDhcpStatus``. A row's own
state *is* its current state; there
is no live device push in this pass to produce a history of (see module
docstring -- realized onto a device later by Network Configuration
Management's own provisioning pass, not this domain).

Extends ``app.database.base.BaseModel`` (UUID PK, timestamps, soft-delete,
audit, version columns) for the same reason every other domain does.

## Why range-overlap conflict detection is not a database constraint

Unlike ``app.domains.vlan.models.Vlan``'s own ``vlan_id`` uniqueness (a
plain equality check a partial unique b-tree index can enforce directly),
"do these two IP address ranges overlap" is not expressible as a simple
column-equality index -- it would need a PostgreSQL range type + GiST
exclusion constraint, real infrastructure this codebase's own migrations
have never introduced for any domain. Conflict detection is therefore a
service-layer check only (``service.py``'s own ``_check_range_conflict``)
-- a real, honest gap documented here rather than silently assumed away.
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

from .constants import (
    DEFAULT_LEASE_TIME_SECONDS,
    DhcpDevicePushStatus,
    RogueDhcpAlertState,
)


class DhcpPool(BaseModel):
    """One DHCP address pool a router serves -- see module docstring."""

    __tablename__ = "dhcp_pools"

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
    # The router's own interface this pool serves (e.g. "ether2",
    # "vlan10") -- conflict detection (service.py) only compares ranges
    # between pools sharing the same interface value (including two pools
    # both left NULL), since different interfaces are different L2
    # domains and may legitimately reuse the same private range.
    interface: Mapped[str | None] = mapped_column(String(100), nullable=True)
    address_range_start: Mapped[str] = mapped_column(String(45), nullable=False)
    address_range_end: Mapped[str] = mapped_column(String(45), nullable=False)
    gateway_ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dns_primary: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dns_secondary: Mapped[str | None] = mapped_column(String(45), nullable=True)
    lease_time_seconds: Mapped[int] = mapped_column(
        Integer, default=DEFAULT_LEASE_TIME_SECONDS, nullable=False
    )
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    #: Whether a real ``/ip pool`` + ``/ip dhcp-server`` +
    #: ``/ip dhcp-server network`` triple for this row exists on the router
    #: right now -- see ``constants.DhcpDevicePushStatus``. Deliberately
    #: independent of ``is_enabled``, which is intent: a pool can be enabled
    #: and never have reached a device. Before this existed, creating a pool
    #: wrote a row and contacted nothing, so a guest joining the network got
    #: no address at all.
    device_push_status: Mapped[str] = mapped_column(
        String(20), default=DhcpDevicePushStatus.PENDING.value, nullable=False
    )
    #: The raw ``str(exc)`` from the last failed push, shown to the operator
    #: verbatim -- a RouterOS error is more useful unedited than summarized.
    device_push_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    device_pushed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index("ix_dhcp_pools_router_id", "router_id"),
        Index("ix_dhcp_pools_organization_id", "organization_id"),
        Index("ix_dhcp_pools_location_id", "location_id"),
        Index("ix_dhcp_pools_interface", "interface"),
        Index("ix_dhcp_pools_is_enabled", "is_enabled"),
    )

    def __repr__(self) -> str:
        return (
            f"<DhcpPool(id={self.id}, name={self.name}, "
            f"range={self.address_range_start}-{self.address_range_end})>"
        )


class RouterRogueDhcpStatus(BaseModel):
    """What the last rogue-DHCP detection pass saw on one interface of one
    router -- one row per ``(router_id, interface)``, updated in place.

    ## Why this table exists at all

    ``wyfy_device_gateway.mikrotik_adapter.read_rogue_dhcp_alerts`` answers
    this question against a live device. Nothing may ask it on a request
    path: ``app.domains.readiness.service.ReadinessService.get_checklist``
    re-runs every AUTO item on *every* GET, so a device read wired in there
    would put a RouterOS round trip -- and a RouterOS timeout -- behind an
    ordinary dashboard page load. So the read happens on a schedule
    (``tasks.py``), lands here, and the checklist reads this row. Detector
    writes, surface reads.

    ## The three columns that could have been one, and must not be

    ``alert_state`` is the rolled-up answer. ``alert_present`` and
    ``enabled`` are kept beside it as separate booleans because
    ``UNGUARDED`` is reached two different ways and the difference is the
    whole operational point: "no alert row here" is a gap, while "row
    present, switched off" is the state **RouterOS's own default
    produces** -- it reads as configured in a ``/export`` and watches
    nothing. Collapsing both into a bare ``unguarded`` would throw away
    exactly the distinction that made the lab router's three dead alert
    rows look fine. See ``constants.RogueDhcpAlertState``.

    ``serves_dhcp`` is recorded too, because an alert row on an interface
    this router serves no DHCP on means the configuration and the device
    disagree -- reported rather than hidden, per the reader's own contract.

    ## ``detail`` is where an ``unknown`` says why

    A row in ``UNKNOWN`` carries the device's own words (a connection
    refusal, a timeout, an unsupported reply) verbatim. An unreachable
    router is an unanswered question, and an unanswered question with no
    reason attached is barely better than no row at all.

    Does not import ``app.domains.router.models.Router`` -- only FKs its
    table name, the same loose-coupling convention ``DhcpPool`` above and
    ``app.domains.readiness.models`` already follow.
    """

    __tablename__ = "router_rogue_dhcp_statuses"

    router_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("routers.id", ondelete="CASCADE"), nullable=False
    )
    #: The router's own interface name as the device reports it (e.g.
    #: "ether2", "vlan10"). Half of this row's identity -- RouterOS holds
    #: one ``/ip dhcp-server alert`` per interface, so the interface *is*
    #: the subject of the finding.
    interface: Mapped[str] = mapped_column(String(100), nullable=False)
    #: One of ``constants.RogueDhcpAlertState`` -- a plain string column,
    #: not a native enum type, matching every other status column in this
    #: codebase (see ``DhcpPool.device_push_status`` above).
    alert_state: Mapped[str] = mapped_column(
        String(20), default=RogueDhcpAlertState.UNKNOWN.value, nullable=False
    )
    #: Whether an ``/ip dhcp-server alert`` row exists for this interface.
    #: Deliberately NOT merged with ``enabled`` below -- see the class
    #: docstring.
    alert_present: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    #: Whether that row is switched on. Presence without this is a guard
    #: that watches nothing, and is what RouterOS creates by default.
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    #: Whether this router runs an enabled ``/ip dhcp-server`` on this
    #: interface. An alert is only meaningful where it does: with no server
    #: of our own there is no baseline for calling a reply rogue.
    serves_dhcp: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    #: When the detection pass that produced this row ran -- not when the
    #: row was last written. A consumer showing ``alert_state`` without
    #: this cannot tell a current answer from a months-old one.
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    #: Why, in the device's or the adapter's own words. Always set for
    #: ``UNKNOWN``; a short human-readable summary otherwise.
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_router_rogue_dhcp_statuses_router_id", "router_id"),
        Index(
            "uq_router_rogue_dhcp_statuses_router_id_interface",
            "router_id",
            "interface",
            unique=True,
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<RouterRogueDhcpStatus(router_id={self.router_id}, "
            f"interface={self.interface}, alert_state={self.alert_state})>"
        )


__all__ = ["DhcpPool", "RouterRogueDhcpStatus"]
