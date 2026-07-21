"""SQLAlchemy ORM model for the Connected Device Management domain.

One table -- ``ConnectedDevice``. Mirrors ``app.domains.isp``'s own
"current state, updated in place by every sync" convention (like
``IspLink.health_status``) rather than a "current state + history"
split -- there is no per-tick history table here (unlike
``IspHealthCheck``): a connected-device inventory row *is* the device's
most recently synced state, and nothing about "was this device connected
five sync ticks ago" is a real, named capability this domain's own
roadmap item asks for.

## ``guest_id``/``guest_session_id``: a synced snapshot, not the source of truth

These two columns are refreshed at every sync from a read-only
cross-reference against ``app.domains.guest``'s own ``GuestDevice``/
``GuestSession`` tables (see ``service.py``'s own
``_resolve_guest_association``) -- mirrors
``app.domains.router.models.Router.health_status``'s own "a synced
snapshot of another system's real state, not authoritative itself"
convention. ``app.domains.guest`` remains the sole source of truth for
who a guest is or which session is active; this domain never creates or
mutates either table.

Extends ``app.database.base.BaseModel`` (UUID PK, timestamps, soft-delete,
audit, version columns) for the same reason every other domain does.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import ConnectionType


class ConnectedDevice(BaseModel):
    """One device seen on a router's own network -- see module
    docstring. A router may not hold two non-deleted rows for the same
    ``mac_address`` -- enforced by the partial unique index below,
    mirroring ``app.domains.vlan.models.Vlan``'s own identical
    partial-unique-index precedent for "logically unique among
    non-deleted rows"."""

    __tablename__ = "connected_devices"

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
    # Canonical uppercase colon-separated form, normalized before every
    # write -- mirrors app.domains.mac_authorization's identical
    # normalization convention.
    mac_address: Mapped[str] = mapped_column(String(17), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    # Client-reported hostname from the router's own DHCP lease table --
    # often blank for devices that don't send DHCP option 12.
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Best-effort MAC-OUI lookup -- see constants.OUI_VENDOR_PREFIXES's
    # own "small and honest, not comprehensive" docstring. NULL means
    # genuinely unknown, never a guessed vendor name.
    vendor: Mapped[str | None] = mapped_column(String(100), nullable=True)
    connection_type: Mapped[str] = mapped_column(
        String(10), default=ConnectionType.UNKNOWN.value, nullable=False
    )
    # The router's own interface/SSID this device was last seen on.
    interface: Mapped[str | None] = mapped_column(String(100), nullable=True)
    # Only ever populated for a WIRELESS device, from the same wireless
    # registration-table query that determines connection_type -- real
    # data when present (never fabricated for a wired device), NULL
    # otherwise. The roadmap's own "(Future)" marker on Signal
    # Information reflects that wired devices structurally can never
    # have this value, not that this column is unused.
    signal_strength_dbm: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Whether this device was present in the most recent sync -- flipped
    # to False (never deleted) when a device drops off the router's own
    # DHCP-lease/ARP/wireless tables, so history-adjacent context
    # ("this device used to be here") survives a disconnect.
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # First observed at the start of this device's *current* active
    # streak -- reset the moment is_active transitions False -> True
    # again (a genuinely new connection, not a continuation).
    connected_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Synced snapshot, not authoritative -- see module docstring.
    guest_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("guests.id", ondelete="SET NULL"), nullable=True
    )
    guest_session_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("guest_sessions.id", ondelete="SET NULL"),
        nullable=True,
    )

    __table_args__ = (
        Index("ix_connected_devices_router_id", "router_id"),
        Index("ix_connected_devices_organization_id", "organization_id"),
        Index("ix_connected_devices_location_id", "location_id"),
        Index("ix_connected_devices_mac_address", "mac_address"),
        Index("ix_connected_devices_is_active", "is_active"),
        Index("ix_connected_devices_guest_id", "guest_id"),
        Index(
            "uq_connected_devices_router_id_mac_address",
            "router_id",
            "mac_address",
            unique=True,
            postgresql_where=text("is_deleted = false"),
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<ConnectedDevice(id={self.id}, mac_address={self.mac_address}, "
            f"is_active={self.is_active})>"
        )


__all__ = ["ConnectedDevice"]
