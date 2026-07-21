"""SQLAlchemy ORM model for the Network Device (NAC) domain.

One table -- ``NetworkDevice``. See ``__init__.py``'s own module docstring
for the full "identity/compliance registry, distinct from
connected_devices/mac_authorization/guest_access" design write-up.

Extends ``app.database.base.BaseModel`` (UUID PK, timestamps, soft-delete,
audit, version columns) for the same reason every other domain does --
``created_by``/``updated_by`` already track who registered/last edited a
device, so there is no separate ``reviewed_by_user_id`` column here.

Uniqueness: one row per ``(organization_id, mac_address)`` -- mirrors
``app.domains.mac_authorization.models.MacAuthorizationEntry``'s identical
posture. ``router_id`` is nullable (a device can be pre-registered before
it has ever been seen on any specific router -- a real NAC use case, e.g.
enrolling a known corporate laptop ahead of its first connection) and is
otherwise expected to track whichever router the device was last observed
on.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import ComplianceStatus


class NetworkDevice(BaseModel):
    """One registered device identity/compliance record -- see module
    docstring."""

    __tablename__ = "network_devices"

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
    # Nullable -- see module docstring for why (pre-registration ahead of
    # first connection, and a device may roam across routers at one
    # location over time).
    router_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("routers.id", ondelete="SET NULL"),
        nullable=True,
    )
    mac_address: Mapped[str] = mapped_column(String(17), nullable=False)
    # Auto-suggested from the MAC's own OUI at creation time when not
    # explicitly supplied (see service.py) -- still just a display label,
    # never authoritative device identity.
    vendor: Mapped[str | None] = mapped_column(String(100), nullable=True)
    # Admin-entered free-text classification (e.g. "laptop", "iot-camera")
    # -- see __init__.py's own module docstring for why this is not named
    # "os_fingerprint".
    device_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    compliance_status: Mapped[str] = mapped_column(
        String(20), default=ComplianceStatus.UNKNOWN.value, nullable=False
    )
    compliance_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    __table_args__ = (
        Index("ix_network_devices_organization_id", "organization_id"),
        Index("ix_network_devices_location_id", "location_id"),
        Index("ix_network_devices_router_id", "router_id"),
        Index("ix_network_devices_mac_address", "mac_address"),
        Index("ix_network_devices_compliance_status", "compliance_status"),
        Index("ix_network_devices_is_active", "is_active"),
    )

    def __repr__(self) -> str:
        return (
            f"<NetworkDevice(id={self.id}, mac_address={self.mac_address}, "
            f"compliance_status={self.compliance_status})>"
        )


__all__ = ["NetworkDevice"]
