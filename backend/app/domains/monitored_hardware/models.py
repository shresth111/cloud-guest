"""SQLAlchemy ORM model for the Monitored Hardware domain.

One table -- ``MonitoredHardware``. See ``__init__.py``'s own module
docstring for the full "why this exists / status is derived, never
fabricated" design write-up.

Extends ``app.database.base.BaseModel`` (UUID PK, timestamps, soft-delete,
audit, version columns), the same convention every domain in this
codebase follows -- mirrors ``app.domains.network_device.models
.NetworkDevice``'s identical shape closely (same organization_id/
location_id/router_id/mac_address posture) since both are real device
registries, just for different purposes.
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel


class MonitoredHardware(BaseModel):
    """One admin-registered piece of venue network hardware -- see module
    docstring."""

    __tablename__ = "monitored_hardware"

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
    # Nullable -- hardware isn't always tied to a specific router (e.g. a
    # printer sitting on the LAN), mirrors NetworkDevice's identical
    # posture.
    router_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("routers.id", ondelete="SET NULL"),
        nullable=True,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    mac_address: Mapped[str] = mapped_column(String(17), nullable=False)
    device_type: Mapped[str] = mapped_column(String(50), nullable=False)
    # Free-text floor label ("GF", "3F", custom) -- the frontend already
    # offers a suggestion list, never a fixed enum (a venue's own floor
    # naming varies too much to constrain server-side).
    floor: Mapped[str | None] = mapped_column(String(50), nullable=True)

    __table_args__ = (
        Index("ix_monitored_hardware_organization_id", "organization_id"),
        Index("ix_monitored_hardware_location_id", "location_id"),
        Index("ix_monitored_hardware_router_id", "router_id"),
        Index("ix_monitored_hardware_mac_address", "mac_address"),
    )

    def __repr__(self) -> str:
        return (
            f"<MonitoredHardware(id={self.id}, mac_address={self.mac_address}, "
            f"device_type={self.device_type})>"
        )


__all__ = ["MonitoredHardware"]
