"""SQLAlchemy ORM model for the DHCP Pool Management domain.

One table -- ``DhcpPool``. A row's own state *is* its current state; there
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

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import DEFAULT_LEASE_TIME_SECONDS


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


__all__ = ["DhcpPool"]
