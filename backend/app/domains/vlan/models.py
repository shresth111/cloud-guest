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

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel


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
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

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
