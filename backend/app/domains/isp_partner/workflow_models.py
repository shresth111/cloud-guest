"""RAKESH-FS tables (migration 0225_isp_workflow). Additive only; no existing
column changes.

* ``isp_franchisee_zones`` -- the zones (each with its whole ZONE-1 subtree)
  an ``isp-franchisee`` user may work in. No row = sees nothing.
* ``isp_router_zones`` -- several zones may share one physical router
  (many-to-many). A router still belongs to exactly one customer location.
* ``isp_subscriber_routers`` -- the router a subscriber was placed on at
  onboarding (one per subscriber). A record only: PPPoE/hotspot still work on
  whatever NAS the subscriber reaches.
* ``isp_zone_packages`` -- packages a zone may sell. No rows for a zone =
  every package.

Link rows are hard-deleted when a set is replaced (they carry no history).
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel


def _fk(target: str, *, ondelete: str = "CASCADE"):  # noqa: ANN202
    return mapped_column(
        UUID(as_uuid=True), ForeignKey(target, ondelete=ondelete), nullable=False
    )


class IspFranchiseeZone(BaseModel):
    __tablename__ = "isp_franchisee_zones"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    user_id: Mapped[uuid.UUID] = _fk("users.id")
    zone_id: Mapped[uuid.UUID] = _fk("isp_zones.id")

    __table_args__ = (
        Index("uq_isp_franchisee_zones_user_zone", "user_id", "zone_id", unique=True),
        Index("ix_isp_franchisee_zones_isp_user", "isp_organization_id", "user_id"),
    )


class IspRouterZone(BaseModel):
    __tablename__ = "isp_router_zones"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    router_id: Mapped[uuid.UUID] = _fk("routers.id")
    zone_id: Mapped[uuid.UUID] = _fk("isp_zones.id")

    __table_args__ = (
        Index("uq_isp_router_zones_router_zone", "router_id", "zone_id", unique=True),
        Index("ix_isp_router_zones_isp_zone", "isp_organization_id", "zone_id"),
    )


class IspSubscriberRouter(BaseModel):
    __tablename__ = "isp_subscriber_routers"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    subscriber_id: Mapped[uuid.UUID] = _fk("isp_subscribers.id")
    router_id: Mapped[uuid.UUID] = _fk("routers.id")

    __table_args__ = (
        Index("uq_isp_subscriber_routers_subscriber", "subscriber_id", unique=True),
        Index("ix_isp_subscriber_routers_router", "router_id"),
    )


class IspZonePackage(BaseModel):
    __tablename__ = "isp_zone_packages"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    zone_id: Mapped[uuid.UUID] = _fk("isp_zones.id")
    package_id: Mapped[uuid.UUID] = _fk("isp_packages.id")

    __table_args__ = (
        Index("uq_isp_zone_packages_zone_pkg", "zone_id", "package_id", unique=True),
        Index("ix_isp_zone_packages_isp", "isp_organization_id"),
    )


WORKFLOW_TABLES = (
    "isp_franchisee_zones",
    "isp_router_zones",
    "isp_subscriber_routers",
    "isp_zone_packages",
)

__all__ = [
    "WORKFLOW_TABLES",
    "IspFranchiseeZone",
    "IspRouterZone",
    "IspSubscriberRouter",
    "IspZonePackage",
]
