"""RAKESH-P1 tables. New tables only, keyed by an existing id; no column of
an existing table is added or changed.

* ``isp_speed_group_device_rules`` (P1-1, migration 0221): device count and
  MAC binding held by a speed template. Enforcement never reads this table:
  "apply" copies the values onto the packages that use the template (the
  same ``isp_packages.max_devices`` and ``isp_package_policies`` fields the
  package form writes), so what enforcement reads is unchanged.
* ``isp_package_cycle_basis`` (P1-2, migration 0222): is the package's billing
  cycle its own validity (``package``, = no row) or the subscriber's billing
  anchor day (``subscriber``)? Read only by ``p1_cycle_hook.cycle_end``.
* ``isp_zone_coupon_rights`` (P1-3, migration 0224): an explicit "may the
  franchisee generate coupons here" per zone. No row = inherit from the
  parent zone; no explicit row on the whole path = allowed (the RAKESH-FS
  franchisee role behaviour). Read only by ``p1_coupon_rights.coupon_gate``.
"""

from __future__ import annotations

import uuid

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    SmallInteger,
    String,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

__all__ = [
    "CYCLE_BASES",
    "P1_TABLES",
    "IspPackageCycleBasis",
    "IspZoneCouponRight",
    "IspSpeedGroupDeviceRules",
]

CYCLE_BASES = ("package", "subscriber")


class IspSpeedGroupDeviceRules(BaseModel):
    __tablename__ = "isp_speed_group_device_rules"

    isp_organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    speed_group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("isp_speed_groups.id", ondelete="CASCADE"),
        nullable=False,
    )
    #: the package's ``max_devices`` (devices per coupon / login), 1..50
    max_devices: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, server_default="1"
    )
    #: policy ``mac_bind_count``: auto-bind the first N device MACs (0 = off)
    mac_bind_count: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, server_default="0"
    )
    #: policy ``mac_restriction``: only bound MACs may connect
    mac_restriction: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=text("false")
    )
    #: policy ``max_simultaneous``: devices online at once (NULL = no limit)
    max_simultaneous: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)

    __table_args__ = (
        Index(
            "uq_isp_speed_group_device_rules_group",
            "speed_group_id",
            unique=True,
            postgresql_where=text("is_deleted = false"),
        ),
        Index("ix_isp_speed_group_device_rules_isp", "isp_organization_id"),
    )


class IspPackageCycleBasis(BaseModel):
    __tablename__ = "isp_package_cycle_basis"

    isp_organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    package_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("isp_packages.id", ondelete="CASCADE"),
        nullable=False,
    )
    #: package | subscriber
    basis: Mapped[str] = mapped_column(
        String(12), nullable=False, server_default="package"
    )

    __table_args__ = (
        CheckConstraint("basis in ('package','subscriber')", name="basis"),
        Index(
            "uq_isp_package_cycle_basis_package",
            "package_id",
            unique=True,
            postgresql_where=text("is_deleted = false"),
        ),
        Index("ix_isp_package_cycle_basis_isp", "isp_organization_id"),
    )


class IspZoneCouponRight(BaseModel):
    __tablename__ = "isp_zone_coupon_rights"

    isp_organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    zone_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("isp_zones.id", ondelete="CASCADE"),
        nullable=False,
    )
    allow_generate: Mapped[bool] = mapped_column(Boolean, nullable=False)

    __table_args__ = (
        Index(
            "uq_isp_zone_coupon_rights_zone",
            "zone_id",
            unique=True,
            postgresql_where=text("is_deleted = false"),
        ),
        Index("ix_isp_zone_coupon_rights_isp", "isp_organization_id"),
    )


P1_TABLES = (
    "isp_speed_group_device_rules",
    "isp_package_cycle_basis",
    "isp_zone_coupon_rights",
)
