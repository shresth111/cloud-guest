"""J22 fiber plant registry tables (ADDENDUM_05 §7, JAZE-6 part B).

New, ISP-owned tables only. Nothing here is enforced on a device; it is a
record of where the plant is and what hangs off it.

* ``isp_fiber_nodes`` -- one row per OLT / pole / splitter / joint closure /
  ONT / other, with lat/long and its upstream ``parent_id`` (the route). A
  node with ports (OLT PON ports, splitter outputs) declares ``port_count``;
  a child that hangs off a numbered port records ``parent_port``.
* ``isp_fiber_port_assignments`` -- splitter (or OLT) port -> subscriber.
  One subscriber per port and one port per subscriber.

"Affected subscribers" for a node = the port assignments on the node and on
every node below it (recursive over ``parent_id``).
"""

from __future__ import annotations

import uuid

from sqlalchemy import (
    CheckConstraint,
    Float,
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

__all__ = ["FIBER_TABLES", "IspFiberNode", "IspFiberPortAssignment"]


def _fk(target: str, *, nullable: bool = False, ondelete: str | None = None):  # noqa: ANN202
    return mapped_column(
        UUID(as_uuid=True), ForeignKey(target, ondelete=ondelete), nullable=nullable
    )


class IspFiberNode(BaseModel):
    __tablename__ = "isp_fiber_nodes"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    #: Optional: plant usually serves many customers of the ISP. When set,
    #: confined staff only see the node if they cover this customer.
    customer_organization_id: Mapped[uuid.UUID | None] = _fk(
        "organizations.id", nullable=True
    )
    #: olt | pole | splitter | joint_closure | ont | other
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    #: The ISP's own tag on the box / pole ("SPL-14"). Unique per ISP.
    code: Mapped[str | None] = mapped_column(String(40), nullable=True)
    latitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    longitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    address: Mapped[str | None] = mapped_column(String(500), nullable=True)
    parent_id: Mapped[uuid.UUID | None] = _fk("isp_fiber_nodes.id", nullable=True)
    #: Which numbered port of the parent this node hangs off (optional).
    parent_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: Numbered outputs (OLT PON ports, splitter 1:8 -> 8). NULL = none.
    port_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: Free text: "1:8 PLC", "24F", "Huawei MA5800".
    spec: Mapped[str | None] = mapped_column(String(120), nullable=True)
    #: active | planned | retired
    status: Mapped[str] = mapped_column(
        String(10), nullable=False, default="active", server_default="active"
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        CheckConstraint(
            "kind in ('olt','pole','splitter','joint_closure','ont','other')",
            name="kind",
        ),
        CheckConstraint(
            "status in ('active','planned','retired')",
            name="status",
        ),
        CheckConstraint(
            "port_count is null or (port_count >= 1 and port_count <= 1024)",
            name="port_count",
        ),
        CheckConstraint(
            "parent_port is null or parent_port >= 1",
            name="parent_port",
        ),
        Index("ix_isp_fiber_nodes_isp_kind", "isp_organization_id", "kind"),
        Index("ix_isp_fiber_nodes_parent", "parent_id"),
        Index(
            "uq_isp_fiber_nodes_isp_code",
            "isp_organization_id",
            "code",
            unique=True,
            postgresql_where=text("is_deleted = false and code is not null"),
        ),
        Index(
            "uq_isp_fiber_nodes_parent_port",
            "parent_id",
            "parent_port",
            unique=True,
            postgresql_where=text("is_deleted = false and parent_port is not null"),
        ),
    )


class IspFiberPortAssignment(BaseModel):
    __tablename__ = "isp_fiber_port_assignments"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    node_id: Mapped[uuid.UUID] = _fk("isp_fiber_nodes.id")
    port_no: Mapped[int] = mapped_column(Integer, nullable=False)
    subscriber_id: Mapped[uuid.UUID] = _fk("isp_subscribers.id")
    #: The subscriber's customer, copied for confinement filters.
    customer_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    notes: Mapped[str | None] = mapped_column(String(500), nullable=True)

    __table_args__ = (
        CheckConstraint("port_no >= 1", name="port_no"),
        Index(
            "uq_isp_fiber_port_assignments_node_port",
            "node_id",
            "port_no",
            unique=True,
            postgresql_where=text("is_deleted = false"),
        ),
        Index(
            "uq_isp_fiber_port_assignments_subscriber",
            "subscriber_id",
            unique=True,
            postgresql_where=text("is_deleted = false"),
        ),
    )


FIBER_TABLES = ("isp_fiber_nodes", "isp_fiber_port_assignments")
