"""SMALL-5: incidents auto-opened from router DOWN (J14 device status).

* ``IspIncidentAutoSettings``: per-ISP switch (default off) + minutes.
* ``IspIncidentAutoRouter``: debounce state per router (status + since).
* ``IspIncidentAuto``: one row per auto-opened incident; the partial unique
  index allows at most ONE open (``closed_at IS NULL``) auto-incident per
  router, enforced by the database.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

__all__ = ["IspIncidentAuto", "IspIncidentAutoRouter", "IspIncidentAutoSettings"]


def _fk(target: str, *, nullable: bool = False, ondelete: str | None = None):  # noqa: ANN202
    return mapped_column(
        UUID(as_uuid=True), ForeignKey(target, ondelete=ondelete), nullable=nullable
    )


class IspIncidentAutoSettings(BaseModel):
    __tablename__ = "isp_incident_auto_settings"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id", ondelete="CASCADE")
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    #: a router must stay DOWN this long before an incident opens
    down_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    #: and UP this long before the auto-incident resolves
    up_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=15)

    __table_args__ = (
        Index("uq_isp_incident_auto_settings_isp", "isp_organization_id", unique=True),
    )


class IspIncidentAutoRouter(BaseModel):
    __tablename__ = "isp_incident_auto_routers"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id", ondelete="CASCADE")
    router_id: Mapped[uuid.UUID] = _fk("routers.id", ondelete="CASCADE")
    #: up | down
    observed_status: Mapped[str] = mapped_column(String(6), nullable=False)
    observed_since: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    __table_args__ = (
        Index("uq_isp_incident_auto_routers_router", "router_id", unique=True),
        Index("ix_isp_incident_auto_routers_isp", "isp_organization_id"),
    )


class IspIncidentAuto(BaseModel):
    __tablename__ = "isp_incident_autos"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id", ondelete="CASCADE")
    router_id: Mapped[uuid.UUID] = _fk("routers.id", ondelete="CASCADE")
    #: the router's venue, so lists scope by customer without reading routers
    customer_organization_id: Mapped[uuid.UUID] = _fk(
        "organizations.id", ondelete="CASCADE"
    )
    incident_id: Mapped[uuid.UUID] = _fk("isp_incidents.id", ondelete="CASCADE")
    down_since: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: True = resolved by this job (router back UP); False = closed because
    #: staff resolved it by hand. Auto-resolved incidents never get auto-grace.
    auto_resolved: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )

    __table_args__ = (
        Index("uq_isp_incident_autos_incident", "incident_id", unique=True),
        Index(
            "uq_isp_incident_autos_router_open",
            "router_id",
            unique=True,
            postgresql_where=text("closed_at IS NULL"),
        ),
        Index("ix_isp_incident_autos_isp", "isp_organization_id"),
    )
