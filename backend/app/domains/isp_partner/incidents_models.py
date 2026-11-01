"""INCIDENTS-1: outage incidents. Own tables only.

An incident is opened on ONE thing: a router (``router_id``), a fiber node
(``fiber_node_id``, JAZE-6) or a zone (``zone_id``, its whole ZONE-1
subtree). The affected subscribers are snapshotted into
``isp_incident_subscribers`` when it is opened (and on an explicit refresh),
so the broadcast, the grace and the history all talk about the same people.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

__all__ = [
    "INCIDENT_TABLES",
    "IspIncident",
    "IspIncidentEvent",
    "IspIncidentSubscriber",
]


def _fk(target: str, *, nullable: bool = False, ondelete: str | None = None) -> Any:
    return mapped_column(
        UUID(as_uuid=True), ForeignKey(target, ondelete=ondelete), nullable=nullable
    )


class IspIncident(BaseModel):
    """Status: investigating -> identified -> resolved (identified may be
    skipped). ``rfo_reason`` uses the JAZE-5 RFO list and is required to
    resolve."""

    __tablename__ = "isp_incidents"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id", ondelete="CASCADE")
    number: Mapped[int] = mapped_column(Integer, nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    #: router | fiber_node | zone
    scope_kind: Mapped[str] = mapped_column(String(12), nullable=False)
    router_id: Mapped[uuid.UUID | None] = _fk("routers.id", nullable=True)
    fiber_node_id: Mapped[uuid.UUID | None] = _fk("isp_fiber_nodes.id", nullable=True)
    zone_id: Mapped[uuid.UUID | None] = _fk("isp_zones.id", nullable=True)
    #: the router's / node's customer; NULL for a zone or shared plant
    customer_organization_id: Mapped[uuid.UUID | None] = _fk(
        "organizations.id", nullable=True, ondelete="CASCADE"
    )
    scope_label: Mapped[str] = mapped_column(String(255), nullable=False)
    #: minor | major | critical
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    status: Mapped[str] = mapped_column(String(14), nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    identified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    rfo_reason: Mapped[str | None] = mapped_column(String(16), nullable=True)
    rfo_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    affected_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    grace_hours: Mapped[int | None] = mapped_column(Integer, nullable=True)
    grace_applied_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index("uq_isp_incidents_number", "isp_organization_id", "number", unique=True),
        Index(
            "ix_isp_incidents_isp_status",
            "isp_organization_id",
            "status",
            "started_at",
        ),
        Index("ix_isp_incidents_router", "router_id"),
        Index("ix_isp_incidents_fiber_node", "fiber_node_id"),
        Index("ix_isp_incidents_zone", "zone_id"),
    )


class IspIncidentEvent(BaseModel):
    """Timeline: created / status / note / affected_refreshed / broadcast /
    grace."""

    __tablename__ = "isp_incident_events"

    incident_id: Mapped[uuid.UUID] = _fk("isp_incidents.id", ondelete="CASCADE")
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str | None] = mapped_column(String(14), nullable=True)
    body: Mapped[str | None] = mapped_column(Text, nullable=True)
    detail: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    __table_args__ = (
        Index("ix_isp_incident_events_incident", "incident_id", "occurred_at"),
    )


class IspIncidentSubscriber(BaseModel):
    """One affected subscriber. ``grace_status``: NULL (not run) | applied |
    skipped; one grace per (incident, subscriber), ever. ``outage_message`` /
    ``restored_message``: the outcome of the WhatsApp broadcast for this
    subscriber (sent | failed | no_consent | no_phone), NULL = not sent."""

    __tablename__ = "isp_incident_subscribers"

    incident_id: Mapped[uuid.UUID] = _fk("isp_incidents.id", ondelete="CASCADE")
    subscriber_id: Mapped[uuid.UUID] = _fk("isp_subscribers.id", ondelete="CASCADE")
    customer_organization_id: Mapped[uuid.UUID] = _fk(
        "organizations.id", ondelete="CASCADE"
    )
    #: how it was found: router | fiber | zone
    source: Mapped[str] = mapped_column(String(8), nullable=False)
    node_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    port_no: Mapped[int | None] = mapped_column(Integer, nullable=True)
    grace_status: Mapped[str | None] = mapped_column(String(10), nullable=True)
    grace_detail: Mapped[str | None] = mapped_column(String(255), nullable=True)
    grace_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    outage_message: Mapped[str | None] = mapped_column(String(12), nullable=True)
    restored_message: Mapped[str | None] = mapped_column(String(12), nullable=True)

    __table_args__ = (
        Index(
            "uq_isp_incident_subscribers_pair",
            "incident_id",
            "subscriber_id",
            unique=True,
        ),
        Index("ix_isp_incident_subscribers_subscriber", "subscriber_id"),
    )


INCIDENT_TABLES = (
    "isp_incidents",
    "isp_incident_events",
    "isp_incident_subscribers",
)
