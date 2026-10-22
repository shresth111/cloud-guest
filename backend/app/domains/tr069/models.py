"""TR-069 control-plane tables (API_CONTRACT §2). New tables only.

GenieACS is single-tenant; tenant isolation lives here. A CPE belongs to the
ISP whose credential its ``ManagementServer.Username`` names, and every task
is posted only after ``IspScope.assert_cpe`` has checked the row.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
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


class Tr069AcsCredential(BaseModel):
    """One per ISP (``customer_organization_id`` NULL: devices arrive
    unassigned) and one per customer with TR-069 enabled."""

    __tablename__ = "tr069_acs_credentials"

    isp_organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    customer_organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True
    )
    username: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    password_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    rotated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        # One credential per (ISP, customer), and exactly one ISP credential.
        # Two partial indexes rather than NULLS NOT DISTINCT, which needs
        # PostgreSQL 15.
        Index(
            "uq_tr069_acs_credentials_isp_customer",
            "isp_organization_id",
            "customer_organization_id",
            unique=True,
            postgresql_where=text("customer_organization_id IS NOT NULL"),
        ),
        Index(
            "uq_tr069_acs_credentials_isp_only",
            "isp_organization_id",
            unique=True,
            postgresql_where=text("customer_organization_id IS NULL"),
        ),
    )


class Tr069Device(BaseModel):
    __tablename__ = "tr069_devices"

    isp_organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    customer_organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True
    )
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("locations.id"), nullable=True
    )
    router_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("routers.id"), nullable=True
    )
    genieacs_device_id: Mapped[str] = mapped_column(
        String(255), nullable=False, unique=True
    )
    credential_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tr069_acs_credentials.id"), nullable=True
    )
    oui: Mapped[str | None] = mapped_column(String(6), nullable=True)
    product_class: Mapped[str | None] = mapped_column(String(64), nullable=True)
    serial_number: Mapped[str | None] = mapped_column(String(64), nullable=True)
    manufacturer: Mapped[str | None] = mapped_column(String(64), nullable=True)
    model: Mapped[str | None] = mapped_column(String(64), nullable=True)
    software_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    data_model: Mapped[str | None] = mapped_column(String(8), nullable=True)
    wan_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    last_inform_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    periodic_inform_interval_s: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    params_cache: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    params_refreshed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    label: Mapped[str | None] = mapped_column(String(200), nullable=True)

    __table_args__ = (
        Index(
            "ix_tr069_devices_isp_customer",
            "isp_organization_id",
            "customer_organization_id",
        ),
        Index("ix_tr069_devices_last_inform_at", "last_inform_at"),
    )


class Tr069Task(BaseModel):
    """Our audit of every NBI task we post."""

    __tablename__ = "tr069_tasks"

    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tr069_devices.id"), nullable=False
    )
    isp_organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False
    )
    requested_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    genieacs_task_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    fault: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index("ix_tr069_tasks_device_created", "device_id", text("created_at DESC")),
    )


class Tr069LocationSetting(BaseModel):
    __tablename__ = "tr069_location_settings"

    location_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("locations.id"), nullable=False, unique=True
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    periodic_inform_interval_s: Mapped[int] = mapped_column(
        Integer, nullable=False, default=300, server_default="300"
    )


__all__ = [
    "Tr069AcsCredential",
    "Tr069Device",
    "Tr069LocationSetting",
    "Tr069Task",
]
