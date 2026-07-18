"""SQLAlchemy ORM models for the Monitoring domain."""

from __future__ import annotations

import uuid
from typing import Any
from sqlalchemy import DateTime, ForeignKey, String, Float, Integer
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

class RouterMetric(BaseModel):
    """Router device metrics collected periodically."""

    __tablename__ = "router_metrics"

    router_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("routers.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    cpu_usage: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    memory_usage: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    disk_usage: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    temperature: Mapped[float | None] = mapped_column(Float, nullable=True)
    voltage: Mapped[float | None] = mapped_column(Float, nullable=True)
    uptime: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    rx_throughput: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    tx_throughput: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    bandwidth: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    latency: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    packet_loss: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    jitter: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    connected_clients: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    freeradius_status: Mapped[str] = mapped_column(String(50), default="up", nullable=False)

    interface_status: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, nullable=False
    )
    wireguard_tunnel_status: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, nullable=False
    )


class SystemHealth(BaseModel):
    """Overall platform service component health status."""

    __tablename__ = "system_health"

    component: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    status: Mapped[str] = mapped_column(String(50), default="healthy", nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, nullable=False
    )
