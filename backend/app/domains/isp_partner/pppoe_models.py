"""Phase 2b PPPoE tables (JAZE-6). New tables only, keyed by subscriber.

* ``isp_pppoe_credentials`` -- one PPPoE login per ``isp_subscribers`` row.
  The password is Fernet-encrypted with the platform router key
  (``app.domains.router.crypto``), never hashed: FreeRADIUS must verify
  CHAP and MS-CHAPv2, and both need the clear secret on the server side.
  It is returned to a user once, when set or regenerated, and never again.
* ``isp_pppoe_sessions`` -- one row per RADIUS accounting session
  (``nas_client_id`` + ``Acct-Session-Id``), with the columns the IPDR /
  session dump and the FUP counters need. Byte counters are running
  totals as RADIUS reports them (gigawords already folded in).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, String, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

__all__ = ["IspPppoeCredential", "IspPppoeSession", "PPPOE_TABLES"]


def _fk(target: str, *, nullable: bool = False, ondelete: str | None = None):  # noqa: ANN202
    return mapped_column(
        UUID(as_uuid=True), ForeignKey(target, ondelete=ondelete), nullable=nullable
    )


class IspPppoeCredential(BaseModel):
    __tablename__ = "isp_pppoe_credentials"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    customer_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    subscriber_id: Mapped[uuid.UUID] = _fk("isp_subscribers.id")
    #: As typed; matching is on ``username_lower``.
    username: Mapped[str] = mapped_column(String(64), nullable=False)
    username_lower: Mapped[str] = mapped_column(String(64), nullable=False)
    password_encrypted: Mapped[str] = mapped_column(String(512), nullable=False)
    #: active | disabled
    status: Mapped[str] = mapped_column(
        String(10), nullable=False, default="active", server_default="active"
    )
    #: Framed-IP-Address (static IP). Pool assignment when NULL.
    static_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    #: Framed-Pool name on the router; NULL = the PPP profile's pool.
    ip_pool_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_auth_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: accepted | <reject reason code>
    last_auth_result: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_calling_station_id: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    password_set_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index(
            "uq_isp_pppoe_credentials_subscriber",
            "subscriber_id",
            unique=True,
            postgresql_where=text("is_deleted = false"),
        ),
        Index(
            "uq_isp_pppoe_credentials_isp_username",
            "isp_organization_id",
            "username_lower",
            unique=True,
            postgresql_where=text("is_deleted = false"),
        ),
        Index(
            "ix_isp_pppoe_credentials_customer_username",
            "customer_organization_id",
            "username_lower",
        ),
    )


class IspPppoeSession(BaseModel):
    __tablename__ = "isp_pppoe_sessions"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    customer_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    location_id: Mapped[uuid.UUID | None] = _fk("locations.id", nullable=True)
    router_id: Mapped[uuid.UUID | None] = _fk("routers.id", nullable=True)
    nas_client_id: Mapped[uuid.UUID] = _fk("radius_nas_clients.id")
    subscriber_id: Mapped[uuid.UUID | None] = _fk("isp_subscribers.id", nullable=True)
    credential_id: Mapped[uuid.UUID | None] = _fk(
        "isp_pppoe_credentials.id", nullable=True
    )
    username: Mapped[str] = mapped_column(String(64), nullable=False)
    acct_session_id: Mapped[str] = mapped_column(String(128), nullable=False)
    #: The PPPoE client's MAC (Calling-Station-Id), normalised AA:BB:...
    calling_station_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    framed_ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    framed_ipv6_prefix: Mapped[str | None] = mapped_column(String(64), nullable=True)
    delegated_ipv6_prefix: Mapped[str | None] = mapped_column(String(64), nullable=True)
    nas_port_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_update_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    stopped_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: active | closed
    status: Mapped[str] = mapped_column(String(10), nullable=False)
    bytes_uploaded: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )
    bytes_downloaded: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )
    terminate_cause: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        Index(
            "uq_isp_pppoe_sessions_nas_acct",
            "nas_client_id",
            "acct_session_id",
            unique=True,
        ),
        Index("ix_isp_pppoe_sessions_isp_started", "isp_organization_id", "started_at"),
        Index("ix_isp_pppoe_sessions_subscriber", "subscriber_id", "status"),
        Index("ix_isp_pppoe_sessions_framed_ip", "framed_ip_address", "started_at"),
        Index(
            "ix_isp_pppoe_sessions_customer_status",
            "customer_organization_id",
            "status",
        ),
    )


PPPOE_TABLES = ("isp_pppoe_credentials", "isp_pppoe_sessions")
