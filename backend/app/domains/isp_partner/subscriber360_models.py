"""ADDENDUM_05 J1/J2/J11 (JAZE-1): the subscriber's onboarding profile and
its activity timeline.

Both tables are ISP-owned and keyed by ``subscriber_id``; ``isp_subscribers``
itself is not altered. Other lanes keep their own per-subscriber state (FUP,
MAC bindings, KYC, deposit) in their own tables, keyed the same way.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Numeric,
    SmallInteger,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel


def _fk(target: str, *, nullable: bool = False) -> Any:
    return mapped_column(
        UUID(as_uuid=True), ForeignKey(target, ondelete="CASCADE"), nullable=nullable
    )


#: J2 enums (validated in the router; stored as strings).
USER_TYPES = ("home", "commercial", "sme")
CONNECTION_TYPES = ("fiber", "wireless", "ethernet", "other")
GENDERS = ("male", "female", "other", "undisclosed")
AFTER_DUE_ACTIONS = ("suspend", "keep_active", "disconnect_once")
BLOCK_KINDS = ("temporary", "permanent")


class IspSubscriberProfile(BaseModel):
    __tablename__ = "isp_subscriber_profiles"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    subscriber_id: Mapped[uuid.UUID] = _fk("isp_subscribers.id")

    # -- personal / contact (J2 3.3) --------------------------------------
    alt_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    gender: Mapped[str | None] = mapped_column(String(12), nullable=True)
    billing_city: Mapped[str | None] = mapped_column(String(100), nullable=True)
    billing_pincode: Mapped[str | None] = mapped_column(String(10), nullable=True)

    # -- installation (J2 3.4) --------------------------------------------
    install_same_as_billing: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    install_address: Mapped[str | None] = mapped_column(Text, nullable=True)
    install_area: Mapped[str | None] = mapped_column(String(120), nullable=True)
    install_building: Mapped[str | None] = mapped_column(String(120), nullable=True)
    install_city: Mapped[str | None] = mapped_column(String(100), nullable=True)
    install_pincode: Mapped[str | None] = mapped_column(String(10), nullable=True)
    latitude: Mapped[Decimal | None] = mapped_column(Numeric(9, 6), nullable=True)
    longitude: Mapped[Decimal | None] = mapped_column(Numeric(9, 6), nullable=True)
    installed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # -- other (J2 3.6) ---------------------------------------------------
    user_type: Mapped[str] = mapped_column(
        String(12), nullable=False, default="home", server_default="home"
    )
    connection_type: Mapped[str | None] = mapped_column(String(12), nullable=True)
    ont_serial: Mapped[str | None] = mapped_column(String(64), nullable=True)
    stb_serial: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # -- billing behaviour (J2 3.2 / 3.5) ---------------------------------
    #: Replaces the package price on renewals for this subscriber only.
    override_price_paise: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    billing_anchor_day: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    after_due_action: Mapped[str] = mapped_column(
        String(16), nullable=False, default="suspend", server_default="suspend"
    )
    exclude_reminders: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )

    # -- activation (J2 3.9) ----------------------------------------------
    activation_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    comments: Mapped[str | None] = mapped_column(Text, nullable=True)

    # -- lifecycle state (J1 4.2) -----------------------------------------
    block_kind: Mapped[str | None] = mapped_column(String(10), nullable=True)
    blocked_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    blocked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: Status before block/freeze, restored on unblock/unfreeze.
    status_before_hold: Mapped[str | None] = mapped_column(String(10), nullable=True)
    frozen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    frozen_remaining_seconds: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True
    )
    grace_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index(
            "uq_isp_subscriber_profiles_subscriber",
            "subscriber_id",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index("ix_isp_subscriber_profiles_isp", "isp_organization_id"),
    )


class IspSubscriberEvent(BaseModel):
    """Append-only timeline. ``kind`` examples: created, profile_updated,
    renewed, reverted, grace, blocked, unblocked, frozen, unfrozen,
    disconnected, moved, note, plan_sync. ``detail`` holds what a revert or
    an audit needs (previous validity, package, invoice id)."""

    __tablename__ = "isp_subscriber_events"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    subscriber_id: Mapped[uuid.UUID] = _fk("isp_subscribers.id")
    kind: Mapped[str] = mapped_column(String(24), nullable=False)
    summary: Mapped[str | None] = mapped_column(String(255), nullable=True)
    detail: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    __table_args__ = (
        Index("ix_isp_subscriber_events_sub_created", "subscriber_id", "created_at"),
        Index("ix_isp_subscriber_events_isp_kind", "isp_organization_id", "kind"),
    )


SUBSCRIBER360_TABLES = ("isp_subscriber_profiles", "isp_subscriber_events")

__all__ = [
    "AFTER_DUE_ACTIONS",
    "BLOCK_KINDS",
    "CONNECTION_TYPES",
    "GENDERS",
    "SUBSCRIBER360_TABLES",
    "USER_TYPES",
    "IspSubscriberEvent",
    "IspSubscriberProfile",
]
