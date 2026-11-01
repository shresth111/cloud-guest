"""SMALL-3 (CHURN-RISK save rate): one row per win-back action taken from the
Churn risk tab. ``saved_at`` is filled by the 120 s pass when the subscriber
renews (a recharge invoice) or pays (a confirmed payment) inside the action's
window; nothing else writes it."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

__all__ = ["WINBACK_ACTIONS", "IspWinbackAction"]

WINBACK_ACTIONS = ("offer_renew", "ticket", "whatsapp_share")


def _fk(target: str, *, nullable: bool = False, ondelete: str | None = None):  # noqa: ANN202
    return mapped_column(
        UUID(as_uuid=True), ForeignKey(target, ondelete=ondelete), nullable=nullable
    )


class IspWinbackAction(BaseModel):
    __tablename__ = "isp_winback_actions"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id", ondelete="CASCADE")
    customer_organization_id: Mapped[uuid.UUID] = _fk(
        "organizations.id", ondelete="CASCADE"
    )
    subscriber_id: Mapped[uuid.UUID] = _fk("isp_subscribers.id", ondelete="CASCADE")
    #: offer_renew | ticket | whatsapp_share
    action: Mapped[str] = mapped_column(String(20), nullable=False)
    #: risk reason codes shown when the action was taken (display only)
    reasons: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    #: the ticket / invoice the action produced, if any (opaque)
    ref_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    acted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_days: Mapped[int] = mapped_column(Integer, nullable=False)
    window_ends_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    saved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: renewal | payment
    saved_via: Mapped[str | None] = mapped_column(String(10), nullable=True)
    saved_ref_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    __table_args__ = (
        Index("ix_isp_winback_actions_isp_acted", "isp_organization_id", "acted_at"),
        Index("ix_isp_winback_actions_subscriber", "subscriber_id"),
        Index(
            "uq_isp_winback_actions_key",
            "isp_organization_id",
            "idempotency_key",
            unique=True,
            postgresql_where=text("idempotency_key IS NOT NULL"),
        ),
        Index(
            "ix_isp_winback_actions_open",
            "isp_organization_id",
            "window_ends_at",
            postgresql_where=text("saved_at IS NULL"),
        ),
    )
