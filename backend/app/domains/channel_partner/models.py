"""SQLAlchemy ORM model for the Channel Partner domain.

:class:`ChannelPartner` -- a Wyfy Guest channel/reseller partner a Master
console operator onboards by hand. Carries no `organization_id`, the same
"belongs to no organization" shape `app.domains.quotation.models.Quotation`
and `app.domains.demo_request.models.DemoRequest` already establish: a
channel partner is Wyfy Guest's own business relationship, never a row
scoped to (or owned by) any customer Organization.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import ChannelPartnerStatus


class ChannelPartner(BaseModel):
    """One onboarded channel partner. `created_at`/`created_by`
    (from `BaseModel`'s `TimestampMixin`/`AuditMixin`) already serve as this
    row's "onboarded at" / "onboarded by staff user" -- no separate
    `onboarded_at`/`onboarded_by` columns needed, the exact same "reuse the
    base audit columns, don't duplicate them" call `Quotation` makes for its
    own creation metadata."""

    __tablename__ = "channel_partners"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # E.164, always +91-prefixed -- see schemas.py's normalize_phone. Used
    # to place a real Twilio SMS send, not just stored as contact info.
    phone: Mapped[str] = mapped_column(String(20), nullable=False)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    address: Mapped[str] = mapped_column(Text, nullable=False)
    city: Mapped[str] = mapped_column(String(100), nullable=False)
    # Always uppercase, 15 chars, validated against the real GSTIN format
    # (see schemas.py). Unique -- a GSTIN is a real government-issued tax ID
    # legally unique per registered business, so a second partner row with
    # the same GSTIN is always a data-entry mistake, not a legitimate case.
    gst_number: Mapped[str] = mapped_column(String(15), nullable=False)

    # Simple active/inactive toggle, independent of BaseModel's own
    # soft-delete (`is_deleted`). A partner relationship can legitimately
    # end without erasing the historical record the way a delete implies --
    # same "status is a business-lifecycle concept, is_deleted is a
    # data-lifecycle concept" split `QuotationStatus` draws for its own
    # domain. No API surface toggles this in v1 (see the module's own
    # out-of-scope notes) -- the column exists now so the cheap, obvious
    # follow-up (a deactivate action) never needs a migration.
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=ChannelPartnerStatus.ACTIVE.value
    )

    # Welcome-message delivery outcome, one pair of columns per channel --
    # mirrors Quotation.sent_at/email_error exactly, just doubled for SMS +
    # email. A failed/unconfigured send on either channel is never a
    # rollback of the partner row itself (see service.py).
    welcome_sms_sent_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    welcome_sms_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    welcome_email_sent_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    welcome_email_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_channel_partners_status", "status"),
        Index("ix_channel_partners_gst_number", "gst_number", unique=True),
        Index("ix_channel_partners_phone", "phone"),
    )

    def __repr__(self) -> str:
        return (
            f"<ChannelPartner(id={self.id}, name={self.name!r}, "
            f"gst_number={self.gst_number})>"
        )


__all__ = ["ChannelPartner"]
