"""SQLAlchemy ORM models for the Campaigns domain.

Five tables -- see each class's own docstring. Extends
``app.database.base.BaseModel`` (UUID PK, timestamps, soft-delete, audit,
version columns) for the same reason every other domain does.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import (
    DEFAULT_DISPLAY_INTERVAL_DAYS,
    DEFAULT_DISPLAY_RULE,
    DEFAULT_IS_SKIPPABLE,
    CampaignStatus,
)


class Campaign(BaseModel):
    """One post-login guest campaign -- see ``__init__.py``'s own module
    docstring for the full friction-avoidance/runtime-status design
    write-up.

    ``location_id IS NULL`` means an org-wide campaign (every location in
    the organization); a non-null value scopes it to one location --
    mirrors ``app.domains.router_provisioning.models.ConfigTemplate``'s
    own identical nullable-FK-means-platform/org-wide convention, one
    level down the hierarchy."""

    __tablename__ = "campaigns"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="CASCADE"),
        nullable=True,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    campaign_type: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), default=CampaignStatus.DRAFT.value, nullable=False
    )
    starts_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    ends_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    display_rule: Mapped[str] = mapped_column(
        String(20), default=DEFAULT_DISPLAY_RULE.value, nullable=False
    )
    # Only meaningful when display_rule=ONCE_PER_N_DAYS -- validated at
    # the service layer (validators.validate_display_rule_fields), not a
    # database CHECK constraint (mirrors this codebase's own established
    # "cross-field business rule, not a schema-level one" convention).
    display_interval_days: Mapped[int | None] = mapped_column(
        Integer, default=DEFAULT_DISPLAY_INTERVAL_DAYS, nullable=True
    )
    # See __init__.py's own module docstring: a JSONB array of real
    # Router.id values, no foreign key (no finer-grained "network"
    # entity exists in this codebase to reference) -- empty means every
    # router in scope.
    target_networks: Mapped[list[str]] = mapped_column(
        JSONB, default=list, nullable=False
    )
    is_skippable: Mapped[bool] = mapped_column(
        Boolean, default=DEFAULT_IS_SKIPPABLE, nullable=False
    )

    __table_args__ = (
        Index("ix_campaigns_organization_id", "organization_id"),
        Index("ix_campaigns_location_id", "location_id"),
        Index("ix_campaigns_status", "status"),
        Index("ix_campaigns_campaign_type", "campaign_type"),
    )

    def __repr__(self) -> str:
        return f"<Campaign(id={self.id}, name={self.name}, status={self.status})>"


class CampaignQuestion(BaseModel):
    """One question in a ``CampaignType.SURVEY`` campaign. ``options``
    (JSONB list of strings) is only populated for
    ``AnswerType.SINGLE_CHOICE``/``MULTI_CHOICE`` -- ``NULL``/empty for
    ``RATING_5``/``FREE_TEXT``, validated at the service layer."""

    __tablename__ = "campaign_questions"

    campaign_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("campaigns.id", ondelete="CASCADE"),
        nullable=False,
    )
    order_index: Mapped[int] = mapped_column(Integer, nullable=False)
    question_text: Mapped[str] = mapped_column(Text, nullable=False)
    answer_type: Mapped[str] = mapped_column(String(20), nullable=False)
    options: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    is_required: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    __table_args__ = (
        Index("ix_campaign_questions_campaign_id", "campaign_id"),
        Index(
            "ix_campaign_questions_campaign_id_order_index",
            "campaign_id",
            "order_index",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<CampaignQuestion(id={self.id}, campaign_id={self.campaign_id}, "
            f"order_index={self.order_index})>"
        )


class CampaignResponse(BaseModel):
    """One guest's completed answers to a ``SURVEY`` campaign.
    ``answers`` (JSONB) is keyed by the responding ``CampaignQuestion``'s
    own ``id`` (string) -> the guest's raw answer (a string, a list of
    strings for ``MULTI_CHOICE``, or an int 1-5 for ``RATING_5``) -- a
    real, structured, but variably-shaped JSONB use, the same precedent
    ``app.domains.device_sync.models.DeviceSyncRun.component_results``
    already establishes.

    **No database-level unique constraint enforcing "one response per
    guest when `Campaign.display_rule=FIRST_LOGIN_ONLY`".** That rule
    depends on a *different* table's own column
    (``Campaign.display_rule``) -- not expressible as a partial unique
    index on this table alone (a partial index's own predicate can only
    reference columns of the table it is declared on). Enforced instead
    at the service layer (``service.py``'s own
    ``submit_response``/``_enforce_first_login_only_uniqueness``) -- a
    real, honest gap documented here rather than silently assumed away,
    mirroring ``app.domains.dhcp.models.DhcpPool``'s own identical
    "why this is a service-layer check, not a database constraint"
    precedent. A plain (non-unique) index on ``(campaign_id, guest_id)``
    still exists below for that check's own query performance."""

    __tablename__ = "campaign_responses"

    campaign_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("campaigns.id", ondelete="CASCADE"),
        nullable=False,
    )
    guest_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("guests.id", ondelete="CASCADE"), nullable=False
    )
    guest_session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("guest_sessions.id", ondelete="CASCADE"),
        nullable=False,
    )
    submitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    answers: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    __table_args__ = (
        Index("ix_campaign_responses_campaign_id", "campaign_id"),
        Index("ix_campaign_responses_guest_id", "guest_id"),
        Index("ix_campaign_responses_guest_session_id", "guest_session_id"),
        Index("ix_campaign_responses_campaign_id_guest_id", "campaign_id", "guest_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<CampaignResponse(id={self.id}, campaign_id={self.campaign_id}, "
            f"guest_id={self.guest_id})>"
        )


class CampaignAsset(BaseModel):
    """The visual/redirect content for a ``BANNER``/``REDIRECT``
    campaign. ``image_url``/``click_url`` are both nullable since the
    two campaign types share this one table (see
    ``constants.CampaignType``'s own module docstring): a ``BANNER``
    typically sets both; a pure ``REDIRECT`` sets only ``click_url``.
    Validated at the service layer that at least one of the two is set
    (``validators.validate_asset_urls``) -- a row with neither would be
    inert."""

    __tablename__ = "campaign_assets"

    campaign_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("campaigns.id", ondelete="CASCADE"),
        nullable=False,
    )
    image_url: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    click_url: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    alt_text: Mapped[str | None] = mapped_column(String(300), nullable=True)
    locale: Mapped[str | None] = mapped_column(String(10), nullable=True)

    __table_args__ = (Index("ix_campaign_assets_campaign_id", "campaign_id"),)

    def __repr__(self) -> str:
        return f"<CampaignAsset(id={self.id}, campaign_id={self.campaign_id})>"


class CampaignImpression(BaseModel):
    """One "this campaign was shown to this guest session" event --
    immutable/append-only (mirrors ``app.domains.device_sync.models
    .DeviceSyncRun``'s own "new row, not mutate" convention: no
    ``update``/soft-delete method exists for this row in this domain's
    own repository). Drives ``DisplayRule.FIRST_LOGIN_ONLY``/
    ``ONCE_PER_N_DAYS`` eligibility (``service.py``'s own
    ``_has_been_shown_recently``, joined through to the responding
    guest via ``guest_session_id`` -> ``GuestSession.guest_id``, since
    this table's own column list has no direct ``guest_id`` of its own
    -- a guest is identified across multiple sessions only through that
    join)."""

    __tablename__ = "campaign_impressions"

    campaign_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("campaigns.id", ondelete="CASCADE"),
        nullable=False,
    )
    guest_session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("guest_sessions.id", ondelete="CASCADE"),
        nullable=False,
    )
    shown_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    was_skipped: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    was_clicked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    __table_args__ = (
        Index("ix_campaign_impressions_campaign_id", "campaign_id"),
        Index("ix_campaign_impressions_guest_session_id", "guest_session_id"),
        Index("ix_campaign_impressions_shown_at", "shown_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<CampaignImpression(id={self.id}, campaign_id={self.campaign_id}, "
            f"guest_session_id={self.guest_session_id})>"
        )


__all__ = [
    "Campaign",
    "CampaignQuestion",
    "CampaignResponse",
    "CampaignAsset",
    "CampaignImpression",
]
