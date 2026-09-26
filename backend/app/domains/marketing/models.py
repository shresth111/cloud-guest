"""SQLAlchemy models for the Guest Marketing domain.

Contract: ``wyfy-specs/guest-marketing-campaigns.md`` §4. Every table
extends ``BaseModel`` (UUID id, timestamps, soft delete, audit, version).
Enums are plain strings (see ``constants``).

Tenant scoping: every row carries a non-null ``organization_id`` except a
*system* template (``MarketingTemplate.organization_id IS NULL``), which is
global, seeded, and read-only. Repositories filter on ``organization_id``
for every read; nothing is ever looked up by id alone.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

from .constants import CampaignStatus, RecipientStatus, WhatsAppApprovalStatus


class GuestMarketingConsent(BaseModel):
    """Current consent state, one live row per guest per channel (§4.1)."""

    __tablename__ = "guest_marketing_consents"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    guest_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("guests.id", ondelete="CASCADE"), nullable=False
    )
    channel: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    consent_text_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    captured_at_location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="SET NULL"),
        nullable=True,
    )
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    status_changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    __table_args__ = (
        Index(
            "uq_gmc_guest_channel",
            "guest_id",
            "channel",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index("ix_gmc_org_channel_status", "organization_id", "channel", "status"),
    )


class GuestMarketingConsentEvent(BaseModel):
    """Append-only consent history -- the DPDP proof (§4.2). Never updated,
    never pruned by retention."""

    __tablename__ = "guest_marketing_consent_events"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    guest_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("guests.id", ondelete="CASCADE"), nullable=False
    )
    channel: Mapped[str] = mapped_column(String(16), nullable=False)
    action: Mapped[str] = mapped_column(String(16), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    consent_text_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    __table_args__ = (Index("ix_gmce_guest_occurred", "guest_id", "occurred_at"),)


class MarketingSuppression(BaseModel):
    """Organization-level do-not-contact entry keyed on the normalized
    address (§4.3). Wins over consent, and covers a second ``guests`` row
    carrying the same address."""

    __tablename__ = "marketing_suppressions"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    channel: Mapped[str] = mapped_column(String(16), nullable=False)
    address_normalized: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str] = mapped_column(String(32), nullable=False)
    source_recipient_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    __table_args__ = (
        Index(
            "uq_ms_org_channel_address",
            "organization_id",
            "channel",
            "address_normalized",
            unique=True,
        ),
    )


class MarketingTemplate(BaseModel):
    """A message template (§4.4). ``organization_id IS NULL`` = a system
    template, seeded by migration and read-only to every customer."""

    __tablename__ = "marketing_templates"

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
    )
    system_key: Mapped[str | None] = mapped_column(String(50), nullable=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[str | None] = mapped_column(String(300), nullable=True)
    sms_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    sms_dlt_template_id: Mapped[str | None] = mapped_column(String(30), nullable=True)
    whatsapp_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    whatsapp_content_sid: Mapped[str | None] = mapped_column(String(40), nullable=True)
    whatsapp_variable_order: Mapped[list[str] | None] = mapped_column(
        JSONB, nullable=True
    )
    whatsapp_approval_status: Mapped[str] = mapped_column(
        String(16),
        default=WhatsAppApprovalStatus.NOT_SUBMITTED.value,
        nullable=False,
    )
    email_subject: Mapped[str | None] = mapped_column(String(150), nullable=True)
    email_preheader: Mapped[str | None] = mapped_column(String(150), nullable=True)
    email_body_html: Mapped[str | None] = mapped_column(Text, nullable=True)
    # WABA template sync (spec §12.2/§12.3): "wyfy" for the system rows,
    # "own_waba" for templates synced from a venue's own WhatsApp Business
    # Account. Synced rows are sent by provider template name + language.
    whatsapp_source: Mapped[str | None] = mapped_column(String(12), nullable=True)
    whatsapp_provider_template_name: Mapped[str | None] = mapped_column(
        String(512), nullable=True
    )
    whatsapp_provider_language: Mapped[str | None] = mapped_column(
        String(15), nullable=True
    )
    whatsapp_synced_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index("ix_mt_org", "organization_id"),
        Index(
            "uq_mt_org_waba_template",
            "organization_id",
            "whatsapp_provider_template_name",
            "whatsapp_provider_language",
            unique=True,
            postgresql_where=text(
                "whatsapp_source = 'own_waba' AND deleted_at IS NULL"
            ),
        ),
        Index(
            "uq_mt_system_key",
            "system_key",
            unique=True,
            postgresql_where=text("system_key IS NOT NULL"),
        ),
        Index(
            "uq_mt_org_name",
            "organization_id",
            func.lower(text("name")),
            unique=True,
            postgresql_where=text("deleted_at IS NULL AND organization_id IS NOT NULL"),
        ),
    )

    @property
    def is_system(self) -> bool:
        return self.organization_id is None


class MarketingCampaign(BaseModel):
    """One single-channel outbound campaign (§4.5)."""

    __tablename__ = "marketing_campaigns"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="SET NULL"),
        nullable=True,
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    channel: Mapped[str] = mapped_column(String(16), nullable=False)
    template_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("marketing_templates.id", ondelete="RESTRICT"),
        nullable=False,
    )
    template_snapshot: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB, nullable=True
    )
    variables: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, nullable=False
    )
    audience_filter: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), default=CampaignStatus.DRAFT.value, nullable=False
    )
    scheduled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    cancelled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    cancel_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    paused_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    recipient_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    count_pending: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    count_submitted: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    count_delivered: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    count_failed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    count_skipped: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    exclusion_counts: Mapped[dict[str, int] | None] = mapped_column(
        JSONB, nullable=True
    )
    last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    schedule_idempotency_key: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    schedule_idempotency_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Provider snapshot (spec §12.1), written at schedule time and the only
    # thing the dispatcher and send_batch read: never re-resolved, never a
    # fallback from own to Wyfy or back.
    provider_source: Mapped[str] = mapped_column(
        String(8), default="wyfy", server_default="wyfy", nullable=False
    )
    provider_type: Mapped[str | None] = mapped_column(String(20), nullable=True)
    org_provider_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("org_marketing_providers.id", ondelete="SET NULL"),
        nullable=True,
    )
    # Credits (spec §13.4): the price frozen at schedule/send-now --
    # ``{channel, unit, unit_price_minor, price_book_row_id,
    # units_per_recipient_max}`` -- NULL for drafts and own-provider
    # campaigns. Every reservation, extension and debit of this campaign
    # uses it, whatever the price book says later.
    price_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    # Reachable recipients left out at dispatch because the wallet could not
    # cover them (stats.capped_by_credits).
    capped_by_credits: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )

    __table_args__ = (
        Index("ix_mc_org_status", "organization_id", "status"),
        Index(
            "ix_mc_due",
            "status",
            "scheduled_at",
            postgresql_where=text("status = 'scheduled'"),
        ),
        Index("ix_mc_location", "location_id"),
        Index(
            "uq_mc_org_idempotency_key",
            "organization_id",
            "schedule_idempotency_key",
            unique=True,
            postgresql_where=text("schedule_idempotency_key IS NOT NULL"),
        ),
    )


class MarketingCampaignRecipient(BaseModel):
    """One materialized recipient of a campaign -- the delivery log (§4.7).

    ``uq_mcr_campaign_guest`` is the idempotency guarantee: a guest is never
    materialized twice for one campaign, so a re-run of materialization
    cannot double-send."""

    __tablename__ = "marketing_campaign_recipients"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    campaign_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("marketing_campaigns.id", ondelete="CASCADE"),
        nullable=False,
    )
    guest_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("guests.id", ondelete="SET NULL"), nullable=True
    )
    channel: Mapped[str] = mapped_column(String(16), nullable=False)
    # The venue this send is attributed to (contract change 2026-09-25): the
    # location of the guest's most recent session among the campaign's
    # audience venues (all org venues when the audience names none), inside
    # the audience's visit window when it has one. Fixed at materialization
    # so the delivery log does not shift as the guest keeps visiting.
    location_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("locations.id", ondelete="SET NULL"),
        nullable=True,
    )
    address: Mapped[str | None] = mapped_column(String(255), nullable=True)
    rendered_preview: Mapped[str | None] = mapped_column(String(200), nullable=True)
    status: Mapped[str] = mapped_column(
        String(16), default=RecipientStatus.PENDING.value, nullable=False
    )
    skip_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    provider: Mapped[str | None] = mapped_column(String(20), nullable=True)
    provider_source: Mapped[str | None] = mapped_column(String(8), nullable=True)
    provider_message_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(String(500), nullable=True)
    attempt_count: Mapped[int] = mapped_column(SmallInteger, default=0, nullable=False)
    unsubscribe_token: Mapped[str] = mapped_column(String(32), nullable=False)
    sending_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    next_attempt_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    submitted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    delivered_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    failed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index("uq_mcr_campaign_guest", "campaign_id", "guest_id", unique=True),
        Index("ix_mcr_campaign_status", "campaign_id", "status"),
        Index("uq_mcr_unsub_token", "unsubscribe_token", unique=True),
        Index("ix_mcr_provider_msg", "provider", "provider_message_id"),
        Index("ix_mcr_org_created", "organization_id", "created_at"),
        Index("ix_mcr_org_location", "organization_id", "location_id"),
    )


class OrgMarketingProvider(BaseModel):
    """A venue organization's own provider account for one channel
    (spec §12.3). At most one live row per (organization, channel).

    ``config_encrypted`` holds every config field, secret and not,
    Fernet-encrypted under ``router_encryption_key``; it is decrypted only
    inside the verify and send code paths and never leaves the process.
    ``display`` is the only thing any API reads: non-secret fields verbatim
    plus a ``{set, hint}`` stub per secret."""

    __tablename__ = "org_marketing_providers"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    channel: Mapped[str] = mapped_column(String(16), nullable=False)
    provider_type: Mapped[str] = mapped_column(String(20), nullable=False)
    config_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    display: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), default="unverified", nullable=False
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false", nullable=False
    )
    last_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    verified_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    updated_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    __table_args__ = (
        Index(
            "uq_omp_org_channel",
            "organization_id",
            "channel",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )


class MarketingPriceBook(BaseModel):
    """Per-unit prices for Wyfy-provider sends, in credit minor units
    (spec §13.3). **Versioned and append-only**: a change inserts a row with
    ``effective_from = now()``; nothing is updated, so the history answers
    "what was the price on the day this campaign was scheduled".

    ``organization_id`` NULL = the platform default; set = a per-org
    override. An org row with ``unit_price_minor`` NULL clears the override
    (inherit the platform price). The current price for ``(org, channel)``
    is the org's latest row with ``effective_from <= now()`` when that row
    has a price, else the platform's latest.
    """

    __tablename__ = "marketing_price_book"

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
    )
    channel: Mapped[str] = mapped_column(String(16), nullable=False)
    unit: Mapped[str] = mapped_column(String(8), nullable=False)
    unit_price_minor: Mapped[int | None] = mapped_column(Integer, nullable=True)
    effective_from: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    set_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    note: Mapped[str | None] = mapped_column(String(300), nullable=True)

    __table_args__ = (
        Index(
            "uq_mpb_org_channel_effective",
            "organization_id",
            "channel",
            "effective_from",
            unique=True,
            postgresql_nulls_not_distinct=True,
        ),
        Index("ix_mpb_channel_effective", "channel", "effective_from"),
        CheckConstraint(
            "unit_price_minor IS NULL OR (unit_price_minor >= 0 "
            "AND unit_price_minor <= 10000)",
            name="price_range",
        ),
        CheckConstraint(
            "organization_id IS NOT NULL OR unit_price_minor IS NOT NULL",
            name="platform_price_required",
        ),
        CheckConstraint("channel IN ('sms','whatsapp','email')", name="channel_valid"),
    )


__all__ = [
    "MarketingPriceBook",
    "OrgMarketingProvider",
    "GuestMarketingConsent",
    "GuestMarketingConsentEvent",
    "MarketingCampaign",
    "MarketingCampaignRecipient",
    "MarketingSuppression",
    "MarketingTemplate",
]
