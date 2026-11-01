"""J16 "Apps" tables (ADDENDUM_05): helpdesk, field tasks, announcements,
discount codes, light inventory, leads. New tables only, every one carries
``isp_organization_id``; rows about a customer also carry
``customer_organization_id`` and are only ever read through ``IspScope``
(confinement applies). Nothing here alters a pre-existing table.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
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


def _fk(target: str, *, nullable: bool = False, ondelete: str | None = None):  # noqa: ANN202
    return mapped_column(
        UUID(as_uuid=True), ForeignKey(target, ondelete=ondelete), nullable=nullable
    )


def _ts(nullable: bool = True):  # noqa: ANN202
    return mapped_column(DateTime(timezone=True), nullable=nullable)


class IspAppsCounter(BaseModel):
    """Per-ISP running numbers (ticket T-000001, lead L-000001). Bumped with
    one ``INSERT .. ON CONFLICT DO UPDATE .. RETURNING`` so it is atomic."""

    __tablename__ = "isp_apps_counters"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    value: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (
        Index(
            "uq_isp_apps_counters_isp_kind", "isp_organization_id", "kind", unique=True
        ),
    )


# -- helpdesk ----------------------------------------------------------------
class IspTicketType(BaseModel):
    __tablename__ = "isp_ticket_types"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    #: target time to resolve; None = no SLA for this type
    sla_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    requires_rfo: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (
        Index(
            "uq_isp_ticket_types_isp_name",
            "isp_organization_id",
            "name",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )


class IspTicket(BaseModel):
    __tablename__ = "isp_tickets"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    customer_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    subscriber_id: Mapped[uuid.UUID | None] = _fk("isp_subscribers.id", nullable=True)
    number: Mapped[int] = mapped_column(Integer, nullable=False)
    type_id: Mapped[uuid.UUID | None] = _fk("isp_ticket_types.id", nullable=True)
    subject: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(12), nullable=False)
    priority: Mapped[str] = mapped_column(String(8), nullable=False)
    status: Mapped[str] = mapped_column(String(12), nullable=False)
    assignee_user_id: Mapped[uuid.UUID | None] = _fk("users.id", nullable=True)
    rfo_reason: Mapped[str | None] = mapped_column(String(16), nullable=True)
    resolution_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: snapshot of the type's SLA when opened (later type edits don't move it)
    sla_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    opened_at: Mapped[datetime] = _ts(nullable=False)
    due_at: Mapped[datetime | None] = _ts()
    first_response_at: Mapped[datetime | None] = _ts()
    resolved_at: Mapped[datetime | None] = _ts()
    closed_at: Mapped[datetime | None] = _ts()
    raised_by_user_id: Mapped[uuid.UUID | None] = _fk("users.id", nullable=True)

    __table_args__ = (
        Index(
            "uq_isp_tickets_isp_number", "isp_organization_id", "number", unique=True
        ),
        Index("ix_isp_tickets_isp_status", "isp_organization_id", "status"),
        Index("ix_isp_tickets_customer", "customer_organization_id"),
        Index("ix_isp_tickets_subscriber", "subscriber_id"),
        Index("ix_isp_tickets_opened", "isp_organization_id", "opened_at"),
    )


class IspTicketEvent(BaseModel):
    __tablename__ = "isp_ticket_events"

    ticket_id: Mapped[uuid.UUID] = _fk("isp_tickets.id", ondelete="CASCADE")
    #: comment | status | assign | update
    kind: Mapped[str] = mapped_column(String(10), nullable=False)
    body: Mapped[str | None] = mapped_column(Text, nullable=True)
    detail: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    actor_user_id: Mapped[uuid.UUID | None] = _fk("users.id", nullable=True)
    at: Mapped[datetime] = _ts(nullable=False)

    __table_args__ = (Index("ix_isp_ticket_events_ticket", "ticket_id", "at"),)


# -- field tasks -------------------------------------------------------------
class IspFieldTask(BaseModel):
    __tablename__ = "isp_field_tasks"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    #: None only for a lead's survey/install before it has a customer
    customer_organization_id: Mapped[uuid.UUID | None] = _fk(
        "organizations.id", nullable=True
    )
    subscriber_id: Mapped[uuid.UUID | None] = _fk("isp_subscribers.id", nullable=True)
    ticket_id: Mapped[uuid.UUID | None] = _fk("isp_tickets.id", nullable=True)
    lead_id: Mapped[uuid.UUID | None] = _fk("isp_leads.id", nullable=True)
    kind: Mapped[str] = mapped_column(String(10), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    address: Mapped[str | None] = mapped_column(Text, nullable=True)
    latitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    longitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    scheduled_at: Mapped[datetime | None] = _ts()
    status: Mapped[str] = mapped_column(String(12), nullable=False)
    assignee_user_id: Mapped[uuid.UUID | None] = _fk("users.id", nullable=True)
    started_at: Mapped[datetime | None] = _ts()
    completed_at: Mapped[datetime | None] = _ts()
    completion_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    rejected_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)

    __table_args__ = (
        Index("ix_isp_field_tasks_isp_status", "isp_organization_id", "status"),
        Index("ix_isp_field_tasks_assignee", "assignee_user_id"),
        Index("ix_isp_field_tasks_customer", "customer_organization_id"),
    )


# -- announcements -----------------------------------------------------------
class IspAnnouncement(BaseModel):
    __tablename__ = "isp_announcements"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    title: Mapped[str] = mapped_column(String(150), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    #: all | selected
    audience: Mapped[str] = mapped_column(String(10), nullable=False)
    customer_ids: Mapped[list] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    send_email: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    #: draft | sent
    status: Mapped[str] = mapped_column(String(8), nullable=False)
    sent_at: Mapped[datetime | None] = _ts()
    sent_by_user_id: Mapped[uuid.UUID | None] = _fk("users.id", nullable=True)

    __table_args__ = (Index("ix_isp_announcements_isp", "isp_organization_id"),)


class IspAnnouncementRecipient(BaseModel):
    __tablename__ = "isp_announcement_recipients"

    announcement_id: Mapped[uuid.UUID] = _fk("isp_announcements.id", ondelete="CASCADE")
    customer_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    phone: Mapped[str | None] = mapped_column(String(20), nullable=True)
    #: queued | skipped (no email) | failed
    email_status: Mapped[str] = mapped_column(String(8), nullable=False)
    delivery_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    __table_args__ = (Index("ix_isp_announcement_recipients_ann", "announcement_id"),)


# -- discount codes ----------------------------------------------------------
class IspDiscountCode(BaseModel):
    __tablename__ = "isp_discount_codes"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    code: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[str | None] = mapped_column(String(200), nullable=True)
    #: percent (value = basis points) | flat (value = paise)
    kind: Mapped[str] = mapped_column(String(8), nullable=False)
    value: Mapped[int] = mapped_column(BigInteger, nullable=False)
    max_discount_paise: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    min_amount_paise: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    max_uses: Mapped[int | None] = mapped_column(Integer, nullable=True)
    used_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    valid_from: Mapped[datetime | None] = _ts()
    valid_until: Mapped[datetime | None] = _ts()
    #: None = every package
    package_ids: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    __table_args__ = (
        Index(
            "uq_isp_discount_codes_isp_code",
            "isp_organization_id",
            "code",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )


class IspDiscountRedemption(BaseModel):
    __tablename__ = "isp_discount_redemptions"

    discount_id: Mapped[uuid.UUID] = _fk("isp_discount_codes.id")
    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    customer_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    subscriber_id: Mapped[uuid.UUID | None] = _fk("isp_subscribers.id", nullable=True)
    invoice_id: Mapped[uuid.UUID | None] = _fk("isp_invoices.id", nullable=True)
    amount_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)
    at: Mapped[datetime] = _ts(nullable=False)

    __table_args__ = (
        Index("ix_isp_discount_redemptions_discount", "discount_id"),
        Index(
            "uq_isp_discount_redemptions_invoice",
            "discount_id",
            "invoice_id",
            unique=True,
            postgresql_where=text("invoice_id IS NOT NULL"),
        ),
    )


# -- inventory ---------------------------------------------------------------
class IspInventoryItem(BaseModel):
    """A catalogue entry (e.g. "Dual-band ONT")."""

    __tablename__ = "isp_inventory_items"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    sku: Mapped[str] = mapped_column(String(40), nullable=False)
    #: ont | router | cpe | ap | switch | other
    category: Mapped[str] = mapped_column(String(10), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index(
            "uq_isp_inventory_items_isp_sku",
            "isp_organization_id",
            "sku",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
    )


class IspInventoryUnit(BaseModel):
    """One physical serialised device."""

    __tablename__ = "isp_inventory_units"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    item_id: Mapped[uuid.UUID] = _fk("isp_inventory_items.id")
    serial: Mapped[str] = mapped_column(String(64), nullable=False)
    mac: Mapped[str | None] = mapped_column(String(17), nullable=True)
    #: in_stock | assigned | returned | faulty | retired
    state: Mapped[str] = mapped_column(String(10), nullable=False)
    customer_organization_id: Mapped[uuid.UUID | None] = _fk(
        "organizations.id", nullable=True
    )
    subscriber_id: Mapped[uuid.UUID | None] = _fk("isp_subscribers.id", nullable=True)
    state_changed_at: Mapped[datetime] = _ts(nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index(
            "uq_isp_inventory_units_isp_serial",
            "isp_organization_id",
            "serial",
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index("ix_isp_inventory_units_item_state", "item_id", "state"),
        Index("ix_isp_inventory_units_subscriber", "subscriber_id"),
    )


class IspInventoryMovement(BaseModel):
    __tablename__ = "isp_inventory_movements"

    unit_id: Mapped[uuid.UUID] = _fk("isp_inventory_units.id", ondelete="CASCADE")
    from_state: Mapped[str | None] = mapped_column(String(10), nullable=True)
    to_state: Mapped[str] = mapped_column(String(10), nullable=False)
    customer_organization_id: Mapped[uuid.UUID | None] = _fk(
        "organizations.id", nullable=True
    )
    subscriber_id: Mapped[uuid.UUID | None] = _fk("isp_subscribers.id", nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    actor_user_id: Mapped[uuid.UUID | None] = _fk("users.id", nullable=True)
    at: Mapped[datetime] = _ts(nullable=False)

    __table_args__ = (Index("ix_isp_inventory_movements_unit", "unit_id", "at"),)


# -- leads -------------------------------------------------------------------
class IspLead(BaseModel):
    __tablename__ = "isp_leads"

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    number: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    phone: Mapped[str | None] = mapped_column(String(20), nullable=True)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    address: Mapped[str | None] = mapped_column(Text, nullable=True)
    city: Mapped[str | None] = mapped_column(String(100), nullable=True)
    latitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    longitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    #: walk_in | phone | website | referral | campaign | other
    source: Mapped[str] = mapped_column(String(10), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    #: the customer this lead would be served under (required to convert)
    customer_organization_id: Mapped[uuid.UUID | None] = _fk(
        "organizations.id", nullable=True
    )
    interested_package_id: Mapped[uuid.UUID | None] = _fk(
        "isp_packages.id", nullable=True
    )
    assignee_user_id: Mapped[uuid.UUID | None] = _fk("users.id", nullable=True)
    feasibility_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    dropped_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    converted_subscriber_id: Mapped[uuid.UUID | None] = _fk(
        "isp_subscribers.id", nullable=True
    )
    converted_at: Mapped[datetime | None] = _ts()

    __table_args__ = (
        Index("uq_isp_leads_isp_number", "isp_organization_id", "number", unique=True),
        Index("ix_isp_leads_isp_status", "isp_organization_id", "status"),
    )


APPS_TABLES = (
    "isp_apps_counters",
    "isp_ticket_types",
    "isp_tickets",
    "isp_ticket_events",
    "isp_leads",
    "isp_field_tasks",
    "isp_announcements",
    "isp_announcement_recipients",
    "isp_discount_codes",
    "isp_discount_redemptions",
    "isp_inventory_items",
    "isp_inventory_units",
    "isp_inventory_movements",
)

__all__ = [
    "APPS_TABLES",
    "IspAnnouncement",
    "IspAnnouncementRecipient",
    "IspAppsCounter",
    "IspDiscountCode",
    "IspDiscountRedemption",
    "IspFieldTask",
    "IspInventoryItem",
    "IspInventoryMovement",
    "IspInventoryUnit",
    "IspLead",
    "IspTicket",
    "IspTicketEvent",
    "IspTicketType",
]
