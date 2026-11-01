"""APPS-2 tables (ADDENDUM_06): helpdesk escalation, task approvals,
inventory vendors / stock locations / checkout approval / device links,
lead timers, per-ISP Apps settings.

New side tables keyed to JAZE-5's rows; JAZE-5's own tables are not altered
except one nullable column (``isp_announcements.scheduled_at``, migration
0184). Everything sits behind ``ISP_APPS_ENABLED`` like the rest of Apps.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import BaseModel

__all__ = [
    "APPS2_TABLES",
    "IspAppsSettings",
    "IspInventoryCheckout",
    "IspInventoryUnitMeta",
    "IspInventoryVendor",
    "IspLeadTimer",
    "IspStockLocation",
    "IspTaskApproval",
    "IspTicketEscalation",
    "IspTicketEscalationRule",
]


def _fk(target: str, *, nullable: bool = False, ondelete: str | None = None):  # noqa: ANN202
    return mapped_column(
        UUID(as_uuid=True), ForeignKey(target, ondelete=ondelete), nullable=nullable
    )


def _ts(nullable: bool = True):  # noqa: ANN202
    return mapped_column(DateTime(timezone=True), nullable=nullable)


class IspAppsSettings(BaseModel):
    """One row per ISP (created on first save; defaults apply until then)."""

    __tablename__ = "isp_apps_settings"
    __table_args__ = (
        Index(
            "uq_isp_apps_settings_isp",
            "isp_organization_id",
            unique=True,
            postgresql_where=text("is_deleted = false"),
        ),
    )

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    #: a new lead should be contacted within this many minutes
    lead_contact_sla_minutes: Mapped[int] = mapped_column(
        Integer, nullable=False, default=240
    )
    #: and converted (or dropped) within this many days
    lead_convert_sla_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=14
    )


class IspTicketEscalationRule(BaseModel):
    """Unresolved for ``after_minutes`` -> escalate (once per ticket)."""

    __tablename__ = "isp_ticket_escalation_rules"
    __table_args__ = (
        Index("ix_isp_ticket_escalation_rules_isp", "isp_organization_id"),
    )

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    #: None = every type / every priority
    type_id: Mapped[uuid.UUID | None] = _fk("isp_ticket_types.id", nullable=True)
    priority: Mapped[str | None] = mapped_column(String(8), nullable=True)
    after_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    #: one or both: a role slug (isp-noc, isp-admin, ...) and/or a staff member
    escalate_to_role: Mapped[str | None] = mapped_column(String(40), nullable=True)
    escalate_to_user_id: Mapped[uuid.UUID | None] = _fk("users.id", nullable=True)
    notify_telegram: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class IspTicketEscalation(BaseModel):
    __tablename__ = "isp_ticket_escalations"
    __table_args__ = (
        Index(
            "uq_isp_ticket_escalations_rule_ticket", "rule_id", "ticket_id", unique=True
        ),
        Index("ix_isp_ticket_escalations_isp", "isp_organization_id", "escalated_at"),
    )

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    rule_id: Mapped[uuid.UUID] = _fk(
        "isp_ticket_escalation_rules.id", ondelete="CASCADE"
    )
    ticket_id: Mapped[uuid.UUID] = _fk("isp_tickets.id", ondelete="CASCADE")
    escalated_at: Mapped[datetime] = _ts(nullable=False)
    to_role: Mapped[str | None] = mapped_column(String(40), nullable=True)
    to_user_id: Mapped[uuid.UUID | None] = _fk("users.id", nullable=True)
    #: sent | failed | off (flag off / no bot) | none (rule says no)
    telegram_status: Mapped[str] = mapped_column(String(8), nullable=False)
    telegram_error: Mapped[str | None] = mapped_column(String(200), nullable=True)


class IspTaskApproval(BaseModel):
    """A supervisor's decision on a completed task (history; latest wins)."""

    __tablename__ = "isp_task_approvals"
    __table_args__ = (Index("ix_isp_task_approvals_task", "task_id"),)

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    task_id: Mapped[uuid.UUID] = _fk("isp_field_tasks.id", ondelete="CASCADE")
    #: approved | rejected (sent back for rework)
    decision: Mapped[str] = mapped_column(String(10), nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    decided_by: Mapped[uuid.UUID | None] = _fk("users.id", nullable=True)
    decided_at: Mapped[datetime] = _ts(nullable=False)


class IspInventoryVendor(BaseModel):
    __tablename__ = "isp_inventory_vendors"
    __table_args__ = (Index("ix_isp_inventory_vendors_isp", "isp_organization_id"),)

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    contact_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    phone: Mapped[str | None] = mapped_column(String(20), nullable=True)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    gstin: Mapped[str | None] = mapped_column(String(15), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class IspStockLocation(BaseModel):
    __tablename__ = "isp_stock_locations"
    __table_args__ = (Index("ix_isp_stock_locations_isp", "isp_organization_id"),)

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    #: warehouse | office | technician_bag
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    #: the technician who carries a bag
    holder_user_id: Mapped[uuid.UUID | None] = _fk("users.id", nullable=True)
    address: Mapped[str | None] = mapped_column(Text, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class IspInventoryUnitMeta(BaseModel):
    """Where a unit came from, where it sits, which TR-069 device it is."""

    __tablename__ = "isp_inventory_unit_meta"
    __table_args__ = (
        Index(
            "uq_isp_inventory_unit_meta_unit",
            "unit_id",
            unique=True,
            postgresql_where=text("is_deleted = false"),
        ),
        Index("ix_isp_inventory_unit_meta_location", "location_id"),
    )

    unit_id: Mapped[uuid.UUID] = _fk("isp_inventory_units.id", ondelete="CASCADE")
    vendor_id: Mapped[uuid.UUID | None] = _fk("isp_inventory_vendors.id", nullable=True)
    location_id: Mapped[uuid.UUID | None] = _fk("isp_stock_locations.id", nullable=True)
    tr069_device_id: Mapped[uuid.UUID | None] = _fk("tr069_devices.id", nullable=True)


class IspInventoryCheckout(BaseModel):
    """A request to check a unit out to an install; a manager decides."""

    __tablename__ = "isp_inventory_checkouts"
    __table_args__ = (
        Index("ix_isp_inventory_checkouts_isp_status", "isp_organization_id", "status"),
        Index(
            "uq_isp_inventory_checkouts_open_unit",
            "unit_id",
            unique=True,
            postgresql_where=text("status = 'pending' AND is_deleted = false"),
        ),
    )

    isp_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    unit_id: Mapped[uuid.UUID] = _fk("isp_inventory_units.id", ondelete="CASCADE")
    customer_organization_id: Mapped[uuid.UUID] = _fk("organizations.id")
    subscriber_id: Mapped[uuid.UUID | None] = _fk("isp_subscribers.id", nullable=True)
    task_id: Mapped[uuid.UUID | None] = _fk("isp_field_tasks.id", nullable=True)
    #: pending | approved | rejected | cancelled
    status: Mapped[str] = mapped_column(String(10), nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_by: Mapped[uuid.UUID | None] = _fk("users.id", nullable=True)
    requested_at: Mapped[datetime] = _ts(nullable=False)
    decided_by: Mapped[uuid.UUID | None] = _fk("users.id", nullable=True)
    decided_at: Mapped[datetime | None] = _ts()
    decision_note: Mapped[str | None] = mapped_column(Text, nullable=True)


class IspLeadTimer(BaseModel):
    __tablename__ = "isp_lead_timers"
    __table_args__ = (
        Index(
            "uq_isp_lead_timers_lead",
            "lead_id",
            unique=True,
            postgresql_where=text("is_deleted = false"),
        ),
    )

    lead_id: Mapped[uuid.UUID] = _fk("isp_leads.id", ondelete="CASCADE")
    #: first time the lead left "new"
    first_contacted_at: Mapped[datetime | None] = _ts()
    status_changed_at: Mapped[datetime | None] = _ts()


APPS2_TABLES = (
    "isp_apps_settings",
    "isp_ticket_escalation_rules",
    "isp_ticket_escalations",
    "isp_task_approvals",
    "isp_inventory_vendors",
    "isp_stock_locations",
    "isp_inventory_unit_meta",
    "isp_inventory_checkouts",
    "isp_lead_timers",
)
