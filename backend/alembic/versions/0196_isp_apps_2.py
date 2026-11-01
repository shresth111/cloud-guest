"""APPS-2 (ADDENDUM_06): helpdesk escalation, task approvals, inventory
vendors / stock locations / checkout approval / device links, lead timers,
per-ISP Apps settings, scheduled announcements.

Additive: nine new tables plus one nullable column
(``isp_announcements.scheduled_at``). ``downgrade`` drops exactly these.

Revision ID: 0196_isp_apps_2
Revises: 0195_isp_zone_branding
Create Date: 2026-11-01
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0196_isp_apps_2"
down_revision = "0195_isp_zone_branding"
branch_labels = None
depends_on = None

_TS = sa.DateTime(timezone=True)


def _uuid(name: str, *args: object, **kw: object) -> sa.Column:
    return sa.Column(name, postgresql.UUID(as_uuid=True), *args, **kw)


def _fk(
    name: str, target: str, *, nullable: bool = True, ondelete: str | None = None
) -> sa.Column:
    return _uuid(name, sa.ForeignKey(target, ondelete=ondelete), nullable=nullable)


def _base() -> list[sa.Column]:
    return [
        _uuid("id", primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("created_at", _TS, nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", _TS, nullable=False, server_default=sa.text("now()")),
        sa.Column("deleted_at", _TS, nullable=True),
        sa.Column(
            "is_deleted", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
        _uuid("created_by", nullable=True),
        _uuid("updated_by", nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
    ]


def _table(name: str, *cols: sa.Column) -> None:
    op.create_table(name, *_base(), *cols)
    for col in ("created_at", "deleted_at", "is_deleted", "created_by", "updated_by"):
        op.create_index(f"ix_{name}_{col}", name, [col])


def upgrade() -> None:
    _table(
        "isp_apps_settings",
        _fk("isp_organization_id", "organizations.id", nullable=False),
        sa.Column("lead_contact_sla_minutes", sa.Integer(), nullable=False),
        sa.Column("lead_convert_sla_days", sa.Integer(), nullable=False),
    )
    op.create_index(
        "uq_isp_apps_settings_isp",
        "isp_apps_settings",
        ["isp_organization_id"],
        unique=True,
        postgresql_where=sa.text("is_deleted = false"),
    )

    _table(
        "isp_ticket_escalation_rules",
        _fk("isp_organization_id", "organizations.id", nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        _fk("type_id", "isp_ticket_types.id"),
        sa.Column("priority", sa.String(8), nullable=True),
        sa.Column("after_minutes", sa.Integer(), nullable=False),
        sa.Column("escalate_to_role", sa.String(40), nullable=True),
        _fk("escalate_to_user_id", "users.id"),
        sa.Column("notify_telegram", sa.Boolean(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
    )
    op.create_index(
        "ix_isp_ticket_escalation_rules_isp",
        "isp_ticket_escalation_rules",
        ["isp_organization_id"],
    )

    _table(
        "isp_ticket_escalations",
        _fk("isp_organization_id", "organizations.id", nullable=False),
        _fk(
            "rule_id",
            "isp_ticket_escalation_rules.id",
            nullable=False,
            ondelete="CASCADE",
        ),
        _fk("ticket_id", "isp_tickets.id", nullable=False, ondelete="CASCADE"),
        sa.Column("escalated_at", _TS, nullable=False),
        sa.Column("to_role", sa.String(40), nullable=True),
        _fk("to_user_id", "users.id"),
        sa.Column("telegram_status", sa.String(8), nullable=False),
        sa.Column("telegram_error", sa.String(200), nullable=True),
    )
    op.create_index(
        "uq_isp_ticket_escalations_rule_ticket",
        "isp_ticket_escalations",
        ["rule_id", "ticket_id"],
        unique=True,
    )
    op.create_index(
        "ix_isp_ticket_escalations_isp",
        "isp_ticket_escalations",
        ["isp_organization_id", "escalated_at"],
    )

    _table(
        "isp_task_approvals",
        _fk("isp_organization_id", "organizations.id", nullable=False),
        _fk("task_id", "isp_field_tasks.id", nullable=False, ondelete="CASCADE"),
        sa.Column("decision", sa.String(10), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        _fk("decided_by", "users.id"),
        sa.Column("decided_at", _TS, nullable=False),
    )
    op.create_index("ix_isp_task_approvals_task", "isp_task_approvals", ["task_id"])

    _table(
        "isp_inventory_vendors",
        _fk("isp_organization_id", "organizations.id", nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("contact_name", sa.String(120), nullable=True),
        sa.Column("phone", sa.String(20), nullable=True),
        sa.Column("email", sa.String(255), nullable=True),
        sa.Column("gstin", sa.String(15), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False),
    )
    op.create_index(
        "ix_isp_inventory_vendors_isp", "isp_inventory_vendors", ["isp_organization_id"]
    )

    _table(
        "isp_stock_locations",
        _fk("isp_organization_id", "organizations.id", nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        _fk("holder_user_id", "users.id"),
        sa.Column("address", sa.Text(), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False),
    )
    op.create_index(
        "ix_isp_stock_locations_isp", "isp_stock_locations", ["isp_organization_id"]
    )

    _table(
        "isp_inventory_unit_meta",
        _fk("unit_id", "isp_inventory_units.id", nullable=False, ondelete="CASCADE"),
        _fk("vendor_id", "isp_inventory_vendors.id"),
        _fk("location_id", "isp_stock_locations.id"),
        _fk("tr069_device_id", "tr069_devices.id"),
    )
    op.create_index(
        "uq_isp_inventory_unit_meta_unit",
        "isp_inventory_unit_meta",
        ["unit_id"],
        unique=True,
        postgresql_where=sa.text("is_deleted = false"),
    )
    op.create_index(
        "ix_isp_inventory_unit_meta_location",
        "isp_inventory_unit_meta",
        ["location_id"],
    )

    _table(
        "isp_inventory_checkouts",
        _fk("isp_organization_id", "organizations.id", nullable=False),
        _fk("unit_id", "isp_inventory_units.id", nullable=False, ondelete="CASCADE"),
        _fk("customer_organization_id", "organizations.id", nullable=False),
        _fk("subscriber_id", "isp_subscribers.id"),
        _fk("task_id", "isp_field_tasks.id"),
        sa.Column("status", sa.String(10), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        _fk("requested_by", "users.id"),
        sa.Column("requested_at", _TS, nullable=False),
        _fk("decided_by", "users.id"),
        sa.Column("decided_at", _TS, nullable=True),
        sa.Column("decision_note", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_isp_inventory_checkouts_isp_status",
        "isp_inventory_checkouts",
        ["isp_organization_id", "status"],
    )
    op.create_index(
        "uq_isp_inventory_checkouts_open_unit",
        "isp_inventory_checkouts",
        ["unit_id"],
        unique=True,
        postgresql_where=sa.text("status = 'pending' AND is_deleted = false"),
    )

    _table(
        "isp_lead_timers",
        _fk("lead_id", "isp_leads.id", nullable=False, ondelete="CASCADE"),
        sa.Column("first_contacted_at", _TS, nullable=True),
        sa.Column("status_changed_at", _TS, nullable=True),
    )
    op.create_index(
        "uq_isp_lead_timers_lead",
        "isp_lead_timers",
        ["lead_id"],
        unique=True,
        postgresql_where=sa.text("is_deleted = false"),
    )

    op.add_column("isp_announcements", sa.Column("scheduled_at", _TS, nullable=True))


def downgrade() -> None:
    op.drop_column("isp_announcements", "scheduled_at")
    for name in (
        "isp_lead_timers",
        "isp_inventory_checkouts",
        "isp_inventory_unit_meta",
        "isp_stock_locations",
        "isp_inventory_vendors",
        "isp_task_approvals",
        "isp_ticket_escalations",
        "isp_ticket_escalation_rules",
        "isp_apps_settings",
    ):
        op.drop_table(name)
