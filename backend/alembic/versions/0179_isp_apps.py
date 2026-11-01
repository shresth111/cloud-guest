"""ISP J16 Apps (ADDENDUM_05, JAZE-5): helpdesk, field tasks, announcements,
discount codes, light inventory, leads.

Additive only: thirteen new ``isp_*`` tables. No pre-existing table is
touched. ``downgrade`` drops exactly these.

Revision ID: 0179_isp_apps
Revises: 0178_merge_integ_parity_settings
Create Date: 2026-11-01
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0179_isp_apps"
down_revision = "0179_isp_finance_jaze4"
branch_labels = None
depends_on = None

_BASE_INDEXED = ("created_at", "deleted_at", "is_deleted", "created_by", "updated_by")
_TS = sa.DateTime(timezone=True)


def _uuid(name: str, *args: object, **kw: object) -> sa.Column:
    return sa.Column(name, postgresql.UUID(as_uuid=True), *args, **kw)


def _fk(
    name: str, target: str, *, nullable: bool = False, ondelete: str | None = None
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


def _s(name: str, n: int, nullable: bool = True) -> sa.Column:
    return sa.Column(name, sa.String(n), nullable=nullable)


def _text(name: str) -> sa.Column:
    return sa.Column(name, sa.Text(), nullable=True)


def _ts(name: str, nullable: bool = True) -> sa.Column:
    return sa.Column(name, _TS, nullable=nullable)


def _bool(name: str, default: bool) -> sa.Column:
    return sa.Column(
        name,
        sa.Boolean(),
        nullable=False,
        server_default=sa.text("true" if default else "false"),
    )


def _jsonb(name: str, default: str | None, nullable: bool = False) -> sa.Column:
    kw = {"server_default": sa.text(default)} if default else {}
    return sa.Column(name, postgresql.JSONB(), nullable=nullable, **kw)


_ISP = ("isp_organization_id", "organizations.id")

TABLES: list[tuple[str, list[sa.Column]]] = [
    (
        "isp_apps_counters",
        [
            _fk(*_ISP),
            _s("kind", 16, False),
            sa.Column("value", sa.Integer(), nullable=False, server_default="0"),
        ],
    ),
    (
        "isp_ticket_types",
        [
            _fk(*_ISP),
            _s("name", 100, False),
            sa.Column("sla_minutes", sa.Integer(), nullable=True),
            _bool("requires_rfo", True),
            _bool("active", True),
            sa.Column("sort_order", sa.Integer(), nullable=False, server_default="0"),
        ],
    ),
    (
        "isp_tickets",
        [
            _fk(*_ISP),
            _fk("customer_organization_id", "organizations.id"),
            _fk("subscriber_id", "isp_subscribers.id", nullable=True),
            sa.Column("number", sa.Integer(), nullable=False),
            _fk("type_id", "isp_ticket_types.id", nullable=True),
            _s("subject", 200, False),
            _text("description"),
            _s("source", 12, False),
            _s("priority", 8, False),
            _s("status", 12, False),
            _fk("assignee_user_id", "users.id", nullable=True),
            _s("rfo_reason", 16),
            _text("resolution_note"),
            sa.Column("sla_minutes", sa.Integer(), nullable=True),
            _ts("opened_at", False),
            _ts("due_at"),
            _ts("first_response_at"),
            _ts("resolved_at"),
            _ts("closed_at"),
            _fk("raised_by_user_id", "users.id", nullable=True),
        ],
    ),
    (
        "isp_ticket_events",
        [
            _fk("ticket_id", "isp_tickets.id", ondelete="CASCADE"),
            _s("kind", 10, False),
            _text("body"),
            _jsonb("detail", "'{}'::jsonb"),
            _fk("actor_user_id", "users.id", nullable=True),
            _ts("at", False),
        ],
    ),
    (
        "isp_leads",
        [
            _fk(*_ISP),
            sa.Column("number", sa.Integer(), nullable=False),
            _s("name", 200, False),
            _s("phone", 20),
            _s("email", 255),
            _text("address"),
            _s("city", 100),
            sa.Column("latitude", sa.Float(), nullable=True),
            sa.Column("longitude", sa.Float(), nullable=True),
            _s("source", 10, False),
            _s("status", 20, False),
            _fk("customer_organization_id", "organizations.id", nullable=True),
            _fk("interested_package_id", "isp_packages.id", nullable=True),
            _fk("assignee_user_id", "users.id", nullable=True),
            _text("feasibility_note"),
            _s("dropped_reason", 255),
            _text("notes"),
            _fk("converted_subscriber_id", "isp_subscribers.id", nullable=True),
            _ts("converted_at"),
        ],
    ),
    (
        "isp_field_tasks",
        [
            _fk(*_ISP),
            _fk("customer_organization_id", "organizations.id", nullable=True),
            _fk("subscriber_id", "isp_subscribers.id", nullable=True),
            _fk("ticket_id", "isp_tickets.id", nullable=True),
            _fk("lead_id", "isp_leads.id", nullable=True),
            _s("kind", 10, False),
            _s("title", 200, False),
            _text("notes"),
            _text("address"),
            sa.Column("latitude", sa.Float(), nullable=True),
            sa.Column("longitude", sa.Float(), nullable=True),
            _ts("scheduled_at"),
            _s("status", 12, False),
            _fk("assignee_user_id", "users.id", nullable=True),
            _ts("started_at"),
            _ts("completed_at"),
            _text("completion_note"),
            _s("rejected_reason", 255),
        ],
    ),
    (
        "isp_announcements",
        [
            _fk(*_ISP),
            _s("title", 150, False),
            sa.Column("body", sa.Text(), nullable=False),
            _s("audience", 10, False),
            _jsonb("customer_ids", "'[]'::jsonb"),
            _bool("send_email", True),
            _s("status", 8, False),
            _ts("sent_at"),
            _fk("sent_by_user_id", "users.id", nullable=True),
        ],
    ),
    (
        "isp_announcement_recipients",
        [
            _fk("announcement_id", "isp_announcements.id", ondelete="CASCADE"),
            _fk("customer_organization_id", "organizations.id"),
            _s("email", 255),
            _s("phone", 20),
            _s("email_status", 8, False),
            _uuid("delivery_id", nullable=True),
        ],
    ),
    (
        "isp_discount_codes",
        [
            _fk(*_ISP),
            _s("code", 32, False),
            _s("description", 200),
            _s("kind", 8, False),
            sa.Column("value", sa.BigInteger(), nullable=False),
            sa.Column("max_discount_paise", sa.BigInteger(), nullable=True),
            sa.Column("min_amount_paise", sa.BigInteger(), nullable=True),
            sa.Column("max_uses", sa.Integer(), nullable=True),
            sa.Column("used_count", sa.Integer(), nullable=False, server_default="0"),
            _ts("valid_from"),
            _ts("valid_until"),
            _jsonb("package_ids", None, nullable=True),
            _bool("active", True),
        ],
    ),
    (
        "isp_discount_redemptions",
        [
            _fk("discount_id", "isp_discount_codes.id"),
            _fk(*_ISP),
            _fk("customer_organization_id", "organizations.id"),
            _fk("subscriber_id", "isp_subscribers.id", nullable=True),
            _fk("invoice_id", "isp_invoices.id", nullable=True),
            sa.Column("amount_paise", sa.BigInteger(), nullable=False),
            _ts("at", False),
        ],
    ),
    (
        "isp_inventory_items",
        [
            _fk(*_ISP),
            _s("name", 120, False),
            _s("sku", 40, False),
            _s("category", 10, False),
            _text("notes"),
        ],
    ),
    (
        "isp_inventory_units",
        [
            _fk(*_ISP),
            _fk("item_id", "isp_inventory_items.id"),
            _s("serial", 64, False),
            _s("mac", 17),
            _s("state", 10, False),
            _fk("customer_organization_id", "organizations.id", nullable=True),
            _fk("subscriber_id", "isp_subscribers.id", nullable=True),
            _ts("state_changed_at", False),
            _text("note"),
        ],
    ),
    (
        "isp_inventory_movements",
        [
            _fk("unit_id", "isp_inventory_units.id", ondelete="CASCADE"),
            _s("from_state", 10),
            _s("to_state", 10, False),
            _fk("customer_organization_id", "organizations.id", nullable=True),
            _fk("subscriber_id", "isp_subscribers.id", nullable=True),
            _text("note"),
            _fk("actor_user_id", "users.id", nullable=True),
            _ts("at", False),
        ],
    ),
]

_ACTIVE = sa.text("deleted_at IS NULL")

#: (name, table, columns, unique, partial-where)
INDEXES: list[tuple[str, str, list[str], bool, object]] = [
    (
        "uq_isp_apps_counters_isp_kind",
        "isp_apps_counters",
        ["isp_organization_id", "kind"],
        True,
        None,
    ),
    (
        "uq_isp_ticket_types_isp_name",
        "isp_ticket_types",
        ["isp_organization_id", "name"],
        True,
        _ACTIVE,
    ),
    (
        "uq_isp_tickets_isp_number",
        "isp_tickets",
        ["isp_organization_id", "number"],
        True,
        None,
    ),
    (
        "ix_isp_tickets_isp_status",
        "isp_tickets",
        ["isp_organization_id", "status"],
        False,
        None,
    ),
    (
        "ix_isp_tickets_customer",
        "isp_tickets",
        ["customer_organization_id"],
        False,
        None,
    ),
    ("ix_isp_tickets_subscriber", "isp_tickets", ["subscriber_id"], False, None),
    (
        "ix_isp_tickets_opened",
        "isp_tickets",
        ["isp_organization_id", "opened_at"],
        False,
        None,
    ),
    (
        "ix_isp_ticket_events_ticket",
        "isp_ticket_events",
        ["ticket_id", "at"],
        False,
        None,
    ),
    (
        "uq_isp_leads_isp_number",
        "isp_leads",
        ["isp_organization_id", "number"],
        True,
        None,
    ),
    (
        "ix_isp_leads_isp_status",
        "isp_leads",
        ["isp_organization_id", "status"],
        False,
        None,
    ),
    (
        "ix_isp_field_tasks_isp_status",
        "isp_field_tasks",
        ["isp_organization_id", "status"],
        False,
        None,
    ),
    (
        "ix_isp_field_tasks_assignee",
        "isp_field_tasks",
        ["assignee_user_id"],
        False,
        None,
    ),
    (
        "ix_isp_field_tasks_customer",
        "isp_field_tasks",
        ["customer_organization_id"],
        False,
        None,
    ),
    (
        "ix_isp_announcements_isp",
        "isp_announcements",
        ["isp_organization_id"],
        False,
        None,
    ),
    (
        "ix_isp_announcement_recipients_ann",
        "isp_announcement_recipients",
        ["announcement_id"],
        False,
        None,
    ),
    (
        "uq_isp_discount_codes_isp_code",
        "isp_discount_codes",
        ["isp_organization_id", "code"],
        True,
        _ACTIVE,
    ),
    (
        "ix_isp_discount_redemptions_discount",
        "isp_discount_redemptions",
        ["discount_id"],
        False,
        None,
    ),
    (
        "uq_isp_discount_redemptions_invoice",
        "isp_discount_redemptions",
        ["discount_id", "invoice_id"],
        True,
        sa.text("invoice_id IS NOT NULL"),
    ),
    (
        "uq_isp_inventory_items_isp_sku",
        "isp_inventory_items",
        ["isp_organization_id", "sku"],
        True,
        _ACTIVE,
    ),
    (
        "uq_isp_inventory_units_isp_serial",
        "isp_inventory_units",
        ["isp_organization_id", "serial"],
        True,
        _ACTIVE,
    ),
    (
        "ix_isp_inventory_units_item_state",
        "isp_inventory_units",
        ["item_id", "state"],
        False,
        None,
    ),
    (
        "ix_isp_inventory_units_subscriber",
        "isp_inventory_units",
        ["subscriber_id"],
        False,
        None,
    ),
    (
        "ix_isp_inventory_movements_unit",
        "isp_inventory_movements",
        ["unit_id", "at"],
        False,
        None,
    ),
]


def upgrade() -> None:
    for name, cols in TABLES:
        op.create_table(name, *_base(), *cols)
        for column in _BASE_INDEXED:
            op.create_index(f"ix_{name}_{column}", name, [column])
    for name, table, cols, unique, where in INDEXES:
        kw = {"postgresql_where": where} if where is not None else {}
        op.create_index(name, table, cols, unique=unique, **kw)


def downgrade() -> None:
    for name, _cols in reversed(TABLES):
        op.drop_table(name)
