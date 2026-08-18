"""Create Channel Partner domain table: channel_partners.

Mirrors ``0082_create_quotations_tables``'s conventions: the table gets the
``BaseModel`` column set (id, created_at, updated_at, soft-delete, audit,
version) plus its own base-model indexes, using the same
``_base_model_columns``/``_create_base_model_indexes`` helpers (duplicated
here, not imported -- Alembic migrations in this repo are meant to be
self-contained snapshots rather than depending on other migration
modules).

A brand-new domain: a Master console operator onboards a channel/reseller
partner by hand and the system sends them a real welcome message (SMS
always, email when provided) in the same action -- see
``app.domains.channel_partner.models``'s own module docstring. No
``organization_id`` FK -- a channel partner is Wyfy Guest's own business
relationship, never scoped to a customer Organization, the identical shape
``quotations`` already established.

``channel_partners`` -- one row per onboarded partner.
* ``name``/``phone``/``address``/``city``/``gst_number`` -- required.
  ``phone`` is stored already-normalized to E.164 (``+91...``) by the
  request schema's own validator; ``gst_number`` is stored uppercased and
  validated against the real 15-character GSTIN shape.
* ``email`` -- optional; when present, a welcome email is sent in addition
  to the welcome SMS.
* ``gst_number`` -- unique. A GSTIN is a real government-issued tax ID,
  legally unique per registered business, so a second partner row with the
  same GSTIN is always a data-entry mistake.
* ``status`` -- active/inactive, indexed, independent of ``is_deleted``.
  No API surface toggles this in v1 -- the column exists now so a future
  deactivate/reactivate action never needs its own migration.
* ``welcome_sms_sent_at``/``welcome_sms_error``/``welcome_email_sent_at``/
  ``welcome_email_error`` -- delivery outcome per channel, nullable.
  Mirrors ``quotations.sent_at``/``email_error`` exactly, just doubled for
  SMS + email.

No RBAC FK follow-up migration is needed (mirrors
``0082_create_quotations_tables``'s own note): this table is not
referenced by any RBAC scope column (``PermissionModule.CHANNEL_PARTNERS``
is seeded at ``ScopeType.GLOBAL``, no per-row scope column required).

Revision ID: 0086_create_channel_partners_table
Revises: 0085_add_portal_pin_login
Create Date: 2026-08-18
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0086_create_channel_partners_table"
down_revision = "0085_add_portal_pin_login"
branch_labels = None
depends_on = None


def _base_model_columns() -> list[sa.Column]:
    """Columns provided by ``app.database.base.BaseModel`` for every table."""
    return [
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "is_deleted", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
    ]


def _create_base_model_indexes(table_name: str) -> None:
    op.create_index(f"ix_{table_name}_created_at", table_name, ["created_at"])
    op.create_index(f"ix_{table_name}_deleted_at", table_name, ["deleted_at"])
    op.create_index(f"ix_{table_name}_is_deleted", table_name, ["is_deleted"])
    op.create_index(f"ix_{table_name}_created_by", table_name, ["created_by"])
    op.create_index(f"ix_{table_name}_updated_by", table_name, ["updated_by"])


def _drop_base_model_indexes(table_name: str) -> None:
    op.drop_index(f"ix_{table_name}_updated_by", table_name=table_name)
    op.drop_index(f"ix_{table_name}_created_by", table_name=table_name)
    op.drop_index(f"ix_{table_name}_is_deleted", table_name=table_name)
    op.drop_index(f"ix_{table_name}_deleted_at", table_name=table_name)
    op.drop_index(f"ix_{table_name}_created_at", table_name=table_name)


def upgrade() -> None:
    op.create_table(
        "channel_partners",
        *_base_model_columns(),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("phone", sa.String(20), nullable=False),
        sa.Column("email", sa.String(255), nullable=True),
        sa.Column("address", sa.Text(), nullable=False),
        sa.Column("city", sa.String(100), nullable=False),
        sa.Column("gst_number", sa.String(15), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("welcome_sms_sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("welcome_sms_error", sa.Text(), nullable=True),
        sa.Column("welcome_email_sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("welcome_email_error", sa.Text(), nullable=True),
        sa.UniqueConstraint("gst_number", name="uq_channel_partners_gst_number"),
    )
    _create_base_model_indexes("channel_partners")
    op.create_index("ix_channel_partners_status", "channel_partners", ["status"])
    op.create_index(
        "ix_channel_partners_gst_number",
        "channel_partners",
        ["gst_number"],
        unique=True,
    )
    op.create_index("ix_channel_partners_phone", "channel_partners", ["phone"])


def downgrade() -> None:
    op.drop_index("ix_channel_partners_phone", table_name="channel_partners")
    op.drop_index("ix_channel_partners_gst_number", table_name="channel_partners")
    op.drop_index("ix_channel_partners_status", table_name="channel_partners")
    _drop_base_model_indexes("channel_partners")
    op.drop_table("channel_partners")
