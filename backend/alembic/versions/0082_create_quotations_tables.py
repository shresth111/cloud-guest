"""Create Quotation domain tables: quotations, quotation_line_items.

Mirrors ``0062_create_demo_requests_table``'s conventions: the table gets
the ``BaseModel`` column set (id, created_at, updated_at, soft-delete,
audit, version) plus its own base-model indexes, using the same
``_base_model_columns``/``_create_base_model_indexes`` helpers (duplicated
here, not imported -- Alembic migrations are meant to be self-contained
snapshots rather than depending on other migration modules).

A brand-new domain: a Master console operator generates a branded PDF
quotation for a prospective/existing client and emails it to them (see
``app.domains.quotation.models``'s own module docstring). No
``organization_id`` FK -- the client is very often a prospect who is not
yet a platform user or member of any organization, the identical shape
``demo_requests`` already established.

``quotations`` -- one row per generated quotation.
* ``quotation_number`` -- unique, human-readable identifier.
* ``status`` -- draft/sent/failed, indexed (the Master console's own
  primary filter, mirroring ``demo_requests.status``'s identical
  reasoning).
* ``client_name``/``client_email``/``client_company_name`` -- required.
* ``subtotal``/``tax_percentage``/``tax_amount``/``total_amount`` -- real
  ``Numeric`` money columns, computed once at creation and stored, never
  recomputed on read -- same discipline ``invoices``'s own tax columns
  already establish.
* ``currency`` -- 3-letter code.
* ``valid_until`` -- required.
* ``notes`` -- nullable free text.
* ``sent_at``/``email_error`` -- delivery outcome, nullable.

``quotation_line_items`` -- one row per quotation line item, FK'd to
``quotations`` with ``ON DELETE CASCADE``, the same shape
``invoice_items`` already establishes for ``invoices``.

No RBAC FK follow-up migration is needed (mirrors
``0062_create_demo_requests_table``'s own note): this table is not
referenced by any RBAC scope column (``PermissionModule.QUOTATIONS`` is
seeded at ``ScopeType.GLOBAL``, no per-row scope column required).

Revision ID: 0082_create_quotations_tables
Revises: 0081_denormalize_organization_id_onto_vouchers
Create Date: 2026-08-14
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0082_create_quotations_tables"
down_revision = "0081_denormalize_organization_id_onto_vouchers"
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
        "quotations",
        *_base_model_columns(),
        sa.Column("quotation_number", sa.String(50), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="draft"),
        sa.Column("client_name", sa.String(255), nullable=False),
        sa.Column("client_email", sa.String(255), nullable=False),
        sa.Column("client_company_name", sa.String(255), nullable=False),
        sa.Column("subtotal", sa.Numeric(12, 2), nullable=False),
        sa.Column(
            "tax_percentage", sa.Numeric(5, 2), nullable=False, server_default="0"
        ),
        sa.Column("tax_amount", sa.Numeric(12, 2), nullable=False, server_default="0"),
        sa.Column("total_amount", sa.Numeric(12, 2), nullable=False),
        sa.Column("currency", sa.String(3), nullable=False, server_default="USD"),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("email_error", sa.Text(), nullable=True),
        sa.UniqueConstraint("quotation_number", name="uq_quotations_quotation_number"),
    )
    _create_base_model_indexes("quotations")
    op.create_index("ix_quotations_status", "quotations", ["status"])
    op.create_index("ix_quotations_client_email", "quotations", ["client_email"])
    op.create_index(
        "ix_quotations_quotation_number",
        "quotations",
        ["quotation_number"],
        unique=True,
    )

    op.create_table(
        "quotation_line_items",
        *_base_model_columns(),
        sa.Column(
            "quotation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("quotations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("description", sa.String(500), nullable=False),
        sa.Column("quantity", sa.Numeric(12, 2), nullable=False, server_default="1"),
        sa.Column("unit_price", sa.Numeric(12, 2), nullable=False),
        sa.Column("amount", sa.Numeric(12, 2), nullable=False),
    )
    _create_base_model_indexes("quotation_line_items")
    op.create_index(
        "ix_quotation_line_items_quotation_id",
        "quotation_line_items",
        ["quotation_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_quotation_line_items_quotation_id", table_name="quotation_line_items"
    )
    _drop_base_model_indexes("quotation_line_items")
    op.drop_table("quotation_line_items")

    op.drop_index("ix_quotations_quotation_number", table_name="quotations")
    op.drop_index("ix_quotations_client_email", table_name="quotations")
    op.drop_index("ix_quotations_status", table_name="quotations")
    _drop_base_model_indexes("quotations")
    op.drop_table("quotations")
