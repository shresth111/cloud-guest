"""Create Billing Invoice + Tax/GST tables (BE-013 Part 4: Invoice Engine +
Tax/GST).

Mirrors ``0022``/``0023``/``0024``'s conventions: the ``BaseModel`` column
set (id, created_at, updated_at, soft-delete, audit, version) plus its own
base-model indexes, using the same ``_base_model_columns``/
``_create_base_model_indexes`` helpers (duplicated here, not imported --
Alembic migrations are meant to be self-contained snapshots rather than
depending on other migration modules).

Six new tables, in FK-dependency order:

* ``tax_rates`` -- Super-Admin-managed tax jurisdiction config (no FK).
* ``billing_profiles`` -- one organization's billing address/GSTIN,
  **entirely owned by this domain** (not a column added to
  ``organizations``) -- FK to ``organizations`` (``CASCADE``), unique on
  ``organization_id`` (one profile per organization, ever -- mirrors
  ``licenses``/``subscriptions``' identical one-to-one cardinality). See
  ``app.domains.billing.models.BillingProfile``'s own docstring for the
  full "why a billing-owned table, not an ``Organization`` column
  extension" write-up.
* ``invoice_number_counters`` -- the dedicated, real, DB-level-atomic
  counter table backing every sequential document number this part
  generates (no FK) -- see
  ``app.domains.billing.number_generator``'s own module docstring for the
  exact ``INSERT ... ON CONFLICT DO UPDATE ... RETURNING`` concurrency
  mechanism this table's ``counter_key`` unique constraint enables.
* ``invoices`` -- FK to ``organizations`` (``CASCADE``), ``subscriptions``
  (``SET NULL``, nullable), ``payments`` (``SET NULL``, nullable, set once
  a real payment settles it). ``invoice_number`` is **unique, not
  nullable**. Tax breakdown stored as three typed, precisely-named
  columns (``cgst_amount``/``sgst_amount``/``igst_amount``) rather than a
  variable-cardinality child table -- see
  ``app.domains.billing.models.Invoice``'s own docstring for the full
  "three typed columns, not a separate InvoiceTaxLine table" write-up.
  ``billing_snapshot`` (JSONB) is a frozen copy of the organization's
  ``BillingProfile`` at issue time -- never re-read from that table
  afterward.
* ``invoice_items`` -- FK to ``invoices`` (``CASCADE``).
* ``credit_debit_notes`` -- one discriminated table for both credit and
  debit notes (``note_type``) -- FK to ``invoices`` (``CASCADE``).
  ``note_number`` is **unique, not nullable**, generated from its own,
  independent counter-key sequence per ``note_type`` -- never the invoice
  sequence, never shared between credit and debit notes.

No RBAC schema change -- this part's only edit to ``app.domains.rbac`` is
additive ``AuditAction`` enum values (``enums.py``), no migration needed.
``PermissionModule.INVOICES`` was already seeded since BE-004 (create/
read/update/delete/export/approve/manage); no new permission group/action/
scope row is seeded by this part. No ``alembic/env.py`` edit was needed
either -- that file already imports ``app.domains.billing.models`` as a
whole module, so these six new classes (defined in that same
``models.py``) are registered on ``Base.metadata`` automatically.

Revision ID: 0025_create_billing_invoice_tax_tables
Revises: 0024_create_billing_payment_tables
Create Date: 2026-07-19
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0025_create_billing_invoice_tax_tables"
down_revision = "0024_create_billing_payment_tables"
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
    # -- tax_rates --------------------------------------------------------------
    op.create_table(
        "tax_rates",
        *_base_model_columns(),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("tax_type", sa.String(20), nullable=False),
        sa.Column("rate_percentage", sa.Numeric(5, 2), nullable=False),
        sa.Column("country_code", sa.String(2), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    _create_base_model_indexes("tax_rates")
    op.create_index("ix_tax_rates_country_code", "tax_rates", ["country_code"])
    op.create_index("ix_tax_rates_tax_type", "tax_rates", ["tax_type"])
    op.create_index("ix_tax_rates_is_active", "tax_rates", ["is_active"])

    # -- billing_profiles ---------------------------------------------------------
    op.create_table(
        "billing_profiles",
        *_base_model_columns(),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("billing_name", sa.String(200), nullable=False),
        sa.Column("billing_address_line1", sa.String(255), nullable=False),
        sa.Column("billing_address_line2", sa.String(255), nullable=True),
        sa.Column("billing_city", sa.String(100), nullable=False),
        sa.Column("billing_state", sa.String(100), nullable=False),
        sa.Column("billing_country", sa.String(2), nullable=False),
        sa.Column("billing_postal_code", sa.String(20), nullable=False),
        sa.Column("gst_identifier", sa.String(20), nullable=True),
        sa.Column(
            "tax_exempt", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_billing_profiles_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "organization_id", name="uq_billing_profiles_organization_id"
        ),
    )
    _create_base_model_indexes("billing_profiles")
    op.create_index(
        "ix_billing_profiles_organization_id",
        "billing_profiles",
        ["organization_id"],
        unique=True,
    )
    op.create_index(
        "ix_billing_profiles_billing_country", "billing_profiles", ["billing_country"]
    )

    # -- invoice_number_counters ----------------------------------------------------
    op.create_table(
        "invoice_number_counters",
        *_base_model_columns(),
        sa.Column("counter_key", sa.String(50), nullable=False),
        sa.Column("last_value", sa.Integer(), nullable=False, server_default="0"),
        sa.UniqueConstraint(
            "counter_key", name="uq_invoice_number_counters_counter_key"
        ),
    )
    _create_base_model_indexes("invoice_number_counters")
    op.create_index(
        "ix_invoice_number_counters_counter_key",
        "invoice_number_counters",
        ["counter_key"],
        unique=True,
    )

    # -- invoices -----------------------------------------------------------------
    op.create_table(
        "invoices",
        *_base_model_columns(),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("subscription_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("payment_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("invoice_number", sa.String(50), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("issue_date", sa.DateTime(timezone=True), nullable=False),
        sa.Column("due_date", sa.DateTime(timezone=True), nullable=False),
        sa.Column("subtotal", sa.Numeric(12, 2), nullable=False),
        sa.Column("cgst_amount", sa.Numeric(12, 2), nullable=False, server_default="0"),
        sa.Column("sgst_amount", sa.Numeric(12, 2), nullable=False, server_default="0"),
        sa.Column("igst_amount", sa.Numeric(12, 2), nullable=False, server_default="0"),
        sa.Column("tax_amount", sa.Numeric(12, 2), nullable=False, server_default="0"),
        sa.Column(
            "tax_rate_percentage", sa.Numeric(5, 2), nullable=False, server_default="0"
        ),
        sa.Column("total_amount", sa.Numeric(12, 2), nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("billing_snapshot", postgresql.JSONB(), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_invoices_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["subscription_id"],
            ["subscriptions.id"],
            name="fk_invoices_subscription_id_subscriptions",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["payment_id"],
            ["payments.id"],
            name="fk_invoices_payment_id_payments",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint("invoice_number", name="uq_invoices_invoice_number"),
    )
    _create_base_model_indexes("invoices")
    op.create_index("ix_invoices_organization_id", "invoices", ["organization_id"])
    op.create_index("ix_invoices_subscription_id", "invoices", ["subscription_id"])
    op.create_index("ix_invoices_payment_id", "invoices", ["payment_id"])
    op.create_index(
        "ix_invoices_invoice_number", "invoices", ["invoice_number"], unique=True
    )
    op.create_index("ix_invoices_status", "invoices", ["status"])
    op.create_index("ix_invoices_issue_date", "invoices", ["issue_date"])
    op.create_index("ix_invoices_due_date", "invoices", ["due_date"])

    # -- invoice_items --------------------------------------------------------------
    op.create_table(
        "invoice_items",
        *_base_model_columns(),
        sa.Column("invoice_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("description", sa.String(500), nullable=False),
        sa.Column("quantity", sa.Numeric(12, 2), nullable=False, server_default="1"),
        sa.Column("unit_price", sa.Numeric(12, 2), nullable=False),
        sa.Column("amount", sa.Numeric(12, 2), nullable=False),
        sa.ForeignKeyConstraint(
            ["invoice_id"],
            ["invoices.id"],
            name="fk_invoice_items_invoice_id_invoices",
            ondelete="CASCADE",
        ),
    )
    _create_base_model_indexes("invoice_items")
    op.create_index("ix_invoice_items_invoice_id", "invoice_items", ["invoice_id"])

    # -- credit_debit_notes -----------------------------------------------------------
    op.create_table(
        "credit_debit_notes",
        *_base_model_columns(),
        sa.Column("invoice_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("note_type", sa.String(10), nullable=False),
        sa.Column("note_number", sa.String(50), nullable=False),
        sa.Column("amount", sa.Numeric(12, 2), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["invoice_id"],
            ["invoices.id"],
            name="fk_credit_debit_notes_invoice_id_invoices",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("note_number", name="uq_credit_debit_notes_note_number"),
    )
    _create_base_model_indexes("credit_debit_notes")
    op.create_index(
        "ix_credit_debit_notes_invoice_id", "credit_debit_notes", ["invoice_id"]
    )
    op.create_index(
        "ix_credit_debit_notes_note_type", "credit_debit_notes", ["note_type"]
    )
    op.create_index(
        "ix_credit_debit_notes_note_number",
        "credit_debit_notes",
        ["note_number"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_credit_debit_notes_note_number", table_name="credit_debit_notes")
    op.drop_index("ix_credit_debit_notes_note_type", table_name="credit_debit_notes")
    op.drop_index("ix_credit_debit_notes_invoice_id", table_name="credit_debit_notes")
    _drop_base_model_indexes("credit_debit_notes")
    op.drop_table("credit_debit_notes")

    op.drop_index("ix_invoice_items_invoice_id", table_name="invoice_items")
    _drop_base_model_indexes("invoice_items")
    op.drop_table("invoice_items")

    op.drop_index("ix_invoices_due_date", table_name="invoices")
    op.drop_index("ix_invoices_issue_date", table_name="invoices")
    op.drop_index("ix_invoices_status", table_name="invoices")
    op.drop_index("ix_invoices_invoice_number", table_name="invoices")
    op.drop_index("ix_invoices_payment_id", table_name="invoices")
    op.drop_index("ix_invoices_subscription_id", table_name="invoices")
    op.drop_index("ix_invoices_organization_id", table_name="invoices")
    _drop_base_model_indexes("invoices")
    op.drop_table("invoices")

    op.drop_index(
        "ix_invoice_number_counters_counter_key",
        table_name="invoice_number_counters",
    )
    _drop_base_model_indexes("invoice_number_counters")
    op.drop_table("invoice_number_counters")

    op.drop_index("ix_billing_profiles_billing_country", table_name="billing_profiles")
    op.drop_index("ix_billing_profiles_organization_id", table_name="billing_profiles")
    _drop_base_model_indexes("billing_profiles")
    op.drop_table("billing_profiles")

    op.drop_index("ix_tax_rates_is_active", table_name="tax_rates")
    op.drop_index("ix_tax_rates_tax_type", table_name="tax_rates")
    op.drop_index("ix_tax_rates_country_code", table_name="tax_rates")
    _drop_base_model_indexes("tax_rates")
    op.drop_table("tax_rates")
