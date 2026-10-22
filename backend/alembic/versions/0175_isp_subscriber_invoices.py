"""ISP ADDENDUM_03 Part B: subscriber invoices, circuit ids.

Additive and confined to the ISP partner domain's OWN tables (created by
0173/0174). No pre-ISP table is touched:

- ``isp_subscribers``: + circuit_id (backfilled per ISP in created_at order,
  then NOT NULL + unique per ISP), zone_id, contact/buyer fields,
  reminder_opt_in.
- ``isp_invoices``: + subscriber_id, bill_to_username, circuit_id_snapshot;
  the ``bill_to`` check also admits ``bill_to_kind='subscriber'``.
- ``isp_invoice_lines``: + package_id.
- ``isp_payments``: + subscriber_id, coupon_batch_id.
- ``isp_invoice_sequences``: one ``(isp, 'circuit', '----')`` row per ISP
  that already has subscribers, so new circuit ids continue after the
  backfill.

Downgrade refuses while any subscriber invoice exists (the old check
constraint could not be restored without deleting GST documents).

Revision ID: 0175_isp_subscriber_invoices
Revises: 0174_isp_plans_coupons
Create Date: 2026-10-22
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0175_isp_subscriber_invoices"
down_revision = "0174_isp_plans_coupons"
branch_labels = None
depends_on = None

_OLD_CHECK = "bill_to_kind = 'customer' AND customer_organization_id IS NOT NULL"
_NEW_CHECK = (
    "bill_to_kind = 'customer' AND customer_organization_id IS NOT NULL"
    " OR bill_to_kind = 'subscriber' AND subscriber_id IS NOT NULL"
)


def upgrade() -> None:
    # ---- isp_subscribers -------------------------------------------------
    op.add_column(
        "isp_subscribers", sa.Column("circuit_id", sa.Integer(), nullable=True)
    )
    op.add_column("isp_subscribers", sa.Column("zone_id", sa.UUID(), nullable=True))
    for name, type_ in (
        ("first_name", sa.String(length=100)),
        ("last_name", sa.String(length=100)),
        ("phone", sa.String(length=20)),
        ("email", sa.String(length=255)),
        ("gstin", sa.String(length=15)),
        ("address", sa.Text()),
        ("state_code", sa.String(length=2)),
    ):
        op.add_column("isp_subscribers", sa.Column(name, type_, nullable=True))
    op.add_column(
        "isp_subscribers",
        sa.Column(
            "reminder_opt_in",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text(
                """'{"email": true, "sms": false, "whatsapp": false}'::jsonb"""
            ),
            nullable=False,
        ),
    )
    op.create_foreign_key(
        op.f("fk_isp_subscribers_zone_id_isp_zones"),
        "isp_subscribers",
        "isp_zones",
        ["zone_id"],
        ["id"],
    )
    op.execute(
        """
        UPDATE isp_subscribers s SET circuit_id = n.rn
        FROM (
            SELECT id, row_number() OVER (
                PARTITION BY isp_organization_id ORDER BY created_at, id
            ) AS rn
            FROM isp_subscribers
        ) n
        WHERE n.id = s.id
        """
    )
    op.execute(
        """
        INSERT INTO isp_invoice_sequences
            (id, isp_organization_id, series, fy, next_value,
             created_at, updated_at, is_deleted, version)
        SELECT gen_random_uuid(), isp_organization_id, 'circuit', '----',
               max(circuit_id) + 1, now(), now(), false, 1
        FROM isp_subscribers
        GROUP BY isp_organization_id
        ON CONFLICT (isp_organization_id, series, fy) DO NOTHING
        """
    )
    op.alter_column("isp_subscribers", "circuit_id", nullable=False)
    op.create_index(
        "uq_isp_subscribers_circuit",
        "isp_subscribers",
        ["isp_organization_id", "circuit_id"],
        unique=True,
    )

    # ---- isp_invoices ----------------------------------------------------
    op.add_column("isp_invoices", sa.Column("subscriber_id", sa.UUID(), nullable=True))
    op.add_column(
        "isp_invoices",
        sa.Column("bill_to_username", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "isp_invoices", sa.Column("circuit_id_snapshot", sa.Integer(), nullable=True)
    )
    op.create_foreign_key(
        op.f("fk_isp_invoices_subscriber_id_isp_subscribers"),
        "isp_invoices",
        "isp_subscribers",
        ["subscriber_id"],
        ["id"],
    )
    op.create_index("ix_isp_invoices_subscriber", "isp_invoices", ["subscriber_id"])
    op.drop_constraint(op.f("ck_isp_invoices_bill_to"), "isp_invoices", type_="check")
    op.create_check_constraint(
        op.f("ck_isp_invoices_bill_to"), "isp_invoices", _NEW_CHECK
    )

    # ---- isp_invoice_lines -----------------------------------------------
    op.add_column(
        "isp_invoice_lines", sa.Column("package_id", sa.UUID(), nullable=True)
    )
    op.create_foreign_key(
        op.f("fk_isp_invoice_lines_package_id_isp_packages"),
        "isp_invoice_lines",
        "isp_packages",
        ["package_id"],
        ["id"],
    )

    # ---- isp_payments ----------------------------------------------------
    op.add_column("isp_payments", sa.Column("subscriber_id", sa.UUID(), nullable=True))
    op.add_column(
        "isp_payments", sa.Column("coupon_batch_id", sa.UUID(), nullable=True)
    )
    op.create_foreign_key(
        op.f("fk_isp_payments_subscriber_id_isp_subscribers"),
        "isp_payments",
        "isp_subscribers",
        ["subscriber_id"],
        ["id"],
    )
    op.create_foreign_key(
        op.f("fk_isp_payments_coupon_batch_id_isp_coupon_batches"),
        "isp_payments",
        "isp_coupon_batches",
        ["coupon_batch_id"],
        ["id"],
    )
    op.create_index("ix_isp_payments_subscriber", "isp_payments", ["subscriber_id"])


def downgrade() -> None:
    bind = op.get_bind()
    n = bind.execute(
        sa.text("SELECT count(*) FROM isp_invoices WHERE bill_to_kind = 'subscriber'")
    ).scalar_one()
    if n:
        raise RuntimeError(
            f"refusing to downgrade: {n} subscriber invoice(s) exist "
            "(GST documents are never deleted; ops must decide)"
        )
    op.drop_index("ix_isp_payments_subscriber", table_name="isp_payments")
    op.drop_constraint(
        op.f("fk_isp_payments_coupon_batch_id_isp_coupon_batches"),
        "isp_payments",
        type_="foreignkey",
    )
    op.drop_constraint(
        op.f("fk_isp_payments_subscriber_id_isp_subscribers"),
        "isp_payments",
        type_="foreignkey",
    )
    op.drop_column("isp_payments", "coupon_batch_id")
    op.drop_column("isp_payments", "subscriber_id")

    op.drop_constraint(
        op.f("fk_isp_invoice_lines_package_id_isp_packages"),
        "isp_invoice_lines",
        type_="foreignkey",
    )
    op.drop_column("isp_invoice_lines", "package_id")

    op.drop_constraint(op.f("ck_isp_invoices_bill_to"), "isp_invoices", type_="check")
    op.create_check_constraint(
        op.f("ck_isp_invoices_bill_to"), "isp_invoices", _OLD_CHECK
    )
    op.drop_index("ix_isp_invoices_subscriber", table_name="isp_invoices")
    op.drop_constraint(
        op.f("fk_isp_invoices_subscriber_id_isp_subscribers"),
        "isp_invoices",
        type_="foreignkey",
    )
    op.drop_column("isp_invoices", "circuit_id_snapshot")
    op.drop_column("isp_invoices", "bill_to_username")
    op.drop_column("isp_invoices", "subscriber_id")

    op.execute("DELETE FROM isp_invoice_sequences WHERE series = 'circuit'")
    op.drop_index("uq_isp_subscribers_circuit", table_name="isp_subscribers")
    op.drop_constraint(
        op.f("fk_isp_subscribers_zone_id_isp_zones"),
        "isp_subscribers",
        type_="foreignkey",
    )
    for name in (
        "reminder_opt_in",
        "state_code",
        "address",
        "gstin",
        "email",
        "phone",
        "last_name",
        "first_name",
        "zone_id",
        "circuit_id",
    ):
        op.drop_column("isp_subscribers", name)
