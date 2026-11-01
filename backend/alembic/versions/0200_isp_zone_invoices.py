"""FINISH: a zone can be billed through the regular invoice engine.

* ``ck_isp_invoices_bill_to`` additionally admits ``bill_to_kind='zone'`` with
  ``zone_id`` set (customer + subscriber rows keep exactly their old rule).
* ``isp_zone_settlements.invoice_id`` links a FRANCHISE-2 ``ZS/`` settlement to
  the GST tax invoice issued for it (the ZS number stays on the settlement
  for audit).

``downgrade`` restores the old check (it fails while zone invoices exist, by
design) and drops the link column.

Revision ID: 0200_isp_zone_invoices
Revises: 0199_isp_comms_2b
Create Date: 2026-11-01
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0200_isp_zone_invoices"
down_revision = "0199_isp_comms_2b"
branch_labels = None
depends_on = None

_OLD_CHECK = (
    "bill_to_kind = 'customer' AND customer_organization_id IS NOT NULL"
    " OR bill_to_kind = 'subscriber' AND subscriber_id IS NOT NULL"
)
_NEW_CHECK = _OLD_CHECK + " OR bill_to_kind = 'zone' AND zone_id IS NOT NULL"


def upgrade() -> None:
    op.drop_constraint(op.f("ck_isp_invoices_bill_to"), "isp_invoices", type_="check")
    op.create_check_constraint(
        op.f("ck_isp_invoices_bill_to"), "isp_invoices", _NEW_CHECK
    )
    op.add_column(
        "isp_zone_settlements",
        sa.Column(
            "invoice_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("isp_invoices.id"),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_isp_zone_settlements_invoice", "isp_zone_settlements", ["invoice_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_isp_zone_settlements_invoice", "isp_zone_settlements")
    op.drop_column("isp_zone_settlements", "invoice_id")
    op.drop_constraint(op.f("ck_isp_invoices_bill_to"), "isp_invoices", type_="check")
    op.create_check_constraint(
        op.f("ck_isp_invoices_bill_to"), "isp_invoices", _OLD_CHECK
    )
