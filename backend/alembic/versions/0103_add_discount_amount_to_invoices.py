"""``discount_amount`` on ``invoices``. Additive-only, one column, one table.

A coupon redeemed at signup was, until now, *consumed but never granted*.
``CouponService.apply_coupon`` really does run at subscription creation: it
re-validates the code, computes the discount, writes a ``CouponUsage`` row
with ``discount_amount_applied`` frozen at that value, increments the
coupon's ``current_uses``, and stamps ``Subscription.applied_coupon_id``.
Every one of those is a real, committed write. What never happened is the
only part the customer can see: no invoice ever subtracted the amount.
``InvoiceService.generate_invoice_for_subscription`` computed
``subtotal = compute_renewal_charge_amount(plan)`` -- the plan's bare
``base_price`` -- and never read ``applied_coupon_id`` or ``CouponUsage``
at all. So the coupon burned a use, hit its ``max_uses`` ceiling for
everyone behind it, and the organization was billed the undiscounted
amount.

**Why a column and not just a smaller ``subtotal``.** Quietly netting the
discount into ``subtotal`` would balance the arithmetic and produce a
legally wrong invoice: under CGST Act s.15(3)(a) a discount given at or
before the time of supply and *recorded in the invoice* is excluded from
taxable value, which presumes the invoice records it as its own line. A
customer comparing a ``5,000`` plan against a ``4,500`` subtotal has no
way to see that a coupon was the difference, and neither does an auditor.
The discount is a distinct fact about the transaction and gets a distinct
column, exactly as ``cgst_amount``/``sgst_amount``/``igst_amount`` are
three real columns rather than one lumped "tax" (see ``models.Invoice``'s
own write-up of that same judgment).

**Tax is computed on the discounted value, not the gross.** With this
column present the invoice reads ``subtotal`` (gross, and still the line
item's own amount) minus ``discount_amount`` = the taxable value that
``compute_tax_breakdown`` is handed, then ``+ tax_amount`` =
``total_amount``. That ordering is the s.15(3)(a) treatment; taxing the
gross and then deducting would over-collect GST on money the customer
never paid.

**NOT NULL with a server_default of ``0``, matching the sibling money
columns.** ``cgst_amount``/``sgst_amount``/``igst_amount``/``tax_amount``
are all ``NOT NULL DEFAULT 0`` on this same table, and zero is the honest
value for every existing row: no invoice ever issued has carried a
discount, because no code path could produce one. The backfill is exactly
the default, and a nullable column would invent an "unknown discount"
state that nothing in the domain means or handles.

**Reversibility.** ``downgrade`` drops the column. Lossless for behaviour
-- without it the domain has no way to express a discount, which is the
pre-migration state. It discards the record of which invoices were
discounted while leaving ``subtotal``/``tax_amount``/``total_amount``
internally consistent as issued, since those are stored values and are not
recomputed from the dropped column.

Revision ID: 0103_add_discount_amount_to_invoices
Revises: 0102_add_device_push_columns_to_vlans
Create Date: 2026-09-02
"""

import sqlalchemy as sa

from alembic import op

revision = "0103_add_discount_amount_to_invoices"
down_revision = "0102_add_device_push_columns_to_vlans"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "invoices",
        sa.Column(
            "discount_amount",
            sa.Numeric(precision=12, scale=2),
            nullable=False,
            server_default="0",
        ),
    )


def downgrade() -> None:
    op.drop_column("invoices", "discount_amount")
