"""Add Razorpay Checkout correlation fields to ``payments`` -- flat-plan
billing paid online via Razorpay's Checkout widget (UPI/card/netbanking).

``razorpay_order_id`` is this row's own correlation key BEFORE any
``provider_payment_id`` is known: ``POST /billing/checkout`` creates a
Razorpay Order server-side (no charge attempt yet) and hands its id to the
frontend's Checkout widget; the customer's real payment outcome is only
learned later, from a signature-verified ``POST /webhooks/razorpay``
delivery, which resolves the PENDING row by this column when
``provider_payment_id`` isn't set yet (see ``app.domains.billing.webhooks
.process_razorpay_event``). ``razorpay_signature`` is the verified
``X-Razorpay-Signature`` header value from the webhook delivery that
resolved this payment -- a permanent, auditable record that this row's
SUCCEEDED/FAILED status came from a real, cryptographically-verified
webhook, never an unverified client-side callback. Both columns are
nullable and additive -- every pre-existing row (and every payment created
via the pre-existing recurring/e-mandate charge path, which has no
order-first step) is unaffected.

See ``app.domains.billing.models.Payment``'s own docstring for the full
write-up.

Revision ID: 0077_add_razorpay_checkout_fields_to_payments
Revises: 0076_create_monitored_hardware_table
Create Date: 2026-08-09
"""

import sqlalchemy as sa

from alembic import op

revision = "0077_add_razorpay_checkout_fields_to_payments"
down_revision = "0076_create_monitored_hardware_table"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "payments",
        sa.Column("razorpay_order_id", sa.String(255), nullable=True),
    )
    op.add_column(
        "payments",
        sa.Column("razorpay_signature", sa.String(512), nullable=True),
    )
    op.create_index(
        "ix_payments_razorpay_order_id",
        "payments",
        ["razorpay_order_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_payments_razorpay_order_id", table_name="payments")
    op.drop_column("payments", "razorpay_signature")
    op.drop_column("payments", "razorpay_order_id")
