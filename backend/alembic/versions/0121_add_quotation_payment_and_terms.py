"""quotations: payment_terms and terms_and_conditions copy for the PDF.

The quotation PDF printed only a free-text NOTES section; operators asked
for two distinct, generically-worded blocks they can edit per quotation --
"Payment terms" and "Terms & Conditions" -- rather than folding both into
notes. Both are additive and nullable: existing quotations keep rendering
exactly as before (no NOTES-equivalent section printed when NULL).

Revision ID: 0121_add_quotation_payment_and_terms
Revises: 0120_add_content_image_key_to_captive_portal_configs
Create Date: 2026-09-09
"""

import sqlalchemy as sa

from alembic import op

revision = "0121_add_quotation_payment_and_terms"
down_revision = "0120_add_content_image_key_to_captive_portal_configs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "quotations",
        sa.Column("payment_terms", sa.Text(), nullable=True),
    )
    op.add_column(
        "quotations",
        sa.Column("terms_and_conditions", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("quotations", "terms_and_conditions")
    op.drop_column("quotations", "payment_terms")
