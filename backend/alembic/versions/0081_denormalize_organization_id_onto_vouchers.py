"""Denormalize organization_id onto vouchers, add redemption-query indexes.

``vouchers`` previously carried no ``organization_id`` of its own -- every
tenant-scoped query in ``app.domains.voucher.repository`` (the redemption
analytics family backing the "Voucher Redemption Log"/"Most Redeemed
Vouchers" reports) could only express that scoping by joining through
``voucher_batches``, which also meant no composite index on
``(organization_id, redeemed_at)``/``(organization_id, use_count)`` was
possible for those queries' ``ORDER BY``. Every page of those reports paid
for a full unindexed sort of the organization's entire redeemed-voucher
history before ``OFFSET``/``LIMIT`` could slice a page.

Mirrors ``app.domains.guest.models.GuestSession.organization_id``'s
identical "denormalized at creation time, immutable after, lets analytics
queries filter directly instead of joining through location every time"
precedent.

Backfilled from ``voucher_batches.organization_id`` (every existing
``vouchers.batch_id`` is ``NOT NULL`` and FK-guaranteed to resolve to a
real batch, so this is a complete, lossless backfill, not a best-effort
default) before the column is made ``NOT NULL``.

Revision ID: 0081_denormalize_organization_id_onto_vouchers
Revises: 0080_create_content_filter_rules_table
Create Date: 2026-08-14
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0081_denormalize_organization_id_onto_vouchers"
down_revision = "0080_create_content_filter_rules_table"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vouchers",
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.execute(
        """
        UPDATE vouchers
        SET organization_id = voucher_batches.organization_id
        FROM voucher_batches
        WHERE vouchers.batch_id = voucher_batches.id
        """
    )
    op.alter_column("vouchers", "organization_id", nullable=False)
    op.create_foreign_key(
        "fk_vouchers_organization_id_organizations",
        "vouchers",
        "organizations",
        ["organization_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index(
        "ix_vouchers_organization_id", "vouchers", ["organization_id"]
    )
    op.create_index(
        "ix_vouchers_org_redeemed_at",
        "vouchers",
        ["organization_id", "redeemed_at"],
    )
    op.create_index(
        "ix_vouchers_org_use_count",
        "vouchers",
        ["organization_id", "use_count"],
    )


def downgrade() -> None:
    op.drop_index("ix_vouchers_org_use_count", table_name="vouchers")
    op.drop_index("ix_vouchers_org_redeemed_at", table_name="vouchers")
    op.drop_index("ix_vouchers_organization_id", table_name="vouchers")
    op.drop_constraint(
        "fk_vouchers_organization_id_organizations", "vouchers", type_="foreignkey"
    )
    op.drop_column("vouchers", "organization_id")
