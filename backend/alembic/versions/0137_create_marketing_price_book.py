"""Marketing price book, and the credits columns on ``marketing_campaigns``.

Contract: ``wyfy-specs/guest-marketing-campaigns.md`` §13.3 / §13.4 (BE-12b).

Additive only:

* ``marketing_price_book`` -- versioned, append-only per-unit prices in credit
  minor units. ``organization_id`` NULL = platform default, set = per-org
  override (NULL price = clear the override). Unique
  ``(organization_id, channel, effective_from)`` NULLS NOT DISTINCT.
* Seed: the three platform defaults (§13.3) -- SMS 30/segment, WhatsApp
  120/message, email 5/message -- effective 2026-09-26 00:00 UTC.
  Master changes them; the seed never overwrites a later row.
* ``marketing_campaigns.price_snapshot`` (JSONB, NULL) and
  ``marketing_campaigns.capped_by_credits`` (int, NOT NULL default 0).

Revision ID: 0137_create_marketing_price_book
Revises: 0136_create_credit_wallets_and_ledger
Create Date: 2026-09-26
"""

import uuid

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0137_create_marketing_price_book"
down_revision = "0136_create_credit_wallets_and_ledger"
branch_labels = None
depends_on = None

TABLE = "marketing_price_book"

SEED_EFFECTIVE_FROM = "2026-09-26T00:00:00+00:00"
# (fixed id, channel, unit, unit_price_minor) -- fixed ids keep the seed
# idempotent across a downgrade/upgrade cycle.
PLATFORM_DEFAULTS = (
    ("6d1c2f8a-2b52-4f0e-9a51-0000000013a1", "sms", "segment", 30),
    ("6d1c2f8a-2b52-4f0e-9a51-0000000013a2", "whatsapp", "message", 120),
    ("6d1c2f8a-2b52-4f0e-9a51-0000000013a3", "email", "message", 5),
)


# House convention: base-model helpers are duplicated into each migration so
# it stays a frozen snapshot (see 0122's note).
def _base_model_columns() -> list[sa.Column]:
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
        TABLE,
        *_base_model_columns(),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("channel", sa.String(length=16), nullable=False),
        sa.Column("unit", sa.String(length=8), nullable=False),
        sa.Column("unit_price_minor", sa.Integer(), nullable=True),
        sa.Column("effective_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("set_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("note", sa.String(length=300), nullable=True),
        sa.CheckConstraint(
            "unit_price_minor IS NULL OR (unit_price_minor >= 0 "
            "AND unit_price_minor <= 10000)",
            name="ck_marketing_price_book_price_range",
        ),
        sa.CheckConstraint(
            "organization_id IS NOT NULL OR unit_price_minor IS NOT NULL",
            name="ck_marketing_price_book_platform_price_required",
        ),
        sa.CheckConstraint(
            "channel IN ('sms','whatsapp','email')",
            name="ck_marketing_price_book_channel_valid",
        ),
    )
    op.create_index(
        "uq_mpb_org_channel_effective",
        TABLE,
        ["organization_id", "channel", "effective_from"],
        unique=True,
        postgresql_nulls_not_distinct=True,
    )
    op.create_index("ix_mpb_channel_effective", TABLE, ["channel", "effective_from"])
    _create_base_model_indexes(TABLE)

    seed = sa.table(
        TABLE,
        sa.column("id", postgresql.UUID(as_uuid=True)),
        sa.column("organization_id", postgresql.UUID(as_uuid=True)),
        sa.column("channel", sa.String),
        sa.column("unit", sa.String),
        sa.column("unit_price_minor", sa.Integer),
        sa.column("effective_from", sa.DateTime(timezone=True)),
        sa.column("note", sa.String),
    )
    op.bulk_insert(
        seed,
        [
            {
                "id": uuid.UUID(row_id),
                "organization_id": None,
                "channel": channel,
                "unit": unit,
                "unit_price_minor": price,
                "effective_from": _seed_time(),
                "note": "Platform default (spec §13.3 seed)",
            }
            for row_id, channel, unit, price in PLATFORM_DEFAULTS
        ],
    )

    op.add_column(
        "marketing_campaigns",
        sa.Column("price_snapshot", postgresql.JSONB(), nullable=True),
    )
    op.add_column(
        "marketing_campaigns",
        sa.Column(
            "capped_by_credits", sa.Integer(), nullable=False, server_default="0"
        ),
    )


def _seed_time():
    from datetime import datetime

    return datetime.fromisoformat(SEED_EFFECTIVE_FROM)


def downgrade() -> None:
    op.drop_column("marketing_campaigns", "capped_by_credits")
    op.drop_column("marketing_campaigns", "price_snapshot")
    _drop_base_model_indexes(TABLE)
    op.drop_index("ix_mpb_channel_effective", table_name=TABLE)
    op.drop_index("uq_mpb_org_channel_effective", table_name=TABLE)
    op.drop_table(TABLE)
