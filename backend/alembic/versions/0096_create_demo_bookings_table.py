"""Demo booking calendar: ``demo_bookings``.

One new table, additive only. **Nothing on ``demo_requests`` changes** --
the 15 leads already in that table are untouched, no column is added to
it, no backfill runs, and the plain "Book a Demo" form keeps working
exactly as it does today. A booking is a second row that points at a lead;
see ``app.domains.demo_booking.models``'s module docstring for why that is
two tables and not one.

## The point of this migration

``uq_demo_bookings_active_slot`` -- a **partial unique index** on
``starts_at``, restricted to rows that are actually holding the slot::

    CREATE UNIQUE INDEX uq_demo_bookings_active_slot
        ON demo_bookings (starts_at)
     WHERE status = 'confirmed' AND is_deleted = false;

This index *is* the double-booking prevention. Two visitors clicking 11:00
in the same millisecond both pass any application-level "is this slot
free?" query -- that check is a race by construction, and the application
does not perform one. Both ``INSERT``s arrive, Postgres serializes them on
this index, exactly one commits and the other raises
``unique_violation``, which the service turns into a 409 carrying the next
free times.

Partial (not a plain unique index) so that cancelling a booking genuinely
frees the slot: a ``cancelled`` or soft-deleted row leaves the index and
the time returns to the published calendar. A plain unique index would
make every cancellation a permanent tombstone on that time.

Why a unique index on a single column rather than
``EXCLUDE USING gist (tstzrange(starts_at, ends_at) WITH &&)``: every
booking is exactly one configured slot long and every accepted start must
be exactly on the published grid (enforced in
``availability.BookingWindow.is_on_grid``), so "same start" and
"overlapping range" are the same question. The exclusion constraint would
additionally require the ``btree_gist`` extension. The one case this
leaves open -- changing ``demo_booking_slot_minutes`` or the workday start
while future bookings already exist, so that a new grid slot could overlap
an old booking without colliding on ``starts_at`` -- is documented on the
model and needs a human looking at the calendar anyway.

## Foreign keys

``demo_request_id`` is ``ON DELETE RESTRICT``: deleting a lead out from
under a confirmed meeting would silently erase something a salesperson has
in their calendar. The two ``notification_deliveries`` references are
``ON DELETE SET NULL`` -- losing the outbox row loses the mail's audit
trail, which is worth recording as "unknown", not worth blocking a purge
over.

Revision ID: 0096_create_demo_bookings_table
Revises: 0095_add_snapshot_version_to_router_snapshots
Create Date: 2026-08-22
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0096_create_demo_bookings_table"
down_revision = "0095_add_snapshot_version_to_router_snapshots"
branch_labels = None
depends_on = None

TABLE = "demo_bookings"

# Duplicated as a literal from app.domains.demo_booking.models
# .ACTIVE_SLOT_INDEX_NAME -- migrations are self-contained snapshots by
# this repo's own convention (see 0082/0086/0095's own docstrings).
ACTIVE_SLOT_INDEX = "uq_demo_bookings_active_slot"
ACTIVE_SLOT_PREDICATE = "status = 'confirmed' AND is_deleted = false"


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
        TABLE,
        *_base_model_columns(),
        sa.Column(
            "demo_request_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("demo_requests.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        # TIMESTAMPTZ. Always holds a UTC instant; every availability rule
        # is defined in Settings.demo_booking_timezone. See
        # app.domains.demo_booking.availability's module docstring.
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ends_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("booked_timezone", sa.String(64), nullable=False),
        # SHA-256 hex of the visitor's opaque manage token; the token
        # itself is never stored.
        sa.Column("manage_token_hash", sa.String(64), nullable=False),
        sa.Column("cancellation_reason", sa.Text(), nullable=True),
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "guest_confirmation_delivery_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("notification_deliveries.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "team_notification_delivery_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("notification_deliveries.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    _create_base_model_indexes(TABLE)

    # ---------------------------------------------------------------------
    # THE constraint. See this module's docstring.
    # ---------------------------------------------------------------------
    op.create_index(
        ACTIVE_SLOT_INDEX,
        TABLE,
        ["starts_at"],
        unique=True,
        postgresql_where=sa.text(ACTIVE_SLOT_PREDICATE),
    )

    op.create_index("ix_demo_bookings_starts_at", TABLE, ["starts_at"])
    op.create_index("ix_demo_bookings_status", TABLE, ["status"])
    op.create_index("ix_demo_bookings_demo_request_id", TABLE, ["demo_request_id"])
    op.create_index(
        "ix_demo_bookings_manage_token_hash", TABLE, ["manage_token_hash"]
    )


def downgrade() -> None:
    op.drop_index("ix_demo_bookings_manage_token_hash", table_name=TABLE)
    op.drop_index("ix_demo_bookings_demo_request_id", table_name=TABLE)
    op.drop_index("ix_demo_bookings_status", table_name=TABLE)
    op.drop_index("ix_demo_bookings_starts_at", table_name=TABLE)
    op.drop_index(ACTIVE_SLOT_INDEX, table_name=TABLE)
    _drop_base_model_indexes(TABLE)
    op.drop_table(TABLE)
