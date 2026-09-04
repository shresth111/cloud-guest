"""``router_rogue_dhcp_statuses`` -- where the rogue-DHCP detector's
findings live between the scheduled device read and the readiness checklist
that displays them.

One row per ``(router_id, interface)``. See
``app.domains.dhcp.models.RouterRogueDhcpStatus`` for the full design
write-up; the two things worth repeating at the schema level are why there
are three status columns instead of one, and why ``checked_at`` is NOT NULL.

## Three columns, not one

``alert_state`` is the rolled-up tri-state
(``guarded``/``unguarded``/``unknown``), and ``alert_present``/``enabled``
sit beside it as separate booleans rather than being folded into it.

``unguarded`` is reached two different ways and the difference is the whole
operational point. "No alert row on this interface" is a gap someone forgot
to close. "Alert row present, switched off" is what **RouterOS creates by
default** -- it appears in a ``/export`` looking exactly like a configured
watch and observes nothing. The first careful by-hand attempt on the lab
router left three of those. A single collapsed column would record both as
the same bare ``unguarded`` and throw away the only evidence that
distinguishes a forgotten interface from a switched-off one.

``serves_dhcp`` is recorded for the converse case: an alert row on an
interface this router serves no DHCP on means the configuration and the
device disagree, which is reported rather than hidden.

## ``checked_at`` is NOT NULL, with no server default

Every row is written by a detection pass that knows exactly when it ran, so
there is no such thing as a row of this kind without a timestamp -- and a
consumer reading ``alert_state`` without knowing the row's age cannot tell
a current answer from a months-old one. No ``server_default``: a default
here would let a future insert that forgot the column land a fabricated
"checked just now" on a row nothing actually checked, which is precisely
the class of invented fact this table exists to avoid.

## Nothing to backfill

A new table with no pre-existing rows, so there is no honest state to
backfill *to*. Absence is already the correct and truthful answer: the
readiness item reads "no rows yet" as NOT_CHECKED ("this router has not
been checked yet"), never as a pass and never as a failure. Seeding rows in
any state would be asserting a device fact nobody has observed.

Revision ID: 0113_create_router_rogue_dhcp_statuses_table
Revises: 0112_add_confirm_takes_port_to_vlans
Create Date: 2026-09-04
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0113_create_router_rogue_dhcp_statuses_table"
down_revision = "0112_add_confirm_takes_port_to_vlans"
branch_labels = None
depends_on = None

TABLE = "router_rogue_dhcp_statuses"


# ``_base_model_columns``/``_create_base_model_indexes``/
# ``_drop_base_model_indexes`` are duplicated verbatim into each migration
# that needs them rather than imported from a shared module -- the
# convention this directory has followed since ``0012_create_otp_tables``,
# so a migration stays a frozen snapshot of the schema at its own point in
# history and cannot be changed retroactively by editing a helper.
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
            "router_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("routers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("interface", sa.String(length=100), nullable=False),
        # Plain string, not a native enum type -- the same "no native enum"
        # posture every other status column in this codebase takes, so a
        # future fourth state is a code change and not a migration.
        sa.Column(
            "alert_state",
            sa.String(length=20),
            nullable=False,
            server_default="unknown",
        ),
        # Presence and liveness, kept apart on purpose. See the module
        # docstring above.
        sa.Column(
            "alert_present", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "serves_dhcp", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
    )
    _create_base_model_indexes(TABLE)
    op.create_index(f"ix_{TABLE}_router_id", TABLE, ["router_id"])
    # RouterOS holds one ``/ip dhcp-server alert`` per interface, so
    # ``(router_id, interface)`` is the finding's real identity -- a second
    # row for the same pair would be two contradictory answers to one
    # question, with nothing to say which is current.
    op.create_index(
        f"uq_{TABLE}_router_id_interface",
        TABLE,
        ["router_id", "interface"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(f"uq_{TABLE}_router_id_interface", table_name=TABLE)
    op.drop_index(f"ix_{TABLE}_router_id", table_name=TABLE)
    _drop_base_model_indexes(TABLE)
    op.drop_table(TABLE)
