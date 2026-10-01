"""``device_access_router_blocks`` -- which MikroTik routers hold a durable
block for a device rule, so it can be taken off again.

A ``BLOCKLIST`` device rule (``device_access_rules``) used to be a login-gate
check only: a device already online, or one the venue had bypassed, was
never cut off. It is now also written to each MikroTik router in the rule's
scope as ``/ip hotspot ip-binding type=blocked`` with the comment
``cloudguest-devblock:<rule id>``, and the device's live session is removed.

The binding outlives the request, so one row per (rule, router) records it:
an unblock, a rule deletion and the expiry sweep read the rows whose
``cleared_at`` is NULL and ask each router to remove exactly that binding.

``rule_id`` is ``ON DELETE CASCADE`` for the reason
``0127_create_guest_access_controller_blocks`` gives: rule deletion is a soft
delete, so the cascade only fires when the organization itself goes.
``router_id`` cascades too: a router row that is really deleted takes its
record with it, and there is no device left to release anything at.

Nothing to backfill: no device rule has ever been written to a router.

Downgrade drops the table. Any binding still on a router becomes unfindable
from here (its comment still names the rule); unblock first.

Additive only. If another branch also adds a migration on top of
``0139_add_dns_bypass_layers``, re-point one ``down_revision`` so there is a
single head.

Revision ID: 0140_create_device_access_router_blocks
Revises: 0139_add_dns_bypass_layers
Create Date: 2026-10-01
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0140_create_device_access_router_blocks"
down_revision = "0139_add_dns_bypass_layers"
branch_labels = None
depends_on = None

_TABLE = "device_access_router_blocks"
_BASE_INDEXED = ("created_at", "deleted_at", "is_deleted", "created_by", "updated_by")


def upgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "rule_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("device_access_rules.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "router_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("routers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "location_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("locations.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("mac_address", sa.String(length=17), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("sessions_ended", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("blocked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cleared_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("release_error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "is_deleted",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
    )
    for column in _BASE_INDEXED:
        op.create_index(f"ix_{_TABLE}_{column}", _TABLE, [column])
    op.create_index(f"ix_{_TABLE}_rule_id", _TABLE, ["rule_id"])
    op.create_index(f"ix_{_TABLE}_router_id", _TABLE, ["router_id"])
    op.create_index(f"ix_{_TABLE}_organization_id", _TABLE, ["organization_id"])
    op.create_index(f"ix_{_TABLE}_open", _TABLE, ["cleared_at", "rule_id"])


def downgrade() -> None:
    for name in ("open", "organization_id", "router_id", "rule_id"):
        op.drop_index(f"ix_{_TABLE}_{name}", table_name=_TABLE)
    for column in reversed(_BASE_INDEXED):
        op.drop_index(f"ix_{_TABLE}_{column}", table_name=_TABLE)
    op.drop_table(_TABLE)
