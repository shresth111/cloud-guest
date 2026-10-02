"""``guest_access_controller_blocks`` -- what this platform asked a venue's
controller to block, so that it can be found again and released.

## Why a table, and not a column

A ``BLOCKLIST`` rule names a person. A controller blocks a MAC. One rule
therefore produces *n* controller writes, one per known device, with a
genuinely per-device result: some confirmed, some for a device the
controller has never seen, some refused. A status column on the rule cannot
express "three of five", and rounding it to one value is how a venue comes
to believe five devices are blocked when three are.

## Why the rows must outlive the moment

**There is no readable list of blocked clients through the connection this
platform holds.** Measured on the real controller: ``filters.blocked`` is
silently ignored (it returned every row, all unblocked) and the Open API
client grid carries no block field at all. So a MAC that is blocked and then
forgotten is a device nobody can find again from the controller -- on a
customer's own network, with nothing anywhere explaining why it will not
associate.

That is why ``cleared_at`` exists and why nothing deletes these rows on the
way past. A row with ``status='enforced'`` and ``cleared_at IS NULL`` is this
platform's standing claim that a venue's controller is still holding a block
it put there; those rows, and only those, are what an unblock, a rule
deletion and the expiry sweep read.

## The foreign keys, and the one that is deliberately not ``SET NULL``

``rule_id`` is ``ON DELETE CASCADE``, which looks wrong for a table whose
whole purpose is to survive. It is not, because the rule delete this domain
performs is a *soft* delete (``GuestAccessRepository.delete_guest_rule`` ->
``soft_delete``) and never removes the parent row. The cascade only fires
when the organization itself is deleted, and at that point the tenant, its
locations and its integrations are gone too -- there is no controller left to
release anything at. What must not happen is a release that is skipped
because the rule went away first, and that is prevented in the service: the
blocks are released *before* the rule is deactivated or deleted.

``location_id`` is ``NOT NULL`` here although the rule's own is nullable. An
organization-wide rule means "every venue"; a controller block is per-site
and cannot mean that. The venue on this row is the one whose controller was
actually written to, resolved either from the rule's own ``location_id`` or,
for an org-wide rule, from the venue the guest's live session was on.

## Nothing to backfill

No block has ever been written to a controller from this path -- the
capability existed as a provider method and a manual per-client route, and
nothing in the blocklist path called it. So an empty table is a true
statement about every venue on the platform, which is exactly what a
backfill could not have produced.

Downgrade drops the table. Any block this platform had placed and not yet
released becomes unfindable, which is the honest consequence of removing the
record: it is the state that existed before this migration.
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0127_create_guest_access_controller_blocks"
down_revision = "0126_add_subject_id_to_alerts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "guest_access_controller_blocks",
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
            sa.ForeignKey("guest_access_rules.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "location_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("locations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("mac_address", sa.String(length=17), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
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
    # The BaseModel mixins declare these five ``index=True``; created here so
    # the table matches the ORM and autogenerate has nothing left to report.
    for column in (
        "created_at",
        "deleted_at",
        "is_deleted",
        "created_by",
        "updated_by",
    ):
        op.create_index(
            f"ix_guest_access_controller_blocks_{column}",
            "guest_access_controller_blocks",
            [column],
        )
    op.create_index(
        "ix_guest_access_controller_blocks_rule_id",
        "guest_access_controller_blocks",
        ["rule_id"],
    )
    op.create_index(
        "ix_guest_access_controller_blocks_organization_id",
        "guest_access_controller_blocks",
        ["organization_id"],
    )
    op.create_index(
        "ix_guest_access_controller_blocks_location_id",
        "guest_access_controller_blocks",
        ["location_id"],
    )
    op.create_index(
        "ix_guest_access_controller_blocks_open",
        "guest_access_controller_blocks",
        ["cleared_at", "rule_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_guest_access_controller_blocks_open",
        table_name="guest_access_controller_blocks",
    )
    op.drop_index(
        "ix_guest_access_controller_blocks_location_id",
        table_name="guest_access_controller_blocks",
    )
    op.drop_index(
        "ix_guest_access_controller_blocks_organization_id",
        table_name="guest_access_controller_blocks",
    )
    op.drop_index(
        "ix_guest_access_controller_blocks_rule_id",
        table_name="guest_access_controller_blocks",
    )
    for column in (
        "updated_by",
        "created_by",
        "is_deleted",
        "deleted_at",
        "created_at",
    ):
        op.drop_index(
            f"ix_guest_access_controller_blocks_{column}",
            table_name="guest_access_controller_blocks",
        )
    op.drop_table("guest_access_controller_blocks")
