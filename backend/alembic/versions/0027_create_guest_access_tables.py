"""Create Guest Access Control domain tables: guest_access_rules,
device_access_rules.

Mirrors ``0013_create_voucher_tables``'s conventions: each table gets the
``BaseModel`` column set (id, created_at, updated_at, soft-delete, audit,
version) plus its own base-model indexes, using the same
``_base_model_columns``/``_create_base_model_indexes`` helpers (duplicated
here, not imported -- Alembic migrations are meant to be self-contained
snapshots rather than depending on other migration modules).

Guest Session Engine roadmap item, "Guest Access Control" sub-item -- two
new tables:

* ``guest_access_rules`` -- one row per allow/deny rule keyed by a guest
  login ``identifier`` (phone/email/etc.), **not** a foreign key to
  ``guests.id``. See ``app.domains.guest_access.models``'s module
  docstring for why: a rule must be able to exist and take effect before a
  ``Guest`` row is ever created.
* ``device_access_rules`` -- the identical shape, keyed by ``mac_address``
  instead of ``identifier``.

Both share a ``rule_type`` column (``whitelist``/``blocklist``/
``temporary``/``vip`` -- see ``app.domains.guest_access.constants
.AccessRuleType``), a nullable ``location_id`` (``NULL`` == org-wide, the
same convention ``voucher_batches.location_id`` already established), and
a nullable ``expires_at`` (required at the application level, not a DB
constraint, for ``temporary`` rules only).

No RBAC FK follow-up migration is needed (unlike Modules 005/006/008's own
follow-ups): neither table is referenced by any RBAC scope column.

Revision ID: 0027_create_guest_access_tables
Revises: 0026_add_location_provisioning
Create Date: 2026-07-20
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0027_create_guest_access_tables"
down_revision = "0026_add_location_provisioning"
branch_labels = None
depends_on = None


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
        "guest_access_rules",
        *_base_model_columns(),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("location_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("identifier", sa.String(255), nullable=False),
        sa.Column("rule_type", sa.String(20), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "is_active", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_guest_access_rules_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["location_id"],
            ["locations.id"],
            name="fk_guest_access_rules_location_id_locations",
            ondelete="CASCADE",
        ),
    )
    _create_base_model_indexes("guest_access_rules")
    op.create_index(
        "ix_guest_access_rules_organization_id",
        "guest_access_rules",
        ["organization_id"],
    )
    op.create_index(
        "ix_guest_access_rules_location_id", "guest_access_rules", ["location_id"]
    )
    op.create_index(
        "ix_guest_access_rules_identifier", "guest_access_rules", ["identifier"]
    )
    op.create_index(
        "ix_guest_access_rules_rule_type", "guest_access_rules", ["rule_type"]
    )
    op.create_index(
        "ix_guest_access_rules_is_active", "guest_access_rules", ["is_active"]
    )

    op.create_table(
        "device_access_rules",
        *_base_model_columns(),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("location_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("mac_address", sa.String(17), nullable=False),
        sa.Column("rule_type", sa.String(20), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "is_active", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_device_access_rules_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["location_id"],
            ["locations.id"],
            name="fk_device_access_rules_location_id_locations",
            ondelete="CASCADE",
        ),
    )
    _create_base_model_indexes("device_access_rules")
    op.create_index(
        "ix_device_access_rules_organization_id",
        "device_access_rules",
        ["organization_id"],
    )
    op.create_index(
        "ix_device_access_rules_location_id", "device_access_rules", ["location_id"]
    )
    op.create_index(
        "ix_device_access_rules_mac_address", "device_access_rules", ["mac_address"]
    )
    op.create_index(
        "ix_device_access_rules_rule_type", "device_access_rules", ["rule_type"]
    )
    op.create_index(
        "ix_device_access_rules_is_active", "device_access_rules", ["is_active"]
    )


def downgrade() -> None:
    op.drop_index(
        "ix_device_access_rules_is_active", table_name="device_access_rules"
    )
    op.drop_index(
        "ix_device_access_rules_rule_type", table_name="device_access_rules"
    )
    op.drop_index(
        "ix_device_access_rules_mac_address", table_name="device_access_rules"
    )
    op.drop_index(
        "ix_device_access_rules_location_id", table_name="device_access_rules"
    )
    op.drop_index(
        "ix_device_access_rules_organization_id", table_name="device_access_rules"
    )
    _drop_base_model_indexes("device_access_rules")
    op.drop_table("device_access_rules")

    op.drop_index("ix_guest_access_rules_is_active", table_name="guest_access_rules")
    op.drop_index("ix_guest_access_rules_rule_type", table_name="guest_access_rules")
    op.drop_index("ix_guest_access_rules_identifier", table_name="guest_access_rules")
    op.drop_index(
        "ix_guest_access_rules_location_id", table_name="guest_access_rules"
    )
    op.drop_index(
        "ix_guest_access_rules_organization_id", table_name="guest_access_rules"
    )
    _drop_base_model_indexes("guest_access_rules")
    op.drop_table("guest_access_rules")
