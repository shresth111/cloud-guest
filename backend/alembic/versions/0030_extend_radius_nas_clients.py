"""NAS extension: adds ``organization_id``/``location_id`` (denormalized,
backfilled), ``nas_code`` (human-readable, nullable, not backfilled for
pre-existing rows), ``status`` (backfilled from ``is_active``),
``name``/``description``/``ip_address``/``vendor`` to ``radius_nas_clients``,
plus a new ``radius_nas_code_counters`` table.

## Backfill strategy

``organization_id``/``location_id`` are deterministically derivable from
each row's existing ``router_id`` (every ``Router`` already has both,
``NOT NULL``) -- this migration backfills them via a single
``UPDATE ... FROM routers`` statement, then tightens both columns to
``NOT NULL`` and adds their foreign keys, so no pre-existing row is ever
left without a real tenant scope.

``nas_code`` is **not** backfilled -- mirrors migration ``0026``'s own
identical choice for ``Location.location_code`` (see that migration's own
module docstring): a real, per-location sequence number is not
retroactively inventable for rows that already exist without
disrupting the guarantee that the sequence for a given location starts at
1 and has no gaps for rows generated going forward. Pre-existing NAS
rows simply keep ``nas_code IS NULL`` -- the partial unique index below
(``WHERE nas_code IS NOT NULL``) is exactly what makes that safe.

``status`` backfills from the existing ``is_active`` boolean
(``true -> 'active'``, ``false -> 'disabled'``) -- every pre-existing row
gets a real, meaningful status immediately, not a placeholder.

Revision ID: 0030_extend_radius_nas_clients
Revises: 0029_create_policy_tables
Create Date: 2026-07-20
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0030_extend_radius_nas_clients"
down_revision = "0029_create_policy_tables"
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
    # -- radius_nas_clients: new columns ---------------------------------------
    op.add_column(
        "radius_nas_clients",
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "radius_nas_clients",
        sa.Column("location_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "radius_nas_clients", sa.Column("nas_code", sa.String(80), nullable=True)
    )
    op.add_column(
        "radius_nas_clients",
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
    )
    op.add_column(
        "radius_nas_clients", sa.Column("name", sa.String(200), nullable=True)
    )
    op.add_column(
        "radius_nas_clients", sa.Column("description", sa.Text(), nullable=True)
    )
    op.add_column(
        "radius_nas_clients", sa.Column("ip_address", sa.String(45), nullable=True)
    )
    op.add_column(
        "radius_nas_clients",
        sa.Column("vendor", sa.String(50), nullable=False, server_default="MikroTik"),
    )

    # -- backfill organization_id/location_id from each row's own router -------
    op.execute(
        """
        UPDATE radius_nas_clients
        SET organization_id = routers.organization_id,
            location_id = routers.location_id
        FROM routers
        WHERE routers.id = radius_nas_clients.router_id
        """
    )

    # -- backfill status from is_active (see module docstring) -----------------
    op.execute(
        "UPDATE radius_nas_clients SET status = 'disabled' WHERE is_active = false"
    )

    # -- tighten organization_id/location_id to NOT NULL + real FKs ------------
    op.alter_column("radius_nas_clients", "organization_id", nullable=False)
    op.alter_column("radius_nas_clients", "location_id", nullable=False)
    op.create_foreign_key(
        "fk_radius_nas_clients_organization_id_organizations",
        "radius_nas_clients",
        "organizations",
        ["organization_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "fk_radius_nas_clients_location_id_locations",
        "radius_nas_clients",
        "locations",
        ["location_id"],
        ["id"],
        ondelete="CASCADE",
    )

    # -- new indexes -------------------------------------------------------------
    op.create_index(
        "ix_radius_nas_clients_organization_id",
        "radius_nas_clients",
        ["organization_id"],
    )
    op.create_index(
        "ix_radius_nas_clients_location_id", "radius_nas_clients", ["location_id"]
    )
    op.create_index(
        "uq_radius_nas_clients_nas_code",
        "radius_nas_clients",
        ["nas_code"],
        unique=True,
        postgresql_where=sa.text("nas_code IS NOT NULL"),
    )
    op.create_index("ix_radius_nas_clients_status", "radius_nas_clients", ["status"])

    # -- radius_nas_code_counters (new table) -----------------------------------
    op.create_table(
        "radius_nas_code_counters",
        *_base_model_columns(),
        sa.Column("counter_key", sa.String(80), nullable=False),
        sa.Column("last_value", sa.Integer(), nullable=False, server_default="0"),
        sa.UniqueConstraint(
            "counter_key", name="uq_radius_nas_code_counters_counter_key"
        ),
    )
    _create_base_model_indexes("radius_nas_code_counters")
    op.create_index(
        "ix_radius_nas_code_counters_counter_key",
        "radius_nas_code_counters",
        ["counter_key"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_radius_nas_code_counters_counter_key",
        table_name="radius_nas_code_counters",
    )
    _drop_base_model_indexes("radius_nas_code_counters")
    op.drop_table("radius_nas_code_counters")

    op.drop_index("ix_radius_nas_clients_status", table_name="radius_nas_clients")
    op.drop_index("uq_radius_nas_clients_nas_code", table_name="radius_nas_clients")
    op.drop_index("ix_radius_nas_clients_location_id", table_name="radius_nas_clients")
    op.drop_index(
        "ix_radius_nas_clients_organization_id", table_name="radius_nas_clients"
    )
    op.drop_constraint(
        "fk_radius_nas_clients_location_id_locations",
        "radius_nas_clients",
        type_="foreignkey",
    )
    op.drop_constraint(
        "fk_radius_nas_clients_organization_id_organizations",
        "radius_nas_clients",
        type_="foreignkey",
    )
    op.drop_column("radius_nas_clients", "vendor")
    op.drop_column("radius_nas_clients", "ip_address")
    op.drop_column("radius_nas_clients", "description")
    op.drop_column("radius_nas_clients", "name")
    op.drop_column("radius_nas_clients", "status")
    op.drop_column("radius_nas_clients", "nas_code")
    op.drop_column("radius_nas_clients", "location_id")
    op.drop_column("radius_nas_clients", "organization_id")
