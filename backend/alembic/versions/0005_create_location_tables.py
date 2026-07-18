"""Create Location domain table: locations.

Mirrors ``0003_create_organization_tables``'s conventions: the table gets
the ``BaseModel`` column set (id, created_at, updated_at, soft-delete,
audit, version) plus its own base-model indexes, using the same
``_base_model_columns``/``_create_base_model_indexes`` helpers (duplicated
here, not imported, since Alembic migrations are meant to be self-contained
snapshots rather than depending on other migration modules).

``locations.organization_id`` is a real, ``NOT NULL`` FK to
``organizations.id`` (``ON DELETE CASCADE`` -- a location has no meaning
once its owning organization is gone, the same reasoning
``organization_members.organization_id`` already uses). ``slug`` is unique
*per organization* (a composite unique constraint on
``(organization_id, slug)``), not globally -- a location slug can repeat
across different organizations.

Revision ID: 0005_create_location_tables
Revises: 0004_add_organization_fk_to_rbac_tables
Create Date: 2026-07-18
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0005_create_location_tables"
down_revision = "0004_add_organization_fk_to_rbac_tables"
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
        "locations",
        *_base_model_columns(),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("slug", sa.String(150), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("address_line1", sa.String(255), nullable=False),
        sa.Column("address_line2", sa.String(255), nullable=True),
        sa.Column("city", sa.String(100), nullable=False),
        sa.Column("state_province", sa.String(100), nullable=False),
        sa.Column("postal_code", sa.String(20), nullable=False),
        sa.Column("country", sa.String(2), nullable=False),
        sa.Column("timezone", sa.String(50), nullable=False, server_default="UTC"),
        sa.Column("latitude", sa.Float(), nullable=True),
        sa.Column("longitude", sa.Float(), nullable=True),
        sa.Column("contact_name", sa.String(200), nullable=True),
        sa.Column("contact_phone", sa.String(20), nullable=True),
        sa.Column("contact_email", sa.String(255), nullable=True),
        sa.Column(
            "settings",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_locations_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "organization_id", "slug", name="uq_locations_organization_id_slug"
        ),
    )
    _create_base_model_indexes("locations")
    op.create_index("ix_locations_organization_id", "locations", ["organization_id"])
    op.create_index("ix_locations_slug", "locations", ["slug"])
    op.create_index("ix_locations_status", "locations", ["status"])
    op.create_index("ix_locations_name", "locations", ["name"])
    op.create_index("ix_locations_city", "locations", ["city"])


def downgrade() -> None:
    op.drop_index("ix_locations_city", table_name="locations")
    op.drop_index("ix_locations_name", table_name="locations")
    op.drop_index("ix_locations_status", table_name="locations")
    op.drop_index("ix_locations_slug", table_name="locations")
    op.drop_index("ix_locations_organization_id", table_name="locations")
    _drop_base_model_indexes("locations")
    op.drop_table("locations")
