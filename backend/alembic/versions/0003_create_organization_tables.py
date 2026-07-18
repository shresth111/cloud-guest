"""Create Organization domain tables: organizations, organization_members.

Mirrors ``0001_create_auth_tables``/``0002_create_rbac_tables``'s conventions:
every table gets the ``BaseModel`` column set (id, created_at, updated_at,
soft-delete, audit, version) plus its own base-model indexes, using the same
``_base_model_columns``/``_create_base_model_indexes`` helpers (duplicated
here, not imported, since Alembic migrations are meant to be self-contained
snapshots rather than depending on other migration modules).

``organizations.parent_organization_id`` is a self-FK (an MSP-type
organization owns child organizations). ``organization_members`` carries a
partial unique index -- Postgres-only, via ``postgresql_where`` -- enforcing
that a user can hold at most one ``ACTIVE`` membership row per organization
at a time, while still allowing historical rows (invited -> active ->
removed -> re-invited) to coexist.

Revision ID: 0003_create_organization_tables
Revises: 0002_create_rbac_tables
Create Date: 2026-07-18
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0003_create_organization_tables"
down_revision = "0002_create_rbac_tables"
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
    # -- organizations ---------------------------------------------------------
    op.create_table(
        "organizations",
        *_base_model_columns(),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("slug", sa.String(150), nullable=False),
        sa.Column("legal_name", sa.String(255), nullable=True),
        sa.Column("org_type", sa.String(20), nullable=False, server_default="standard"),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column(
            "parent_organization_id", postgresql.UUID(as_uuid=True), nullable=True
        ),
        sa.Column("contact_email", sa.String(255), nullable=False),
        sa.Column("contact_phone", sa.String(20), nullable=True),
        sa.Column("timezone", sa.String(50), nullable=False, server_default="UTC"),
        sa.Column("default_locale", sa.String(10), nullable=False, server_default="en"),
        sa.Column(
            "settings",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("subscription_tier", sa.String(50), nullable=True),
        sa.ForeignKeyConstraint(
            ["parent_organization_id"],
            ["organizations.id"],
            name="fk_organizations_parent_organization_id_organizations",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint("slug", name="uq_organizations_slug"),
    )
    _create_base_model_indexes("organizations")
    op.create_index("ix_organizations_name", "organizations", ["name"])
    op.create_index("ix_organizations_slug", "organizations", ["slug"])
    op.create_index("ix_organizations_status", "organizations", ["status"])
    op.create_index("ix_organizations_org_type", "organizations", ["org_type"])
    op.create_index(
        "ix_organizations_parent_organization_id",
        "organizations",
        ["parent_organization_id"],
    )
    op.create_index(
        "ix_organizations_contact_email", "organizations", ["contact_email"]
    )

    # -- organization_members --------------------------------------------------
    op.create_table(
        "organization_members",
        *_base_model_columns(),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="invited"),
        sa.Column("invited_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "invited_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("joined_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "is_primary_contact",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_organization_members_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_organization_members_user_id_users",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["invited_by_user_id"],
            ["users.id"],
            name="fk_organization_members_invited_by_user_id_users",
            ondelete="SET NULL",
        ),
    )
    _create_base_model_indexes("organization_members")
    op.create_index(
        "ix_organization_members_organization_id",
        "organization_members",
        ["organization_id"],
    )
    op.create_index(
        "ix_organization_members_user_id", "organization_members", ["user_id"]
    )
    op.create_index(
        "ix_organization_members_status", "organization_members", ["status"]
    )
    op.create_index(
        "ix_organization_members_invited_by_user_id",
        "organization_members",
        ["invited_by_user_id"],
    )
    op.create_index(
        "ix_organization_members_org_user",
        "organization_members",
        ["organization_id", "user_id"],
    )
    op.create_index(
        "uq_organization_members_active_org_user",
        "organization_members",
        ["organization_id", "user_id"],
        unique=True,
        postgresql_where=sa.text("status = 'active'"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_organization_members_active_org_user",
        table_name="organization_members",
    )
    op.drop_index("ix_organization_members_org_user", table_name="organization_members")
    op.drop_index(
        "ix_organization_members_invited_by_user_id",
        table_name="organization_members",
    )
    op.drop_index("ix_organization_members_status", table_name="organization_members")
    op.drop_index("ix_organization_members_user_id", table_name="organization_members")
    op.drop_index(
        "ix_organization_members_organization_id", table_name="organization_members"
    )
    _drop_base_model_indexes("organization_members")
    op.drop_table("organization_members")

    op.drop_index("ix_organizations_contact_email", table_name="organizations")
    op.drop_index("ix_organizations_parent_organization_id", table_name="organizations")
    op.drop_index("ix_organizations_org_type", table_name="organizations")
    op.drop_index("ix_organizations_status", table_name="organizations")
    op.drop_index("ix_organizations_slug", table_name="organizations")
    op.drop_index("ix_organizations_name", table_name="organizations")
    _drop_base_model_indexes("organizations")
    op.drop_table("organizations")
