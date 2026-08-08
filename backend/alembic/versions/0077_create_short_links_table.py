"""URL Shortener domain: ``short_links``.

New domain (``app.domains.url_shortener``) -- a small, self-contained
"shorten a URL, redirect on visit" utility, creatable from three distinct
surfaces (the anonymous public marketing-site tool, the authenticated
customer dashboard, and the Master console) and resolved through one
guest-facing redirect endpoint (``GET /api/v1/s/{code}``). One new table,
additive only. See ``app.domains.url_shortener.models.ShortLink``'s own
module docstring for the full "why organization_id/created_by_user_id are
both nullable" write-up.

New RBAC module -- ``PermissionModule.URL_SHORTENER`` (scope
``ORGANIZATION``, actions CREATE/READ/UPDATE/DELETE) and three additive
``AuditAction`` enum values (``SHORT_LINK_CREATED``/``SHORT_LINK_REVOKED``/
``SHORT_LINK_MODERATED``) need no migration (seeded idempotently by
``seed_rbac``/written directly by the service, never by a migration, per
this codebase's own established convention -- see
``alembic/versions/0076_create_monitored_hardware_table.py`` for the
identical precedent).

Revision ID: 0077_create_short_links_table
Revises: 0076_create_monitored_hardware_table
Create Date: 2026-08-08
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0077_create_short_links_table"
down_revision = "0076_create_monitored_hardware_table"
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
        "short_links",
        *_base_model_columns(),
        sa.Column("code", sa.String(16), nullable=False),
        sa.Column("target_url", sa.Text(), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "source", sa.String(20), nullable=False, server_default="customer"
        ),
        sa.Column("click_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_clicked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "is_active", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_short_links_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["users.id"],
            name="fk_short_links_created_by_user_id_users",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint("code", name="uq_short_links_code"),
    )
    _create_base_model_indexes("short_links")
    op.create_index("ix_short_links_code", "short_links", ["code"], unique=True)
    op.create_index(
        "ix_short_links_organization_id", "short_links", ["organization_id"]
    )
    op.create_index(
        "ix_short_links_created_by_user_id", "short_links", ["created_by_user_id"]
    )
    op.create_index("ix_short_links_source", "short_links", ["source"])
    op.create_index("ix_short_links_is_active", "short_links", ["is_active"])
    op.create_index("ix_short_links_expires_at", "short_links", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_short_links_expires_at", table_name="short_links")
    op.drop_index("ix_short_links_is_active", table_name="short_links")
    op.drop_index("ix_short_links_source", table_name="short_links")
    op.drop_index("ix_short_links_created_by_user_id", table_name="short_links")
    op.drop_index("ix_short_links_organization_id", table_name="short_links")
    op.drop_index("ix_short_links_code", table_name="short_links")
    _drop_base_model_indexes("short_links")
    op.drop_table("short_links")
