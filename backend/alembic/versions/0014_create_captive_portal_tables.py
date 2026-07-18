"""Create Captive Portal domain table: captive_portal_configs.

Mirrors ``0013_create_voucher_tables``'s conventions: the table gets the
``BaseModel`` column set (id, created_at, updated_at, soft-delete, audit,
version) plus its own base-model indexes, using the same
``_base_model_columns``/``_create_base_model_indexes`` helpers (duplicated
here, not imported -- Alembic migrations are meant to be self-contained
snapshots rather than depending on other migration modules).

This is Module 010 Part 3's only migration -- one new table:

* ``captive_portal_configs`` -- one row per branding/content/enabled-
  login-methods configuration for a guest WiFi captive portal.
  ``organization_id`` is a real, **non-nullable** FK to
  ``organizations.id`` (mirrors ``voucher_batches.organization_id`` -- a
  config always belongs to a tenant); ``location_id`` is a real, nullable
  FK to ``locations.id`` (``NULL`` means the organization's own default
  config, non-null means a location-specific override -- see
  ``app.domains.captive_portal.models.CaptivePortalConfig``'s module
  docstring for the full most-specific-wins resolution write-up).

A partial unique index enforces "at most one ``is_default=True``
organization-level (``location_id IS NULL``) config per organization" at
the database layer -- the backstop half of this module's two-layered
single-default enforcement (the service layer, which un-defaults any prior
default before persisting a new one, is the half that actually runs on
every write).

No RBAC FK follow-up migration is needed (unlike Modules 005/006/008's own
follow-ups): this table is not referenced by any RBAC scope column.

Revision ID: 0014_create_captive_portal_tables
Revises: 0013_create_voucher_tables
Create Date: 2026-07-18
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0014_create_captive_portal_tables"
down_revision = "0013_create_voucher_tables"
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
        "captive_portal_configs",
        *_base_model_columns(),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("location_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "is_default", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("theme", sa.String(20), nullable=False, server_default="light"),
        sa.Column("logo_url", sa.String(500), nullable=True),
        sa.Column("background_image_url", sa.String(500), nullable=True),
        sa.Column(
            "primary_color", sa.String(7), nullable=False, server_default="#1A73E8"
        ),
        sa.Column(
            "secondary_color", sa.String(7), nullable=False, server_default="#FFFFFF"
        ),
        sa.Column(
            "default_language", sa.String(10), nullable=False, server_default="en"
        ),
        sa.Column(
            "supported_languages",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[\"en\"]'::jsonb"),
        ),
        sa.Column("advertisement_banner_url", sa.String(500), nullable=True),
        sa.Column("advertisement_banner_link", sa.String(500), nullable=True),
        sa.Column("terms_and_conditions_text", sa.Text(), nullable=True),
        sa.Column("terms_and_conditions_url", sa.String(500), nullable=True),
        sa.Column("privacy_policy_text", sa.Text(), nullable=True),
        sa.Column("privacy_policy_url", sa.String(500), nullable=True),
        sa.Column("splash_headline", sa.String(200), nullable=True),
        sa.Column("splash_welcome_message", sa.Text(), nullable=True),
        sa.Column("redirect_url", sa.String(500), nullable=True),
        sa.Column(
            "otp_sms_enabled", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
        sa.Column(
            "otp_email_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "voucher_enabled", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
        sa.Column(
            "username_password_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "social_login_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "social_login_providers",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_captive_portal_configs_organization_id_organizations",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["location_id"],
            ["locations.id"],
            name="fk_captive_portal_configs_location_id_locations",
            ondelete="CASCADE",
        ),
    )
    _create_base_model_indexes("captive_portal_configs")
    op.create_index(
        "ix_captive_portal_configs_organization_id",
        "captive_portal_configs",
        ["organization_id"],
    )
    op.create_index(
        "ix_captive_portal_configs_location_id",
        "captive_portal_configs",
        ["location_id"],
    )
    op.create_index(
        "ix_captive_portal_configs_is_active",
        "captive_portal_configs",
        ["is_active"],
    )
    op.create_index(
        "ix_captive_portal_configs_is_default",
        "captive_portal_configs",
        ["is_default"],
    )
    # Partial unique index: at most one is_default=True org-level
    # (location_id IS NULL) config per organization -- the database-layer
    # backstop for this module's single-default enforcement (see
    # app.domains.captive_portal.models.CaptivePortalConfig's module
    # docstring).
    op.create_index(
        "uq_captive_portal_configs_org_default",
        "captive_portal_configs",
        ["organization_id"],
        unique=True,
        postgresql_where=sa.text("location_id IS NULL AND is_default = true"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_captive_portal_configs_org_default",
        table_name="captive_portal_configs",
    )
    op.drop_index(
        "ix_captive_portal_configs_is_default", table_name="captive_portal_configs"
    )
    op.drop_index(
        "ix_captive_portal_configs_is_active", table_name="captive_portal_configs"
    )
    op.drop_index(
        "ix_captive_portal_configs_location_id", table_name="captive_portal_configs"
    )
    op.drop_index(
        "ix_captive_portal_configs_organization_id",
        table_name="captive_portal_configs",
    )
    _drop_base_model_indexes("captive_portal_configs")
    op.drop_table("captive_portal_configs")
