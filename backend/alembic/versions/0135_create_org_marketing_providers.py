"""Guest Marketing bring-your-own providers (spec §12.3).

Additive only:

* new table ``org_marketing_providers`` -- one venue organization's own
  SMS / WhatsApp / email account per channel (at most one live row per
  channel). ``config_encrypted`` is Fernet ciphertext; ``display`` holds only
  non-secret fields and masked hints;
* ``marketing_campaigns``: ``provider_source`` (NOT NULL, server default
  'wyfy' -- the backfill for every existing campaign), ``provider_type``,
  ``org_provider_id`` (FK SET NULL) -- the schedule-time provider snapshot;
* ``marketing_campaign_recipients.provider_source``;
* ``marketing_templates``: ``whatsapp_source``, ``whatsapp_provider_template_name``,
  ``whatsapp_provider_language``, ``whatsapp_synced_at`` for WABA template
  sync, plus a partial unique index on the synced identity. The ten system
  templates are marked ``whatsapp_source='wyfy'``.

Revision ID: 0135_create_org_marketing_providers
Revises: 0134_create_guest_marketing_tables
Create Date: 2026-09-26
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0135_create_org_marketing_providers"
down_revision = "0134_create_guest_marketing_tables"
branch_labels = None
depends_on = None


# House convention: base-model helpers are duplicated into each migration so
# it stays a frozen snapshot (see 0122's note).
def _base_model_columns() -> list[sa.Column]:
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


PROVIDERS = "org_marketing_providers"


def upgrade() -> None:
    op.create_table(
        PROVIDERS,
        *_base_model_columns(),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("channel", sa.String(16), nullable=False),
        sa.Column("provider_type", sa.String(20), nullable=False),
        sa.Column("config_encrypted", sa.Text(), nullable=False),
        sa.Column("display", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="unverified"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(500), nullable=True),
        sa.Column("verified_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("updated_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_index(
        "uq_omp_org_channel",
        PROVIDERS,
        ["organization_id", "channel"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    _create_base_model_indexes(PROVIDERS)

    op.add_column(
        "marketing_campaigns",
        sa.Column(
            "provider_source", sa.String(8), nullable=False, server_default="wyfy"
        ),
    )
    op.add_column(
        "marketing_campaigns",
        sa.Column("provider_type", sa.String(20), nullable=True),
    )
    op.add_column(
        "marketing_campaigns",
        sa.Column(
            "org_provider_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("org_marketing_providers.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.add_column(
        "marketing_campaign_recipients",
        sa.Column("provider_source", sa.String(8), nullable=True),
    )
    op.add_column(
        "marketing_templates",
        sa.Column("whatsapp_source", sa.String(12), nullable=True),
    )
    op.add_column(
        "marketing_templates",
        sa.Column("whatsapp_provider_template_name", sa.String(512), nullable=True),
    )
    op.add_column(
        "marketing_templates",
        sa.Column("whatsapp_provider_language", sa.String(15), nullable=True),
    )
    op.add_column(
        "marketing_templates",
        sa.Column("whatsapp_synced_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "uq_mt_org_waba_template",
        "marketing_templates",
        [
            "organization_id",
            "whatsapp_provider_template_name",
            "whatsapp_provider_language",
        ],
        unique=True,
        postgresql_where=sa.text("whatsapp_source = 'own_waba' AND deleted_at IS NULL"),
    )
    op.execute(
        "UPDATE marketing_templates SET whatsapp_source = 'wyfy' "
        "WHERE organization_id IS NULL AND whatsapp_body IS NOT NULL"
    )


def downgrade() -> None:
    op.drop_index("uq_mt_org_waba_template", table_name="marketing_templates")
    for column in (
        "whatsapp_synced_at",
        "whatsapp_provider_language",
        "whatsapp_provider_template_name",
        "whatsapp_source",
    ):
        op.drop_column("marketing_templates", column)
    op.drop_column("marketing_campaign_recipients", "provider_source")
    op.drop_column("marketing_campaigns", "org_provider_id")
    op.drop_column("marketing_campaigns", "provider_type")
    op.drop_column("marketing_campaigns", "provider_source")
    _drop_base_model_indexes(PROVIDERS)
    op.drop_index("uq_omp_org_channel", table_name=PROVIDERS)
    op.drop_table(PROVIDERS)
