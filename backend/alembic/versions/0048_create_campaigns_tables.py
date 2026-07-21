"""Campaigns domain: ``campaigns``/``campaign_questions``/
``campaign_responses``/``campaign_assets``/``campaign_impressions``.

New domain (``app.domains.campaigns``), post-login guest campaigns
(survey/banner/redirect) served on the captive portal -- see
``service.py``'s own module docstring and ``__init__.py``'s own
friction-avoidance/runtime-status design write-up.

Five new tables, additive only:

* ``campaigns`` -- one row per campaign; ``location_id IS NULL`` means
  org-wide.
* ``campaign_questions`` -- ``SURVEY`` campaign questions, ordered by
  ``order_index``.
* ``campaign_responses`` -- one guest's completed survey answers. No
  database-level unique constraint enforcing "one response per guest
  when ``Campaign.display_rule=FIRST_LOGIN_ONLY``" -- see ``models.py``'s
  own module docstring for why that is a service-layer check only. A
  plain (non-unique) composite index on ``(campaign_id, guest_id)``
  still exists for that check's own query performance.
* ``campaign_assets`` -- the visual/redirect content for ``BANNER``/
  ``REDIRECT`` campaigns.
* ``campaign_impressions`` -- append-only "this campaign was shown to
  this guest session" events; no direct ``guest_id`` column (joined
  through ``guest_session_id`` -> ``GuestSession.guest_id`` -- see
  ``models.py``'s own module docstring).

No RBAC schema change -- ``PermissionModule.CAMPAIGNS`` was already
seeded (scope ``LOCATION``) with the full ``(CREATE, READ, UPDATE,
DELETE, APPROVE, EXPORT, MANAGE)`` action set before this domain existed
to claim it; additive ``AuditAction`` enum values
(``CAMPAIGN_CREATED``/``CAMPAIGN_UPDATED``/``CAMPAIGN_STATUS_CHANGED``/
``CAMPAIGN_DELETED``/``CAMPAIGN_CLONED``) need no migration either
(``permission_groups``/``permissions``/``permission_scopes``/
``role_permissions`` rows are all seeded idempotently at
application/CLI startup by ``seed_rbac``, never by a migration, per this
codebase's own established convention -- see e.g. migration ``0039``'s
identical note).

Revision ID: 0048_create_campaigns_tables
Revises: 0047_add_user_data_masking_enabled
Create Date: 2026-07-21
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "0048_create_campaigns_tables"
down_revision = "0047_add_user_data_masking_enabled"
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
        "campaigns",
        *_base_model_columns(),
        sa.Column(
            "organization_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "location_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("locations.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("campaign_type", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="draft"),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ends_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "display_rule",
            sa.String(20),
            nullable=False,
            server_default="once_per_n_days",
        ),
        sa.Column(
            "display_interval_days", sa.Integer(), nullable=True, server_default="7"
        ),
        sa.Column(
            "target_networks",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "is_skippable", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
    )
    _create_base_model_indexes("campaigns")
    op.create_index("ix_campaigns_organization_id", "campaigns", ["organization_id"])
    op.create_index("ix_campaigns_location_id", "campaigns", ["location_id"])
    op.create_index("ix_campaigns_status", "campaigns", ["status"])
    op.create_index("ix_campaigns_campaign_type", "campaigns", ["campaign_type"])

    op.create_table(
        "campaign_questions",
        *_base_model_columns(),
        sa.Column(
            "campaign_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("campaigns.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("order_index", sa.Integer(), nullable=False),
        sa.Column("question_text", sa.Text(), nullable=False),
        sa.Column("answer_type", sa.String(20), nullable=False),
        sa.Column(
            "options",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "is_required", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
    )
    _create_base_model_indexes("campaign_questions")
    op.create_index(
        "ix_campaign_questions_campaign_id", "campaign_questions", ["campaign_id"]
    )
    op.create_index(
        "ix_campaign_questions_campaign_id_order_index",
        "campaign_questions",
        ["campaign_id", "order_index"],
    )

    op.create_table(
        "campaign_responses",
        *_base_model_columns(),
        sa.Column(
            "campaign_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("campaigns.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "guest_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("guests.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "guest_session_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("guest_sessions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "answers",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    _create_base_model_indexes("campaign_responses")
    op.create_index(
        "ix_campaign_responses_campaign_id", "campaign_responses", ["campaign_id"]
    )
    op.create_index(
        "ix_campaign_responses_guest_id", "campaign_responses", ["guest_id"]
    )
    op.create_index(
        "ix_campaign_responses_guest_session_id",
        "campaign_responses",
        ["guest_session_id"],
    )
    op.create_index(
        "ix_campaign_responses_campaign_id_guest_id",
        "campaign_responses",
        ["campaign_id", "guest_id"],
    )

    op.create_table(
        "campaign_assets",
        *_base_model_columns(),
        sa.Column(
            "campaign_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("campaigns.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("image_url", sa.String(1000), nullable=True),
        sa.Column("click_url", sa.String(1000), nullable=True),
        sa.Column("alt_text", sa.String(300), nullable=True),
        sa.Column("locale", sa.String(10), nullable=True),
    )
    _create_base_model_indexes("campaign_assets")
    op.create_index(
        "ix_campaign_assets_campaign_id", "campaign_assets", ["campaign_id"]
    )

    op.create_table(
        "campaign_impressions",
        *_base_model_columns(),
        sa.Column(
            "campaign_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("campaigns.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "guest_session_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("guest_sessions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("shown_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "was_skipped", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column(
            "was_clicked", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
    )
    _create_base_model_indexes("campaign_impressions")
    op.create_index(
        "ix_campaign_impressions_campaign_id",
        "campaign_impressions",
        ["campaign_id"],
    )
    op.create_index(
        "ix_campaign_impressions_guest_session_id",
        "campaign_impressions",
        ["guest_session_id"],
    )
    op.create_index(
        "ix_campaign_impressions_shown_at", "campaign_impressions", ["shown_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_campaign_impressions_shown_at", table_name="campaign_impressions")
    op.drop_index(
        "ix_campaign_impressions_guest_session_id",
        table_name="campaign_impressions",
    )
    op.drop_index(
        "ix_campaign_impressions_campaign_id", table_name="campaign_impressions"
    )
    _drop_base_model_indexes("campaign_impressions")
    op.drop_table("campaign_impressions")

    op.drop_index("ix_campaign_assets_campaign_id", table_name="campaign_assets")
    _drop_base_model_indexes("campaign_assets")
    op.drop_table("campaign_assets")

    op.drop_index(
        "ix_campaign_responses_campaign_id_guest_id",
        table_name="campaign_responses",
    )
    op.drop_index(
        "ix_campaign_responses_guest_session_id", table_name="campaign_responses"
    )
    op.drop_index("ix_campaign_responses_guest_id", table_name="campaign_responses")
    op.drop_index("ix_campaign_responses_campaign_id", table_name="campaign_responses")
    _drop_base_model_indexes("campaign_responses")
    op.drop_table("campaign_responses")

    op.drop_index(
        "ix_campaign_questions_campaign_id_order_index",
        table_name="campaign_questions",
    )
    op.drop_index("ix_campaign_questions_campaign_id", table_name="campaign_questions")
    _drop_base_model_indexes("campaign_questions")
    op.drop_table("campaign_questions")

    op.drop_index("ix_campaigns_campaign_type", table_name="campaigns")
    op.drop_index("ix_campaigns_status", table_name="campaigns")
    op.drop_index("ix_campaigns_location_id", table_name="campaigns")
    op.drop_index("ix_campaigns_organization_id", table_name="campaigns")
    _drop_base_model_indexes("campaigns")
    op.drop_table("campaigns")
