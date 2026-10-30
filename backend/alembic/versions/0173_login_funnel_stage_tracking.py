"""Record the two login-funnel stages the venue dashboard could not show.

* ``portal_impressions`` -- one row per real captive-portal page load
  ("portal opened"). Lean on purpose (no soft-delete/audit/version columns),
  no personal data: a device appears only as a keyed, per-organization hash.
* ``guest_sessions.internet_confirmed_at`` / ``internet_confirmed_source`` --
  when the NAS or controller itself first reported the session's device as
  let through ("internet confirmed"). Nullable, no default, so adding them is
  a catalog-only change on Postgres 11+ and does not rewrite the table.

Both start empty: the dashboard reports each stage's ``tracked_since`` rather
than a count that silently covers only part of its window.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision = "0173_login_funnel_stage_tracking"
down_revision = "0172_add_otp_sms_usage_index"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "portal_impressions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            UUID(as_uuid=True),
            sa.ForeignKey(
                "organizations.id",
                ondelete="CASCADE",
                name="fk_portal_impressions_organization_id_organizations",
            ),
            nullable=False,
        ),
        sa.Column(
            "location_id",
            UUID(as_uuid=True),
            sa.ForeignKey(
                "locations.id",
                ondelete="CASCADE",
                name="fk_portal_impressions_location_id_locations",
            ),
            nullable=False,
        ),
        sa.Column(
            "router_id",
            UUID(as_uuid=True),
            sa.ForeignKey(
                "routers.id",
                ondelete="SET NULL",
                name="fk_portal_impressions_router_id_routers",
            ),
            nullable=True,
        ),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("client_mac_hash", sa.String(length=64), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_portal_impressions"),
    )
    op.create_index(
        "ix_portal_impressions_org_location_occurred_at",
        "portal_impressions",
        ["organization_id", "location_id", "occurred_at"],
    )
    op.create_index(
        "ix_portal_impressions_location_device_occurred_at",
        "portal_impressions",
        ["location_id", "client_mac_hash", "occurred_at"],
        postgresql_where=sa.text("client_mac_hash IS NOT NULL"),
    )
    op.create_index(
        "ix_portal_impressions_occurred_at",
        "portal_impressions",
        ["occurred_at"],
    )

    op.add_column(
        "guest_sessions",
        sa.Column("internet_confirmed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "guest_sessions",
        sa.Column("internet_confirmed_source", sa.String(length=40), nullable=True),
    )
    # CONCURRENTLY: guest_sessions takes a write on every guest sign-in, and
    # a plain CREATE INDEX blocks writes for the length of the build (same
    # reasoning as 0075). The new tables above are empty, so they don't
    # need it.
    with op.get_context().autocommit_block():
        op.create_index(
            "ix_guest_sessions_internet_confirmed",
            "guest_sessions",
            ["location_id", "internet_confirmed_at"],
            postgresql_where=sa.text("internet_confirmed_at IS NOT NULL"),
            postgresql_concurrently=True,
        )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.drop_index(
            "ix_guest_sessions_internet_confirmed",
            table_name="guest_sessions",
            postgresql_concurrently=True,
        )
    op.drop_column("guest_sessions", "internet_confirmed_source")
    op.drop_column("guest_sessions", "internet_confirmed_at")

    op.drop_index("ix_portal_impressions_occurred_at", table_name="portal_impressions")
    op.drop_index(
        "ix_portal_impressions_location_device_occurred_at",
        table_name="portal_impressions",
    )
    op.drop_index(
        "ix_portal_impressions_org_location_occurred_at",
        table_name="portal_impressions",
    )
    op.drop_table("portal_impressions")
