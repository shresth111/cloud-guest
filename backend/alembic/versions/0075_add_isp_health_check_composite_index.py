"""ISP Management: composite index for the bucketed/ranged health-check query.

``isp_health_checks`` previously only had two independent single-column
indexes (``isp_link_id``, ``checked_at``). The table's own real, dominant
access pattern -- both ``IspRepository.list_health_checks_for_link``'s
date-range branch and ``bucketed_health_checks_for_link`` (the Bandwidth
Utilization card / history-dialog SQL-side aggregation) -- always filters
``isp_link_id == X AND checked_at BETWEEN start AND end`` together, never
one alone. At real scale (tens of thousands of rows per link after a few
weeks at the health-check sweep's 60-second cadence), a single composite
index serving that predicate directly is materially cheaper than forcing
Postgres into a bitmap-AND of the two separate single-column indexes.

Revision ID: 0075_add_isp_health_check_composite_index
Revises: 0074_add_otp_whatsapp_enabled_to_captive_portal_configs
Create Date: 2026-08-04
"""

from alembic import op

revision = "0075_add_isp_health_check_composite_index"
down_revision = "0074_add_otp_whatsapp_enabled_to_captive_portal_configs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # CONCURRENTLY: isp_health_checks takes a real, continuous write every
    # 60 seconds from the health-check sweep across every enabled link on
    # this live production database. A plain CREATE INDEX takes a
    # table-level lock that blocks those writes (and any read of this
    # table) for the duration of the build; CONCURRENTLY avoids that at
    # the cost of needing to run outside the migration's normal
    # transaction (autocommit_block below), and can't run inside Alembic's
    # default transactional DDL wrapper.
    with op.get_context().autocommit_block():
        op.create_index(
            "ix_isp_health_checks_link_id_checked_at",
            "isp_health_checks",
            ["isp_link_id", "checked_at"],
            postgresql_concurrently=True,
        )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.drop_index(
            "ix_isp_health_checks_link_id_checked_at",
            table_name="isp_health_checks",
            postgresql_concurrently=True,
        )
