"""ISP Management: live traffic-load monitoring.

Adds real, sampled traffic-load tracking to WAN links -- "how much
traffic is flowing on this link right now", distinct from the existing
``download_bandwidth_mbps``/``upload_bandwidth_mbps`` columns (a link's
*provisioned* plan capacity, e.g. "500 Mbps fiber", never measured).

``isp_links`` gains:

* ``last_rx_bytes``/``last_tx_bytes`` (``BIGINT``, nullable) -- the raw,
  cumulative interface byte counters from the most recent successful
  sample, kept only to compute the next tick's delta (mirrors
  ``app.domains.guest``'s own "counter now, delta computed against the
  previous reading" convention). Never displayed directly.
* ``current_download_mbps``/``current_upload_mbps`` (``FLOAT``,
  nullable) -- the most recently *computed* rate (current state).

``isp_health_checks`` gains ``download_mbps``/``upload_mbps`` (``FLOAT``,
nullable) -- the same tick's rate, persisted as history so the "Traffic
Load" graph renders from the exact same rows the up/down "Status
Timeline" already uses, never a second, parallel monitoring table.

All four/two columns are nullable with no server default (unlike this
domain's earlier additive columns) -- there is no honest non-null default
for "the most recent raw byte counter" or "the last computed rate": a
pre-existing link has neither yet, and ``NULL`` (not sampled yet) is the
correct, honest value until the very next real health check populates it.

Revision ID: 0073_add_isp_link_traffic_monitoring
Revises: 0072_add_isp_link_connection_mode
Create Date: 2026-08-01
"""

import sqlalchemy as sa

from alembic import op

revision = "0073_add_isp_link_traffic_monitoring"
down_revision = "0072_add_isp_link_connection_mode"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "isp_links", sa.Column("last_rx_bytes", sa.BigInteger(), nullable=True)
    )
    op.add_column(
        "isp_links", sa.Column("last_tx_bytes", sa.BigInteger(), nullable=True)
    )
    op.add_column(
        "isp_links", sa.Column("current_download_mbps", sa.Float(), nullable=True)
    )
    op.add_column(
        "isp_links", sa.Column("current_upload_mbps", sa.Float(), nullable=True)
    )
    op.add_column(
        "isp_health_checks", sa.Column("download_mbps", sa.Float(), nullable=True)
    )
    op.add_column(
        "isp_health_checks", sa.Column("upload_mbps", sa.Float(), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("isp_health_checks", "upload_mbps")
    op.drop_column("isp_health_checks", "download_mbps")
    op.drop_column("isp_links", "current_upload_mbps")
    op.drop_column("isp_links", "current_download_mbps")
    op.drop_column("isp_links", "last_tx_bytes")
    op.drop_column("isp_links", "last_rx_bytes")
