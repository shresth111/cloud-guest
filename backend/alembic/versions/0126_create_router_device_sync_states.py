"""Record whether each router's device-discovery read actually worked.

One new table, ``router_device_sync_states``: one row per router, overwritten
by every discovery sync.

## What was wrong

Monitored Hardware status (``app.domains.monitored_hardware``) is derived
from ``connected_devices``: a registered access point is UP or DOWN only once
the router's DHCP-lease/ARP discovery has recorded its MAC, and "unknown"
(rendered "Never observed") until then.

The discovery sync's only record of a failure was a warning log line. So a
router the platform could not read at all -- its stored RouterOS API login
rejected -- left ``connected_devices`` exactly as empty as a router that had
simply never seen the device, and the dashboard told a venue owner that a
working access point had never been observed. Measured on production
2026-09-15: every discovery read of that venue's router failed with a
rejected login, and the venue had zero ``connected_devices`` rows ever.

## Why a table rather than columns on ``routers``

The outcome belongs to the connected-devices sync, which is its only writer;
``routers`` is written by a dozen other domains. A separate row keyed by the
router keeps the write a single upsert that touches nothing else, and
cascades away with the router.

## Why nothing is backfilled

No outcome was ever recorded before this. An absent row honestly means "no
discovery read has been attempted since this shipped", which the status
reports as such, and the first sync tick (every 15 minutes) fills it.
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0126_create_router_device_sync_states"
down_revision = "0125_add_portal_mode_to_network_integrations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "router_device_sync_states",
        sa.Column(
            "router_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey(
                "routers.id",
                ondelete="CASCADE",
                name="fk_router_device_sync_states_router_id_routers",
            ),
            nullable=False,
        ),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_failure_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_code", sa.String(length=40), nullable=True),
        sa.Column(
            "consecutive_failures",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.PrimaryKeyConstraint("router_id", name="pk_router_device_sync_states"),
    )


def downgrade() -> None:
    op.drop_table("router_device_sync_states")
