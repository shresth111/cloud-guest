"""Device Logs: ``guest_device_events`` -- DHCP assign/release and hotspot
sign-in/out lines, parsed out of ``device_log_events`` for the customer's
Guest Connection Records.

Derived data: every row points at its source line (``ON DELETE CASCADE``),
so it follows the device-logs retention and is never a record in its own
right. It is NOT a CERT-In table and must not be confused with
``guest_sessions`` / ``guest_login_history``. New and empty; existing lines
are parsed by ``python -m app.domains.device_logs.backfill_guest_events``
(idempotent), not by this migration, so the migration imports no app code.

Idempotent (``IF NOT EXISTS`` throughout), like the SNMP revisions, so an
environment that already has the table from a sibling branch upgrades
cleanly.

## Why it chains on 0150

``main``'s head is ``0150_create_device_logs_tables``. Staging carries 0150
too and continues past it, so on staging this is a second head; the staging
branch adds ``0155_merge_guest_device_events_into_staging`` (no-op) to join
it, the same shape as ``0152_merge_device_logs_into_staging``.

Revision ID: 0154_create_guest_device_events
Revises: 0150_create_device_logs_tables
Create Date: 2026-10-07
"""

from __future__ import annotations

from alembic import op

revision = "0154_create_guest_device_events"
down_revision = "0150_create_device_logs_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS guest_device_events (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            device_log_event_id BIGINT NOT NULL
                REFERENCES device_log_events (id) ON DELETE CASCADE,
            occurred_at TIMESTAMPTZ NOT NULL,
            device_time TIMESTAMPTZ NULL,
            organization_id UUID NOT NULL
                REFERENCES organizations (id) ON DELETE CASCADE,
            location_id UUID NOT NULL
                REFERENCES locations (id) ON DELETE CASCADE,
            router_id UUID NOT NULL
                REFERENCES routers (id) ON DELETE CASCADE,
            kind VARCHAR(32) NOT NULL,
            ip_address VARCHAR(45) NOT NULL,
            mac_address VARCHAR(17) NULL,
            detail VARCHAR(64) NULL,
            CONSTRAINT uq_guest_device_events_source_event
                UNIQUE (device_log_event_id)
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_guest_device_events_location_occurred "
        "ON guest_device_events (location_id, occurred_at)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_guest_device_events_mac_occurred "
        "ON guest_device_events (mac_address, occurred_at)"
    )
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_guest_device_events_natural "
        "ON guest_device_events "
        "(router_id, occurred_at, kind, ip_address, coalesce(mac_address, ''))"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS guest_device_events")
