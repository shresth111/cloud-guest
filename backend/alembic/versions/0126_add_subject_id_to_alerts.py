"""Add ``subject_id`` to ``alerts``.

The fifth dimension of the alert de-duplication key, and the one that was
missing.

## What it fixes

An alert de-duplicates on ``(rule_id, organization_id, location_id,
router_id)``, and a monitored device's ``router_id`` is normally NULL. So
every access point at one location shared a **single** key: the second AP to
go down produced no alert at all, and while the first alert was open --
which, for a device that is still down, is forever -- nothing else at that
location could fire. A venue with five APs got one alert, naming whichever
device the evaluation loop happened to see first.

``ALERT_TARGET_MONITORED_HARDWARE`` now passes the device's own id, so each
device de-duplicates separately. That matters most at exactly the moment it
is hardest to notice: the venue with the most access points gets the most
silent failures.

## Why no existing row changes meaning, and no other target is affected

Nullable, no server default, no backfill. ``NULL`` *is* "no subject
dimension": every row that predates this column was grouped by rule + org +
location + router and nothing else, and every other target (``router``,
``router_reachability``, ``isp_link``, ``rogue_dhcp_guard`` and the three
controller targets) still passes ``None``. Those branches therefore keep
de-duplicating exactly as they did -- this migration cannot change which
alert any of them opens, which is what makes it safe to run against live
rows.

## Why there is no ``ForeignKey``

The subject is polymorphic -- today a ``monitored_hardware.id`` -- so a
constraint to that one table would both misstate the column and block the
next target that needs a subject of its own. Same reasoning
``alerts.related_event_id``'s own column carries for its own polymorphic
neighbour.

Downgrade drops the index and the column. Alerts that were separated by
device lose that distinction and revert to grouping by rule + location, which
is the honest consequence of removing the feature: it is precisely the
grouping that existed before.
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0126_add_subject_id_to_alerts"
down_revision = "0125_add_portal_mode_to_network_integrations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "alerts",
        sa.Column("subject_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_index("ix_alerts_subject_id", "alerts", ["subject_id"])


def downgrade() -> None:
    op.drop_index("ix_alerts_subject_id", table_name="alerts")
    op.drop_column("alerts", "subject_id")
