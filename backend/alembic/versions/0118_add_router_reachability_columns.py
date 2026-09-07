"""Add the fast, alert-only reachability columns to ``routers``.

Four columns holding one debounced verdict and its counters --
``reachability_state``, ``reachability_state_changed_at``,
``reachability_consecutive_misses``, ``reachability_consecutive_hits`` --
written only by ``RouterService.sweep_router_reachability``, read only
by the Alert Engine's ``ALERT_TARGET_ROUTER_REACHABILITY`` branch.

No column is added for the sweep's INPUT signal, on purpose. "Last agent
contact" is ``router_agent_credentials.last_used_at``, which
``app.domains.router_agent.dependencies.CurrentAgent`` already writes on
every device-authenticated request -- including the
``GET /agent/authorized-macs`` poll the agent scheduler runs every 60
seconds, five times more often than the 5-minute ``POST /agent/heartbeat``.
In both of the 2026-09-07 outages that faster poll stopped within a minute
of the site going away and resumed a minute before the heartbeat did. The
signal was already there and already ticking on the real fleet; nothing
read it. A duplicate column would have been a second copy of a fact that
already exists.

And it is deliberately not a second writer of ``routers.last_seen_at``:
that column means "last heartbeat" and is what ``compute_lifecycle_stage``,
``compute_internet_availability`` and the frontend's ``location-liveness``
module all measure staleness against at
``ROUTER_HEARTBEAT_OFFLINE_STALE_MINUTES``. Making it five times fresher
would silently re-time every one of those readers -- the exact drift
``RouterService.sweep_stale_heartbeats``'s own docstring warns about.

The counters are persisted rather than kept in Redis on purpose: a worker
restart must not reset a router's progress through the debounce and start
the two-minute clock over, and "why did this not fire?" has to be a
question a ``SELECT`` can answer.

Backfill: none, and none is correct. Every existing row starts at
``reachability_state IS NULL`` ("never evaluated"), which the evaluator
treats exactly like ``unknown`` -- never alertable. The sweep promotes a
router to ``reachable`` the first time it sees recent agent contact, so a
fleet that is healthy at deploy time settles into ``reachable`` within one
sweep interval without anyone touching a row.
"""

import sqlalchemy as sa

from alembic import op

revision = "0118_add_router_reachability_columns"
down_revision = "0116_backfill_guest_consent_terms_version"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "routers",
        sa.Column("reachability_state", sa.String(length=20), nullable=True),
    )
    op.add_column(
        "routers",
        sa.Column(
            "reachability_state_changed_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "routers",
        sa.Column(
            "reachability_consecutive_misses",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.add_column(
        "routers",
        sa.Column(
            "reachability_consecutive_hits",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )


def downgrade() -> None:
    op.drop_column("routers", "reachability_consecutive_hits")
    op.drop_column("routers", "reachability_consecutive_misses")
    op.drop_column("routers", "reachability_state_changed_at")
    op.drop_column("routers", "reachability_state")
