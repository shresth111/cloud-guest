"""``analytics_snapshots`` -- one row per rollup, enforced.

## What was measured

On production (PostgreSQL 17.11) on 2026-09-22, ``analytics_snapshots``
held **68,501 rows carrying 789 distinct rollups -- 98.8% duplicates**, and
was still growing by roughly 3,300 duplicate rows a day. One organization's
2026-07-25 summary alone had **960 rows**, every one of them written
between 00:00:08 and 00:10:00 the following morning, and
``count(DISTINCT metrics)`` across all 960 was **1**: byte-identical
copies. The per-key multiplicity followed the Beat schedule exactly --
``org_daily_summary`` 96x (the 15-minute rolling tick, 96 ticks a day),
``platform_daily_summary`` 90x, ``location_daily_summary`` 77x. The
master dashboard's snapshot read had become a sequential scan over all
68,501 rows; against the deduplicated set the same global query ran in
0.34ms instead of 59.5ms.

The cause is ``app.domains.analytics.repository.AnalyticsRepository``'s
snapshot writer, which issued a plain ``INSERT``. Recomputation is the
normal case for this table, not an exception -- the rolling tick pins
``period_start`` to UTC midnight and advances only ``period_end``
(``validators.day_bounds_utc``), so all 96 of a day's writes carry one
natural key -- and nothing in the schema said a rollup was allowed to
exist only once. This migration adds the missing constraint; the writer
becomes an ``ON CONFLICT DO UPDATE`` in the same change.

## The order of the two steps here is not a style choice

The index cannot exist before the writer that knows how to conflict
against it. If it reaches a database still served by the old plain-INSERT
writer, every aggregation tick raises a unique violation and analytics
stops being computed at all -- a worse outcome than the duplicates. The
writer fix and this migration ship in the same deploy for that reason.

Within the migration, the deduplication must likewise precede the index:
``CREATE UNIQUE INDEX`` on a table that still holds 67,712 duplicate rows
simply fails.

## Why the index is partial, and NULLS NOT DISTINCT

Both scope columns are nullable and both carry real meaning when NULL: a
``platform_daily_summary`` row has ``organization_id`` and ``location_id``
NULL by design, and an ``org_daily_summary`` row has ``location_id`` NULL
by design. Under Postgres's default ``NULLS DISTINCT`` rule, NULL never
equals NULL, so a plain unique index would have built happily and
deduplicated **nothing** for exactly the two snapshot types that most
needed it. ``NULLS NOT DISTINCT`` (Postgres 15+; both ``docker-compose
.yml`` and ``deploy/docker-compose.prod.yml`` run ``postgres:17-alpine``,
and production reports 17.11) is what makes those rows comparable. It is
preferred here over the portable alternative -- a ``COALESCE(column,
'00000000-...'::uuid)`` expression index -- because the sentinel approach
puts a fake UUID into the index, cannot be read back as the plain column
tuple it stands for, and would have to be spelled identically in the
model, in the ``ON CONFLICT`` arbiter and here, in three places, forever.

The predicate ``organization_id IS NOT NULL OR snapshot_type =
'platform_daily_summary'`` then excludes rows whose scope shape no writer
in this codebase can produce: a scoped snapshot with a NULL
``organization_id``. Production has **7,879** of those, all
``org_daily_summary``. They are not a second writer bug --
``AnalyticsService.compute_and_store_org_daily_summary`` takes a
non-optional ``uuid.UUID``, so no code path can emit one -- they are what
``ondelete="SET NULL"`` leaves behind when an organization row is
hard-deleted out from under its own history. Indexing them would be
actively harmful: two different deleted organizations' summaries for the
same day are indistinguishable once both scope columns read NULL, so the
deduplication below would delete one real tenant's history as a
"duplicate" of another's, and any future organization delete would fail on
a unique violation raised by the FK's own ``SET NULL``. Excluded, they are
left exactly as they are, for the separate decision about what an
unattributable rollup should become.

Revision ID: 0128_add_analytics_snapshot_natural_key_unique_index
Revises: 0127_create_guest_access_controller_blocks
Create Date: 2026-09-22
"""

import sqlalchemy as sa

from alembic import op

revision = "0128_add_analytics_snapshot_natural_key_unique_index"
down_revision = "0127_create_guest_access_controller_blocks"
branch_labels = None
depends_on = None

INDEX_NAME = "uq_analytics_snapshots_natural_key"

# Kept identical to app.domains.analytics.models
# .SNAPSHOT_NATURAL_KEY_INDEX_WHERE, spelled out rather than imported
# because a migration must keep describing the database it was written
# against even after the model moves on.
INDEX_WHERE = "organization_id IS NOT NULL OR snapshot_type = 'platform_daily_summary'"


# Step 1 -- collapse each natural key to its most recently computed row.
# Not "any one of them": the 15-minute rolling tick and the 00:10 finalize
# tick share a key, so within a key the newest computed_at is the closed,
# authoritative window and the older rows are superseded partials.
# computed_at is NOT NULL on this table; created_at and id break ties
# deterministically, so re-running this cannot pick a different survivor.
# Module-level so tests/unit/test_analytics_snapshot_upsert.py can run this
# exact statement against a real Postgres rather than a paraphrase of it.
DEDUPE_SQL = f"""
DELETE FROM analytics_snapshots
WHERE id IN (
    SELECT id FROM (
        SELECT
            id,
            row_number() OVER (
                PARTITION BY
                    snapshot_type,
                    organization_id,
                    location_id,
                    period_start,
                    granularity
                ORDER BY computed_at DESC, created_at DESC, id DESC
            ) AS rn
        FROM analytics_snapshots
        WHERE {INDEX_WHERE}
    ) ranked
    WHERE ranked.rn > 1
)
"""


INDEX_IS_VALID_SQL = f"""
SELECT i.indisvalid
FROM pg_index i
JOIN pg_class c ON c.oid = i.indexrelid
WHERE c.relname = '{INDEX_NAME}'
"""


def _create_index_concurrently() -> None:
    op.create_index(
        INDEX_NAME,
        "analytics_snapshots",
        [
            "snapshot_type",
            "organization_id",
            "location_id",
            "period_start",
            "granularity",
        ],
        unique=True,
        postgresql_concurrently=True,
        postgresql_nulls_not_distinct=True,
        postgresql_where=sa.text(INDEX_WHERE),
    )


def upgrade() -> None:
    op.execute(DEDUPE_SQL)

    # Step 2 -- the constraint itself. CONCURRENTLY because this table is
    # read by the master dashboard on a live production database and a
    # plain CREATE INDEX holds a lock that blocks those reads' writers for
    # the duration of the build; it has to run outside the migration's
    # transaction, which is what autocommit_block is for (the same shape
    # 0075_add_isp_health_check_composite_index already uses here).
    #
    # The retry is not defensiveness for its own sake. `deploy/remote-
    # deploy.sh` runs `docker compose up -d --no-deps api celery-worker
    # celery-beat`, and the api image's own CMD is what runs `alembic
    # upgrade head` -- so for the few seconds compose takes to replace the
    # worker, a container running the OLD plain-INSERT writer can still be
    # alive while this index builds. One duplicate row arriving in that
    # window fails the build, and a failed CONCURRENTLY build leaves an
    # *invalid* index behind rather than nothing at all: the name is
    # taken, nothing enforces anything, and the next attempt fails on the
    # name. Since the api's CMD runs this migration, an unhandled failure
    # here is an api container that crash-loops until the deploy's health
    # wait times out and rolls back. So: drop whatever is there, build,
    # and if the result is missing or invalid, re-deduplicate (the
    # straggler's row is a duplicate by definition) and try once more.
    with op.get_context().autocommit_block():
        for attempt in (1, 2):
            op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {INDEX_NAME}")
            try:
                _create_index_concurrently()
                valid = op.get_bind().execute(sa.text(INDEX_IS_VALID_SQL))
                built = bool(valid.scalar())
            except Exception:
                if attempt == 2:
                    raise
                built = False
            if built:
                return
            if attempt == 2:
                raise RuntimeError(
                    f"{INDEX_NAME} could not be built. A writer is still "
                    "inserting duplicate analytics_snapshots rows -- check "
                    "that no container is running the pre-upsert "
                    "AnalyticsRepository, then re-run this migration."
                )
            op.execute(DEDUPE_SQL)


def downgrade() -> None:
    # The duplicate rows deleted above are not restored, and could not be:
    # they were byte-identical copies of the row that survived.
    with op.get_context().autocommit_block():
        op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {INDEX_NAME}")
