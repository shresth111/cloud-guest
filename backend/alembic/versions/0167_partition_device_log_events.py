"""Device Logs -> NetLogs: monthly range partitions on ``device_log_events``,
structured columns, customer-query indexes.

What it does, in one transaction:

1. Takes ``ACCESS EXCLUSIVE`` on ``device_log_events`` (``lock_timeout`` 15s,
   so it fails fast instead of queueing behind a long reader and stalling
   every writer behind *it*). Ingest blocks while this runs; the collector
   retries un-acknowledged batches, so nothing is lost.
2. Drops the ``guest_device_events -> device_log_events(id)`` FK. A
   partitioned table cannot have a unique key on ``id`` alone (every unique
   key must include ``received_at``), so the FK cannot exist any more;
   retention deletes derived rows explicitly (``partitions``).
3. Renames the old table to ``device_log_events_legacy`` and creates the
   partitioned ``device_log_events`` with the six new nullable columns
   (``category``, ``protocol``, ``src_ip``, ``dst_ip``, ``status``,
   ``device_mac``) and PK ``(id, received_at)``.
4. Creates one partition per month from the oldest row's month through
   three months ahead, plus a DEFAULT partition.
5. Copies every row with its original ``id`` (``OVERRIDING SYSTEM VALUE``),
   moves the identity sequence past ``max(id)``, and **aborts the whole
   migration if the row counts differ**. Then drops the legacy table.
6. Indexes: received_at; (organization_id, received_at); (location_id,
   received_at); (router_id, received_at); (organization_id, category,
   received_at). A ``pg_trgm`` GIN index on ``message`` only if the
   extension is available and creatable -- skipped with a NOTICE otherwise.

New columns are left NULL on copied rows: the migration imports no app code.
``python -m app.domains.device_logs.backfill_classification`` fills them
(idempotent, batched), the same pattern as ``backfill_guest_events``.

Cost: the copy is O(rows). At the volume prod held on 2026-10-18 (feature
live since 2026-10-07, collector-throttled) it is seconds; measure with
``SELECT count(*) FROM device_log_events`` before deploying -- see the PR.

Revision ID: 0167_partition_device_log_events
Revises: 0166_add_review_prompt_columns_to_guest_sessions
Create Date: 2026-10-18
"""

from __future__ import annotations

from alembic import op

revision = "0167_partition_device_log_events"
down_revision = "0166_add_review_prompt_columns_to_guest_sessions"
branch_labels = None
depends_on = None

_COLUMNS = """
    id BIGINT GENERATED ALWAYS AS IDENTITY,
    received_at TIMESTAMPTZ NOT NULL,
    device_time TIMESTAMPTZ NULL,
    organization_id UUID NULL REFERENCES organizations (id) ON DELETE SET NULL,
    location_id UUID NULL REFERENCES locations (id) ON DELETE SET NULL,
    router_id UUID NULL REFERENCES routers (id) ON DELETE SET NULL,
    source_ip VARCHAR(45) NOT NULL,
    vendor VARCHAR(32) NOT NULL,
    source VARCHAR(32) NOT NULL,
    facility SMALLINT NULL,
    severity SMALLINT NULL,
    hostname VARCHAR(255) NULL,
    topics VARCHAR(200) NULL,
    message TEXT NOT NULL,
    attribution VARCHAR(32) NOT NULL,
    claimed_tag VARCHAR(16) NULL
"""

_OLD_COLUMNS = (
    "id, received_at, device_time, organization_id, location_id, router_id, "
    "source_ip, vendor, source, facility, severity, hostname, topics, message, "
    "attribution, claimed_tag"
)

_OLD_INDEXES = (
    "ix_device_log_events_received_at",
    "ix_device_log_events_router_received",
    "ix_device_log_events_org_received",
)

_NEW_INDEXES = (
    ("ix_device_log_events_received_at", "(received_at)"),
    ("ix_device_log_events_org_received", "(organization_id, received_at)"),
    ("ix_device_log_events_location_received", "(location_id, received_at)"),
    ("ix_device_log_events_router_received", "(router_id, received_at)"),
    (
        "ix_device_log_events_org_category_received",
        "(organization_id, category, received_at)",
    ),
)

# Months from the oldest stored row (or now) through 3 ahead, plus DEFAULT.
_CREATE_PARTITIONS = """
DO $$
DECLARE
    first_month date := date_trunc(
        'month',
        coalesce(
            (SELECT min(received_at) FROM device_log_events_legacy), now()
        ) AT TIME ZONE 'UTC'
    )::date;
    last_month date := (
        date_trunc('month', now() AT TIME ZONE 'UTC') + interval '3 months'
    )::date;
    m date;
BEGIN
    m := first_month;
    WHILE m <= last_month LOOP
        EXECUTE format(
            'CREATE TABLE %I PARTITION OF device_log_events '
            'FOR VALUES FROM (%L) TO (%L)',
            'device_log_events_p' || to_char(m, 'YYYYMM'),
            m::text || ' 00:00:00+00',
            (m + interval '1 month')::date::text || ' 00:00:00+00'
        );
        m := (m + interval '1 month')::date;
    END LOOP;
    CREATE TABLE device_log_events_default
        PARTITION OF device_log_events DEFAULT;
END $$;
"""

_VERIFY_COUNTS = """
DO $$
DECLARE
    old_count bigint := (SELECT count(*) FROM device_log_events_legacy);
    new_count bigint := (SELECT count(*) FROM device_log_events);
BEGIN
    IF old_count <> new_count THEN
        RAISE EXCEPTION
            'device_log_events partition copy mismatch: legacy=% new=%',
            old_count, new_count;
    END IF;
END $$;
"""

_TRGM = """
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'pg_trgm') THEN
        BEGIN
            CREATE EXTENSION IF NOT EXISTS pg_trgm;
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'pg_trgm not creatable (%), skipping trigram index',
                SQLERRM;
        END;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm') THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS ix_device_log_events_message_trgm '
                'ON device_log_events USING gin (message gin_trgm_ops)';
    ELSE
        RAISE NOTICE 'pg_trgm unavailable, skipping trigram index';
    END IF;
END $$;
"""

_DROP_GUEST_FK = """
DO $$
DECLARE
    fk record;
BEGIN
    FOR fk IN
        SELECT conname FROM pg_constraint
        WHERE conrelid = 'guest_device_events'::regclass
          AND confrelid = 'device_log_events'::regclass
          AND contype = 'f'
    LOOP
        EXECUTE format(
            'ALTER TABLE guest_device_events DROP CONSTRAINT %I', fk.conname
        );
    END LOOP;
END $$;
"""


def _rename_identity_sequence(table: str) -> str:
    """Move the renamed table's identity sequence out of the way, so the new
    table's own sequence gets the plain ``device_log_events_id_seq`` name.
    Looked up, not hard-coded: the name differs after a downgrade."""
    return f"""
DO $$
DECLARE
    seq text := pg_get_serial_sequence('{table}', 'id');
BEGIN
    IF seq IS NOT NULL THEN
        EXECUTE format('ALTER SEQUENCE %s RENAME TO {table}_id_seq', seq);
    END IF;
END $$;
"""


def upgrade() -> None:
    op.execute("SET LOCAL lock_timeout = '15s'")
    op.execute("LOCK TABLE device_log_events IN ACCESS EXCLUSIVE MODE")
    op.execute(_DROP_GUEST_FK)

    op.execute("ALTER TABLE device_log_events RENAME TO device_log_events_legacy")
    op.execute(
        "ALTER TABLE device_log_events_legacy "
        "RENAME CONSTRAINT device_log_events_pkey TO device_log_events_legacy_pkey"
    )
    op.execute(_rename_identity_sequence("device_log_events_legacy"))
    for name in _OLD_INDEXES:
        op.execute(f"DROP INDEX IF EXISTS {name}")

    op.execute(
        f"""
        CREATE TABLE device_log_events (
            {_COLUMNS},
            category VARCHAR(32) NULL,
            protocol VARCHAR(16) NULL,
            src_ip VARCHAR(45) NULL,
            dst_ip VARCHAR(45) NULL,
            status VARCHAR(16) NULL,
            device_mac VARCHAR(17) NULL,
            CONSTRAINT device_log_events_pkey PRIMARY KEY (id, received_at)
        ) PARTITION BY RANGE (received_at)
        """
    )
    op.execute(_CREATE_PARTITIONS)

    op.execute(
        f"INSERT INTO device_log_events ({_OLD_COLUMNS}) OVERRIDING SYSTEM VALUE "
        f"SELECT {_OLD_COLUMNS} FROM device_log_events_legacy"
    )
    op.execute(
        "SELECT setval(pg_get_serial_sequence('device_log_events', 'id'), "
        "coalesce((SELECT max(id) FROM device_log_events), 0) + 1, false)"
    )
    op.execute(_VERIFY_COUNTS)
    op.execute("DROP TABLE device_log_events_legacy")

    for name, columns in _NEW_INDEXES:
        op.execute(f"CREATE INDEX {name} ON device_log_events {columns}")
    op.execute(_TRGM)


def downgrade() -> None:
    """Back to one plain table. The six structured columns are dropped (they
    are derivable again from ``message``); rows and ids are kept, the FK
    from ``guest_device_events`` is restored."""
    op.execute("SET LOCAL lock_timeout = '15s'")
    op.execute("LOCK TABLE device_log_events IN ACCESS EXCLUSIVE MODE")
    op.execute("DROP INDEX IF EXISTS ix_device_log_events_message_trgm")
    op.execute("ALTER TABLE device_log_events RENAME TO device_log_events_parted")
    op.execute(
        "ALTER TABLE device_log_events_parted "
        "RENAME CONSTRAINT device_log_events_pkey TO device_log_events_parted_pkey"
    )
    op.execute(_rename_identity_sequence("device_log_events_parted"))
    for name, _ in _NEW_INDEXES:
        op.execute(f"DROP INDEX IF EXISTS {name}")
    op.execute(
        f"""
        CREATE TABLE device_log_events (
            {_COLUMNS},
            CONSTRAINT device_log_events_pkey PRIMARY KEY (id)
        )
        """
    )
    op.execute(
        f"INSERT INTO device_log_events ({_OLD_COLUMNS}) OVERRIDING SYSTEM VALUE "
        f"SELECT {_OLD_COLUMNS} FROM device_log_events_parted"
    )
    op.execute(
        "SELECT setval(pg_get_serial_sequence('device_log_events', 'id'), "
        "coalesce((SELECT max(id) FROM device_log_events), 0) + 1, false)"
    )
    op.execute("DROP TABLE device_log_events_parted")
    for name in _OLD_INDEXES:
        columns = {
            "ix_device_log_events_received_at": "(received_at)",
            "ix_device_log_events_router_received": "(router_id, received_at)",
            "ix_device_log_events_org_received": "(organization_id, received_at)",
        }[name]
        op.execute(f"CREATE INDEX {name} ON device_log_events {columns}")
    # Derived rows whose source line no longer exists would violate the FK.
    op.execute(
        "DELETE FROM guest_device_events g WHERE NOT EXISTS "
        "(SELECT 1 FROM device_log_events d WHERE d.id = g.device_log_event_id)"
    )
    op.execute(
        "ALTER TABLE guest_device_events ADD CONSTRAINT "
        "guest_device_events_device_log_event_id_fkey FOREIGN KEY "
        "(device_log_event_id) REFERENCES device_log_events (id) ON DELETE CASCADE"
    )
