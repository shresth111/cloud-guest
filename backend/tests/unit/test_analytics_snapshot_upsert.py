"""``analytics_snapshots`` converges on one row per rollup.

The aggregation pipeline recomputes the same rollup over and over -- 96
times a day for the 15-minute rolling window, all of those writes sharing
one ``period_start`` (``validators.day_bounds_utc`` pins it to UTC midnight
and moves only ``period_end``), plus once more when the 00:10 tick
finalizes the now-closed day. The writer used to ``INSERT`` each of those,
so production accumulated 68,501 rows carrying 789 distinct rollups.

What has to be true now is a database property, not a Python one: an
``INSERT ... ON CONFLICT DO UPDATE`` inferring a **partial**, **NULLS NOT
DISTINCT** unique index. None of that can be exercised by a fake
repository, and all of it is easy to get subtly wrong -- in particular, a
plain unique index over the same five columns would build without
complaint and then deduplicate nothing at all for the two snapshot types
that carry NULLs in the key. So these run against a real Postgres, gated
on ``CLOUDGUEST_TEST_POSTGRES_URL`` exactly as
``tests/unit/test_guest_dashboard_series.py``'s own Postgres half is
(this repo has no database-backed CI harness; that variable is what a
developer sets to run them):

    createdb cg_snapshot_upsert_test
    export CLOUDGUEST_TEST_POSTGRES_URL=\\
        postgresql+asyncpg://localhost/cg_snapshot_upsert_test
    python -m pytest tests/unit/test_analytics_snapshot_upsert.py

Each test builds a throwaway schema holding this domain's real
``analytics_snapshots`` table -- created from ``AnalyticsSnapshot
.__table__`` itself, so the index under test is the one the model
declares, not a copy of it here that could drift -- plus the two stub
parent tables its foreign keys point at, which is what lets the
organization-deleted case below be a real ``ON DELETE SET NULL`` rather
than a hand-written NULL.
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import Column, MetaData, Table, func, select, text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.schema import CreateIndex

from app.domains.analytics.constants import (
    AnalyticsGranularity,
    AnalyticsSnapshotType,
)
from app.domains.analytics.models import (
    SNAPSHOT_NATURAL_KEY_COLUMNS,
    SNAPSHOT_NATURAL_KEY_INDEX_WHERE,
    AnalyticsSnapshot,
)
from app.domains.analytics.repository import AnalyticsRepository


def _migration_0128():
    """The migration module itself, loaded the way
    ``tests/unit/test_guest_consent_terms_version.py`` already loads one --
    so the SQL under test is the SQL that will run, not a copy."""
    path = (
        pathlib.Path(__file__).resolve().parents[2]
        / "alembic"
        / "versions"
        / "0128_add_analytics_snapshot_natural_key_unique_index.py"
    )
    spec = importlib.util.spec_from_file_location("_migration_0128", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_PG_URL = os.environ.get("CLOUDGUEST_TEST_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    not _PG_URL, reason="CLOUDGUEST_TEST_POSTGRES_URL not set"
)

DAY_START = datetime(2026, 7, 25, tzinfo=UTC)
ORG_A = uuid.UUID("00000000-0000-0000-0000-00000000000a")
ORG_B = uuid.UUID("00000000-0000-0000-0000-00000000000b")
LOC_A = uuid.UUID("00000000-0000-0000-0000-0000000000a1")


@pytest.fixture
async def session():
    schema = f"snap_upsert_{uuid.uuid4().hex[:12]}"
    admin = create_async_engine(_PG_URL, isolation_level="AUTOCOMMIT")
    async with admin.connect() as conn:
        await conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(
        _PG_URL, connect_args={"server_settings": {"search_path": schema}}
    )
    # The parents the two foreign keys need. Only `id` matters: nothing
    # here reads an organization or a location, but ON DELETE SET NULL has
    # to be real for the orphan test below to mean anything.
    parents = MetaData()
    for name in ("organizations", "locations"):
        Table(name, parents, Column("id", PG_UUID(as_uuid=True), primary_key=True))
    try:
        async with engine.begin() as conn:
            await conn.run_sync(parents.create_all)
            await conn.run_sync(AnalyticsSnapshot.__table__.create)
            for org_id in (ORG_A, ORG_B):
                await conn.execute(
                    text("INSERT INTO organizations (id) VALUES (:id)"), {"id": org_id}
                )
            await conn.execute(
                text("INSERT INTO locations (id) VALUES (:id)"), {"id": LOC_A}
            )
        async with AsyncSession(engine) as db:
            yield db
    finally:
        await engine.dispose()
        async with admin.connect() as conn:
            await conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin.dispose()


def _fields(
    *,
    snapshot_type: AnalyticsSnapshotType,
    organization_id: uuid.UUID | None,
    location_id: uuid.UUID | None,
    period_end: datetime,
    metrics: dict,
    computed_at: datetime,
) -> dict:
    return {
        "organization_id": organization_id,
        "location_id": location_id,
        "snapshot_type": snapshot_type.value,
        "period_start": DAY_START,
        "period_end": period_end,
        "granularity": AnalyticsGranularity.DAILY.value,
        "metrics": metrics,
        "computed_at": computed_at,
        "computation_duration_ms": 1.0,
    }


async def _rows(session: AsyncSession) -> list[AnalyticsSnapshot]:
    result = await session.execute(
        select(AnalyticsSnapshot).order_by(AnalyticsSnapshot.created_at)
    )
    return list(result.scalars().all())


async def _count(session: AsyncSession) -> int:
    result = await session.execute(select(func.count()).select_from(AnalyticsSnapshot))
    return int(result.scalar_one())


# Every scope shape the aggregation pipeline can write, including the two
# that carry a NULL in the natural key -- which is the whole reason the
# index needs NULLS NOT DISTINCT.
SCOPES = [
    pytest.param(
        AnalyticsSnapshotType.ORG_DAILY_SUMMARY, ORG_A, None, id="org (location NULL)"
    ),
    pytest.param(
        AnalyticsSnapshotType.LOCATION_DAILY_SUMMARY, ORG_A, LOC_A, id="location"
    ),
    pytest.param(
        AnalyticsSnapshotType.PLATFORM_DAILY_SUMMARY,
        None,
        None,
        id="platform (both NULL)",
    ),
]


class TestRepeatedWritesConverge:
    @pytest.mark.parametrize(("snapshot_type", "org_id", "loc_id"), SCOPES)
    async def test_ninety_six_ticks_leave_one_row(
        self, session, snapshot_type, org_id, loc_id
    ) -> None:
        """One UTC day of the 15-minute rolling schedule, at its real
        cadence: same ``period_start`` every time, ``period_end`` and the
        numbers advancing. Before the unique index this produced 96 rows;
        it was 96 in production too."""
        repository = AnalyticsRepository(session)
        for tick in range(96):
            await repository.upsert_snapshot(
                **_fields(
                    snapshot_type=snapshot_type,
                    organization_id=org_id,
                    location_id=loc_id,
                    period_end=DAY_START + timedelta(minutes=15 * (tick + 1)),
                    metrics={"guest_count_unique": tick},
                    computed_at=DAY_START + timedelta(minutes=15 * (tick + 1)),
                )
            )
        await session.commit()

        rows = await _rows(session)
        assert len(rows) == 1
        # The surviving row is the last computation, not the first.
        assert rows[0].metrics == {"guest_count_unique": 95}
        assert rows[0].period_end == DAY_START + timedelta(days=1)
        assert rows[0].version == 96

    async def test_finalize_tick_replaces_the_days_last_partial(self, session) -> None:
        """The 00:10 "finalize yesterday" tick writes the same
        ``period_start`` as that day's 96 rolling ticks -- so it updates
        the row rather than adding a 97th. ``app.core.celery_app``'s beat
        docstring says the two "differ by period_start/period_end, so both
        can coexist"; they do not differ by ``period_start``, and a reader
        asking for yesterday's numbers wants the closed window anyway."""
        repository = AnalyticsRepository(session)
        await repository.upsert_snapshot(
            **_fields(
                snapshot_type=AnalyticsSnapshotType.ORG_DAILY_SUMMARY,
                organization_id=ORG_A,
                location_id=None,
                period_end=DAY_START + timedelta(hours=23, minutes=45),
                metrics={"guest_count_unique": 40},
                computed_at=DAY_START + timedelta(hours=23, minutes=45),
            )
        )
        await repository.upsert_snapshot(
            **_fields(
                snapshot_type=AnalyticsSnapshotType.ORG_DAILY_SUMMARY,
                organization_id=ORG_A,
                location_id=None,
                period_end=DAY_START + timedelta(days=1),
                metrics={"guest_count_unique": 41},
                computed_at=DAY_START + timedelta(days=1, minutes=10),
            )
        )
        await session.commit()

        rows = await _rows(session)
        assert len(rows) == 1
        assert rows[0].metrics == {"guest_count_unique": 41}
        assert rows[0].period_end == DAY_START + timedelta(days=1)

    async def test_distinct_keys_still_get_distinct_rows(self, session) -> None:
        """The index dedupes recomputations, never two real rollups. Two
        organizations, a location, the platform and a second day are five
        different rollups."""
        repository = AnalyticsRepository(session)
        for org_id in (ORG_A, ORG_B):
            await repository.upsert_snapshot(
                **_fields(
                    snapshot_type=AnalyticsSnapshotType.ORG_DAILY_SUMMARY,
                    organization_id=org_id,
                    location_id=None,
                    period_end=DAY_START + timedelta(days=1),
                    metrics={},
                    computed_at=DAY_START,
                )
            )
        await repository.upsert_snapshot(
            **_fields(
                snapshot_type=AnalyticsSnapshotType.LOCATION_DAILY_SUMMARY,
                organization_id=ORG_A,
                location_id=LOC_A,
                period_end=DAY_START + timedelta(days=1),
                metrics={},
                computed_at=DAY_START,
            )
        )
        await repository.upsert_snapshot(
            **_fields(
                snapshot_type=AnalyticsSnapshotType.PLATFORM_DAILY_SUMMARY,
                organization_id=None,
                location_id=None,
                period_end=DAY_START + timedelta(days=1),
                metrics={},
                computed_at=DAY_START,
            )
        )
        second_day = _fields(
            snapshot_type=AnalyticsSnapshotType.ORG_DAILY_SUMMARY,
            organization_id=ORG_A,
            location_id=None,
            period_end=DAY_START + timedelta(days=2),
            metrics={},
            computed_at=DAY_START + timedelta(days=1),
        )
        second_day["period_start"] = DAY_START + timedelta(days=1)
        await repository.upsert_snapshot(**second_day)
        await session.commit()

        assert await _count(session) == 5

    async def test_a_soft_deleted_row_does_not_swallow_later_writes(
        self, session
    ) -> None:
        """Nothing soft-deletes a snapshot today, but if something did,
        the next recomputation must not vanish into a row no reader can
        see -- every read path in this domain filters ``is_deleted``."""
        repository = AnalyticsRepository(session)
        fields = _fields(
            snapshot_type=AnalyticsSnapshotType.ORG_DAILY_SUMMARY,
            organization_id=ORG_A,
            location_id=None,
            period_end=DAY_START + timedelta(hours=1),
            metrics={"guest_count_unique": 1},
            computed_at=DAY_START + timedelta(hours=1),
        )
        snapshot = await repository.upsert_snapshot(**fields)
        snapshot.mark_deleted()
        await session.flush()

        await repository.upsert_snapshot(
            **{**fields, "metrics": {"guest_count_unique": 2}}
        )
        await session.commit()

        rows = await _rows(session)
        assert len(rows) == 1
        assert rows[0].is_deleted is False
        assert rows[0].deleted_at is None
        assert rows[0].metrics == {"guest_count_unique": 2}


class TestWhyNullsNotDistinct:
    async def test_a_plain_unique_index_would_deduplicate_nothing(
        self, session
    ) -> None:
        """The failure mode this index's ``NULLS NOT DISTINCT`` exists to
        avoid, stated as a test so that anyone "simplifying" it back to a
        plain unique index sees why it was not one. Under Postgres's
        default rule NULL never equals NULL, so the platform snapshot --
        both scope columns NULL, by design -- collides with nothing, and
        the index builds happily while the duplicates keep accumulating."""
        migration = _migration_0128()
        await session.execute(text(f"DROP INDEX {migration.INDEX_NAME}"))
        await session.execute(
            text(
                f"CREATE UNIQUE INDEX uq_nulls_distinct ON analytics_snapshots "
                f"({', '.join(SNAPSHOT_NATURAL_KEY_COLUMNS)}) "
                f"WHERE {migration.INDEX_WHERE}"
            )
        )

        table = AnalyticsSnapshot.__table__
        now = datetime.now(UTC)
        for tick in range(2):
            await session.execute(
                table.insert().values(
                    id=uuid.uuid4(),
                    created_at=now,
                    updated_at=now,
                    is_deleted=False,
                    version=1,
                    organization_id=None,
                    location_id=None,
                    snapshot_type=AnalyticsSnapshotType.PLATFORM_DAILY_SUMMARY.value,
                    period_start=DAY_START,
                    period_end=DAY_START + timedelta(days=1),
                    granularity=AnalyticsGranularity.DAILY.value,
                    metrics={"tick": tick},
                    computed_at=now,
                    computation_duration_ms=1.0,
                )
            )
        await session.commit()

        assert await _count(session) == 2


class TestOrphanedRowsAreOutsideTheIndex:
    async def test_two_deleted_organizations_keep_their_own_history(
        self, session
    ) -> None:
        """Production holds 7,879 ``org_daily_summary`` rows with a NULL
        ``organization_id``. No writer can produce one -- they are what
        ``ondelete="SET NULL"`` leaves when an organization row is
        hard-deleted -- and once both scope columns read NULL, two
        tenants' summaries for one day are indistinguishable. A *total*
        NULLS NOT DISTINCT index would therefore call one of them a
        duplicate of the other; the partial predicate is what keeps both,
        and what keeps deleting a second organization from failing on a
        unique violation raised by the foreign key itself."""
        repository = AnalyticsRepository(session)
        for org_id in (ORG_A, ORG_B):
            await repository.upsert_snapshot(
                **_fields(
                    snapshot_type=AnalyticsSnapshotType.ORG_DAILY_SUMMARY,
                    organization_id=org_id,
                    location_id=None,
                    period_end=DAY_START + timedelta(days=1),
                    metrics={"guest_count_unique": 7},
                    computed_at=DAY_START,
                )
            )
        await session.commit()

        await session.execute(text("DELETE FROM organizations"))
        await session.commit()

        rows = await _rows(session)
        assert len(rows) == 2
        assert [row.organization_id for row in rows] == [None, None]


class TestMigrationDeduplication:
    async def test_dedupe_keeps_the_newest_and_leaves_orphans_alone(
        self, session
    ) -> None:
        """The migration's own ``DEDUPE_SQL``, run against real rows: the
        duplicates a plain INSERT left behind collapse to the most
        recently computed row per key, and the orphaned rows outside the
        index predicate are not touched."""
        migration = _migration_0128()

        # Pre-migration state: the table as it stood before this change,
        # with no unique index on it at all. Without dropping it first
        # there is no way to even write the rows the migration exists to
        # clean up.
        await session.execute(text(f"DROP INDEX {migration.INDEX_NAME}"))

        # What the old writer produced: ten identical appends of one key.
        table = AnalyticsSnapshot.__table__
        now = datetime.now(UTC)
        for tick in range(10):
            await session.execute(
                table.insert().values(
                    id=uuid.uuid4(),
                    created_at=now + timedelta(minutes=tick),
                    updated_at=now + timedelta(minutes=tick),
                    is_deleted=False,
                    version=1,
                    organization_id=ORG_A,
                    location_id=None,
                    snapshot_type=AnalyticsSnapshotType.ORG_DAILY_SUMMARY.value,
                    period_start=DAY_START,
                    period_end=DAY_START + timedelta(days=1),
                    granularity=AnalyticsGranularity.DAILY.value,
                    metrics={"guest_count_unique": tick},
                    computed_at=DAY_START + timedelta(minutes=tick),
                    computation_duration_ms=1.0,
                )
            )
        # And two orphans: same key once organization_id reads NULL, but
        # outside the index predicate, so not duplicates of each other.
        for orphan in range(2):
            await session.execute(
                table.insert().values(
                    id=uuid.uuid4(),
                    created_at=now,
                    updated_at=now,
                    is_deleted=False,
                    version=1,
                    organization_id=None,
                    location_id=None,
                    snapshot_type=AnalyticsSnapshotType.ORG_DAILY_SUMMARY.value,
                    period_start=DAY_START,
                    period_end=DAY_START + timedelta(days=1),
                    granularity=AnalyticsGranularity.DAILY.value,
                    metrics={"orphan": orphan},
                    computed_at=DAY_START,
                    computation_duration_ms=1.0,
                )
            )
        await session.commit()
        assert await _count(session) == 12

        await session.execute(text(migration.DEDUPE_SQL))
        await session.commit()

        rows = await _rows(session)
        assert len(rows) == 3
        survivor = next(row for row in rows if row.organization_id == ORG_A)
        assert survivor.metrics == {"guest_count_unique": 9}
        assert sum(1 for row in rows if row.organization_id is None) == 2

        # And the index the migration goes on to create now builds -- the
        # model's own Index object, which is the same DDL minus
        # CONCURRENTLY (which cannot run inside a transaction).
        index = next(
            ix
            for ix in AnalyticsSnapshot.__table__.indexes
            if ix.name == migration.INDEX_NAME
        )
        await session.execute(CreateIndex(index))
        await session.commit()

        # The migration and the model must not have drifted apart.
        assert migration.INDEX_WHERE == SNAPSHOT_NATURAL_KEY_INDEX_WHERE
        assert tuple(c.name for c in index.columns) == SNAPSHOT_NATURAL_KEY_COLUMNS
