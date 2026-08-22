"""The double-booking constraint, exercised against a real database.

This module is deliberately separate from ``test_demo_booking.py`` (which
tests the service layer against in-memory fakes) because it is testing
something a fake cannot test: **that the schema itself refuses a second
booking of the same instant.** The whole design rests on that claim -- the
service performs no "is this slot free?" query at all -- so the claim is
verified against a database engine actually executing the DDL that
``app.domains.demo_booking.models`` declares and that
``alembic/versions/0096_create_demo_bookings_table.py`` creates.

## Why SQLite, and what that does and does not prove

Production is PostgreSQL. CI (``.github/workflows/ci.yml``) runs
``pytest`` with no database service of any kind, and the existing suite is
built entirely on in-memory fakes for exactly that reason. A test that
only runs when someone happens to have Postgres on localhost is a test
that reports success while doing nothing in CI -- precisely the failure
mode this codebase has been burned by. So these tests run everywhere, on
SQLite, which supports partial unique indexes.

What that proves: the index definition on the model is real DDL, it is
accepted by a database engine, its **partial predicate** genuinely scopes
it to ``status = 'confirmed' AND is_deleted = 0``, a second concurrent
insert of the same instant is genuinely rejected, an ``UPDATE`` that moves
a booking onto a held instant is rejected by the same index, and
``repository.is_active_slot_conflict`` correctly recognizes the resulting
error.

What it does not prove: PostgreSQL-specific behaviour. SQLite serializes
writers with a file lock, so the two racing threads below are serialized
by the lock and then rejected by the index, whereas Postgres lets both
inserts proceed and rejects the loser on index insertion. Both end in
"exactly one row exists, the loser got an integrity error" -- which is the
property the application depends on -- but the mechanism differs. The
predicate spelling also differs (``false`` vs ``0``), which is why
``models`` declares both ``postgresql_where`` and ``sqlite_where``; the
migration, which only ever runs against Postgres, hard-codes the Postgres
spelling.
"""

from __future__ import annotations

import sqlite3
import threading
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.compiler import compiles

from app.domains.demo_booking.constants import DemoBookingStatus
from app.domains.demo_booking.models import ACTIVE_SLOT_INDEX_NAME, DemoBooking
from app.domains.demo_booking.repository import is_active_slot_conflict
from app.domains.demo_request.models import DemoRequest

# Imported for its side effect only: DemoBooking's two delivery foreign
# keys name `notification_deliveries`, and SQLAlchemy resolves a FK target
# by table name within the shared MetaData. The table is never *created*
# here (SQLite accepts a dangling REFERENCES clause and does not enforce
# foreign keys unless asked to) -- only registered, so the real
# DemoBooking DDL can be emitted unmodified.
from app.domains.notification.models import NotificationDelivery  # noqa: F401


@compiles(PostgresUUID, "sqlite")
def _compile_pg_uuid_on_sqlite(element, compiler, **kw) -> str:  # noqa: ARG001
    """Render ``postgresql.UUID`` as ``CHAR(36)`` on SQLite.

    ``BaseModel`` uses the PostgreSQL-dialect UUID type for every primary
    key, which has no SQLite rendering. Registering this compilation rule
    lets the *unmodified* production table definitions be created on
    SQLite, so what is tested below is the real ``DemoBooking.__table__``
    -- same columns, same index, same predicate -- rather than a
    hand-written lookalike that could drift from it.
    """
    return "CHAR(36)"


SLOT = datetime(2026, 9, 1, 5, 30, tzinfo=UTC)  # 11:00 IST


@pytest.fixture
def engine(tmp_path):
    """A file-backed SQLite database with the real demo tables.

    File-backed, not ``:memory:``: the concurrency test needs two
    genuinely independent connections looking at the same database, which
    an in-memory database does not provide.
    """
    url = f"sqlite:///{tmp_path / 'demo_booking.db'}"
    engine = create_engine(url)

    @event.listens_for(engine, "connect")
    def _set_busy_timeout(dbapi_connection, _record) -> None:
        # Without this, the losing writer gets "database is locked"
        # instead of waiting for the winner to commit and then hitting the
        # unique index. The test wants the *constraint* to be what rejects
        # the second booking, not lock contention.
        dbapi_connection.execute("PRAGMA busy_timeout = 5000")

    # Only the two tables under test. demo_bookings' foreign keys to
    # notification_deliveries are left dangling on purpose -- SQLite does
    # not enforce foreign keys unless asked to, and creating the entire
    # 100-table schema here would be testing SQLAlchemy, not this index.
    DemoRequest.__table__.create(engine)
    DemoBooking.__table__.create(engine)
    yield engine
    engine.dispose()


def _new_lead(engine, email: str = "race@example.com") -> uuid.UUID:
    lead_id = uuid.uuid4()
    now = datetime.now(UTC)
    with engine.begin() as connection:
        connection.execute(
            DemoRequest.__table__.insert().values(
                id=lead_id,
                created_at=now,
                updated_at=now,
                is_deleted=False,
                version=1,
                full_name="Race Tester",
                email=email,
                company_name="Race Co",
                status="new",
            )
        )
    return lead_id


def _booking_values(lead_id: uuid.UUID, starts_at: datetime, **overrides):
    now = datetime.now(UTC)
    values = {
        "id": uuid.uuid4(),
        "created_at": now,
        "updated_at": now,
        "is_deleted": False,
        "version": 1,
        "demo_request_id": lead_id,
        "starts_at": starts_at,
        "ends_at": starts_at + timedelta(minutes=30),
        "status": DemoBookingStatus.CONFIRMED.value,
        "booked_timezone": "Asia/Kolkata",
        "manage_token_hash": "0" * 64,
    }
    values.update(overrides)
    return values


def _insert(engine, lead_id: uuid.UUID, starts_at: datetime, **overrides) -> None:
    with engine.begin() as connection:
        connection.execute(
            DemoBooking.__table__.insert().values(
                _booking_values(lead_id, starts_at, **overrides)
            )
        )


def _confirmed_count(engine, starts_at: datetime) -> int:
    with engine.connect() as connection:
        return int(
            connection.execute(
                select(func.count())
                .select_from(DemoBooking.__table__)
                .where(
                    DemoBooking.__table__.c.starts_at == starts_at,
                    DemoBooking.__table__.c.status
                    == DemoBookingStatus.CONFIRMED.value,
                    DemoBooking.__table__.c.is_deleted.is_(False),
                )
            ).scalar_one()
        )


# ==========================================================================
# The race
# ==========================================================================


class TestConcurrentBookingOfTheSameSlot:
    def test_two_concurrent_bookings_of_the_same_slot_exactly_one_wins(self, engine):
        """Two threads, two connections, no coordination beyond a barrier
        that releases them together, both inserting the identical
        ``starts_at``.

        Exactly one commits. The other is rejected **by the database**, not
        by any check in the application -- there is no such check to
        remove. This is the single most important behaviour in the feature:
        without it, two visitors are both told "confirmed" and one of them
        arrives to a meeting nobody knows about.
        """
        lead_a = _new_lead(engine, "a@example.com")
        lead_b = _new_lead(engine, "b@example.com")

        barrier = threading.Barrier(2)
        outcomes: list[str] = []
        errors: list[Exception] = []
        lock = threading.Lock()

        def attempt(lead_id: uuid.UUID) -> None:
            barrier.wait()
            try:
                _insert(engine, lead_id, SLOT)
                with lock:
                    outcomes.append("won")
            except IntegrityError as exc:
                with lock:
                    outcomes.append("lost")
                    errors.append(exc)

        threads = [
            threading.Thread(target=attempt, args=(lead_a,)),
            threading.Thread(target=attempt, args=(lead_b,)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)

        assert sorted(outcomes) == ["lost", "won"], (
            f"expected exactly one winner and one loser, got {outcomes}"
        )
        assert _confirmed_count(engine, SLOT) == 1
        # And the loser's error is recognised as *this* constraint, not as
        # some generic integrity failure -- that classification is what
        # turns it into a 409 rather than a 500.
        assert is_active_slot_conflict(errors[0]) is True

    def test_sequential_second_booking_of_the_same_slot_is_rejected(self, engine):
        """The non-racing case: the slot is simply already held."""
        lead_a = _new_lead(engine, "a@example.com")
        lead_b = _new_lead(engine, "b@example.com")
        _insert(engine, lead_a, SLOT)

        with pytest.raises(IntegrityError) as excinfo:
            _insert(engine, lead_b, SLOT)

        assert is_active_slot_conflict(excinfo.value) is True
        assert _confirmed_count(engine, SLOT) == 1

    def test_different_slots_do_not_collide(self, engine):
        lead = _new_lead(engine)
        _insert(engine, lead, SLOT)
        _insert(engine, lead, SLOT + timedelta(minutes=30))
        assert _confirmed_count(engine, SLOT) == 1
        assert _confirmed_count(engine, SLOT + timedelta(minutes=30)) == 1


# ==========================================================================
# The partial predicate -- the half that makes cancellation real
# ==========================================================================


class TestPartialPredicate:
    def test_cancelling_frees_the_slot_for_someone_else(self, engine):
        """A cancelled booking leaves the index, so the time is genuinely
        bookable again. If the index were not partial this would raise, and
        every cancellation would be a permanent tombstone on that time."""
        lead_a = _new_lead(engine, "a@example.com")
        lead_b = _new_lead(engine, "b@example.com")
        _insert(engine, lead_a, SLOT)

        with engine.begin() as connection:
            connection.execute(
                DemoBooking.__table__.update()
                .where(DemoBooking.__table__.c.demo_request_id == lead_a)
                .values(status=DemoBookingStatus.CANCELLED.value)
            )

        _insert(engine, lead_b, SLOT)  # must not raise
        assert _confirmed_count(engine, SLOT) == 1

    def test_soft_deleting_frees_the_slot(self, engine):
        lead_a = _new_lead(engine, "a@example.com")
        lead_b = _new_lead(engine, "b@example.com")
        _insert(engine, lead_a, SLOT)

        with engine.begin() as connection:
            connection.execute(
                DemoBooking.__table__.update()
                .where(DemoBooking.__table__.c.demo_request_id == lead_a)
                .values(is_deleted=True)
            )

        _insert(engine, lead_b, SLOT)
        assert _confirmed_count(engine, SLOT) == 1

    def test_two_cancelled_bookings_may_share_an_instant(self, engine):
        """Non-holding rows are outside the index entirely -- so history
        can accumulate on a popular time without ever blocking it."""
        lead = _new_lead(engine)
        _insert(engine, lead, SLOT, status=DemoBookingStatus.CANCELLED.value)
        _insert(engine, lead, SLOT, status=DemoBookingStatus.CANCELLED.value)
        assert _confirmed_count(engine, SLOT) == 0


# ==========================================================================
# The reschedule path is governed by the same index
# ==========================================================================


class TestRescheduleIsGovernedByTheSameIndex:
    def test_moving_a_booking_onto_a_held_slot_is_rejected(self, engine):
        """Reschedule is an ``UPDATE`` of ``starts_at``, so there is no
        second, weaker code path by which a booking can land on an occupied
        instant."""
        lead_a = _new_lead(engine, "a@example.com")
        lead_b = _new_lead(engine, "b@example.com")
        other = SLOT + timedelta(hours=1)
        _insert(engine, lead_a, SLOT)
        _insert(engine, lead_b, other)

        with pytest.raises(IntegrityError) as excinfo, engine.begin() as connection:
            connection.execute(
                DemoBooking.__table__.update()
                .where(DemoBooking.__table__.c.demo_request_id == lead_b)
                .values(starts_at=SLOT)
            )

        assert is_active_slot_conflict(excinfo.value) is True
        assert _confirmed_count(engine, SLOT) == 1
        assert _confirmed_count(engine, other) == 1


# ==========================================================================
# The index actually exists in the schema we ship
# ==========================================================================


class TestIndexIsInTheShippedSchema:
    def test_index_is_declared_on_the_model_as_a_partial_unique_index(self):
        index = next(
            i for i in DemoBooking.__table__.indexes if i.name == ACTIVE_SLOT_INDEX_NAME
        )
        assert index.unique is True
        assert [c.name for c in index.columns] == ["starts_at"]
        for dialect in ("postgresql", "sqlite"):
            predicate = str(index.dialect_options[dialect]["where"])
            assert "status = 'confirmed'" in predicate
            assert "is_deleted" in predicate

    def test_index_exists_in_the_created_database(self, engine):
        with engine.connect() as connection:
            rows = connection.exec_driver_sql(
                "SELECT name, sql FROM sqlite_master WHERE type = 'index' "
                "AND tbl_name = 'demo_bookings'"
            ).all()
        by_name = {name: sql for name, sql in rows}
        assert ACTIVE_SLOT_INDEX_NAME in by_name
        created_sql = by_name[ACTIVE_SLOT_INDEX_NAME]
        assert "UNIQUE" in created_sql.upper()
        assert "WHERE" in created_sql.upper()

    def test_migration_declares_the_same_index_name_and_predicate(self):
        """The migration is a self-contained snapshot by this repo's own
        convention, so the index name and its predicate are written twice
        -- once on the model, once in the migration. If they ever diverge,
        production gets an index the application does not know about.
        Catch that here rather than in an incident."""
        import pathlib

        source = (
            pathlib.Path(__file__).resolve().parents[2]
            / "alembic"
            / "versions"
            / "0096_create_demo_bookings_table.py"
        ).read_text()
        assert f'ACTIVE_SLOT_INDEX = "{ACTIVE_SLOT_INDEX_NAME}"' in source
        assert (
            "ACTIVE_SLOT_PREDICATE = \"status = 'confirmed' AND is_deleted = false\""
            in source
        )


def test_sqlite_supports_partial_indexes(engine):
    """A guard on the guard: if the SQLite build in some future CI image
    did not support partial indexes, every test above would pass
    vacuously against a *full* unique index -- and the cancellation tests
    would fail loudly, which is the point. This asserts the capability
    directly so the reason is obvious."""
    assert sqlite3.sqlite_version_info >= (3, 8, 0)
