"""SMS delivery log against a real Postgres: the migration's DDL, forward-only
DLR application, the poller, and the day-wise aggregation with tenant
isolation.

Gated on ``CLOUDGUEST_TEST_POSTGRES_URL`` exactly like
``test_marketing_credits_postgres.py`` (this repo has no database-backed CI
harness; that variable is what a developer sets to run them). Each test gets a
throwaway schema built by running migration 0172's own ``upgrade()`` on top of
minimal ``organizations``/``locations`` stubs.
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import uuid
from datetime import UTC, date, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.domains.sms_delivery.constants import DlrSource, SmsDeliveryStatus
from app.domains.sms_delivery.recorder import SmsDeliveryRecorder
from app.domains.sms_delivery.service import (
    ReportScope,
    apply_dlr,
    build_report,
    poll_ping4sms_dlrs,
    prune_logs,
)

_PG_URL = os.environ.get("CLOUDGUEST_TEST_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    not _PG_URL, reason="CLOUDGUEST_TEST_POSTGRES_URL not set"
)

ORG_A = uuid.UUID("00000000-0000-0000-0000-00000000000a")
ORG_B = uuid.UUID("00000000-0000-0000-0000-00000000000b")
LOC_A1 = uuid.UUID("00000000-0000-0000-0000-0000000000a1")
LOC_A2 = uuid.UUID("00000000-0000-0000-0000-0000000000a2")
LOC_B1 = uuid.UUID("00000000-0000-0000-0000-0000000000b1")


def _migration():
    path = (
        pathlib.Path(__file__).resolve().parents[2]
        / "alembic"
        / "versions"
        / "0172_create_sms_delivery_logs.py"
    )
    spec = importlib.util.spec_from_file_location("_migration_0172", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_migration(connection, direction: str) -> None:
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    context = MigrationContext.configure(connection)
    with Operations.context(context):
        getattr(_migration(), direction)()


@pytest.fixture
async def engine():
    schema = f"smsdl_{uuid.uuid4().hex[:12]}"
    admin = create_async_engine(_PG_URL, isolation_level="AUTOCOMMIT")
    async with admin.connect() as conn:
        await conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(
        _PG_URL, connect_args={"server_settings": {"search_path": schema}}
    )
    try:
        async with engine.begin() as conn:
            await conn.execute(text("CREATE TABLE organizations (id uuid PRIMARY KEY)"))
            await conn.execute(
                text(
                    "CREATE TABLE locations (id uuid PRIMARY KEY, "
                    "organization_id uuid NOT NULL)"
                )
            )
            await conn.run_sync(_run_migration, "upgrade")
            for org in (ORG_A, ORG_B):
                await conn.execute(
                    text("INSERT INTO organizations VALUES (:id)"), {"id": org}
                )
            for loc, org in ((LOC_A1, ORG_A), (LOC_A2, ORG_A), (LOC_B1, ORG_B)):
                await conn.execute(
                    text("INSERT INTO locations VALUES (:id, :org)"),
                    {"id": loc, "org": org},
                )
        yield engine
    finally:
        await engine.dispose()
        async with admin.connect() as conn:
            await conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin.dispose()


async def _insert(
    engine,
    *,
    org=ORG_A,
    loc=LOC_A1,
    status="sent",
    message_id: str | None = "1001",
    provider="ping4sms",
    source="wyfy",
    purpose="guest_otp",
    created_at: datetime | None = None,
) -> uuid.UUID:
    row_id = uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO sms_delivery_logs (id, created_at, organization_id, "
                "location_id, purpose, provider, provider_source, "
                "provider_message_id, status) VALUES (:id, :c, :o, :l, :p, :pr, "
                ":s, :m, :st)"
            ),
            {
                "id": row_id,
                "c": created_at or datetime.now(UTC),
                "o": org,
                "l": loc,
                "p": purpose,
                "pr": provider,
                "s": source,
                "m": message_id,
                "st": status,
            },
        )
    return row_id


async def _status(engine, row_id: uuid.UUID) -> tuple[str, str | None, str | None]:
    async with engine.connect() as conn:
        return tuple(
            (
                await conn.execute(
                    text(
                        "SELECT status, dlr_source, dlr_raw FROM sms_delivery_logs "
                        "WHERE id = :id"
                    ),
                    {"id": row_id},
                )
            ).one()
        )


async def _apply(engine, message_id: str, status, raw: str = "x"):
    async with AsyncSession(engine) as session:
        outcome = await apply_dlr(
            session,
            provider="ping4sms",
            provider_message_id=message_id,
            status=status,
            source=DlrSource.WEBHOOK,
            raw=raw,
        )
        await session.commit()
        return outcome


class TestRecorderWritesRealRow:
    async def test_row_lands_with_masked_number(self, engine) -> None:
        factory = async_sessionmaker(engine, expire_on_commit=False)
        await SmsDeliveryRecorder(factory).record(
            purpose="guest_otp",
            provider="ping4sms",
            phone_number="+919876543210",
            status="sent",
            organization_id=ORG_A,
            location_id=LOC_A1,
            provider_message_id="42",
        )
        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    text(
                        "SELECT recipient_masked, provider_message_id, status, "
                        "provider_source, dlr_poll_count FROM sms_delivery_logs"
                    )
                )
            ).one()
        assert tuple(row) == ("+91******3210", "42", "sent", "wyfy", 0)


class TestForwardOnlyDlr:
    async def test_valid_dlr_moves_sent_to_delivered(self, engine) -> None:
        row = await _insert(engine)
        outcome = await _apply(engine, "1001", SmsDeliveryStatus.DELIVERED, "DELIVRD")
        assert (outcome.matched, outcome.applied, outcome.status) == (
            True,
            True,
            "delivered",
        )
        assert await _status(engine, row) == ("delivered", "webhook", "DELIVRD")

    async def test_duplicate_dlr_is_a_no_op(self, engine) -> None:
        row = await _insert(engine)
        await _apply(engine, "1001", SmsDeliveryStatus.DELIVERED, "DELIVRD")
        again = await _apply(engine, "1001", SmsDeliveryStatus.DELIVERED, "DELIVRD")
        assert (again.matched, again.applied, again.status) == (
            True,
            False,
            "delivered",
        )
        assert (await _status(engine, row))[0] == "delivered"

    async def test_out_of_order_reports_never_regress(self, engine) -> None:
        row = await _insert(engine)
        await _apply(engine, "1001", SmsDeliveryStatus.DELIVERED, "DELIVRD")
        # A late "pending" and a contradicting final both arrive afterwards.
        await _apply(engine, "1001", None, "PENDING")
        late = await _apply(engine, "1001", SmsDeliveryStatus.UNDELIVERED, "UNDELIV")
        assert late.applied is False
        assert await _status(engine, row) == ("delivered", "webhook", "DELIVRD")

    async def test_pending_keeps_raw_but_not_status(self, engine) -> None:
        row = await _insert(engine)
        outcome = await _apply(engine, "1001", None, "PENDING")
        assert (outcome.matched, outcome.applied) == (True, False)
        assert await _status(engine, row) == ("sent", None, "PENDING")

    async def test_failed_rows_and_own_accounts_are_never_touched(self, engine) -> None:
        failed = await _insert(engine, status="failed", message_id="2002")
        own = await _insert(engine, message_id="3003", source="own")
        await _apply(engine, "2002", SmsDeliveryStatus.DELIVERED)
        outcome = await _apply(engine, "3003", SmsDeliveryStatus.DELIVERED)
        assert outcome.matched is False
        assert (await _status(engine, failed))[0] == "failed"
        assert (await _status(engine, own))[0] == "sent"

    async def test_unknown_message_id(self, engine) -> None:
        outcome = await _apply(engine, "nope", SmsDeliveryStatus.DELIVERED)
        assert (outcome.matched, outcome.applied, outcome.status) == (
            False,
            False,
            None,
        )


class TestPoller:
    async def test_polls_only_eligible_rows_and_applies_recognised_answers(
        self, engine
    ) -> None:
        now = datetime.now(UTC)
        five_min_ago = now - timedelta(minutes=5)
        delivered = await _insert(engine, message_id="1", created_at=five_min_ago)
        unknown = await _insert(engine, message_id="2", created_at=five_min_ago)
        too_new = await _insert(engine, message_id="3", created_at=now)
        too_old = await _insert(
            engine, message_id="4", created_at=now - timedelta(days=4)
        )
        own = await _insert(
            engine, message_id="5", source="own", created_at=five_min_ago
        )
        answers = {"1": "DELIVRD", "2": "110"}
        asked: list[str] = []

        async def fetch(api_key: str, message_id: str) -> str:
            assert api_key == "k"
            asked.append(message_id)
            return answers[message_id]

        async with AsyncSession(engine) as session:
            summary = await poll_ping4sms_dlrs(
                session, api_key="k", fetch=fetch, now=now
            )

        assert sorted(asked) == ["1", "2"]
        assert summary["polled"] == 2
        assert summary["delivered"] == 1
        assert summary["unchanged"] == 1
        assert await _status(engine, delivered) == ("delivered", "poll", "DELIVRD")
        # The unrecognised answer is kept for diagnosis; the row stays sent.
        assert await _status(engine, unknown) == ("sent", None, "110")
        for row in (too_new, too_old, own):
            assert (await _status(engine, row))[0] == "sent"

        # Re-running immediately polls nothing: the interval has not elapsed.
        asked.clear()
        async with AsyncSession(engine) as session:
            await poll_ping4sms_dlrs(session, api_key="k", fetch=fetch, now=now)
        assert asked == []


class TestReportAggregation:
    async def test_day_wise_counts_are_tenant_and_location_scoped(self, engine) -> None:
        # 2026-10-24 18:40 UTC is 2026-10-25 00:10 IST -- bucketed on the 25th.
        ist_25th = datetime(2026, 10, 24, 18, 40, tzinfo=UTC)
        ist_24th = datetime(2026, 10, 24, 10, 0, tzinfo=UTC)
        await _insert(engine, status="delivered", created_at=ist_24th)
        await _insert(engine, status="failed", message_id=None, created_at=ist_24th)
        await _insert(engine, status="sent", created_at=ist_25th)
        await _insert(engine, loc=LOC_A2, status="undelivered", created_at=ist_25th)
        # Another tenant's rows on the same days must never be counted.
        await _insert(engine, org=ORG_B, loc=LOC_B1, created_at=ist_24th)
        await _insert(engine, org=ORG_B, loc=LOC_B1, created_at=ist_25th)

        async with AsyncSession(engine) as session:
            org_report = await build_report(
                session,
                ReportScope(organization_id=ORG_A, location_filter=None),
                start=date(2026, 10, 24),
                end=date(2026, 10, 25),
                tz="Asia/Kolkata",
            )
            site_report = await build_report(
                session,
                ReportScope(organization_id=ORG_A, location_filter=[LOC_A1]),
                start=date(2026, 10, 24),
                end=date(2026, 10, 25),
                tz="Asia/Kolkata",
            )

        day24, day25 = org_report["days"]
        assert (day24["attempted"], day24["sent"], day24["failed"]) == (2, 1, 1)
        assert day24["delivered"] == 1
        assert (day25["attempted"], day25["awaiting_dlr"], day25["undelivered"]) == (
            2,
            1,
            1,
        )
        assert org_report["totals"]["attempted"] == 4
        assert {r["location_id"] for r in org_report["by_location"]} == {
            str(LOC_A1),
            str(LOC_A2),
        }
        assert site_report["totals"]["attempted"] == 3
        assert site_report["totals"]["undelivered"] == 0


class TestRetention:
    async def test_prune_deletes_only_rows_past_retention(self, engine) -> None:
        now = datetime.now(UTC)
        old = await _insert(engine, created_at=now - timedelta(days=200))
        fresh = await _insert(engine, created_at=now - timedelta(days=10))
        async with AsyncSession(engine) as session:
            deleted = await prune_logs(session, retention_days=180, now=now)
        assert deleted == 1
        async with engine.connect() as conn:
            remaining = {
                row[0]
                for row in await conn.execute(text("SELECT id FROM sms_delivery_logs"))
            }
        assert remaining == {fresh}
        assert old not in remaining

    async def test_migration_downgrade_drops_the_table(self, engine) -> None:
        async with engine.begin() as conn:
            await conn.run_sync(_run_migration, "downgrade")
            exists = (
                await conn.execute(text("SELECT to_regclass('sms_delivery_logs')"))
            ).scalar_one()
        assert exists is None
