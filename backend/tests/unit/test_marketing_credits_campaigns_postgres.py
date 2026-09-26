"""Marketing credits x campaigns against a real Postgres (BE-12b).

Gated on ``CLOUDGUEST_TEST_POSTGRES_URL`` exactly like
``test_marketing_credits_postgres.py`` (this repo has no database-backed CI
harness). Each test gets a throwaway schema built by **running migrations
0136 and 0137's own ``upgrade()``** on minimal stubs, so the price-book DDL,
its seed and its NULLS NOT DISTINCT index are the ones that ship.

What only a real database can show:

* concurrent campaigns racing for one wallet cannot overdraw (row lock);
* the price book's DISTINCT ON lookups, the seed, the override/inherit rule,
  and the constraints (unique per effective time, platform price required);
* the campaign ledger reads (outstanding, totals, per-recipient charge) and
  the settle-with-hold arithmetic on real rows.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

import app.domains.auth.models  # noqa: F401
import app.domains.marketing.models  # noqa: F401
import app.domains.organization.models  # noqa: F401
from app.domains.billing.credits_exceptions import InsufficientCreditsError
from app.domains.billing.credits_repository import CreditRepository
from app.domains.billing.credits_service import CreditWalletService
from app.domains.marketing.constants import Channel
from app.domains.marketing.credits import (
    CampaignCredits,
    PriceBook,
    PriceRepository,
)
from tests.unit.test_marketing_credits_postgres import (
    SlowWriterRepository,
    _migration_0136,
)

_PG_URL = os.environ.get("CLOUDGUEST_TEST_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    not _PG_URL, reason="CLOUDGUEST_TEST_POSTGRES_URL not set"
)

ORG_A = uuid.UUID("00000000-0000-0000-0000-00000000000a")
ACTOR = uuid.UUID("00000000-0000-0000-0000-0000000000f1")


def _migration_0137():
    import importlib.util
    import pathlib

    path = (
        pathlib.Path(__file__).resolve().parents[2]
        / "alembic"
        / "versions"
        / "0137_create_marketing_price_book.py"
    )
    spec = importlib.util.spec_from_file_location("_migration_0137", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_STUBS = [
    "CREATE TABLE organizations (id uuid PRIMARY KEY, name varchar(200), "
    "contact_email varchar(255), is_deleted boolean NOT NULL DEFAULT false)",
    "CREATE TABLE invoices (id uuid PRIMARY KEY, organization_id uuid NOT NULL, "
    "invoice_number varchar(50) NOT NULL)",
    "CREATE TABLE marketing_campaigns (id uuid PRIMARY KEY, "
    "organization_id uuid NOT NULL, name varchar(120) NOT NULL, "
    "status varchar(16) NOT NULL)",
    "CREATE TABLE users (id uuid PRIMARY KEY, first_name varchar(100), "
    "last_name varchar(100))",
]


def _run(connection, module, direction: str) -> None:
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    with Operations.context(MigrationContext.configure(connection)):
        getattr(module, direction)()


@pytest.fixture
async def engine():
    schema = f"credits_b_{uuid.uuid4().hex[:12]}"
    admin = create_async_engine(_PG_URL, isolation_level="AUTOCOMMIT")
    async with admin.connect() as conn:
        await conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_async_engine(
        _PG_URL,
        pool_size=25,
        max_overflow=5,
        connect_args={"server_settings": {"search_path": f"{schema},public"}},
    )
    try:
        async with engine.begin() as conn:
            for statement in _STUBS:
                await conn.execute(text(statement))
            await conn.run_sync(_run, _migration_0136(), "upgrade")
            await conn.run_sync(_run, _migration_0137(), "upgrade")
            await conn.execute(
                text("INSERT INTO organizations VALUES (:id, 'Cafe A', 'o@a.in')"),
                {"id": ORG_A},
            )
        yield engine
    finally:
        await engine.dispose()
        async with admin.connect() as conn:
            await conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin.dispose()


def _credits(session: AsyncSession, *, slow: bool = False, now=None) -> CampaignCredits:
    ledger = (SlowWriterRepository if slow else CreditRepository)(session)
    return CampaignCredits(
        prices=PriceBook(PriceRepository(session), now=now),
        wallets=CreditWalletService(ledger),
        ledger=ledger,
    )


def _campaign(campaign_id=None, **fields):
    base = {
        "id": campaign_id or uuid.uuid4(),
        "organization_id": ORG_A,
        "provider_source": "wyfy",
        "status": "scheduled",
        "price_snapshot": {
            "channel": "email",
            "unit": "message",
            "unit_price_minor": 5,
            "units_per_recipient_max": 1,
        },
    }
    base.update(fields)
    return SimpleNamespace(**base)


async def _topup(engine, amount):
    async with AsyncSession(engine) as session:
        await CreditWalletService(CreditRepository(session)).topup(
            ORG_A, amount, idempotency_key=f"seed-{uuid.uuid4().hex}"
        )
        await session.commit()


async def _wallet(engine):
    async with engine.connect() as conn:
        return (
            await conn.execute(
                text(
                    "SELECT available_minor, reserved_minor FROM credit_wallets "
                    "WHERE organization_id = :o"
                ),
                {"o": ORG_A},
            )
        ).one()


# ============================================================================
# Concurrency
# ============================================================================


async def test_concurrent_campaigns_cannot_overdraw(engine) -> None:
    await _topup(engine, 50)

    async def schedule_one():
        campaign = _campaign()
        async with AsyncSession(engine) as session:
            credits = _credits(session, slow=True)
            try:
                reserved = await credits.reserve_at_schedule(
                    campaign, campaign.price_snapshot, reachable=2
                )
                await session.commit()
                return reserved
            except Exception:
                await session.rollback()
                raise

    results = await asyncio.gather(
        *(schedule_one() for _ in range(10)), return_exceptions=True
    )
    ok = [r for r in results if r == 10]
    refused = [r for r in results if isinstance(r, InsufficientCreditsError)]
    assert (len(ok), len(refused)) == (5, 5), results
    assert tuple(await _wallet(engine)) == (0, 50)


async def test_dispatch_extension_under_contention_never_overdraws(engine) -> None:
    """Two campaigns extend at dispatch at the same time, each wanting 6
    more recipients at 5 with 30 available: together they get at most 6."""
    await _topup(engine, 30)

    async def extend():
        campaign = _campaign(status="sending")
        async with AsyncSession(engine) as session:
            allowed, capped = await _credits(session, slow=True).adjust_at_dispatch(
                campaign, 6
            )
            await session.commit()
            return allowed, capped

    (a1, c1), (a2, c2) = await asyncio.gather(extend(), extend())
    assert a1 + a2 == 6 and c1 + c2 == 6
    assert tuple(await _wallet(engine)) == (0, 30)


# ============================================================================
# Campaign ledger reads and settle-with-hold on real rows
# ============================================================================


async def test_settle_holds_in_flight_then_releases_the_rest(engine) -> None:
    await _topup(engine, 1_000)
    campaign = _campaign()
    recipients = [uuid.uuid4() for _ in range(3)]
    async with AsyncSession(engine) as session:
        credits = _credits(session)
        await credits.reserve_at_schedule(campaign, campaign.price_snapshot, 3)
        await credits.debit_recipient(campaign, recipients[0], 1)
        campaign.status = "cancelled"
        # Two still mid-send: their 10 is held.
        assert await credits.settle(campaign, in_flight=2) == 0
        # One of them is accepted and debited; the other is skipped.
        await credits.debit_recipient(campaign, recipients[1], 1)
        assert await credits.settle(campaign, in_flight=0) == 5
        assert await credits.settle(campaign, in_flight=0) == 0  # idempotent
        await session.commit()

        ledger = CreditRepository(session)
        assert (
            await ledger.campaign_reserved_outstanding(ORG_A, "marketing", campaign.id)
            == 0
        )
        totals = await ledger.campaign_totals(ORG_A, "marketing", [campaign.id])
        assert totals[campaign.id] == (15, 10, 5)
        charges = await ledger.debits_for_recipients(ORG_A, recipients)
        assert charges == {recipients[0]: 5, recipients[1]: 5}
        keys = (
            (
                await session.execute(
                    text(
                        "SELECT idempotency_key FROM credit_ledger_entries "
                        "WHERE entry_type = 'release' ORDER BY created_at"
                    )
                )
            )
            .scalars()
            .all()
        )
        assert keys == [f"release:{campaign.id}:final"]
    assert tuple(await _wallet(engine)) == (990, 0)


async def test_a_second_debit_for_a_recipient_writes_nothing(engine) -> None:
    await _topup(engine, 1_000)
    campaign = _campaign()
    recipient = uuid.uuid4()
    async with AsyncSession(engine) as session:
        credits = _credits(session)
        await credits.reserve_at_schedule(campaign, campaign.price_snapshot, 2)
        await credits.debit_recipient(campaign, recipient, 1)
        await credits.debit_recipient(campaign, recipient, 1)
        await session.commit()
        count = (
            await session.execute(
                text(
                    "SELECT count(*) FROM credit_ledger_entries "
                    "WHERE entry_type='debit'"
                )
            )
        ).scalar_one()
    assert count == 1


# ============================================================================
# Price book
# ============================================================================


async def test_seed_prices_and_override_inherit(engine) -> None:
    async with AsyncSession(engine) as session:
        book = PriceBook(PriceRepository(session))
        quotes = await book.quotes(ORG_A)
        assert {c.value: q.unit_price_minor for c, q in quotes.items()} == {
            "sms": 30,
            "whatsapp": 120,
            "email": 5,
        }
        assert quotes[Channel.SMS].unit == "segment"

        await book.set_org_prices(
            ORG_A, [(Channel.SMS, 20)], note="deal", actor_user_id=ACTOR
        )
        assert (await book.quotes(ORG_A))[Channel.SMS].source == "org_override"
        book._now = lambda: datetime.now(UTC) + timedelta(seconds=1)  # noqa: SLF001
        await book.set_org_prices(
            ORG_A, [(Channel.SMS, None)], note=None, actor_user_id=ACTOR
        )
        assert (await book.quotes(ORG_A))[Channel.SMS].unit_price_minor == 30

        book._now = lambda: datetime.now(UTC) + timedelta(seconds=2)  # noqa: SLF001
        view = await book.set_platform_prices(
            [(Channel.EMAIL, 7)], note="SES up", actor_user_id=ACTOR
        )
        await session.commit()
    assert [p["unit_price_minor"] for p in view["platform"]] == [30, 120, 7]
    assert view["history"][0]["note"] == "SES up"
    assert view["org_overrides"] == []  # the SMS override was cleared


async def test_a_future_price_is_not_yet_effective(engine) -> None:
    future = datetime.now(UTC) + timedelta(days=1)
    async with AsyncSession(engine) as session:
        book = PriceBook(PriceRepository(session), now=lambda: future)
        await book.set_platform_prices(
            [(Channel.SMS, 99)], note=None, actor_user_id=ACTOR
        )
        await session.commit()
        now_book = PriceBook(PriceRepository(session))
        assert (await now_book.quotes(ORG_A))[Channel.SMS].unit_price_minor == 30


async def test_price_book_constraints(engine) -> None:
    for statement in (
        # Two platform rows for one channel at one instant (NULLS NOT DISTINCT).
        "INSERT INTO marketing_price_book (id, organization_id, channel, unit, "
        "unit_price_minor, effective_from) VALUES (gen_random_uuid(), NULL, "
        "'sms', 'segment', 31, '2026-09-26T00:00:00+00')",
        # A platform row without a price.
        "INSERT INTO marketing_price_book (id, organization_id, channel, unit, "
        "unit_price_minor, effective_from) VALUES (gen_random_uuid(), NULL, "
        "'sms', 'segment', NULL, now())",
        # Out of range.
        "INSERT INTO marketing_price_book (id, organization_id, channel, unit, "
        "unit_price_minor, effective_from) VALUES (gen_random_uuid(), NULL, "
        "'sms', 'segment', 10001, now())",
        # Unknown channel.
        "INSERT INTO marketing_price_book (id, organization_id, channel, unit, "
        "unit_price_minor, effective_from) VALUES (gen_random_uuid(), NULL, "
        "'fax', 'message', 1, now())",
    ):
        async with engine.begin() as conn:
            with pytest.raises(IntegrityError):
                await conn.execute(text(statement))


async def test_migration_0137_downgrade_and_upgrade_again(engine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(_run, _migration_0137(), "downgrade")
        columns = (
            (
                await conn.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_schema = current_schema() "
                        "AND table_name = 'marketing_campaigns'"
                    )
                )
            )
            .scalars()
            .all()
        )
        assert "price_snapshot" not in columns
        await conn.run_sync(_run, _migration_0137(), "upgrade")
        seeded = (
            await conn.execute(text("SELECT count(*) FROM marketing_price_book"))
        ).scalar_one()
    assert seeded == 3
