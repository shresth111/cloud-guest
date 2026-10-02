"""Prepaid credits against a real Postgres: row locks, constraints, triggers.

What the ledger promises is a set of database properties -- ``SELECT ... FOR
UPDATE`` serializing concurrent writers, ``CHECK (>= 0)``, a unique
idempotency index, an append-only trigger -- and none of them can be shown by
a fake. So these run against a real Postgres, gated on
``CLOUDGUEST_TEST_POSTGRES_URL`` exactly like
``test_analytics_snapshot_upsert.py`` (this repo has no database-backed CI
harness; that variable is what a developer sets to run them):

    createdb cg_credits_test
    export CLOUDGUEST_TEST_POSTGRES_URL=\\
        postgresql+asyncpg://localhost/cg_credits_test
    python -m pytest tests/unit/test_marketing_credits_postgres.py

Each test gets a throwaway schema. The two credit tables are built by
**running migration 0136's own ``upgrade()``** there (so the DDL under test,
trigger included, is the DDL that ships), on top of minimal stubs of the
tables it and the repository's lookups reference.

Concurrency tests open one session per writer on a real connection pool and
run them with ``asyncio.gather``. The writers go through a repository whose
``insert_entry`` sleeps first: that widens the gap between reading the
balance and writing it, so without the row lock every writer reads the same
balance and the tests fail (revert-checked by removing ``with_for_update``).
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
import pathlib
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

# The ORM resolves every foreign key target in the shared metadata at first
# flush, so the tables the credit models point at must be registered.
import app.domains.auth.models  # noqa: F401, E402
import app.domains.marketing.models  # noqa: F401, E402
import app.domains.organization.models  # noqa: F401, E402
from app.domains.billing.credits_constants import CreditEntryType
from app.domains.billing.credits_exceptions import (
    AdjustmentExceedsAvailableError,
    BillingProfileMissingError,
    InsufficientCreditsError,
)
from app.domains.billing.credits_repository import CreditRepository, LedgerQuery
from app.domains.billing.credits_service import (
    AdjustmentRequest,
    CreditsService,
    CreditWalletService,
    reconcile_credit_wallets,
)

_PG_URL = os.environ.get("CLOUDGUEST_TEST_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    not _PG_URL, reason="CLOUDGUEST_TEST_POSTGRES_URL not set"
)

ORG_A = uuid.UUID("00000000-0000-0000-0000-00000000000a")
ORG_B = uuid.UUID("00000000-0000-0000-0000-00000000000b")
ACTOR = uuid.UUID("00000000-0000-0000-0000-0000000000f1")


def _migration_0136():
    path = (
        pathlib.Path(__file__).resolve().parents[2]
        / "alembic"
        / "versions"
        / "0136_create_credit_wallets_and_ledger.py"
    )
    spec = importlib.util.spec_from_file_location("_migration_0136", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_STUBS = [
    "CREATE TABLE organizations (id uuid PRIMARY KEY, "
    "is_deleted boolean NOT NULL DEFAULT false)",
    "CREATE TABLE invoices (id uuid PRIMARY KEY, organization_id uuid NOT NULL, "
    "invoice_number varchar(50) NOT NULL)",
    "CREATE TABLE marketing_campaigns (id uuid PRIMARY KEY, "
    "organization_id uuid NOT NULL, name varchar(120) NOT NULL, "
    "status varchar(16) NOT NULL)",
    "CREATE TABLE users (id uuid PRIMARY KEY, first_name varchar(100), "
    "last_name varchar(100))",
]


def _run_migration(connection, direction: str) -> None:
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    context = MigrationContext.configure(connection)
    with Operations.context(context):
        getattr(_migration_0136(), direction)()


@pytest.fixture
async def engine():
    schema = f"credits_{uuid.uuid4().hex[:12]}"
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
            await conn.run_sync(_run_migration, "upgrade")
            for org in (ORG_A, ORG_B):
                await conn.execute(
                    text("INSERT INTO organizations (id) VALUES (:id)"), {"id": org}
                )
            await conn.execute(
                text("INSERT INTO users VALUES (:id, 'Asha', 'Ops')"), {"id": ACTOR}
            )
        yield engine
    finally:
        await engine.dispose()
        async with admin.connect() as conn:
            await conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        await admin.dispose()


class SlowWriterRepository(CreditRepository):
    """Sleeps between the (locked) balance read and the ledger write."""

    async def insert_entry(self, **fields):
        await asyncio.sleep(0.05)
        return await super().insert_entry(**fields)


async def _in_session(engine, fn, *, slow: bool = False):
    async with AsyncSession(engine, expire_on_commit=False) as session:
        repo = (SlowWriterRepository if slow else CreditRepository)(session)
        try:
            result = await fn(CreditWalletService(repo), repo)
            await session.commit()
            return result
        except Exception:
            await session.rollback()
            raise


async def _balances(engine, org=ORG_A) -> tuple[int, int, int, int, int]:
    async with engine.connect() as conn:
        wallet = (
            await conn.execute(
                text(
                    "SELECT available_minor, reserved_minor FROM credit_wallets "
                    "WHERE organization_id = :o"
                ),
                {"o": org},
            )
        ).one()
        sums = (
            await conn.execute(
                text(
                    "SELECT coalesce(sum(delta_available_minor),0), "
                    "coalesce(sum(delta_reserved_minor),0), count(*) "
                    "FROM credit_ledger_entries WHERE organization_id = :o"
                ),
                {"o": org},
            )
        ).one()
    return wallet[0], wallet[1], int(sums[0]), int(sums[1]), int(sums[2])


async def _topup(engine, amount, key="seed", org=ORG_A):
    return await _in_session(
        engine, lambda w, _r: w.topup(org, amount, idempotency_key=key)
    )


# ============================================================================
# Concurrency
# ============================================================================


async def test_concurrent_reserves_never_overdraw(engine) -> None:
    await _topup(engine, 1_000)
    campaign = uuid.uuid4()

    async def reserve(n: int):
        return await _in_session(
            engine,
            lambda w, _r: w.reserve(
                ORG_A,
                100,
                idempotency_key=f"reserve:{campaign}:{n}",
                campaign_id=campaign,
            ),
            slow=True,
        )

    results = await asyncio.gather(
        *(reserve(n) for n in range(20)), return_exceptions=True
    )
    succeeded = [r for r in results if not isinstance(r, BaseException)]
    refused = [r for r in results if isinstance(r, InsufficientCreditsError)]
    others = [
        r
        for r in results
        if isinstance(r, BaseException) and not isinstance(r, InsufficientCreditsError)
    ]
    assert not others, others
    assert len(succeeded) == 10
    assert len(refused) == 10
    assert refused[0].data["error_code"] == "insufficient_credits"
    available, reserved, ledger_av, ledger_res, rows = await _balances(engine)
    assert (available, reserved) == (0, 1_000)
    assert (ledger_av, ledger_res) == (0, 1_000)
    assert rows == 11  # the top-up + ten reserves


async def test_concurrent_first_writes_create_one_wallet(engine) -> None:
    """Ten top-ups racing to create the wallet: ON CONFLICT DO NOTHING plus
    the row lock means one wallet row and no lost update."""
    await asyncio.gather(
        *(
            _in_session(
                engine,
                lambda w, _r, n=n: w.topup(ORG_B, 100, idempotency_key=f"t{n}"),
                slow=True,
            )
            for n in range(10)
        )
    )
    async with engine.connect() as conn:
        wallets = (
            await conn.execute(
                text("SELECT count(*) FROM credit_wallets WHERE organization_id=:o"),
                {"o": ORG_B},
            )
        ).scalar_one()
    assert wallets == 1
    available, reserved, ledger_av, _res, rows = await _balances(engine, ORG_B)
    assert available == ledger_av == 1_000
    assert rows == 10


# ============================================================================
# Idempotency
# ============================================================================


async def test_duplicate_idempotency_key_gives_exactly_one_row(engine) -> None:
    first = await _topup(engine, 500, key="dup")
    second = await _topup(engine, 500, key="dup")
    assert first.created is True
    assert second.created is False
    assert second.entry.id == first.entry.id
    available, _reserved, _av, _res, rows = await _balances(engine)
    assert available == 500
    assert rows == 1


async def test_concurrent_duplicate_keys_give_exactly_one_row(engine) -> None:
    await _topup(engine, 1_000)
    campaign = uuid.uuid4()
    results = await asyncio.gather(
        *(
            _in_session(
                engine,
                lambda w, _r: w.reserve(
                    ORG_A,
                    300,
                    idempotency_key=f"reserve:{campaign}:0",
                    campaign_id=campaign,
                ),
                slow=True,
            )
            for _ in range(6)
        )
    )
    assert sum(1 for r in results if r.created) == 1
    assert len({r.entry.id for r in results}) == 1
    available, reserved, _av, _res, rows = await _balances(engine)
    assert (available, reserved) == (700, 300)
    assert rows == 2


async def test_the_unique_index_backstops_a_bypassed_check(engine) -> None:
    """Even a writer that skips the service's check cannot insert the key
    twice: the database refuses."""
    written = await _topup(engine, 100, key="k1")
    async with AsyncSession(engine) as session:
        repo = CreditRepository(session)
        with pytest.raises(IntegrityError):
            await repo.insert_entry(
                organization_id=ORG_A,
                bucket="marketing",
                entry_type="topup",
                delta_available_minor=100,
                delta_reserved_minor=0,
                balance_available_after_minor=200,
                balance_reserved_after_minor=0,
                idempotency_key=written.entry.idempotency_key,
            )


# ============================================================================
# Buckets
# ============================================================================


async def test_negative_adjustment_cannot_touch_reserved(engine) -> None:
    await _topup(engine, 1_000)
    campaign = uuid.uuid4()
    await _in_session(
        engine,
        lambda w, _r: w.reserve(
            ORG_A, 800, idempotency_key="reserve:c:0", campaign_id=campaign
        ),
    )
    # available 200, reserved 800: -300 fits in the total, not in available.
    with pytest.raises(AdjustmentExceedsAvailableError) as info:
        await _in_session(
            engine, lambda w, _r: w.adjust(ORG_A, -300, idempotency_key="adj1")
        )
    assert info.value.data["error_code"] == "adjustment_exceeds_available"
    assert await _balances(engine) == (200, 800, 200, 800, 2)

    await _in_session(
        engine, lambda w, _r: w.adjust(ORG_A, -200, idempotency_key="adj2")
    )
    available, reserved, *_ = await _balances(engine)
    assert (available, reserved) == (0, 800)


async def test_check_constraint_refuses_a_negative_balance(engine) -> None:
    await _topup(engine, 100)
    async with engine.begin() as conn:
        with pytest.raises(IntegrityError):
            await conn.execute(
                text(
                    "UPDATE credit_wallets SET available_minor = -1 "
                    "WHERE organization_id = :o"
                ),
                {"o": ORG_A},
            )


async def test_ledger_sums_reconcile_with_the_wallet(engine) -> None:
    campaign = uuid.uuid4()
    recipient_a, recipient_b = uuid.uuid4(), uuid.uuid4()

    async def run(w: CreditWalletService, _r):
        await w.topup(ORG_A, 10_000, idempotency_key="t")
        await w.reserve(
            ORG_A, 600, idempotency_key=f"reserve:{campaign}:0", campaign_id=campaign
        )
        await w.debit(
            ORG_A,
            60,
            idempotency_key=f"debit:{recipient_a}",
            campaign_id=campaign,
            recipient_id=recipient_a,
            unit_price_minor=30,
            units=2,
        )
        await w.debit(
            ORG_A,
            30,
            idempotency_key=f"debit:{recipient_b}",
            campaign_id=campaign,
            recipient_id=recipient_b,
            unit_price_minor=30,
            units=1,
        )
        await w.debit(
            ORG_A, 30, idempotency_key="test:x", campaign_id=campaign, is_test_send=True
        )
        await w.release(
            ORG_A,
            510,
            idempotency_key=f"release:{campaign}:final",
            campaign_id=campaign,
        )
        await w.refund(ORG_A, 90, idempotency_key="r", campaign_id=campaign)
        await w.adjust(ORG_A, -1_000, idempotency_key="a")

    await _in_session(engine, run)
    available, reserved, ledger_av, ledger_res, rows = await _balances(engine)
    assert (available, reserved) == (ledger_av, ledger_res)
    assert (available, reserved) == (10_000 - 90 - 30 + 90 - 1_000, 0)
    assert rows == 8

    # The running balances chain: each row's "after" is the previous row's
    # "after" plus its own deltas, ending at the wallet.
    async with engine.connect() as conn:
        chain = (
            await conn.execute(
                text(
                    "SELECT delta_available_minor, delta_reserved_minor, "
                    "balance_available_after_minor, balance_reserved_after_minor "
                    "FROM credit_ledger_entries WHERE organization_id = :o "
                    "ORDER BY created_at, id"
                ),
                {"o": ORG_A},
            )
        ).all()
    running = (0, 0)
    for d_av, d_res, after_av, after_res in chain:
        running = (running[0] + d_av, running[1] + d_res)
        assert running == (after_av, after_res)
    assert running == (available, reserved)

    async with AsyncSession(engine) as session:
        report = await reconcile_credit_wallets(CreditRepository(session))
    assert report.ok, report


async def test_one_debit_per_recipient_even_with_a_new_key(engine) -> None:
    """The partial unique index on (recipient_id) WHERE entry_type='debit':
    a recipient cannot be charged twice even under a different key."""
    campaign, recipient = uuid.uuid4(), uuid.uuid4()
    await _topup(engine, 1_000)

    async def run(w, _r):
        await w.reserve(ORG_A, 100, idempotency_key="res", campaign_id=campaign)
        await w.debit(
            ORG_A,
            30,
            idempotency_key="d1",
            campaign_id=campaign,
            recipient_id=recipient,
        )

    await _in_session(engine, run)
    with pytest.raises(IntegrityError):
        await _in_session(
            engine,
            lambda w, _r: w.debit(
                ORG_A,
                30,
                idempotency_key="d2",
                campaign_id=campaign,
                recipient_id=recipient,
            ),
        )


# ============================================================================
# Reconciliation
# ============================================================================


async def test_reconciliation_detects_a_tampered_balance(engine) -> None:
    await _topup(engine, 1_000)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "UPDATE credit_wallets SET available_minor = available_minor + 1 "
                "WHERE organization_id = :o"
            ),
            {"o": ORG_A},
        )
    async with AsyncSession(engine) as session:
        report = await reconcile_credit_wallets(CreditRepository(session))
    assert not report.ok
    [mismatch] = report.wallet_mismatches
    assert mismatch.organization_id == ORG_A
    assert (mismatch.available_minor, mismatch.ledger_available_minor) == (1_001, 1_000)
    # Never auto-corrected.
    available, *_ = await _balances(engine)
    assert available == 1_001


async def test_reconciliation_flags_a_finished_campaign_still_holding_credits(
    engine,
) -> None:
    campaign = uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO marketing_campaigns VALUES (:id, :o, 'Diwali', 'sent')"),
            {"id": campaign, "o": ORG_A},
        )
    await _topup(engine, 1_000)
    await _in_session(
        engine,
        lambda w, _r: w.reserve(
            ORG_A, 400, idempotency_key="res", campaign_id=campaign
        ),
    )
    async with AsyncSession(engine) as session:
        report = await reconcile_credit_wallets(CreditRepository(session))
    assert report.wallet_mismatches == []
    [flagged] = report.campaign_mismatches
    assert (flagged.campaign_id, flagged.net_reserved_minor) == (campaign, 400)

    await _in_session(
        engine,
        lambda w, _r: w.release(
            ORG_A, 400, idempotency_key="rel", campaign_id=campaign
        ),
    )
    async with AsyncSession(engine) as session:
        assert (await reconcile_credit_wallets(CreditRepository(session))).ok


# ============================================================================
# Append-only
# ============================================================================


async def test_ledger_rows_cannot_be_updated_or_deleted(engine) -> None:
    await _topup(engine, 1_000)
    for statement in (
        "UPDATE credit_ledger_entries SET delta_available_minor = 5",
        "DELETE FROM credit_ledger_entries",
    ):
        async with engine.begin() as conn:
            with pytest.raises(DBAPIError, match="append-only"):
                await conn.execute(text(statement))
    *_, rows = await _balances(engine)
    assert rows == 1


async def test_deleting_the_organization_still_cascades(engine) -> None:
    await _topup(engine, 1_000, org=ORG_B)
    async with engine.begin() as conn:
        await conn.execute(
            text("DELETE FROM organizations WHERE id = :o"), {"o": ORG_B}
        )
        remaining = (
            await conn.execute(text("SELECT count(*) FROM credit_ledger_entries"))
        ).scalar_one()
    assert remaining == 0


async def test_migration_downgrade_removes_everything(engine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(_run_migration, "downgrade")
        left = (
            await conn.execute(
                text(
                    "SELECT count(*) FROM pg_proc "
                    "WHERE proname = 'credit_ledger_entries_append_only'"
                )
            )
        ).scalar_one()
        tables = (
            await conn.execute(
                text(
                    "SELECT count(*) FROM information_schema.tables "
                    "WHERE table_schema = current_schema() "
                    "AND table_name IN ('credit_wallets','credit_ledger_entries')"
                )
            )
        ).scalar_one()
    assert (left, tables) == (0, 0)
    # Leave the schema as the fixture's teardown expects.
    async with engine.begin() as conn:
        await conn.run_sync(_run_migration, "upgrade")


# ============================================================================
# Ledger listing
# ============================================================================


async def test_recipient_debits_aggregate_per_campaign_per_day(engine) -> None:
    campaign = uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO marketing_campaigns VALUES (:id, :o, 'Weekend', 'sending')"
            ),
            {"id": campaign, "o": ORG_A},
        )

    async def run(w, _r):
        await w.topup(
            ORG_A, 1_000, idempotency_key="t", actor_user_id=ACTOR, note="UPI"
        )
        await w.reserve(ORG_A, 300, idempotency_key="res", campaign_id=campaign)
        for units in (2, 1, 2):
            recipient = uuid.uuid4()
            await w.debit(
                ORG_A,
                30 * units,
                idempotency_key=f"debit:{recipient}",
                campaign_id=campaign,
                recipient_id=recipient,
                unit_price_minor=30,
                units=units,
            )

    await _in_session(engine, run)
    async with AsyncSession(engine) as session:
        repo = CreditRepository(session)
        rows, total = await repo.list_entries(
            LedgerQuery(organization_id=ORG_A, bucket="marketing"), limit=25, offset=0
        )
        assert total == 3  # topup, reserve, one aggregated debit row
        debit = rows[0]
        assert debit.entry.entry_type == "debit"
        assert debit.aggregated_count == 3
        assert (debit.delta_reserved_minor, debit.units, debit.unit_price_minor) == (
            -150,
            5,
            30,
        )
        # The anchor is the group's latest entry, so its running balance is
        # the balance after the whole group.
        assert debit.entry.balance_reserved_after_minor == 150

        detail, detail_total = await repo.list_entries(
            LedgerQuery(
                organization_id=ORG_A,
                bucket="marketing",
                aggregate_recipient_debits=False,
            ),
            limit=2,
            offset=0,
        )
        assert detail_total == 5
        assert len(detail) == 2

        # Another organization sees none of it.
        other, other_total = await repo.list_entries(
            LedgerQuery(organization_id=ORG_B, bucket="marketing"), limit=25, offset=0
        )
        assert (other, other_total) == ([], 0)

        service = CreditsService(
            repository=repo,
            wallets=CreditWalletService(repo),
            invoices=None,  # type: ignore[arg-type]
            audit_writer=None,  # type: ignore[arg-type]
            committer=session,
        )
        items, meta = await service.list_ledger(
            ORG_A,
            entry_types=None,
            campaign_id=None,
            date_from=None,
            date_to=None,
            detail_recipients=False,
            page=1,
            page_size=25,
        )
    assert meta.total_items == 3
    assert items[0]["campaign"] == {"id": str(campaign), "name": "Weekend"}
    assert items[0]["recipient_id"] is None
    assert items[-1]["actor"] == {"id": str(ACTOR), "name": "Asha Ops"}


# ============================================================================
# Master adjustments with a GST invoice
# ============================================================================


class _Audit:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    async def create_audit_log_entry(self, **fields):
        self.rows.append(fields)


class _Invoices:
    """Inserts a real row into the stub ``invoices`` table (the ledger's FK
    target) -- or refuses like InvoiceService does with no billing profile."""

    def __init__(self, session: AsyncSession, *, has_profile: bool = True) -> None:
        self.session = session
        self.has_profile = has_profile
        self.calls = 0

    async def generate_invoice_for_credit_topup(self, *, organization_id, **_):
        self.calls += 1
        if not self.has_profile:
            raise BillingProfileMissingError(organization_id)
        invoice_id = uuid.uuid4()
        await self.session.execute(
            text("INSERT INTO invoices VALUES (:id, :o, :n)"),
            {"id": invoice_id, "o": organization_id, "n": f"INV-2026-{self.calls:05d}"},
        )

        class _Row:
            id = invoice_id

        return _Row()


async def test_invoiced_topup_is_idempotent_and_audited_once(engine) -> None:
    request = AdjustmentRequest(
        entry_type=CreditEntryType.TOPUP,
        amount_minor=500_000,
        note="Bank transfer",
        reference="UTR123",
        campaign_id=None,
        issue_invoice=True,
        amount_paid_minor_inr=500_000,
        idempotency_key="client-key-1",
    )
    audit = _Audit()
    invoice_calls = 0
    for _attempt in range(2):
        async with AsyncSession(engine, expire_on_commit=False) as session:
            repo = CreditRepository(session)
            invoices = _Invoices(session)
            service = CreditsService(
                repository=repo,
                wallets=CreditWalletService(repo),
                invoices=invoices,
                audit_writer=audit,
                committer=session,
            )
            payload, _created = await service.post_adjustment(
                ORG_A, request, actor_user_id=ACTOR
            )
            await session.commit()
            invoice_calls += invoices.calls
    assert invoice_calls == 1
    assert len(audit.rows) == 1
    assert audit.rows[0]["action"] == "credits_topup"
    assert payload["invoice"]["invoice_number"] == "INV-2026-00001"
    assert payload["wallet"] == {"available_minor": 500_000, "reserved_minor": 0}
    *_, rows = await _balances(engine)
    assert rows == 1


async def test_billing_profile_missing_writes_nothing(engine) -> None:
    request = AdjustmentRequest(
        entry_type=CreditEntryType.TOPUP,
        amount_minor=1_000,
        note="Bank transfer",
        reference=None,
        campaign_id=None,
        issue_invoice=True,
        amount_paid_minor_inr=1_000,
        idempotency_key="client-key-2",
    )
    async with AsyncSession(engine) as session:
        repo = CreditRepository(session)
        service = CreditsService(
            repository=repo,
            wallets=CreditWalletService(repo),
            invoices=_Invoices(session, has_profile=False),
            audit_writer=_Audit(),
            committer=session,
        )
        with pytest.raises(BillingProfileMissingError) as info:
            await service.post_adjustment(ORG_A, request, actor_user_id=ACTOR)
        await session.rollback()
    assert info.value.status_code == 409
    assert info.value.data["error_code"] == "billing_profile_missing"
    async with engine.connect() as conn:
        rows = (
            await conn.execute(text("SELECT count(*) FROM credit_ledger_entries"))
        ).scalar_one()
    assert rows == 0
