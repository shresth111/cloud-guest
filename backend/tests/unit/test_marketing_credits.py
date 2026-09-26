"""Prepaid marketing credits (BE-12a): the ledger core, the routes, the audit.

Contract: ``wyfy-specs/guest-marketing-campaigns.md`` §13. Security and
money properties, not happy paths:

* the Master routes are pinned to GLOBAL, so an organization-scoped holder of
  ``billing.manage`` / ``billing.read`` gets 403 on every one of them;
* the customer ledger needs ``billing.read`` at ORGANIZATION: a
  location-scoped caller who can see the balance still gets 403 on it;
* a locked add-on refuses the customer credit routes with 402 first;
* concurrent reserves never overdraw; a duplicate idempotency key writes one
  row; a negative adjustment cannot touch reserved credits; the ledger sums
  reconcile with the wallet, and the reconciliation catches a tampered one;
* a top-up invoice is a real GST invoice, issued once, and a missing billing
  profile is 409 ``billing_profile_missing`` with nothing written.

These use an in-memory repository that models the row lock with an
``asyncio.Lock`` per wallet. The same properties are proven against a real
Postgres -- row locks, CHECK constraints, the unique index and the
append-only trigger -- in ``test_marketing_credits_postgres.py`` (gated on
``CLOUDGUEST_TEST_POSTGRES_URL``, as this repo's other DB-backed tests are).
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from app.domains.billing.constants import InvoiceStatus, TaxType
from app.domains.billing.credits_constants import CreditEntryType
from app.domains.billing.credits_exceptions import (
    AdjustmentExceedsAvailableError,
    BillingProfileMissingError,
    CreditReservationExceededError,
    IdempotencyKeyReusedError,
    InsufficientCreditsError,
)
from app.domains.billing.credits_repository import (
    CampaignReservation,
    CampaignReservationMismatch,
    LedgerRow,
    WalletMismatch,
)
from app.domains.billing.credits_schemas import (
    CreditAdjustmentCreate,
    CreditSettingsUpdate,
)
from app.domains.billing.credits_service import (
    CreditsService,
    CreditWalletService,
    ReconciliationReport,
    format_reconciliation_alert,
    reconcile_credit_wallets,
)

ORG_A = uuid.UUID("00000000-0000-0000-0000-00000000000a")
ORG_B = uuid.UUID("00000000-0000-0000-0000-00000000000b")
ACTOR = uuid.UUID("00000000-0000-0000-0000-0000000000f1")
NOW = datetime(2026, 9, 26, 6, 0, tzinfo=UTC)


# ============================================================================
# In-memory repository
# ============================================================================


@dataclass
class FakeCreditRepository:
    """Mirrors ``CreditRepository``: one wallet per (org, bucket), an
    append-only entry list, a unique key per (org, bucket), CHECK (>= 0) on
    save, and a per-wallet lock held until the "transaction" ends
    (``end_transaction``), like ``SELECT ... FOR UPDATE``."""

    wallets: dict[tuple[uuid.UUID, str], Any] = field(default_factory=dict)
    entries: list[Any] = field(default_factory=list)
    organizations: set[uuid.UUID] = field(default_factory=lambda: {ORG_A, ORG_B})
    campaigns: dict[uuid.UUID, Any] = field(default_factory=dict)
    invoices: dict[uuid.UUID, str] = field(default_factory=dict)
    locks: dict[tuple[uuid.UUID, str], asyncio.Lock] = field(default_factory=dict)
    held: dict[Any, list[asyncio.Lock]] = field(default_factory=dict)
    #: Off for the HTTP tests: a request's task ends without calling
    #: ``end_transaction`` (the real session's commit/close releases the row
    #: lock), and they never run writers concurrently.
    use_locks: bool = True

    async def lock_wallet(self, organization_id, bucket):
        key = (organization_id, bucket)
        if key not in self.wallets:
            self.wallets[key] = SimpleNamespace(
                id=uuid.uuid4(),
                organization_id=organization_id,
                bucket=bucket,
                available_minor=0,
                reserved_minor=0,
                low_balance_threshold_minor=10_000,
                low_balance_notified_at=None,
                updated_by=None,
            )
        if not self.use_locks:
            return self.wallets[key]
        lock = self.locks.setdefault(key, asyncio.Lock())
        task = asyncio.current_task()
        if lock not in self.held.get(task, []):
            await lock.acquire()
            self.held.setdefault(task, []).append(lock)
        return self.wallets[key]

    def end_transaction(self) -> None:
        for lock in self.held.pop(asyncio.current_task(), []):
            lock.release()

    async def get_wallet(self, organization_id, bucket):
        return self.wallets.get((organization_id, bucket))

    async def get_entry_by_key(self, organization_id, bucket, idempotency_key):
        for entry in self.entries:
            if (entry.organization_id, entry.bucket, entry.idempotency_key) == (
                organization_id,
                bucket,
                idempotency_key,
            ):
                return entry
        return None

    async def insert_entry(self, **fields):
        # Yield between the locked read and the write, so an unlocked
        # implementation would interleave here.
        await asyncio.sleep(0)
        assert (
            await self.get_entry_by_key(
                fields["organization_id"], fields["bucket"], fields["idempotency_key"]
            )
            is None
        ), "unique (organization_id, bucket, idempotency_key) violated"
        base = {
            "id": uuid.uuid4(),
            "created_at": NOW + timedelta(seconds=len(self.entries)),
            "campaign_id": None,
            "recipient_id": None,
            "is_test_send": False,
            "unit_price_minor": None,
            "units": None,
            "reference": None,
            "note": None,
            "invoice_id": None,
            "actor_user_id": None,
        }
        base.update(fields)
        entry = SimpleNamespace(**base)
        self.entries.append(entry)
        return entry

    async def save_wallet(self, wallet):
        assert wallet.available_minor >= 0 and wallet.reserved_minor >= 0, "CHECK"
        return wallet

    async def list_entries(self, query, *, limit, offset):
        rows = [
            e
            for e in self.entries
            if e.organization_id == query.organization_id and e.bucket == query.bucket
        ]
        rows.sort(key=lambda e: e.created_at, reverse=True)
        page = rows[offset : offset + limit]
        return [
            LedgerRow(
                entry=e,
                aggregated_count=None,
                delta_available_minor=e.delta_available_minor,
                delta_reserved_minor=e.delta_reserved_minor,
                units=e.units,
                unit_price_minor=e.unit_price_minor,
            )
            for e in page
        ], len(rows)

    async def list_active_campaign_reservations(self, organization_id, bucket):
        totals: dict[uuid.UUID, list[int]] = {}
        for e in self.entries:
            if e.organization_id == organization_id and e.campaign_id:
                t = totals.setdefault(e.campaign_id, [0, 0])
                t[0] += e.delta_reserved_minor
                if e.entry_type == "debit":
                    t[1] -= e.delta_reserved_minor
        return [
            CampaignReservation(campaign_id=c, reserved_minor=r, debited_minor=d)
            for c, (r, d) in totals.items()
            if r > 0
        ]

    async def organization_exists(self, organization_id):
        return organization_id in self.organizations

    async def campaign_belongs_to(self, organization_id, campaign_id):
        campaign = self.campaigns.get(campaign_id)
        return campaign is not None and campaign.organization_id == organization_id

    async def get_campaign_names(self, organization_id, campaign_ids):
        return {
            cid: self.campaigns[cid].name
            for cid in campaign_ids
            if cid in self.campaigns
            and self.campaigns[cid].organization_id == organization_id
        }

    async def get_invoice_numbers(self, organization_id, invoice_ids):
        return {iid: self.invoices[iid] for iid in invoice_ids if iid in self.invoices}

    async def get_user_names(self, user_ids):
        return {uid: "Asha Ops" for uid in user_ids}

    async def find_wallet_mismatches(self):
        out = []
        for (org, bucket), wallet in self.wallets.items():
            av = sum(
                e.delta_available_minor
                for e in self.entries
                if (e.organization_id, e.bucket) == (org, bucket)
            )
            res = sum(
                e.delta_reserved_minor
                for e in self.entries
                if (e.organization_id, e.bucket) == (org, bucket)
            )
            if (wallet.available_minor, wallet.reserved_minor) != (av, res):
                out.append(
                    WalletMismatch(
                        organization_id=org,
                        bucket=bucket,
                        available_minor=wallet.available_minor,
                        reserved_minor=wallet.reserved_minor,
                        ledger_available_minor=av,
                        ledger_reserved_minor=res,
                    )
                )
        return out

    async def find_terminal_campaign_reservations(self, terminal_statuses):
        out = []
        for cid, campaign in self.campaigns.items():
            if campaign.status not in terminal_statuses:
                continue
            net = sum(
                e.delta_reserved_minor for e in self.entries if e.campaign_id == cid
            )
            if net:
                out.append(
                    CampaignReservationMismatch(
                        organization_id=campaign.organization_id,
                        bucket="marketing",
                        campaign_id=cid,
                        campaign_status=campaign.status,
                        net_reserved_minor=net,
                    )
                )
        return out


async def _tx(repo: FakeCreditRepository, coro):
    try:
        return await coro
    finally:
        repo.end_transaction()


def _wallets(repo: FakeCreditRepository) -> CreditWalletService:
    return CreditWalletService(repo)  # type: ignore[arg-type]


@dataclass
class FakeAudit:
    rows: list[dict[str, Any]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields):
        self.rows.append(fields)


@dataclass
class FakeCommitter:
    commits: int = 0

    async def commit(self):
        self.commits += 1


@dataclass
class FakeInvoices:
    repo: FakeCreditRepository
    has_profile: bool = True
    calls: list[dict[str, Any]] = field(default_factory=list)

    async def generate_invoice_for_credit_topup(self, **kwargs):
        self.calls.append(kwargs)
        if not self.has_profile:
            raise BillingProfileMissingError(kwargs["organization_id"])
        invoice_id = uuid.uuid4()
        self.repo.invoices[invoice_id] = f"INV-2026-{len(self.calls):05d}"
        return SimpleNamespace(id=invoice_id)


def _service(repo=None, *, has_profile=True, http=False):
    repo = repo or FakeCreditRepository(use_locks=not http)
    audit, committer = FakeAudit(), FakeCommitter()
    invoices = FakeInvoices(repo, has_profile=has_profile)
    service = CreditsService(
        repository=repo,  # type: ignore[arg-type]
        wallets=_wallets(repo),
        invoices=invoices,
        audit_writer=audit,
        committer=committer,
    )
    return service, repo, audit, committer, invoices


# ============================================================================
# Wallet service
# ============================================================================


async def test_concurrent_reserves_never_overdraw() -> None:
    repo = FakeCreditRepository()
    wallets = _wallets(repo)
    await _tx(repo, wallets.topup(ORG_A, 1_000, idempotency_key="seed"))
    campaign = uuid.uuid4()
    results = await asyncio.gather(
        *(
            _tx(
                repo,
                wallets.reserve(
                    ORG_A,
                    100,
                    idempotency_key=f"reserve:{campaign}:{n}",
                    campaign_id=campaign,
                ),
            )
            for n in range(20)
        ),
        return_exceptions=True,
    )
    assert sum(not isinstance(r, BaseException) for r in results) == 10
    assert sum(isinstance(r, InsufficientCreditsError) for r in results) == 10
    wallet = repo.wallets[(ORG_A, "marketing")]
    assert (wallet.available_minor, wallet.reserved_minor) == (0, 1_000)
    assert await repo.find_wallet_mismatches() == []


async def test_insufficient_reserve_carries_the_numbers() -> None:
    repo = FakeCreditRepository()
    wallets = _wallets(repo)
    await _tx(repo, wallets.topup(ORG_A, 250, idempotency_key="seed"))
    with pytest.raises(InsufficientCreditsError) as info:
        await _tx(
            repo,
            wallets.reserve(ORG_A, 600, idempotency_key="r", campaign_id=uuid.uuid4()),
        )
    assert info.value.status_code == 402
    assert info.value.data == {
        "error_code": "insufficient_credits",
        "needed_minor": 600,
        "available_minor": 250,
        "shortfall_minor": 350,
    }
    assert len(repo.entries) == 1


async def test_duplicate_idempotency_key_gives_exactly_one_row() -> None:
    repo = FakeCreditRepository()
    wallets = _wallets(repo)
    first = await _tx(repo, wallets.topup(ORG_A, 500, idempotency_key="k"))
    again = await _tx(repo, wallets.topup(ORG_A, 500, idempotency_key="k"))
    assert (first.created, again.created) == (True, False)
    assert again.entry is first.entry
    assert len(repo.entries) == 1
    assert repo.wallets[(ORG_A, "marketing")].available_minor == 500


async def test_concurrent_duplicate_keys_give_exactly_one_row() -> None:
    repo = FakeCreditRepository()
    wallets = _wallets(repo)
    results = await asyncio.gather(
        *(_tx(repo, wallets.topup(ORG_A, 500, idempotency_key="k")) for _ in range(8))
    )
    assert sum(r.created for r in results) == 1
    assert len(repo.entries) == 1


async def test_a_key_reused_for_a_different_movement_is_refused() -> None:
    repo = FakeCreditRepository()
    wallets = _wallets(repo)
    await _tx(repo, wallets.topup(ORG_A, 500, idempotency_key="k"))
    with pytest.raises(IdempotencyKeyReusedError) as info:
        await _tx(repo, wallets.topup(ORG_A, 700, idempotency_key="k"))
    assert info.value.status_code == 422
    assert len(repo.entries) == 1


async def test_keys_are_per_organization() -> None:
    repo = FakeCreditRepository()
    wallets = _wallets(repo)
    await _tx(repo, wallets.topup(ORG_A, 500, idempotency_key="k"))
    other = await _tx(repo, wallets.topup(ORG_B, 500, idempotency_key="k"))
    assert other.created is True
    assert repo.wallets[(ORG_B, "marketing")].available_minor == 500


async def test_negative_adjustment_cannot_touch_reserved() -> None:
    repo = FakeCreditRepository()
    wallets = _wallets(repo)
    await _tx(repo, wallets.topup(ORG_A, 1_000, idempotency_key="t"))
    await _tx(
        repo,
        wallets.reserve(ORG_A, 800, idempotency_key="r", campaign_id=uuid.uuid4()),
    )
    with pytest.raises(AdjustmentExceedsAvailableError) as info:
        await _tx(repo, wallets.adjust(ORG_A, -300, idempotency_key="a1"))
    assert info.value.status_code == 409
    assert info.value.data["error_code"] == "adjustment_exceeds_available"
    wallet = repo.wallets[(ORG_A, "marketing")]
    assert (wallet.available_minor, wallet.reserved_minor) == (200, 800)
    await _tx(repo, wallets.adjust(ORG_A, -200, idempotency_key="a2"))
    assert (wallet.available_minor, wallet.reserved_minor) == (0, 800)


async def test_campaign_debits_come_out_of_reserved_test_sends_out_of_available() -> (
    None
):
    repo = FakeCreditRepository()
    wallets = _wallets(repo)
    campaign = uuid.uuid4()
    await _tx(repo, wallets.topup(ORG_A, 1_000, idempotency_key="t"))
    await _tx(
        repo, wallets.reserve(ORG_A, 100, idempotency_key="r", campaign_id=campaign)
    )
    await _tx(
        repo,
        wallets.debit(
            ORG_A,
            60,
            idempotency_key="debit:1",
            campaign_id=campaign,
            recipient_id=uuid.uuid4(),
            unit_price_minor=30,
            units=2,
        ),
    )
    wallet = repo.wallets[(ORG_A, "marketing")]
    assert (wallet.available_minor, wallet.reserved_minor) == (900, 40)
    await _tx(
        repo,
        wallets.debit(
            ORG_A, 30, idempotency_key="test:1", campaign_id=campaign, is_test_send=True
        ),
    )
    assert (wallet.available_minor, wallet.reserved_minor) == (870, 40)
    # A campaign cannot debit past its reservation...
    with pytest.raises(CreditReservationExceededError):
        await _tx(
            repo,
            wallets.debit(
                ORG_A,
                50,
                idempotency_key="debit:2",
                campaign_id=campaign,
                recipient_id=uuid.uuid4(),
            ),
        )
    # ...nor release more than it holds.
    with pytest.raises(CreditReservationExceededError):
        await _tx(
            repo,
            wallets.release(ORG_A, 41, idempotency_key="rel", campaign_id=campaign),
        )


async def test_a_test_send_with_too_little_available_is_402() -> None:
    repo = FakeCreditRepository()
    wallets = _wallets(repo)
    await _tx(repo, wallets.topup(ORG_A, 20, idempotency_key="t"))
    with pytest.raises(InsufficientCreditsError):
        await _tx(
            repo,
            wallets.debit(
                ORG_A, 30, idempotency_key="test:1", campaign_id=None, is_test_send=True
            ),
        )


@pytest.mark.parametrize("amount", [0, -5, 10**12])
async def test_amounts_must_be_positive_and_in_range(amount: int) -> None:
    repo = FakeCreditRepository()
    with pytest.raises(ValueError):
        await _tx(repo, _wallets(repo).topup(ORG_A, amount, idempotency_key="t"))


async def test_float_amounts_are_refused() -> None:
    repo = FakeCreditRepository()
    with pytest.raises(TypeError):
        await _tx(repo, _wallets(repo).topup(ORG_A, 12.5, idempotency_key="t"))  # type: ignore[arg-type]


async def test_a_topup_back_above_the_threshold_rearms_the_low_balance_alert() -> None:
    repo = FakeCreditRepository()
    wallets = _wallets(repo)
    await _tx(repo, wallets.topup(ORG_A, 5_000, idempotency_key="t1"))
    wallet = repo.wallets[(ORG_A, "marketing")]
    wallet.low_balance_notified_at = NOW
    await _tx(repo, wallets.topup(ORG_A, 1_000, idempotency_key="t2"))
    assert wallet.low_balance_notified_at == NOW  # 6,000 < 10,000
    await _tx(repo, wallets.topup(ORG_A, 4_000, idempotency_key="t3"))
    assert wallet.low_balance_notified_at is None


# ============================================================================
# Reconciliation
# ============================================================================


async def test_ledger_sums_reconcile_with_the_wallet() -> None:
    repo = FakeCreditRepository()
    wallets = _wallets(repo)
    campaign = uuid.uuid4()
    steps = [
        wallets.topup(ORG_A, 10_000, idempotency_key="t"),
        wallets.reserve(ORG_A, 600, idempotency_key="r", campaign_id=campaign),
        wallets.debit(
            ORG_A,
            60,
            idempotency_key="d",
            campaign_id=campaign,
            recipient_id=uuid.uuid4(),
        ),
        wallets.release(ORG_A, 540, idempotency_key="rel", campaign_id=campaign),
        wallets.refund(ORG_A, 60, idempotency_key="ref", campaign_id=campaign),
        wallets.adjust(ORG_A, -500, idempotency_key="a"),
    ]
    for step in steps:
        await _tx(repo, step)
    wallet = repo.wallets[(ORG_A, "marketing")]
    assert wallet.available_minor == sum(e.delta_available_minor for e in repo.entries)
    assert wallet.reserved_minor == sum(e.delta_reserved_minor for e in repo.entries)
    assert (wallet.available_minor, wallet.reserved_minor) == (9_500, 0)
    # The running balances on the last row are the wallet.
    last = repo.entries[-1]
    assert (last.balance_available_after_minor, last.balance_reserved_after_minor) == (
        9_500,
        0,
    )
    assert (await reconcile_credit_wallets(repo)).ok


async def test_reconciliation_detects_a_tampered_balance(caplog) -> None:
    repo = FakeCreditRepository()
    await _tx(repo, _wallets(repo).topup(ORG_A, 1_000, idempotency_key="t"))
    repo.wallets[(ORG_A, "marketing")].available_minor += 1  # tampered
    with caplog.at_level("ERROR"):
        report = await reconcile_credit_wallets(repo)
    assert not report.ok
    [mismatch] = report.wallet_mismatches
    assert (mismatch.available_minor, mismatch.ledger_available_minor) == (1_001, 1_000)
    assert any(r.message == "credit_wallet_mismatch" for r in caplog.records)
    # Never auto-corrected.
    assert repo.wallets[(ORG_A, "marketing")].available_minor == 1_001


async def test_reconciliation_flags_a_finished_campaign_still_holding_credits() -> None:
    repo = FakeCreditRepository()
    campaign = uuid.uuid4()
    repo.campaigns[campaign] = SimpleNamespace(
        organization_id=ORG_A, name="Diwali", status="cancelled"
    )
    wallets = _wallets(repo)
    await _tx(repo, wallets.topup(ORG_A, 1_000, idempotency_key="t"))
    await _tx(
        repo, wallets.reserve(ORG_A, 400, idempotency_key="r", campaign_id=campaign)
    )
    report = await reconcile_credit_wallets(repo)
    assert [m.campaign_id for m in report.campaign_mismatches] == [campaign]


def test_the_alert_names_ids_and_amounts_only() -> None:
    report = ReconciliationReport(
        wallet_mismatches=[
            WalletMismatch(
                organization_id=ORG_A,
                bucket="marketing",
                available_minor=1_001,
                reserved_minor=0,
                ledger_available_minor=1_000,
                ledger_reserved_minor=0,
            )
        ],
        campaign_mismatches=[],
    )
    subject, body = format_reconciliation_alert(report)
    assert "1 wallet(s)" in subject
    assert str(ORG_A) in body
    assert "1001" in body and "1000" in body
    assert "corrected" in body


async def test_the_nightly_task_alerts_only_on_a_mismatch(monkeypatch) -> None:
    from app.domains.billing import credits_repository, tasks

    repo = FakeCreditRepository()
    await _tx(repo, _wallets(repo).topup(ORG_A, 1_000, idempotency_key="t"))

    class _Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def rollback(self):
            return None

    sent: list[tuple[str, str]] = []

    async def fake_alert(subject, body):
        sent.append((subject, body))
        return {"email": 1, "slack": 0}

    monkeypatch.setattr(tasks, "SessionLocal", lambda: _Session())
    monkeypatch.setattr(credits_repository, "CreditRepository", lambda _s: repo)
    monkeypatch.setattr(tasks, "_send_reconciliation_alert", fake_alert)

    clean = await tasks._run_credit_reconciliation_async()
    assert clean["ok"] is True and sent == []

    repo.wallets[(ORG_A, "marketing")].reserved_minor = 7
    dirty = await tasks._run_credit_reconciliation_async()
    assert dirty["ok"] is False
    assert dirty["wallet_mismatches"] == 1
    assert len(sent) == 1


def test_the_nightly_task_is_on_beat() -> None:
    from app.core.celery_app import celery_app
    from app.domains.billing.credits_constants import TASK_RECONCILE_CREDIT_WALLETS

    entry = celery_app.conf.beat_schedule["billing-reconcile-credit-wallets"]
    assert entry["task"] == TASK_RECONCILE_CREDIT_WALLETS
    assert TASK_RECONCILE_CREDIT_WALLETS in celery_app.tasks


# ============================================================================
# Master service: adjustments, audit, invoices
# ============================================================================


def _adjustment(**overrides):
    from app.domains.billing.credits_service import AdjustmentRequest

    fields = {
        "entry_type": CreditEntryType.TOPUP,
        "amount_minor": 500_000,
        "note": "Bank transfer received",
        "reference": "UTR123",
        "campaign_id": None,
        "issue_invoice": False,
        "amount_paid_minor_inr": None,
        "idempotency_key": "client-key-1",
    }
    fields.update(overrides)
    return AdjustmentRequest(**fields)


async def test_topup_is_audited_committed_and_namespaced() -> None:
    service, repo, audit, committer, _inv = _service()
    payload, created = await _tx(
        repo, service.post_adjustment(ORG_A, _adjustment(), actor_user_id=ACTOR)
    )
    assert created is True
    assert payload["wallet"] == {"available_minor": 500_000, "reserved_minor": 0}
    assert payload["entry"]["actor"] == {"id": str(ACTOR), "name": "Asha Ops"}
    assert payload["invoice"] is None
    assert repo.entries[0].idempotency_key == "master:client-key-1"
    assert [row["action"] for row in audit.rows] == ["credits_topup"]
    assert audit.rows[0]["organization_id"] == ORG_A
    assert committer.commits == 1


async def test_a_retried_adjustment_writes_nothing_twice() -> None:
    service, repo, audit, committer, invoices = _service()
    request = _adjustment(issue_invoice=True, amount_paid_minor_inr=500_000)
    first, _ = await _tx(
        repo, service.post_adjustment(ORG_A, request, actor_user_id=ACTOR)
    )
    second, created = await _tx(
        repo, service.post_adjustment(ORG_A, request, actor_user_id=ACTOR)
    )
    assert created is False
    assert second["entry"]["id"] == first["entry"]["id"]
    assert second["invoice"] == first["invoice"]
    assert second["invoice"]["invoice_number"] == "INV-2026-00001"
    assert len(invoices.calls) == 1
    assert len(audit.rows) == 1
    assert committer.commits == 1
    assert len(repo.entries) == 1


async def test_billing_profile_missing_is_409_and_writes_nothing() -> None:
    service, repo, audit, committer, _inv = _service(has_profile=False)
    request = _adjustment(issue_invoice=True, amount_paid_minor_inr=500_000)
    with pytest.raises(BillingProfileMissingError) as info:
        await _tx(repo, service.post_adjustment(ORG_A, request, actor_user_id=ACTOR))
    assert info.value.status_code == 409
    assert info.value.data["error_code"] == "billing_profile_missing"
    assert repo.entries == [] and audit.rows == [] and committer.commits == 0


@pytest.mark.parametrize(
    ("entry_type", "amount", "action"),
    [
        (CreditEntryType.ADJUSTMENT, -100, "credits_adjusted"),
        (CreditEntryType.ADJUSTMENT, 100, "credits_adjusted"),
        (CreditEntryType.REFUND, 100, "credits_refunded"),
    ],
)
async def test_each_master_entry_type_has_its_audit_action(
    entry_type, amount, action
) -> None:
    service, repo, audit, _c, _i = _service()
    await _tx(repo, _wallets(repo).topup(ORG_A, 1_000, idempotency_key="seed"))
    await _tx(
        repo,
        service.post_adjustment(
            ORG_A,
            _adjustment(entry_type=entry_type, amount_minor=amount),
            actor_user_id=ACTOR,
        ),
    )
    assert audit.rows[-1]["action"] == action


async def test_a_refund_cannot_name_another_organizations_campaign() -> None:
    from app.domains.billing.credits_exceptions import CreditsCampaignNotFoundError

    service, repo, _a, _c, _i = _service()
    foreign = uuid.uuid4()
    repo.campaigns[foreign] = SimpleNamespace(
        organization_id=ORG_B, name="Theirs", status="sent"
    )
    with pytest.raises(CreditsCampaignNotFoundError):
        await _tx(
            repo,
            service.post_adjustment(
                ORG_A,
                _adjustment(
                    entry_type=CreditEntryType.REFUND,
                    amount_minor=100,
                    campaign_id=foreign,
                ),
                actor_user_id=ACTOR,
            ),
        )
    assert repo.entries == []


async def test_settings_update_is_audited() -> None:
    service, repo, audit, committer, _i = _service()
    wallet = await _tx(
        repo,
        service.update_settings(
            ORG_A, low_balance_threshold_minor=25_000, actor_user_id=ACTOR
        ),
    )
    assert wallet == {
        "available_minor": 0,
        "reserved_minor": 0,
        "low_balance_threshold_minor": 25_000,
        "is_low": True,
    }
    assert audit.rows[0]["action"] == "credits_settings_updated"
    assert committer.commits == 1


async def test_customer_balance_of_an_org_with_no_wallet_is_zero() -> None:
    service, *_ = _service()
    assert await service.customer_balance(ORG_A) == {
        "available_minor": 0,
        "reserved_minor": 0,
        "low_balance_threshold_minor": 10_000,
        "is_low": True,
        "minor_per_credit": 100,
        "prices": {},
        "byo_channels": [],
    }


# ============================================================================
# Request schemas
# ============================================================================


def _body(**overrides):
    body = {
        "entry_type": "topup",
        "amount_minor": 500_000,
        "note": "Bank transfer",
        "idempotency_key": "3f2b8c1e-5a4d",
    }
    body.update(overrides)
    return body


@pytest.mark.parametrize(
    "overrides",
    [
        {"note": "abc"},  # too short
        {"note": "    x    "},  # too short once stripped
        {"amount_minor": 0},
        {"amount_minor": -5},  # a top-up must be positive
        {"amount_minor": 12.5},  # never a float
        {"amount_minor": "500"},  # never a string
        {"entry_type": "debit"},  # not a Master entry type
        {"entry_type": "adjustment", "amount_minor": 0},
        {"campaign_id": str(uuid.uuid4())},  # campaign only on a refund
        {"issue_invoice": True},  # needs amount_paid_minor_inr
        {"entry_type": "refund", "issue_invoice": True, "amount_paid_minor_inr": 1},
        {"amount_paid_minor_inr": 100},  # only with issue_invoice
        {"idempotency_key": "short"},
        {"idempotency_key": "has spaces in it"},
        {"organization_id": str(ORG_B)},  # extra fields are refused
    ],
)
def test_adjustment_schema_refuses(overrides) -> None:
    with pytest.raises(ValidationError):
        CreditAdjustmentCreate(**_body(**overrides))


def test_adjustment_schema_accepts_a_signed_adjustment() -> None:
    body = CreditAdjustmentCreate(**_body(entry_type="adjustment", amount_minor=-250))
    assert body.amount_minor == -250


def test_settings_schema() -> None:
    assert (
        CreditSettingsUpdate(low_balance_threshold_minor=0).low_balance_threshold_minor
        == 0
    )
    for bad in (-1, 1.5, "10"):
        with pytest.raises(ValidationError):
            CreditSettingsUpdate(low_balance_threshold_minor=bad)


# ============================================================================
# GST top-up invoice (InvoiceService.generate_invoice_for_credit_topup)
# ============================================================================


async def _invoice_service(billing_state: str | None):
    from tests.unit.test_billing_invoices_tax import (
        FakeAuditWriter,
        _make_billing_profile,
        _make_invoice_service,
    )

    audit = FakeAuditWriter()
    service, invoices, _s, _p, profiles, rates = _make_invoice_service(
        audit_writer=audit
    )
    await rates.create_tax_rate(
        name="India GST",
        tax_type=TaxType.GST.value,
        rate_percentage=Decimal("18.00"),
        country_code="IN",
        is_active=True,
    )
    if billing_state is not None:
        await _make_billing_profile(
            profiles, organization_id=ORG_A, billing_state=billing_state
        )
    return service, invoices, audit


async def test_topup_invoice_is_a_paid_gst_invoice() -> None:
    service, invoices, audit = await _invoice_service("Maharashtra")
    invoice = await service.generate_invoice_for_credit_topup(
        organization_id=ORG_A,
        amount_paid_minor_inr=500_000,
        credits_minor=550_000,  # a bonus: credits exceed what was paid
        reference="UTR123",
        actor_user_id=ACTOR,
    )
    assert invoice.status == InvoiceStatus.PAID.value
    assert invoice.subscription_id is None
    assert invoice.subtotal == Decimal("5000.00")  # tax on what was paid
    assert (invoice.cgst_amount, invoice.sgst_amount, invoice.igst_amount) == (
        Decimal("450.00"),
        Decimal("450.00"),
        Decimal("0"),
    )
    assert invoice.total_amount == Decimal("5900.00")
    assert invoice.invoice_number.startswith("INV-")
    [item] = await invoices.list_items(invoice.id)
    assert item.description == "Marketing credits: 5,500 credits (ref UTR123)"
    assert audit.entries[0]["actor_user_id"] == ACTOR


async def test_topup_invoice_is_igst_across_states() -> None:
    service, _invoices, _audit = await _invoice_service("Karnataka")
    invoice = await service.generate_invoice_for_credit_topup(
        organization_id=ORG_A,
        amount_paid_minor_inr=100_050,
        credits_minor=100_050,
        reference=None,
        actor_user_id=None,
    )
    assert invoice.subtotal == Decimal("1000.50")
    assert invoice.igst_amount == Decimal("180.09")
    assert invoice.cgst_amount == Decimal("0")


async def test_topup_invoice_without_billing_profile_is_billing_profile_missing() -> (
    None
):
    service, _invoices, _audit = await _invoice_service(None)
    with pytest.raises(BillingProfileMissingError):
        await service.generate_invoice_for_credit_topup(
            organization_id=ORG_A,
            amount_paid_minor_inr=1_000,
            credits_minor=1_000,
            reference=None,
            actor_user_id=None,
        )


async def test_manual_invoices_are_unchanged_by_the_shared_helper() -> None:
    service, _invoices, audit = await _invoice_service("Maharashtra")
    invoice = await service.create_manual_invoice(
        organization_id=ORG_A,
        line_items=[("Setup", Decimal("2"), Decimal("500.00"))],
    )
    assert invoice.status == InvoiceStatus.ISSUED.value
    assert invoice.due_date - invoice.issue_date == timedelta(days=15)
    assert invoice.total_amount == Decimal("1180.00")
    assert "manually created" in audit.entries[0]["description"]


# ============================================================================
# Routes: guards, scope pins, 402/403
# ============================================================================


_APP = None


def _app():
    global _APP
    if _APP is None:
        from app.main import create_app

        _APP = create_app()
    _APP.dependency_overrides.clear()
    return _APP


MASTER_ROUTES = [
    ("GET", "/api/v1/platform/organizations/{organization_id}/credits", "billing.read"),
    (
        "GET",
        "/api/v1/platform/organizations/{organization_id}/credits/ledger",
        "billing.read",
    ),
    (
        "POST",
        "/api/v1/platform/organizations/{organization_id}/credits/adjustments",
        "billing.manage",
    ),
    (
        "PUT",
        "/api/v1/platform/organizations/{organization_id}/credits/settings",
        "billing.manage",
    ),
]
CUSTOMER_ROUTES = [
    ("GET", "/api/v1/marketing/credits", "marketing.read", "location"),
    ("GET", "/api/v1/marketing/credits/ledger", "billing.read", "organization"),
]


def _route(method: str, path: str):
    return next(
        r
        for r in _app().routes
        if getattr(r, "path", "") == path and method in getattr(r, "methods", ())
    )


def _closure(call) -> set[str]:
    return {str(cell.cell_contents) for cell in (call.__closure__ or ())}


def test_the_credit_route_table() -> None:
    mounted = sorted(
        (method, r.path)
        for r in _app().routes
        if "credits" in getattr(r, "path", "")
        for method in r.methods - {"HEAD", "OPTIONS"}
    )
    expected = sorted(
        [(m, p) for m, p, _ in MASTER_ROUTES]
        + [(m, p) for m, p, _, _ in CUSTOMER_ROUTES]
    )
    assert mounted == expected


@pytest.mark.parametrize(("method", "path", "permission"), MASTER_ROUTES)
def test_master_routes_pin_global_scope(method, path, permission) -> None:
    route = _route(method, path)
    [permission_dep] = [
        d.call
        for d in route.dependant.dependencies
        if getattr(d.call, "__qualname__", "").startswith("RequirePermission")
    ]
    closure = _closure(permission_dep)
    assert permission in closure
    assert "global" in closure


@pytest.mark.parametrize(("method", "path", "permission", "scope"), CUSTOMER_ROUTES)
def test_customer_routes_declare_their_guards_in_order(
    method, path, permission, scope
) -> None:
    from app.domains.rbac.dependencies import RequireOrganization

    route = _route(method, path)
    calls = [d.call for d in route.dependant.dependencies]
    names = [getattr(c, "__qualname__", "") for c in calls]
    org = calls.index(RequireOrganization)
    feature = next(i for i, n in enumerate(names) if n.startswith("RequireFeature"))
    perm = next(i for i, n in enumerate(names) if n.startswith("RequirePermission"))
    assert org < feature < perm
    assert "guest_marketing" in _closure(calls[feature])
    assert {permission, scope} <= _closure(calls[perm])


def _unlocked_checker():
    from app.domains.billing.service import EntitlementSnapshot

    class Checker:
        async def get_snapshot(self, organization_id):
            return EntitlementSnapshot(
                organization_id=organization_id,
                plan_id=uuid.uuid4(),
                license_status="active",
                expires_at=None,
                enabled_features=frozenset({"guest_marketing"}),
                limits={},
                tiers={},
            )

    return Checker()


def _client(*, granted_scope, organization_id=ORG_A, service=None, locked=False):
    """A TestClient whose caller holds every permission, but only at
    ``granted_scope`` -- the way a real org-scoped or location-scoped role
    assignment behaves against a pinned check."""
    from fastapi.testclient import TestClient

    from app.database.session import get_db_session
    from app.domains.auth.models import AuthUser
    from app.domains.billing.credits_dependencies import get_credits_service
    from app.domains.billing.dependencies import get_entitlement_checker
    from app.domains.organization.dependencies import get_organization_service
    from app.domains.rbac.authorization import AccessValidator
    from app.domains.rbac.dependencies import (
        CurrentOrganizationScope,
        CurrentUser,
        get_access_validator,
    )
    from app.domains.rbac.enums import ScopeType
    from app.domains.rbac.exceptions import PermissionDeniedError
    from app.domains.rbac.organization_scope import OrganizationScope

    seen: list[tuple[str, ScopeType]] = []
    order = [ScopeType.GLOBAL, ScopeType.ORGANIZATION, ScopeType.LOCATION]

    class ScopedValidator(AccessValidator):
        def __init__(self) -> None:
            pass

        async def check(self, user_id, permission_key, *, scope_type, scope_context):
            seen.append((permission_key, scope_type))
            # A grant satisfies its own level and anything narrower.
            if order.index(scope_type) < order.index(granted_scope):
                raise PermissionDeniedError(permission_key, str(scope_type))

    class Orgs:
        async def get_organization(self, organization_id, **_):
            return SimpleNamespace(id=organization_id, parent_organization_id=None)

    async def _no_db():
        yield None

    app = _app()
    app.dependency_overrides[CurrentUser] = lambda: AuthUser(
        id=str(ACTOR), email="ops@wyfy.in"
    )
    app.dependency_overrides[get_access_validator] = lambda: ScopedValidator()
    app.dependency_overrides[get_db_session] = _no_db
    app.dependency_overrides[CurrentOrganizationScope] = lambda: (
        OrganizationScope.for_organization(organization_id)
    )
    app.dependency_overrides[get_organization_service] = lambda: Orgs()
    if not locked:
        app.dependency_overrides[get_entitlement_checker] = _unlocked_checker
    else:
        from app.domains.billing.service import EntitlementSnapshot

        class Locked:
            async def get_snapshot(self, organization_id):
                return EntitlementSnapshot(
                    organization_id=organization_id,
                    plan_id=uuid.uuid4(),
                    license_status="active",
                    expires_at=None,
                    enabled_features=frozenset(),
                    limits={},
                    tiers={},
                )

        app.dependency_overrides[get_entitlement_checker] = lambda: Locked()
    if service is not None:
        app.dependency_overrides[get_credits_service] = lambda: service
    return TestClient(app, raise_server_exceptions=False), seen


def _master_request(client, method, path, org=ORG_B):
    concrete = path.replace("{organization_id}", str(org))
    body = None
    if method == "POST":
        body = _body()
    elif method == "PUT":
        body = {"low_balance_threshold_minor": 100}
    return client.request(
        method, concrete, json=body, headers={"X-Organization-Id": str(org)}
    )


@pytest.mark.parametrize(("method", "path", "permission"), MASTER_ROUTES)
def test_org_scoped_billing_holder_gets_403_on_master_routes(
    method, path, permission
) -> None:
    """An organization-scoped holder of billing.manage/billing.read -- even
    for the very organization in the path -- is refused."""
    from app.domains.rbac.enums import ScopeType

    service, *_ = _service(http=True)
    client, seen = _client(
        granted_scope=ScopeType.ORGANIZATION, organization_id=ORG_B, service=service
    )
    response = _master_request(client, method, path)
    assert response.status_code == 403, response.text
    assert response.json()["data"]["error_code"] == "permission_denied"
    assert seen == [(permission, ScopeType.GLOBAL)]


@pytest.mark.parametrize(("method", "path", "_permission"), MASTER_ROUTES)
def test_global_holder_reaches_master_routes(method, path, _permission) -> None:
    from app.domains.rbac.enums import ScopeType

    service, repo, audit, *_ = _service(http=True)
    client, _seen = _client(
        granted_scope=ScopeType.GLOBAL, organization_id=ORG_B, service=service
    )
    response = _master_request(client, method, path)
    assert response.status_code in (200, 201), response.text


def test_master_adjustment_over_http() -> None:
    from app.domains.rbac.enums import ScopeType

    service, repo, audit, committer, _i = _service(http=True)
    client, _seen = _client(
        granted_scope=ScopeType.GLOBAL, organization_id=ORG_B, service=service
    )
    path = f"/api/v1/platform/organizations/{ORG_B}/credits/adjustments"
    created = client.post(path, json=_body())
    assert created.status_code == 201, created.text
    data = created.json()["data"]
    assert data["wallet"] == {"available_minor": 500_000, "reserved_minor": 0}
    assert data["entry"]["entry_type"] == "topup"
    assert data["entry"]["note"] == "Bank transfer"

    replay = client.post(path, json=_body())
    assert replay.status_code == 201
    assert replay.json()["data"]["entry"]["id"] == data["entry"]["id"]
    assert len(repo.entries) == 1 and len(audit.rows) == 1

    too_much = client.post(
        path,
        json=_body(
            entry_type="adjustment", amount_minor=-600_000, idempotency_key="key-two-2"
        ),
    )
    assert too_much.status_code == 409
    assert too_much.json()["data"]["error_code"] == "adjustment_exceeds_available"

    invalid = client.post(path, json=_body(note="no"))
    assert invalid.status_code == 422


def test_master_route_for_an_unknown_organization_is_404() -> None:
    from app.domains.rbac.enums import ScopeType

    unknown = uuid.uuid4()
    service, *_ = _service(http=True)
    client, _seen = _client(
        granted_scope=ScopeType.GLOBAL, organization_id=unknown, service=service
    )
    response = client.get(f"/api/v1/platform/organizations/{unknown}/credits")
    assert response.status_code == 404
    assert response.json()["data"]["error_code"] == "organization_not_found"


@pytest.mark.parametrize(("method", "path", "_p", "_s"), CUSTOMER_ROUTES)
def test_locked_addon_refuses_the_customer_credit_routes(method, path, _p, _s) -> None:
    from app.domains.rbac.enums import ScopeType

    service, *_ = _service(http=True)
    client, seen = _client(granted_scope=ScopeType.GLOBAL, service=service, locked=True)
    response = client.request(method, path, headers={"X-Organization-Id": str(ORG_A)})
    assert response.status_code == 402
    assert response.json()["data"]["error_code"] == "feature_not_entitled"
    assert seen == []  # refused before any permission work


def test_location_scoped_staff_see_the_balance_but_not_the_ledger() -> None:
    from app.domains.rbac.enums import ScopeType

    service, *_ = _service(http=True)
    client, seen = _client(granted_scope=ScopeType.LOCATION, service=service)
    headers = {"X-Organization-Id": str(ORG_A)}
    balance = client.get("/api/v1/marketing/credits", headers=headers)
    assert balance.status_code == 200, balance.text
    assert balance.json()["data"]["minor_per_credit"] == 100
    ledger = client.get("/api/v1/marketing/credits/ledger", headers=headers)
    assert ledger.status_code == 403
    assert ledger.json()["data"]["error_code"] == "permission_denied"
    assert seen == [
        ("marketing.read", ScopeType.LOCATION),
        ("billing.read", ScopeType.ORGANIZATION),
    ]


def test_the_customer_ledger_reads_only_the_callers_organization() -> None:
    from app.domains.rbac.enums import ScopeType

    service, repo, *_ = _service(http=True)

    async def seed():
        wallets = _wallets(repo)
        await _tx(repo, wallets.topup(ORG_A, 700, idempotency_key="a"))
        await _tx(repo, wallets.topup(ORG_B, 900, idempotency_key="b"))

    asyncio.run(seed())
    client, _seen = _client(granted_scope=ScopeType.ORGANIZATION, service=service)
    response = client.get(
        "/api/v1/marketing/credits/ledger", headers={"X-Organization-Id": str(ORG_A)}
    )
    assert response.status_code == 200, response.text
    items = response.json()["data"]["items"]
    assert [i["delta_available_minor"] for i in items] == [700]


@pytest.mark.parametrize(
    "query",
    ["entry_type=topup,bogus", "detail=everything", "from=2026-09-10&to=2026-09-01"],
)
def test_ledger_filters_are_validated(query: str) -> None:
    from app.domains.rbac.enums import ScopeType

    service, *_ = _service(http=True)
    client, _seen = _client(granted_scope=ScopeType.ORGANIZATION, service=service)
    response = client.get(
        f"/api/v1/marketing/credits/ledger?{query}",
        headers={"X-Organization-Id": str(ORG_A)},
    )
    assert response.status_code == 422, response.text
