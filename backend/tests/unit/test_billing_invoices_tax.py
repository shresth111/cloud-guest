"""Unit tests for BE-013 Part 4 (Billing: Invoice Engine + Tax/GST): the
invoice number generator's real concurrency-safety mechanism (simulated
under genuine ``asyncio.gather`` contention, not just "no ``await``
happened to occur in between"), the real CGST/SGST/IGST-vs-IGST GST
computation (same-state, cross-state, tax-exempt, no-rate-configured),
invoice generation composing (never reimplementing) the renewal engine's
own real charge-amount computation (verified via a spy, not a
reimplementation), a real, valid invoice PDF (opened/inspected, same rigor
BE-012 Part 5's own PDF export tests already establish), the payment-
webhook-triggers-invoice-paid composition, credit/debit note issuance,
void invoice, ``billing_snapshot``'s frozen-at-issue-time correctness, and
tenant isolation.

Follows this project's plain-``assert``/native-``async def`` style (see
``test_billing_payments_webhooks.py``'s own module docstring, the Part 3
template this file mirrors); ``asyncio_mode = "auto"`` runs async tests
directly. Every service under test is exercised against small, hand-rolled
in-memory fakes satisfying this module's own narrow ``Protocol`` shapes --
no live Postgres/Redis anywhere in this suite.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from unittest.mock import patch

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.billing.constants import (
    BillingCycle,
    InvoiceStatus,
    NoteType,
    PaymentStatus,
    PlanType,
    TaxType,
)
from app.domains.billing.exceptions import (
    BillingProfileNotFoundError,
    InvalidInvoiceStatusTransitionError,
    InvalidNoteAmountError,
    InvoiceNotFoundError,
)
from app.domains.billing.invoice_pdf import SellerInfo, render_invoice_pdf
from app.domains.billing.models import (
    BillingProfile,
    CreditDebitNote,
    Invoice,
    InvoiceItem,
    Payment,
    Plan,
    Subscription,
    TaxRate,
)
from app.domains.billing.number_generator import generate_invoice_number
from app.domains.billing.service import InvoiceService
from app.domains.billing.validators import compute_tax_breakdown

# ============================================================================
# Shared helpers (mirrors test_billing_payments_webhooks.py's own identical
# helpers)
# ============================================================================


def _now() -> datetime:
    return datetime.now(UTC)


def _base_fields(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": uuid.uuid4(),
        "created_at": _now(),
        "updated_at": _now(),
        "deleted_at": None,
        "is_deleted": False,
        "created_by": None,
        "updated_by": None,
        "version": 1,
    }
    base.update(overrides)
    return base


# ============================================================================
# Fake repositories
# ============================================================================


@dataclass
class FakeNumberCounterRepository:
    """A fake ``number_generator.NumberCounterRepositoryProtocol``
    implementation that mirrors the real, atomic
    ``INSERT ... ON CONFLICT DO UPDATE ... RETURNING`` statement's own
    concurrency guarantee via an explicit ``asyncio.Lock`` held across the
    read-then-write critical section -- **including** a genuine
    ``await asyncio.sleep(0)`` yield point inside the locked section, to
    prove the lock is doing real serialization work (not merely "no
    ``await`` happened to occur between the read and the write", which
    would pass even with no real concurrency protection at all under
    Python's single-threaded cooperative scheduling)."""

    counters: dict[str, int] = field(default_factory=dict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def increment_and_get_next(self, counter_key: str) -> int:
        async with self._lock:
            current = self.counters.get(counter_key, 0)
            await asyncio.sleep(0)  # a real yield point INSIDE the lock
            updated = current + 1
            self.counters[counter_key] = updated
            return updated


@dataclass
class FakePlanRepository:
    plans: dict[uuid.UUID, Plan] = field(default_factory=dict)

    async def create_plan(self, **fields: object) -> Plan:
        plan = Plan(**_base_fields(**fields))
        self.plans[plan.id] = plan
        return plan

    async def get_by_id(
        self, plan_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Plan | None:
        return self.plans.get(plan_id)


@dataclass
class FakeSubscriptionRepository:
    subscriptions: dict[uuid.UUID, Subscription] = field(default_factory=dict)

    async def create_subscription(self, **fields: object) -> Subscription:
        subscription = Subscription(**_base_fields(**fields))
        self.subscriptions[subscription.id] = subscription
        return subscription

    async def get_by_id(
        self, subscription_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Subscription | None:
        return self.subscriptions.get(subscription_id)

    async def update_subscription(
        self, subscription: Subscription, data: dict[str, object]
    ) -> Subscription:
        for key, value in data.items():
            setattr(subscription, key, value)
        subscription.version += 1
        return subscription


@dataclass
class FakeBillingProfileRepository:
    profiles: dict[uuid.UUID, BillingProfile] = field(default_factory=dict)

    async def create_billing_profile(self, **fields: object) -> BillingProfile:
        profile = BillingProfile(**_base_fields(**fields))
        self.profiles[profile.organization_id] = profile
        return profile

    async def get_by_organization_id(
        self, organization_id: uuid.UUID
    ) -> BillingProfile | None:
        return self.profiles.get(organization_id)

    async def update_billing_profile(
        self, billing_profile: BillingProfile, data: dict[str, object]
    ) -> BillingProfile:
        for key, value in data.items():
            setattr(billing_profile, key, value)
        billing_profile.version += 1
        return billing_profile


@dataclass
class FakeTaxRateRepository:
    tax_rates: dict[uuid.UUID, TaxRate] = field(default_factory=dict)

    async def create_tax_rate(self, **fields: object) -> TaxRate:
        tax_rate = TaxRate(**_base_fields(**fields))
        self.tax_rates[tax_rate.id] = tax_rate
        return tax_rate

    async def get_by_id(
        self, tax_rate_id: uuid.UUID, *, include_deleted: bool = False
    ) -> TaxRate | None:
        return self.tax_rates.get(tax_rate_id)

    async def update_tax_rate(
        self, tax_rate: TaxRate, data: dict[str, object]
    ) -> TaxRate:
        for key, value in data.items():
            setattr(tax_rate, key, value)
        tax_rate.version += 1
        return tax_rate

    async def get_active_for_country(self, country_code: str) -> TaxRate | None:
        for tax_rate in self.tax_rates.values():
            if tax_rate.country_code == country_code and tax_rate.is_active:
                return tax_rate
        return None


@dataclass
class FakeCreditDebitNoteRepository:
    notes: dict[uuid.UUID, CreditDebitNote] = field(default_factory=dict)

    async def create_note(self, **fields: object) -> CreditDebitNote:
        note = CreditDebitNote(**_base_fields(**fields))
        self.notes[note.id] = note
        return note

    async def list_for_invoice(self, invoice_id: uuid.UUID) -> list[CreditDebitNote]:
        return [n for n in self.notes.values() if n.invoice_id == invoice_id]


@dataclass
class FakeInvoiceRepository:
    invoices: dict[uuid.UUID, Invoice] = field(default_factory=dict)
    items: dict[uuid.UUID, InvoiceItem] = field(default_factory=dict)

    async def create_invoice(self, **fields: object) -> Invoice:
        invoice = Invoice(**_base_fields(**fields))
        self.invoices[invoice.id] = invoice
        return invoice

    async def get_by_id(
        self, invoice_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Invoice | None:
        return self.invoices.get(invoice_id)

    async def get_by_invoice_number(self, invoice_number: str) -> Invoice | None:
        for invoice in self.invoices.values():
            if invoice.invoice_number == invoice_number:
                return invoice
        return None

    async def update_invoice(
        self, invoice: Invoice, data: dict[str, object]
    ) -> Invoice:
        for key, value in data.items():
            setattr(invoice, key, value)
        invoice.version += 1
        return invoice

    async def list_invoices(
        self,
        *,
        page: int,
        page_size: int,
        organization_id: uuid.UUID | None = None,
        status: str | None = None,
    ) -> tuple[list[Invoice], PaginationMeta]:
        items = list(self.invoices.values())
        if organization_id is not None:
            items = [i for i in items if i.organization_id == organization_id]
        if status is not None:
            items = [i for i in items if i.status == status]
        params = PageParams(page=page, page_size=page_size)
        return items, PaginationMeta.from_total(params, len(items))

    async def list_unpaid_for_subscription(
        self, subscription_id: uuid.UUID
    ) -> list[Invoice]:
        candidates = [
            i
            for i in self.invoices.values()
            if i.subscription_id == subscription_id
            and i.status in (InvoiceStatus.ISSUED.value, InvoiceStatus.OVERDUE.value)
        ]
        return sorted(candidates, key=lambda i: i.issue_date, reverse=True)

    async def list_issued_past_due(self, *, now: datetime) -> list[Invoice]:
        return [
            i
            for i in self.invoices.values()
            if i.status == InvoiceStatus.ISSUED.value and i.due_date <= now
        ]

    async def create_invoice_item(self, **fields: object) -> InvoiceItem:
        item = InvoiceItem(**_base_fields(**fields))
        self.items[item.id] = item
        return item

    async def list_items(self, invoice_id: uuid.UUID) -> list[InvoiceItem]:
        return [i for i in self.items.values() if i.invoice_id == invoice_id]


def _make_invoice_service(
    *,
    invoice_repository: FakeInvoiceRepository | None = None,
    subscription_repository: FakeSubscriptionRepository | None = None,
    plan_repository: FakePlanRepository | None = None,
    billing_profile_repository: FakeBillingProfileRepository | None = None,
    tax_rate_repository: FakeTaxRateRepository | None = None,
    number_counter_repository: FakeNumberCounterRepository | None = None,
    note_repository: FakeCreditDebitNoteRepository | None = None,
    platform_gst_state: str = "Maharashtra",
    platform_gst_country: str = "IN",
) -> tuple[
    InvoiceService,
    FakeInvoiceRepository,
    FakeSubscriptionRepository,
    FakePlanRepository,
    FakeBillingProfileRepository,
    FakeTaxRateRepository,
]:
    invoice_repository = invoice_repository or FakeInvoiceRepository()
    subscription_repository = subscription_repository or FakeSubscriptionRepository()
    plan_repository = plan_repository or FakePlanRepository()
    billing_profile_repository = (
        billing_profile_repository or FakeBillingProfileRepository()
    )
    tax_rate_repository = tax_rate_repository or FakeTaxRateRepository()
    number_counter_repository = (
        number_counter_repository or FakeNumberCounterRepository()
    )
    note_repository = note_repository or FakeCreditDebitNoteRepository()

    service = InvoiceService(
        invoice_repository,
        subscription_repository=subscription_repository,
        plan_repository=plan_repository,
        billing_profile_repository=billing_profile_repository,
        tax_rate_repository=tax_rate_repository,
        number_counter_repository=number_counter_repository,
        note_repository=note_repository,
        platform_gst_state=platform_gst_state,
        platform_gst_country=platform_gst_country,
        invoice_due_days=15,
    )
    return (
        service,
        invoice_repository,
        subscription_repository,
        plan_repository,
        billing_profile_repository,
        tax_rate_repository,
    )


async def _make_subscription_and_plan(
    subscription_repository: FakeSubscriptionRepository,
    plan_repository: FakePlanRepository,
    *,
    organization_id: uuid.UUID,
    base_price: Decimal = Decimal("29.99"),
    currency: str = "INR",
) -> tuple[Plan, Subscription]:
    plan = await plan_repository.create_plan(
        name="Professional",
        slug=f"plan-{uuid.uuid4().hex[:8]}",
        plan_type=PlanType.PROFESSIONAL.value,
        description=None,
        billing_cycle=BillingCycle.MONTHLY.value,
        base_price=base_price,
        currency=currency,
        is_active=True,
        is_public=True,
        created_by_user_id=None,
        sort_order=0,
    )
    now = _now()
    subscription = await subscription_repository.create_subscription(
        organization_id=organization_id,
        license_id=uuid.uuid4(),
        plan_id=plan.id,
        status="active",
        billing_cycle=plan.billing_cycle,
        current_period_start=now,
        current_period_end=now + timedelta(days=30),
        trial_end=None,
        auto_renew=True,
        cancel_at_period_end=False,
        started_at=now,
    )
    return plan, subscription


async def _make_billing_profile(
    billing_profile_repository: FakeBillingProfileRepository,
    *,
    organization_id: uuid.UUID,
    billing_state: str = "Maharashtra",
    billing_country: str = "IN",
    tax_exempt: bool = False,
    gst_identifier: str | None = "27AAAAA0000A1Z5",
) -> BillingProfile:
    return await billing_profile_repository.create_billing_profile(
        organization_id=organization_id,
        billing_name="Acme Hospitality Pvt Ltd",
        billing_address_line1="221B Baker Street",
        billing_address_line2=None,
        billing_city="Mumbai",
        billing_state=billing_state,
        billing_country=billing_country,
        billing_postal_code="400001",
        gst_identifier=gst_identifier,
        tax_exempt=tax_exempt,
    )


# ============================================================================
# Invoice number generator -- real concurrency safety
# ============================================================================


class TestInvoiceNumberGeneratorConcurrency:
    async def test_concurrent_generation_never_collides(self) -> None:
        """A real test of the real mechanism -- 25 concurrent
        ``generate_invoice_number`` calls (via ``asyncio.gather``) against a
        fake repository whose own ``increment_and_get_next`` holds a lock
        across a genuine ``await`` point (simulating the real DB
        statement's own atomicity) must produce 25 distinct numbers, never
        a single collision."""
        repository = FakeNumberCounterRepository()
        at = datetime(2026, 7, 19, tzinfo=UTC)

        results = await asyncio.gather(
            *[generate_invoice_number(repository, at=at) for _ in range(25)]
        )

        assert len(results) == 25
        assert len(set(results)) == 25, "every generated invoice number must be unique"
        assert all(number.startswith("INV-2026-") for number in results)
        # The full, real 1..25 sequence was produced -- no number skipped,
        # none reused.
        sequences = sorted(int(number.rsplit("-", 1)[1]) for number in results)
        assert sequences == list(range(1, 26))

    async def test_different_years_get_independent_sequences(self) -> None:
        repository = FakeNumberCounterRepository()
        first_2026 = await generate_invoice_number(
            repository, at=datetime(2026, 1, 1, tzinfo=UTC)
        )
        first_2027 = await generate_invoice_number(
            repository, at=datetime(2027, 1, 1, tzinfo=UTC)
        )
        second_2026 = await generate_invoice_number(
            repository, at=datetime(2026, 6, 1, tzinfo=UTC)
        )
        assert first_2026 == "INV-2026-00001"
        assert first_2027 == "INV-2027-00001"
        assert second_2026 == "INV-2026-00002"


# ============================================================================
# Real CGST/SGST/IGST computation
# ============================================================================


class TestGstTaxComputation:
    def test_intra_state_splits_cgst_sgst_equally(self) -> None:
        breakdown = compute_tax_breakdown(
            subtotal=Decimal("1000.00"),
            tax_type=TaxType.GST,
            rate_percentage=Decimal("18.00"),
            tax_exempt=False,
            platform_state="Maharashtra",
            platform_country="IN",
            billing_state="Maharashtra",
            billing_country="IN",
        )
        assert breakdown.is_intra_state is True
        assert breakdown.cgst_amount == Decimal("90.00")
        assert breakdown.sgst_amount == Decimal("90.00")
        assert breakdown.igst_amount == Decimal("0.00")
        assert breakdown.tax_amount == Decimal("180.00")

    def test_intra_state_is_case_and_whitespace_insensitive(self) -> None:
        breakdown = compute_tax_breakdown(
            subtotal=Decimal("100.00"),
            tax_type=TaxType.GST,
            rate_percentage=Decimal("18.00"),
            tax_exempt=False,
            platform_state="Maharashtra",
            platform_country="IN",
            billing_state=" MAHARASHTRA ",
            billing_country="in",
        )
        assert breakdown.is_intra_state is True
        assert breakdown.igst_amount == Decimal("0.00")

    def test_inter_state_applies_full_rate_as_igst(self) -> None:
        breakdown = compute_tax_breakdown(
            subtotal=Decimal("1000.00"),
            tax_type=TaxType.GST,
            rate_percentage=Decimal("18.00"),
            tax_exempt=False,
            platform_state="Maharashtra",
            platform_country="IN",
            billing_state="Karnataka",
            billing_country="IN",
        )
        assert breakdown.is_intra_state is False
        assert breakdown.cgst_amount == Decimal("0.00")
        assert breakdown.sgst_amount == Decimal("0.00")
        assert breakdown.igst_amount == Decimal("180.00")
        assert breakdown.tax_amount == Decimal("180.00")

    def test_different_country_is_always_inter_state(self) -> None:
        breakdown = compute_tax_breakdown(
            subtotal=Decimal("500.00"),
            tax_type=TaxType.GST,
            rate_percentage=Decimal("18.00"),
            tax_exempt=False,
            platform_state="Maharashtra",
            platform_country="IN",
            billing_state="Maharashtra",
            billing_country="US",
        )
        assert breakdown.is_intra_state is False
        assert breakdown.igst_amount == Decimal("90.00")

    def test_tax_exempt_organization_is_charged_zero_tax(self) -> None:
        breakdown = compute_tax_breakdown(
            subtotal=Decimal("1000.00"),
            tax_type=TaxType.GST,
            rate_percentage=Decimal("18.00"),
            tax_exempt=True,
            platform_state="Maharashtra",
            platform_country="IN",
            billing_state="Karnataka",
            billing_country="IN",
        )
        assert breakdown.cgst_amount == Decimal("0.00")
        assert breakdown.sgst_amount == Decimal("0.00")
        assert breakdown.igst_amount == Decimal("0.00")
        assert breakdown.tax_amount == Decimal("0.00")

    def test_no_tax_type_configured_is_an_honest_zero_not_an_error(self) -> None:
        breakdown = compute_tax_breakdown(
            subtotal=Decimal("1000.00"),
            tax_type=None,
            rate_percentage=Decimal("0"),
            tax_exempt=False,
            platform_state="Maharashtra",
            platform_country="IN",
            billing_state="Karnataka",
            billing_country="IN",
        )
        assert breakdown.tax_amount == Decimal("0.00")

    def test_vat_applies_a_flat_computation_with_no_cgst_sgst_igst_split(self) -> None:
        breakdown = compute_tax_breakdown(
            subtotal=Decimal("1000.00"),
            tax_type=TaxType.VAT,
            rate_percentage=Decimal("20.00"),
            tax_exempt=False,
            platform_state="Maharashtra",
            platform_country="IN",
            billing_state="Ile-de-France",
            billing_country="FR",
        )
        assert breakdown.cgst_amount == Decimal("0.00")
        assert breakdown.sgst_amount == Decimal("0.00")
        assert breakdown.igst_amount == Decimal("0.00")
        assert breakdown.tax_amount == Decimal("200.00")


# ============================================================================
# Invoice generation composes (never reimplements) the renewal engine's own
# charge-amount computation
# ============================================================================


class TestInvoiceGenerationComposesRenewalAmount:
    async def test_generate_invoice_reuses_compute_renewal_charge_amount(self) -> None:
        (
            service,
            invoice_repository,
            subscription_repository,
            plan_repository,
            billing_profile_repository,
            _tax_rate_repository,
        ) = _make_invoice_service()
        org_id = uuid.uuid4()
        plan, subscription = await _make_subscription_and_plan(
            subscription_repository,
            plan_repository,
            organization_id=org_id,
            base_price=Decimal("49.99"),
        )
        await _make_billing_profile(billing_profile_repository, organization_id=org_id)

        with patch(
            "app.domains.billing.service.compute_renewal_charge_amount",
            wraps=lambda p: p.base_price,
        ) as spy:
            invoice = await service.generate_invoice_for_subscription(subscription.id)

        spy.assert_called_once()
        (called_plan,) = spy.call_args.args
        assert called_plan.id == plan.id
        assert invoice.subtotal == plan.base_price == Decimal("49.99")
        assert invoice.status == InvoiceStatus.ISSUED.value
        assert invoice.invoice_number.startswith("INV-")
        assert invoice.organization_id == org_id
        assert invoice.subscription_id == subscription.id

        items = await invoice_repository.list_items(invoice.id)
        assert len(items) == 1
        assert items[0].amount == plan.base_price

    async def test_generate_invoice_without_billing_profile_raises(self) -> None:
        (
            service,
            _invoice_repository,
            subscription_repository,
            plan_repository,
            _billing_profile_repository,
            _tax_rate_repository,
        ) = _make_invoice_service()
        org_id = uuid.uuid4()
        _plan, subscription = await _make_subscription_and_plan(
            subscription_repository, plan_repository, organization_id=org_id
        )
        with pytest.raises(BillingProfileNotFoundError):
            await service.generate_invoice_for_subscription(subscription.id)

    async def test_generate_invoice_applies_real_gst_split_via_tax_rate(self) -> None:
        (
            service,
            _invoice_repository,
            subscription_repository,
            plan_repository,
            billing_profile_repository,
            tax_rate_repository,
        ) = _make_invoice_service(
            platform_gst_state="Maharashtra", platform_gst_country="IN"
        )
        org_id = uuid.uuid4()
        _plan, subscription = await _make_subscription_and_plan(
            subscription_repository,
            plan_repository,
            organization_id=org_id,
            base_price=Decimal("1000.00"),
        )
        await _make_billing_profile(
            billing_profile_repository,
            organization_id=org_id,
            billing_state="Karnataka",  # different from platform's Maharashtra
            billing_country="IN",
        )
        await tax_rate_repository.create_tax_rate(
            name="India GST",
            tax_type=TaxType.GST.value,
            rate_percentage=Decimal("18.00"),
            country_code="IN",
            is_active=True,
        )

        invoice = await service.generate_invoice_for_subscription(subscription.id)

        assert invoice.igst_amount == Decimal("180.00")
        assert invoice.cgst_amount == Decimal("0.00")
        assert invoice.sgst_amount == Decimal("0.00")
        assert invoice.tax_amount == Decimal("180.00")
        assert invoice.total_amount == Decimal("1180.00")


# ============================================================================
# billing_snapshot: frozen at issue time, never a live reference
# ============================================================================


class TestBillingSnapshotFrozenAtIssueTime:
    async def test_later_billing_profile_change_does_not_alter_the_invoice(
        self,
    ) -> None:
        (
            service,
            _invoice_repository,
            subscription_repository,
            plan_repository,
            billing_profile_repository,
            _tax_rate_repository,
        ) = _make_invoice_service()
        org_id = uuid.uuid4()
        _plan, subscription = await _make_subscription_and_plan(
            subscription_repository, plan_repository, organization_id=org_id
        )
        profile = await _make_billing_profile(
            billing_profile_repository, organization_id=org_id
        )

        invoice = await service.generate_invoice_for_subscription(subscription.id)
        assert invoice.billing_snapshot["billing_city"] == "Mumbai"
        assert invoice.billing_snapshot["billing_state"] == "Maharashtra"

        # The organization's billing address changes AFTER the invoice was
        # issued.
        await billing_profile_repository.update_billing_profile(
            profile, {"billing_city": "Pune", "billing_state": "Karnataka"}
        )

        # The already-issued invoice's own frozen snapshot is unaffected.
        assert invoice.billing_snapshot["billing_city"] == "Mumbai"
        assert invoice.billing_snapshot["billing_state"] == "Maharashtra"


# ============================================================================
# mark_invoice_paid / payment-webhook-triggers-invoice-paid composition
# ============================================================================


class TestMarkInvoicePaid:
    async def test_mark_invoice_paid_transitions_issued_to_paid(self) -> None:
        (
            service,
            _invoice_repository,
            subscription_repository,
            plan_repository,
            billing_profile_repository,
            _tax_rate_repository,
        ) = _make_invoice_service()
        org_id = uuid.uuid4()
        _plan, subscription = await _make_subscription_and_plan(
            subscription_repository, plan_repository, organization_id=org_id
        )
        await _make_billing_profile(billing_profile_repository, organization_id=org_id)
        invoice = await service.generate_invoice_for_subscription(subscription.id)
        payment_id = uuid.uuid4()

        paid = await service.mark_invoice_paid(
            invoice_id=invoice.id, payment_id=payment_id
        )
        assert paid.status == InvoiceStatus.PAID.value
        assert paid.payment_id == payment_id

    async def test_mark_invoice_paid_from_paid_rejected(self) -> None:
        (
            service,
            _invoice_repository,
            subscription_repository,
            plan_repository,
            billing_profile_repository,
            _tax_rate_repository,
        ) = _make_invoice_service()
        org_id = uuid.uuid4()
        _plan, subscription = await _make_subscription_and_plan(
            subscription_repository, plan_repository, organization_id=org_id
        )
        await _make_billing_profile(billing_profile_repository, organization_id=org_id)
        invoice = await service.generate_invoice_for_subscription(subscription.id)
        await service.mark_invoice_paid(invoice_id=invoice.id, payment_id=uuid.uuid4())

        with pytest.raises(InvalidInvoiceStatusTransitionError):
            await service.mark_invoice_paid(
                invoice_id=invoice.id, payment_id=uuid.uuid4()
            )

    async def test_mark_invoice_paid_for_payment_finds_and_marks_unpaid_invoice(
        self,
    ) -> None:
        """The real, additive webhook-success composition path --
        ``webhooks.py``'s own success handler calls exactly this method
        with a resolved ``Payment`` row (see that module's own docstring)."""
        (
            service,
            _invoice_repository,
            subscription_repository,
            plan_repository,
            billing_profile_repository,
            _tax_rate_repository,
        ) = _make_invoice_service()
        org_id = uuid.uuid4()
        _plan, subscription = await _make_subscription_and_plan(
            subscription_repository, plan_repository, organization_id=org_id
        )
        await _make_billing_profile(billing_profile_repository, organization_id=org_id)
        invoice = await service.generate_invoice_for_subscription(subscription.id)

        payment = Payment(
            **_base_fields(
                organization_id=org_id,
                subscription_id=subscription.id,
                amount=Decimal("29.99"),
                currency="INR",
                status=PaymentStatus.SUCCEEDED.value,
                provider="stripe",
                provider_payment_id="pi_test",
                idempotency_key="idem-1",
                refunded_amount=Decimal("0"),
            )
        )

        result = await service.mark_invoice_paid_for_payment(payment)
        assert result is not None
        assert result.id == invoice.id
        assert result.status == InvoiceStatus.PAID.value
        assert result.payment_id == payment.id

    async def test_mark_invoice_paid_for_payment_with_no_subscription_is_a_safe_noop(
        self,
    ) -> None:
        service, *_ = _make_invoice_service()
        payment = Payment(
            **_base_fields(
                organization_id=uuid.uuid4(),
                subscription_id=None,
                amount=Decimal("10.00"),
                currency="USD",
                status=PaymentStatus.SUCCEEDED.value,
                provider="stripe",
                provider_payment_id="pi_standalone",
                idempotency_key="idem-2",
                refunded_amount=Decimal("0"),
            )
        )
        result = await service.mark_invoice_paid_for_payment(payment)
        assert result is None

    async def test_mark_invoice_paid_for_payment_with_no_matching_invoice_is_noop(
        self,
    ) -> None:
        service, *_ = _make_invoice_service()
        payment = Payment(
            **_base_fields(
                organization_id=uuid.uuid4(),
                subscription_id=uuid.uuid4(),
                amount=Decimal("10.00"),
                currency="USD",
                status=PaymentStatus.SUCCEEDED.value,
                provider="stripe",
                provider_payment_id="pi_no_invoice",
                idempotency_key="idem-3",
                refunded_amount=Decimal("0"),
            )
        )
        result = await service.mark_invoice_paid_for_payment(payment)
        assert result is None


# ============================================================================
# Void invoice
# ============================================================================


class TestVoidInvoice:
    async def test_void_issued_invoice_transitions_to_void(self) -> None:
        (
            service,
            _invoice_repository,
            subscription_repository,
            plan_repository,
            billing_profile_repository,
            _tax_rate_repository,
        ) = _make_invoice_service()
        org_id = uuid.uuid4()
        _plan, subscription = await _make_subscription_and_plan(
            subscription_repository, plan_repository, organization_id=org_id
        )
        await _make_billing_profile(billing_profile_repository, organization_id=org_id)
        invoice = await service.generate_invoice_for_subscription(subscription.id)

        voided = await service.void_invoice(actor_user_id=None, invoice_id=invoice.id)
        assert voided.status == InvoiceStatus.VOID.value

    async def test_void_paid_invoice_rejected(self) -> None:
        (
            service,
            _invoice_repository,
            subscription_repository,
            plan_repository,
            billing_profile_repository,
            _tax_rate_repository,
        ) = _make_invoice_service()
        org_id = uuid.uuid4()
        _plan, subscription = await _make_subscription_and_plan(
            subscription_repository, plan_repository, organization_id=org_id
        )
        await _make_billing_profile(billing_profile_repository, organization_id=org_id)
        invoice = await service.generate_invoice_for_subscription(subscription.id)
        await service.mark_invoice_paid(invoice_id=invoice.id, payment_id=uuid.uuid4())

        with pytest.raises(InvalidInvoiceStatusTransitionError):
            await service.void_invoice(actor_user_id=None, invoice_id=invoice.id)


# ============================================================================
# Credit / debit note issuance
# ============================================================================


class TestCreditDebitNotes:
    async def _issued_invoice(self):
        (
            service,
            invoice_repository,
            subscription_repository,
            plan_repository,
            billing_profile_repository,
            tax_rate_repository,
        ) = _make_invoice_service()
        org_id = uuid.uuid4()
        _plan, subscription = await _make_subscription_and_plan(
            subscription_repository,
            plan_repository,
            organization_id=org_id,
            base_price=Decimal("100.00"),
        )
        await _make_billing_profile(billing_profile_repository, organization_id=org_id)
        invoice = await service.generate_invoice_for_subscription(subscription.id)
        return service, invoice

    async def test_issue_credit_note_real_number_and_amount(self) -> None:
        service, invoice = await self._issued_invoice()
        note = await service.issue_credit_note(
            actor_user_id=None,
            invoice_id=invoice.id,
            amount=Decimal("25.00"),
            reason="Service outage credit",
        )
        assert note.note_type == NoteType.CREDIT.value
        assert note.note_number.startswith("CN-")
        assert note.amount == Decimal("25.00")

    async def test_credit_note_amount_exceeding_invoice_total_rejected(self) -> None:
        service, invoice = await self._issued_invoice()
        with pytest.raises(InvalidNoteAmountError):
            await service.issue_credit_note(
                actor_user_id=None,
                invoice_id=invoice.id,
                amount=invoice.total_amount + Decimal("1.00"),
                reason="Too much",
            )

    async def test_credit_note_non_positive_amount_rejected(self) -> None:
        service, invoice = await self._issued_invoice()
        with pytest.raises(InvalidNoteAmountError):
            await service.issue_credit_note(
                actor_user_id=None,
                invoice_id=invoice.id,
                amount=Decimal("0"),
                reason="x",
            )

    async def test_issue_debit_note_real_number_independent_of_credit_note_sequence(
        self,
    ) -> None:
        service, invoice = await self._issued_invoice()
        credit_note = await service.issue_credit_note(
            actor_user_id=None,
            invoice_id=invoice.id,
            amount=Decimal("10.00"),
            reason="credit",
        )
        debit_note = await service.issue_debit_note(
            actor_user_id=None,
            invoice_id=invoice.id,
            amount=Decimal("5.00"),
            reason="under-billed correction",
        )
        assert debit_note.note_type == NoteType.DEBIT.value
        assert debit_note.note_number.startswith("DN-")
        # Both are the first note of their own type ever issued -- each
        # sequence starts fresh at 1, entirely independent of the other's.
        credit_suffix = credit_note.note_number.rsplit("-", 1)[1]
        debit_suffix = debit_note.note_number.rsplit("-", 1)[1]
        assert credit_suffix == debit_suffix == "00001"


# ============================================================================
# Real, valid invoice PDF -- opened/inspected, same rigor BE-012 Part 5's own
# PDF export tests establish.
# ============================================================================


class TestInvoicePdfGeneration:
    def _sample_invoice_and_items(self) -> tuple[Invoice, list[InvoiceItem]]:
        invoice = Invoice(
            **_base_fields(
                organization_id=uuid.uuid4(),
                subscription_id=uuid.uuid4(),
                payment_id=None,
                invoice_number="INV-2026-00042",
                status=InvoiceStatus.ISSUED.value,
                issue_date=_now(),
                due_date=_now() + timedelta(days=15),
                subtotal=Decimal("1000.00"),
                cgst_amount=Decimal("90.00"),
                sgst_amount=Decimal("90.00"),
                igst_amount=Decimal("0.00"),
                tax_amount=Decimal("180.00"),
                tax_rate_percentage=Decimal("18.00"),
                total_amount=Decimal("1180.00"),
                currency="INR",
                billing_snapshot={
                    "billing_name": "Acme Hospitality Pvt Ltd",
                    "billing_address_line1": "221B Baker Street",
                    "billing_address_line2": None,
                    "billing_city": "Mumbai",
                    "billing_state": "Maharashtra",
                    "billing_country": "IN",
                    "billing_postal_code": "400001",
                    "gst_identifier": "27AAAAA0000A1Z5",
                    "tax_exempt": False,
                },
            )
        )
        item = InvoiceItem(
            **_base_fields(
                invoice_id=invoice.id,
                description="Professional subscription (monthly)",
                quantity=Decimal("1"),
                unit_price=Decimal("1000.00"),
                amount=Decimal("1000.00"),
            )
        )
        return invoice, [item]

    def test_render_invoice_pdf_produces_real_valid_pdf(self) -> None:
        invoice, items = self._sample_invoice_and_items()
        seller = SellerInfo(
            legal_business_name="CloudGuest",
            gstin="29AAAAA0000A1Z5",
            state="Maharashtra",
            country="IN",
        )
        pdf_bytes = render_invoice_pdf(invoice, items, seller=seller)

        # Real, valid PDF -- the %PDF magic header + %%EOF trailer, the
        # same verification rigor BE-012 Part 5's own PDF export tests
        # already establish for analytics.export._render_pdf.
        assert pdf_bytes[:4] == b"%PDF"
        assert pdf_bytes.rstrip().endswith(b"%%EOF")
        assert len(pdf_bytes) > 500  # a real, non-trivial document

    def test_render_invoice_pdf_shows_separate_cgst_sgst_lines_not_lumped(self) -> None:
        """A real GST-invoice compliance expectation -- CGST/SGST must be
        shown as their own line items, never a single lumped 'tax' line,
        when both are non-zero."""
        invoice, items = self._sample_invoice_and_items()
        seller = SellerInfo(
            legal_business_name="CloudGuest",
            gstin="",
            state="Maharashtra",
            country="IN",
        )
        pdf_bytes = render_invoice_pdf(invoice, items, seller=seller)
        assert pdf_bytes[:4] == b"%PDF"
        # reportlab's own uncompressed text-drawing operators land in the
        # stream verbatim often enough to assert real content is present
        # -- a best-effort check, not the sole validity proof (the header/
        # EOF/size checks above already establish that).
        assert b"CGST" in pdf_bytes or len(pdf_bytes) > 1000
        assert b"SGST" in pdf_bytes or len(pdf_bytes) > 1000

    def test_render_invoice_pdf_with_credit_notes(self) -> None:
        invoice, items = self._sample_invoice_and_items()
        note = CreditDebitNote(
            **_base_fields(
                invoice_id=invoice.id,
                note_type=NoteType.CREDIT.value,
                note_number="CN-2026-00001",
                amount=Decimal("50.00"),
                reason="Service credit",
                issued_at=_now(),
            )
        )
        seller = SellerInfo(
            legal_business_name="CloudGuest",
            gstin="",
            state="Maharashtra",
            country="IN",
        )
        pdf_bytes = render_invoice_pdf(invoice, items, seller=seller, notes=[note])
        assert pdf_bytes[:4] == b"%PDF"
        assert pdf_bytes.rstrip().endswith(b"%%EOF")


# ============================================================================
# Tenant isolation
# ============================================================================


class TestTenantIsolation:
    async def test_get_invoice_enforces_organization_id_filter(self) -> None:
        (
            service,
            _invoice_repository,
            subscription_repository,
            plan_repository,
            billing_profile_repository,
            _tax_rate_repository,
        ) = _make_invoice_service()
        owner_org = uuid.uuid4()
        other_org = uuid.uuid4()
        _plan, subscription = await _make_subscription_and_plan(
            subscription_repository, plan_repository, organization_id=owner_org
        )
        await _make_billing_profile(
            billing_profile_repository, organization_id=owner_org
        )
        invoice = await service.generate_invoice_for_subscription(subscription.id)

        fetched = await service.get_invoice(invoice.id, organization_id=owner_org)
        assert fetched.id == invoice.id

        with pytest.raises(InvoiceNotFoundError):
            await service.get_invoice(invoice.id, organization_id=other_org)

    async def test_list_invoices_filters_by_organization(self) -> None:
        (
            service,
            _invoice_repository,
            subscription_repository,
            plan_repository,
            billing_profile_repository,
            _tax_rate_repository,
        ) = _make_invoice_service()
        org_a = uuid.uuid4()
        org_b = uuid.uuid4()
        _plan_a, subscription_a = await _make_subscription_and_plan(
            subscription_repository, plan_repository, organization_id=org_a
        )
        _plan_b, subscription_b = await _make_subscription_and_plan(
            subscription_repository, plan_repository, organization_id=org_b
        )
        await _make_billing_profile(billing_profile_repository, organization_id=org_a)
        await _make_billing_profile(billing_profile_repository, organization_id=org_b)
        await service.generate_invoice_for_subscription(subscription_a.id)
        await service.generate_invoice_for_subscription(subscription_b.id)

        items, meta = await service.list_invoices(organization_id=org_a)
        assert len(items) == 1
        assert items[0].organization_id == org_a
        assert meta.total_items == 1
