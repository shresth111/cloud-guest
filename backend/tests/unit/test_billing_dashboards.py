"""Unit tests for BE-013 Part 5 (Billing: Super Admin + Customer Billing
Dashboards): Super Admin Revenue Dashboard aggregate correctness (total
revenue/MRR/ARR computed from constructed fixture ``Payment``/
``Subscription``/``Plan`` rows), the real churn-rate formula against a
known scenario, the Failed Payments Dashboard's retry-eligibility flag
(reusing ``validators.is_payment_retry_eligible`` -- the exact rule
``PaymentService.retry_failed_payment`` itself enforces), the Customer
Billing Dashboard's pure composition (verified via call-recording fakes
that it reuses each existing service method exactly once, never
recomputing anything), the "Renewal Settings" ``auto_renew`` update
(tenant-scoped), the customer self-service upgrade/downgrade permission
fix, and RBAC scope wiring for the Super Admin dashboard route (mirrors
``test_analytics.py``'s own "no route-level TestClient pattern -- verify
permission-key/scope wiring directly off the registered routes"
introspection convention).

Follows this project's plain-``assert``/native-``async def`` style;
``asyncio_mode = "auto"`` runs async tests directly. Every service under
test is exercised against small, hand-rolled in-memory fakes -- no live
Postgres/Redis anywhere in this suite.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.billing.constants import (
    BillingCycle,
    InvoiceStatus,
    PaymentStatus,
    PlanType,
    SubscriptionStatus,
)
from app.domains.billing.exceptions import SubscriptionNotFoundError
from app.domains.billing.models import (
    Invoice,
    License,
    Payment,
    PaymentMethod,
    Plan,
    Subscription,
)
from app.domains.billing.router import _require_subscription_self_service_permission
from app.domains.billing.service import (
    CustomerBillingDashboardService,
    SubscriptionService,
    SuperAdminBillingDashboardService,
    UsageLimitCheck,
    UsageValidationResult,
)
from app.domains.billing.validators import is_payment_retry_eligible
from app.domains.rbac.context import ScopeContext
from app.domains.rbac.enums import ScopeType
from app.domains.rbac.exceptions import PermissionDeniedError

# ============================================================================
# Shared helpers (mirrors this domain's other Part test files' own
# identical helpers)
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


def _make_plan(
    *, base_price: Decimal, billing_cycle: str, currency: str = "USD"
) -> Plan:
    return Plan(
        **_base_fields(
            name="Professional",
            slug=f"plan-{uuid.uuid4().hex[:8]}",
            plan_type=PlanType.PROFESSIONAL.value,
            description=None,
            billing_cycle=billing_cycle,
            base_price=base_price,
            currency=currency,
            is_active=True,
            is_public=True,
            created_by_user_id=None,
            sort_order=0,
        )
    )


def _make_subscription(
    *,
    organization_id: uuid.UUID,
    plan_id: uuid.UUID,
    status: str = SubscriptionStatus.ACTIVE.value,
    billing_cycle: str = BillingCycle.MONTHLY.value,
    started_at: datetime | None = None,
    cancelled_at: datetime | None = None,
) -> Subscription:
    now = started_at or _now()
    return Subscription(
        **_base_fields(
            organization_id=organization_id,
            license_id=uuid.uuid4(),
            plan_id=plan_id,
            status=status,
            billing_cycle=billing_cycle,
            current_period_start=now,
            current_period_end=now + timedelta(days=30),
            trial_end=None,
            auto_renew=True,
            cancel_at_period_end=False,
            started_at=now,
            cancelled_at=cancelled_at,
        )
    )


def _make_payment(
    *,
    organization_id: uuid.UUID,
    amount: Decimal,
    status: str,
    refunded_amount: Decimal = Decimal("0"),
    provider: str = "stripe",
) -> Payment:
    return Payment(
        **_base_fields(
            organization_id=organization_id,
            subscription_id=None,
            amount=amount,
            currency="USD",
            status=status,
            provider=provider,
            provider_payment_id=f"pi_{uuid.uuid4().hex[:8]}",
            idempotency_key=f"idem-{uuid.uuid4().hex[:12]}",
            failure_reason="card_declined"
            if status == PaymentStatus.FAILED.value
            else None,
            refunded_amount=refunded_amount,
        )
    )


# ============================================================================
# Fakes
# ============================================================================


@dataclass
class FakeBillingDashboardRepository:
    """A hand-rolled, configurable double for
    ``repository.BillingDashboardRepositoryProtocol`` -- each method's
    return value is set directly by the test, isolating the SERVICE-layer
    formula (MRR/ARR/churn-rate) under test from any real SQL."""

    captured_totals: tuple[Decimal, Decimal] = (Decimal("0"), Decimal("0"))
    org_captured_totals: dict[uuid.UUID, tuple[Decimal, Decimal]] = field(
        default_factory=dict
    )
    monthly_rows: list[tuple[datetime, Decimal, Decimal]] = field(default_factory=list)
    active_subscription_plans: list[tuple[Plan, str]] = field(default_factory=list)
    status_counts: list[tuple[str, int]] = field(default_factory=list)
    plan_type_counts: list[tuple[str, int]] = field(default_factory=list)
    active_before_count: int = 0
    cancelled_between_count: int = 0
    customer_rows: list[tuple[Subscription, object, Plan]] = field(default_factory=list)

    async def sum_captured_payments(
        self, *, organization_id: uuid.UUID | None = None
    ) -> tuple[Decimal, Decimal]:
        if organization_id is not None:
            return self.org_captured_totals.get(
                organization_id, (Decimal("0"), Decimal("0"))
            )
        return self.captured_totals

    async def revenue_by_month(
        self, *, start: datetime, end: datetime
    ) -> list[tuple[datetime, Decimal, Decimal]]:
        return self.monthly_rows

    async def list_active_subscription_plans(self) -> list[tuple[Plan, str]]:
        return self.active_subscription_plans

    async def count_subscriptions_by_status(self) -> list[tuple[str, int]]:
        return self.status_counts

    async def count_subscriptions_by_plan_type(self) -> list[tuple[str, int]]:
        return self.plan_type_counts

    async def count_subscriptions_active_before(self, cutoff: datetime) -> int:
        return self.active_before_count

    async def count_subscriptions_cancelled_between(
        self, start: datetime, end: datetime
    ) -> int:
        return self.cancelled_between_count

    async def paginate_subscriptions_with_org_and_plan(
        self, *, page: int, page_size: int
    ) -> tuple[list[tuple[Subscription, object, Plan]], PaginationMeta]:
        params = PageParams(page=page, page_size=page_size)
        return self.customer_rows, PaginationMeta.from_total(
            params, len(self.customer_rows)
        )


@dataclass
class FakeOrganization:
    id: uuid.UUID
    name: str


@dataclass
class FakeFailedPaymentsPaymentService:
    """Only ``list_failed_payments`` is exercised by
    ``SuperAdminBillingDashboardService`` -- the exact, already-built Part 3
    method this dashboard reuses verbatim."""

    payments: list[Payment] = field(default_factory=list)
    calls: list[uuid.UUID | None] = field(default_factory=list)

    async def list_failed_payments(
        self, organization_id: uuid.UUID | None = None
    ) -> list[Payment]:
        self.calls.append(organization_id)
        if organization_id is None:
            return self.payments
        return [p for p in self.payments if p.organization_id == organization_id]

    async def list_payments(
        self,
        *,
        page: int,
        page_size: int,
        organization_id: uuid.UUID | None = None,
        status: str | None = None,
        provider: str | None = None,
    ) -> tuple[list[Payment], PaginationMeta]:
        params = PageParams(page=page, page_size=page_size)
        return [], PaginationMeta.from_total(params, 0)


@dataclass
class FakeInvoiceServiceForDashboard:
    """Only ``list_invoices`` is exercised -- reused for both the
    per-organization "outstanding invoice count" (Super Admin Customer
    Billing Dashboard) and the "recent invoices" summary (Customer Billing
    Dashboard)."""

    totals_by_org_and_status: dict[tuple[uuid.UUID, str], int] = field(
        default_factory=dict
    )
    recent_invoices: list[Invoice] = field(default_factory=list)
    calls: list[tuple[uuid.UUID | None, str | None]] = field(default_factory=list)

    async def list_invoices(
        self,
        *,
        page: int,
        page_size: int,
        organization_id: uuid.UUID | None = None,
        status: str | None = None,
    ) -> tuple[list[Invoice], PaginationMeta]:
        self.calls.append((organization_id, status))
        params = PageParams(page=page, page_size=page_size)
        if organization_id is not None and status is not None:
            total = self.totals_by_org_and_status.get((organization_id, status), 0)
            return [], PaginationMeta.from_total(params, total)
        return self.recent_invoices, PaginationMeta.from_total(
            params, len(self.recent_invoices)
        )


@dataclass
class CallRecordingCustomerDashboardDeps:
    """One call-recording fake per composed dependency
    ``CustomerBillingDashboardService.get_dashboard`` needs -- proves (via
    ``self.calls``) that each existing service method is reused exactly
    once, with the right argument, never recomputed a second way."""

    license_: License
    plan: Plan
    subscription: Subscription
    usage_result: UsageValidationResult
    payment_methods: list[PaymentMethod]
    calls: list[str] = field(default_factory=list)

    async def get_license_for_organization(self, organization_id: uuid.UUID) -> License:
        self.calls.append(f"license:{organization_id}")
        return self.license_

    async def get_plan(
        self, plan_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Plan:
        self.calls.append(f"plan:{plan_id}")
        return self.plan

    async def get_subscription_for_organization(
        self, organization_id: uuid.UUID
    ) -> Subscription:
        self.calls.append(f"subscription:{organization_id}")
        return self.subscription

    async def validate_usage_against_license(
        self, organization_id: uuid.UUID
    ) -> UsageValidationResult:
        self.calls.append(f"usage:{organization_id}")
        return self.usage_result

    async def list_payment_methods(
        self, organization_id: uuid.UUID
    ) -> list[PaymentMethod]:
        self.calls.append(f"payment_methods:{organization_id}")
        return self.payment_methods


@dataclass
class FakeAccessValidator:
    """A minimal double for ``AccessValidator`` satisfying exactly the two
    methods ``_require_subscription_self_service_permission`` calls --
    ``allowed`` is the set of ``(permission_key, scope_type, organization_id)``
    triples this fake user actually holds."""

    allowed: set[tuple[str, str, uuid.UUID | None]]

    async def has_permission(
        self,
        user_id: uuid.UUID,
        permission_key: str,
        *,
        scope_type: ScopeType,
        scope_context: ScopeContext | None = None,
    ) -> bool:
        org_id = scope_context.organization_id if scope_context else None
        return (permission_key, scope_type.value, org_id) in self.allowed

    async def check(
        self,
        user_id: uuid.UUID,
        permission_key: str,
        *,
        scope_type: ScopeType,
        scope_context: ScopeContext | None = None,
    ) -> None:
        if not await self.has_permission(
            user_id, permission_key, scope_type=scope_type, scope_context=scope_context
        ):
            raise PermissionDeniedError(permission_key)


@dataclass
class FakeUser:
    id: str


@dataclass
class FakeSubscriptionRepository:
    subscriptions: dict[uuid.UUID, Subscription] = field(default_factory=dict)

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


# ============================================================================
# Revenue Dashboard: total revenue, MRR/ARR, trend
# ============================================================================


class TestRevenueDashboard:
    async def test_total_revenue_nets_out_refunds(self) -> None:
        repository = FakeBillingDashboardRepository(
            captured_totals=(Decimal("1000.00"), Decimal("150.00"))
        )
        payment_service = FakeFailedPaymentsPaymentService()
        invoice_service = FakeInvoiceServiceForDashboard()
        service = SuperAdminBillingDashboardService(
            repository, payment_service, invoice_service
        )

        result = await service.get_revenue_dashboard(user_id=uuid.uuid4(), months=6)

        assert result.total_revenue == Decimal("850.00")
        assert result.total_refunded == Decimal("150.00")

    async def test_mrr_arr_formula_normalizes_yearly_and_excludes_none_cycle(
        self,
    ) -> None:
        """The real, documented MRR formula: MONTHLY plans count in full;
        YEARLY plans are divided by 12; a NONE-cycle (cycle-less) plan is
        excluded entirely -- ARR is always MRR * 12."""
        monthly_plan = _make_plan(
            base_price=Decimal("100.00"), billing_cycle=BillingCycle.MONTHLY.value
        )
        yearly_plan = _make_plan(
            base_price=Decimal("1200.00"), billing_cycle=BillingCycle.YEARLY.value
        )
        none_cycle_plan = _make_plan(
            base_price=Decimal("999.00"), billing_cycle=BillingCycle.NONE.value
        )
        repository = FakeBillingDashboardRepository(
            active_subscription_plans=[
                (monthly_plan, BillingCycle.MONTHLY.value),
                (yearly_plan, BillingCycle.YEARLY.value),
                (none_cycle_plan, BillingCycle.NONE.value),
            ]
        )
        payment_service = FakeFailedPaymentsPaymentService()
        invoice_service = FakeInvoiceServiceForDashboard()
        service = SuperAdminBillingDashboardService(
            repository, payment_service, invoice_service
        )

        result = await service.get_revenue_dashboard(user_id=uuid.uuid4())

        # 100.00 (monthly) + 1200.00/12 = 100.00 (yearly normalized) = 200.00.
        # The NONE-cycle plan's 999.00 contributes nothing.
        assert result.mrr == Decimal("200.00")
        assert result.arr == Decimal("2400.00")
        assert result.active_paying_subscription_count == 3

    async def test_revenue_trend_reflects_repository_rows(self) -> None:
        month_a = datetime(2026, 5, 1, tzinfo=UTC)
        month_b = datetime(2026, 6, 1, tzinfo=UTC)
        repository = FakeBillingDashboardRepository(
            monthly_rows=[
                (month_a, Decimal("500.00"), Decimal("0.00")),
                (month_b, Decimal("700.00"), Decimal("50.00")),
            ]
        )
        payment_service = FakeFailedPaymentsPaymentService()
        invoice_service = FakeInvoiceServiceForDashboard()
        service = SuperAdminBillingDashboardService(
            repository, payment_service, invoice_service
        )

        result = await service.get_revenue_dashboard(user_id=uuid.uuid4())

        assert [point.month for point in result.trend] == ["2026-05", "2026-06"]
        assert result.trend[1].net_amount == Decimal("650.00")

    async def test_currency_note_is_always_present(self) -> None:
        repository = FakeBillingDashboardRepository()
        service = SuperAdminBillingDashboardService(
            repository,
            FakeFailedPaymentsPaymentService(),
            FakeInvoiceServiceForDashboard(),
        )
        result = await service.get_revenue_dashboard(user_id=uuid.uuid4())
        assert (
            "FX" in result.currency_note or "currency" in result.currency_note.lower()
        )


# ============================================================================
# Subscription Dashboard: counts + churn-rate formula
# ============================================================================


class TestSubscriptionDashboardChurnRate:
    async def test_churn_rate_known_scenario(self) -> None:
        """active_at_period_start=20, cancelled_this_period=5 -> 0.25,
        exactly ``cancelled_this_period / active_at_period_start``."""
        repository = FakeBillingDashboardRepository(
            status_counts=[
                (SubscriptionStatus.ACTIVE.value, 15),
                (SubscriptionStatus.CANCELLED.value, 5),
            ],
            plan_type_counts=[(PlanType.PROFESSIONAL.value, 20)],
            active_before_count=20,
            cancelled_between_count=5,
        )
        service = SuperAdminBillingDashboardService(
            repository,
            FakeFailedPaymentsPaymentService(),
            FakeInvoiceServiceForDashboard(),
        )

        result = await service.get_subscription_dashboard(user_id=uuid.uuid4())

        assert result.churn.active_at_period_start == 20
        assert result.churn.cancelled_this_period == 5
        assert result.churn.churn_rate == pytest.approx(0.25)
        assert result.counts_by_status[SubscriptionStatus.ACTIVE.value] == 15
        assert result.counts_by_plan_type[PlanType.PROFESSIONAL.value] == 20

    async def test_churn_rate_is_none_not_a_fabricated_zero_with_no_active_base(
        self,
    ) -> None:
        repository = FakeBillingDashboardRepository(
            active_before_count=0, cancelled_between_count=0
        )
        service = SuperAdminBillingDashboardService(
            repository,
            FakeFailedPaymentsPaymentService(),
            FakeInvoiceServiceForDashboard(),
        )

        result = await service.get_subscription_dashboard(user_id=uuid.uuid4())

        assert result.churn.churn_rate is None


# ============================================================================
# Customer Billing Dashboard (Super Admin): per-organization summary rows
# ============================================================================


class TestCustomerBillingSummaryRows:
    async def test_summary_row_computes_lifetime_revenue_and_outstanding_invoices(
        self,
    ) -> None:
        organization_id = uuid.uuid4()
        plan = _make_plan(
            base_price=Decimal("29.99"), billing_cycle=BillingCycle.MONTHLY.value
        )
        subscription = _make_subscription(
            organization_id=organization_id, plan_id=plan.id
        )
        organization = FakeOrganization(id=organization_id, name="Acme Hospitality")
        repository = FakeBillingDashboardRepository(
            customer_rows=[(subscription, organization, plan)],
            org_captured_totals={
                organization_id: (Decimal("300.00"), Decimal("50.00"))
            },
        )
        invoice_service = FakeInvoiceServiceForDashboard(
            totals_by_org_and_status={
                (organization_id, InvoiceStatus.ISSUED.value): 2,
                (organization_id, InvoiceStatus.OVERDUE.value): 1,
            }
        )
        service = SuperAdminBillingDashboardService(
            repository, FakeFailedPaymentsPaymentService(), invoice_service
        )

        rows, meta = await service.get_customer_billing_dashboard(
            user_id=uuid.uuid4(), page=1, page_size=25
        )

        assert meta.total_items == 1
        assert len(rows) == 1
        row = rows[0]
        assert row.organization_id == organization_id
        assert row.organization_name == "Acme Hospitality"
        assert row.plan_id == plan.id
        assert row.subscription_status == subscription.status
        # 300.00 captured - 50.00 refunded = 250.00 lifetime revenue.
        assert row.lifetime_revenue == Decimal("250.00")
        # 2 ISSUED + 1 OVERDUE = 3 outstanding invoices.
        assert row.outstanding_invoice_count == 3


# ============================================================================
# Failed Payments Dashboard: retry-eligibility reuse + pagination/grouping
# ============================================================================


class TestFailedPaymentsDashboard:
    def test_is_payment_retry_eligible_matches_retry_failed_payment_rule(self) -> None:
        assert is_payment_retry_eligible(PaymentStatus.FAILED.value) is True
        assert is_payment_retry_eligible(PaymentStatus.SUCCEEDED.value) is False
        assert is_payment_retry_eligible(PaymentStatus.REFUNDED.value) is False
        assert is_payment_retry_eligible(PaymentStatus.PENDING.value) is False

    async def test_failed_payments_are_listed_with_retry_eligible_flag_and_grouped(
        self,
    ) -> None:
        org_id = uuid.uuid4()
        failed_stripe = _make_payment(
            organization_id=org_id,
            amount=Decimal("29.99"),
            status=PaymentStatus.FAILED.value,
            provider="stripe",
        )
        failed_razorpay = _make_payment(
            organization_id=org_id,
            amount=Decimal("49.99"),
            status=PaymentStatus.FAILED.value,
            provider="razorpay",
        )
        payment_service = FakeFailedPaymentsPaymentService(
            payments=[failed_stripe, failed_razorpay]
        )
        repository = FakeBillingDashboardRepository()
        service = SuperAdminBillingDashboardService(
            repository, payment_service, FakeInvoiceServiceForDashboard()
        )

        result = await service.get_failed_payments_dashboard(
            user_id=uuid.uuid4(), page=1, page_size=25
        )

        assert result.total_items == 2
        assert result.counts_by_provider == {"stripe": 1, "razorpay": 1}
        assert all(row.retry_eligible for row in result.items)
        assert payment_service.calls == [None]

    async def test_failed_payments_pagination_slices_in_python(self) -> None:
        org_id = uuid.uuid4()
        payments = [
            _make_payment(
                organization_id=org_id,
                amount=Decimal("10.00"),
                status=PaymentStatus.FAILED.value,
            )
            for _ in range(5)
        ]
        payment_service = FakeFailedPaymentsPaymentService(payments=payments)
        service = SuperAdminBillingDashboardService(
            FakeBillingDashboardRepository(),
            payment_service,
            FakeInvoiceServiceForDashboard(),
        )

        page_one = await service.get_failed_payments_dashboard(
            user_id=uuid.uuid4(), page=1, page_size=2
        )
        page_two = await service.get_failed_payments_dashboard(
            user_id=uuid.uuid4(), page=2, page_size=2
        )

        assert len(page_one.items) == 2
        assert len(page_two.items) == 2
        assert page_one.total_items == page_two.total_items == 5

    async def test_organization_filter_is_passed_through(self) -> None:
        org_a, org_b = uuid.uuid4(), uuid.uuid4()
        payment_service = FakeFailedPaymentsPaymentService(
            payments=[
                _make_payment(
                    organization_id=org_a,
                    amount=Decimal("5.00"),
                    status=PaymentStatus.FAILED.value,
                ),
                _make_payment(
                    organization_id=org_b,
                    amount=Decimal("6.00"),
                    status=PaymentStatus.FAILED.value,
                ),
            ]
        )
        service = SuperAdminBillingDashboardService(
            FakeBillingDashboardRepository(),
            payment_service,
            FakeInvoiceServiceForDashboard(),
        )

        result = await service.get_failed_payments_dashboard(
            user_id=uuid.uuid4(), organization_id=org_a
        )
        assert result.total_items == 1
        assert payment_service.calls == [org_a]


# ============================================================================
# Customer Billing Dashboard: pure composition, verified via spies
# ============================================================================


class TestCustomerBillingDashboardComposition:
    async def test_get_dashboard_reuses_every_existing_service_exactly_once(
        self,
    ) -> None:
        organization_id = uuid.uuid4()
        plan = _make_plan(
            base_price=Decimal("49.99"), billing_cycle=BillingCycle.MONTHLY.value
        )
        license_ = License(
            **_base_fields(
                organization_id=organization_id,
                plan_id=plan.id,
                status="active",
                activated_at=_now(),
                expires_at=None,
                suspended_at=None,
                suspended_reason=None,
                cancelled_at=None,
            )
        )
        subscription = _make_subscription(
            organization_id=organization_id, plan_id=plan.id
        )
        usage_result = UsageValidationResult(
            organization_id=organization_id,
            metrics=[],
            limit_checks=[
                UsageLimitCheck(
                    metric_key="guests",
                    current_value=Decimal("10"),
                    limit_value=Decimal("100"),
                    exceeded=False,
                )
            ],
        )
        deps = CallRecordingCustomerDashboardDeps(
            license_=license_,
            plan=plan,
            subscription=subscription,
            usage_result=usage_result,
            payment_methods=[],
        )
        invoice_service = FakeInvoiceServiceForDashboard(
            recent_invoices=[],
        )
        payment_service = FakeFailedPaymentsPaymentService()

        service = CustomerBillingDashboardService(
            license_service=deps,
            plan_service=deps,
            subscription_service=deps,
            usage_service=deps,
            invoice_service=invoice_service,
            payment_service=payment_service,
            payment_method_service=deps,
        )

        result = await service.get_dashboard(organization_id)

        assert result.license is license_
        assert result.plan is plan
        assert result.subscription is subscription
        assert result.usage is usage_result
        # Every composed dependency was called exactly once -- proves this
        # is pure composition, never a second, independent recomputation.
        assert deps.calls == [
            f"license:{organization_id}",
            f"plan:{plan.id}",
            f"subscription:{organization_id}",
            f"usage:{organization_id}",
            f"payment_methods:{organization_id}",
        ]
        assert invoice_service.calls == [(organization_id, None)]


# ============================================================================
# Renewal Settings: PATCH /subscriptions/{id}/renewal-settings
# ============================================================================


class TestRenewalSettingsUpdate:
    async def test_update_renewal_settings_toggles_auto_renew(self) -> None:
        organization_id = uuid.uuid4()
        subscription = _make_subscription(
            organization_id=organization_id, plan_id=uuid.uuid4()
        )
        assert subscription.auto_renew is True
        repository = FakeSubscriptionRepository({subscription.id: subscription})
        service = SubscriptionService(
            repository, plan_repository=None, license_service=None
        )

        updated = await service.update_renewal_settings(
            actor_user_id=uuid.uuid4(),
            subscription_id=subscription.id,
            organization_id=organization_id,
            auto_renew=False,
        )

        assert updated.auto_renew is False

    async def test_update_renewal_settings_rejects_cross_organization_caller(
        self,
    ) -> None:
        """A real, new tenant check this Part adds -- a caller supplying a
        DIFFERENT organization_id than the subscription's own owner gets an
        honest not-found, never a leak (mirrors
        ``PaymentService.get_payment``'s identical convention)."""
        owner_org = uuid.uuid4()
        other_org = uuid.uuid4()
        subscription = _make_subscription(
            organization_id=owner_org, plan_id=uuid.uuid4()
        )
        repository = FakeSubscriptionRepository({subscription.id: subscription})
        service = SubscriptionService(
            repository, plan_repository=None, license_service=None
        )

        with pytest.raises(SubscriptionNotFoundError):
            await service.update_renewal_settings(
                actor_user_id=uuid.uuid4(),
                subscription_id=subscription.id,
                organization_id=other_org,
                auto_renew=False,
            )


# ============================================================================
# Customer self-service upgrade/downgrade permission fix
# ============================================================================


class TestUpgradeDowngradeSelfServiceFix:
    async def test_global_scoped_subscriptions_update_still_works_unchanged(
        self,
    ) -> None:
        """A Billing-Manager-shaped caller (GLOBAL subscriptions.update,
        no organization header) keeps working exactly as before this fix."""
        access_validator = FakeAccessValidator(
            allowed={("subscriptions.update", ScopeType.GLOBAL.value, None)}
        )
        user = FakeUser(id=str(uuid.uuid4()))

        result = await _require_subscription_self_service_permission(
            request=None,
            user=user,
            organization_id=None,
            access_validator=access_validator,
        )
        assert result is user

    async def test_organization_owner_shaped_billing_update_now_allowed(self) -> None:
        """The real fix: an Organization Owner holds ``billing.update`` at
        ``ORGANIZATION`` scope but NOT ``subscriptions.update`` (RBAC's own
        seed data gives that role an explicit SUBSCRIPTIONS: READ override
        -- see this function's own docstring). Self-service upgrade/
        downgrade must now succeed for exactly this caller shape."""
        organization_id = uuid.uuid4()
        access_validator = FakeAccessValidator(
            allowed={("billing.update", ScopeType.ORGANIZATION.value, organization_id)}
        )
        user = FakeUser(id=str(uuid.uuid4()))

        result = await _require_subscription_self_service_permission(
            request=None,
            user=user,
            organization_id=organization_id,
            access_validator=access_validator,
        )
        assert result is user

    async def test_caller_holding_neither_permission_is_rejected(self) -> None:
        organization_id = uuid.uuid4()
        access_validator = FakeAccessValidator(allowed=set())
        user = FakeUser(id=str(uuid.uuid4()))

        with pytest.raises(PermissionDeniedError):
            await _require_subscription_self_service_permission(
                request=None,
                user=user,
                organization_id=organization_id,
                access_validator=access_validator,
            )


# ============================================================================
# RBAC scope wiring -- verified directly off the registered routes (mirrors
# tests/unit/test_analytics.py's identical introspection pattern; this
# codebase has no established route-level TestClient pattern)
# ============================================================================


def _permission_key_and_scope_for_route(route) -> tuple[str | None, object | None]:
    for dependency in route.dependant.dependencies:
        call = dependency.call
        freevars = getattr(call.__code__, "co_freevars", ())
        if "permission_key" in freevars:
            key_index = freevars.index("permission_key")
            key = call.__closure__[key_index].cell_contents
            scope = None
            if "scope" in freevars:
                scope_index = freevars.index("scope")
                scope = call.__closure__[scope_index].cell_contents
            return key, scope
    return None, None


class TestSuperAdminDashboardScopeWiring:
    def test_super_admin_dashboard_requires_global_scoped_billing_read(self) -> None:
        """Confirms the Super Admin Billing Dashboard is gated exactly like
        every other platform-wide dashboard in this codebase: pinned to
        ``scope=ScopeType.GLOBAL`` -- a caller lacking a GLOBAL-scoped
        ``billing.read`` grant is rejected by RBAC's own, already-tested
        ``AccessValidator.check`` (real 403), never reaching this domain's
        own dashboard logic at all."""
        from app.main import create_app

        app = create_app()
        route = next(
            r
            for r in app.routes
            if getattr(r, "path", None) == "/api/v1/billing/dashboard/super-admin"
            and "GET" in getattr(r, "methods", set())
        )
        key, scope = _permission_key_and_scope_for_route(route)
        assert key == "billing.read"
        assert scope == ScopeType.GLOBAL

    def test_customer_dashboard_me_route_requires_organization_context(self) -> None:
        """The customer dashboard's real tenant boundary: ``/billing/
        dashboard/me`` resolves its organization through RBAC's own
        ``RequireOrganization``/``CurrentOrganization`` (which validates
        real, active organization membership -- see that dependency's own
        docstring), never a caller-supplied, unchecked value."""
        from app.domains.rbac.dependencies import RequireOrganization
        from app.main import create_app

        app = create_app()
        route = next(
            r
            for r in app.routes
            if getattr(r, "path", None) == "/api/v1/billing/dashboard/me"
            and "GET" in getattr(r, "methods", set())
        )

        def _walk(dependant) -> set:
            calls = {d.call for d in dependant.dependencies}
            for d in dependant.dependencies:
                calls |= _walk(d)
            return calls

        assert RequireOrganization in _walk(route.dependant)

    def test_no_duplicate_routes_and_dashboard_paths_registered(self) -> None:
        from app.main import create_app

        app = create_app()
        expected_paths = {
            "/api/v1/billing/dashboard/super-admin",
            "/api/v1/billing/dashboard/me",
            "/api/v1/billing/dashboard/{organization_id}",
            "/api/v1/subscriptions/{subscription_id}/renewal-settings",
        }
        actual_paths = {getattr(r, "path", None) for r in app.routes}
        assert expected_paths.issubset(actual_paths)

        seen: set[tuple[str, frozenset[str]]] = set()
        for route in app.routes:
            path = getattr(route, "path", None)
            methods = getattr(route, "methods", None)
            if path is None or methods is None:
                continue
            key = (path, frozenset(methods))
            assert key not in seen, f"duplicate route registered: {key}"
            seen.add(key)
