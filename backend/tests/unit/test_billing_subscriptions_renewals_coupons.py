"""Unit tests for BE-013 Part 2 (Billing: Subscription + Renewal + Coupon
Engines): Subscription lifecycle (create with/without a coupon, cancel
immediate vs. at-period-end, pause/resume, reactivate), Coupon validation
(expired/exhausted/wrong-org/wrong-plan/valid) and discount computation
correctness (PERCENTAGE and FLAT, including the flat-discount-never-
exceeds-base-amount clamp), the ``PaymentGatewayProtocol`` seam (verifies
``process_renewal`` calls it, and both of ``UnconfiguredPaymentGateway``'s
honest default behaviors), the renewal sweep's due-date detection +
per-subscription failure isolation, the grace-period-then-expire flow
(composing Part 1's ``LicenseService.expire_license`` -- verified as
actually called, not reimplemented), and reminder event dispatch.

Follows this project's plain-``assert``/native-``async def`` style (see
``test_billing_plans_licenses_usage.py``'s own module docstring, the Part 1
template this file mirrors); ``asyncio_mode = "auto"`` runs async tests
directly. Every service under test is exercised against small, hand-rolled
in-memory fakes satisfying this module's own narrow ``Protocol`` shapes --
no live Postgres/Redis anywhere in this test suite. ``SubscriptionService``/
``RenewalService`` are exercised against the **real** ``LicenseService``
(Part 1, unmodified) wired to fake repositories -- proving this part
composes with Part 1's real license lifecycle rather than reimplementing
any of it.
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
    DiscountType,
    LicenseStatus,
    PlanType,
    SubscriptionStatus,
)
from app.domains.billing.exceptions import (
    CouponExhaustedError,
    CouponExpiredError,
    CouponNotApplicableToOrganizationError,
    CouponNotApplicableToPlanError,
    DuplicateSubscriptionError,
    InvalidDiscountValueError,
    InvalidSubscriptionStatusForRenewalError,
    InvalidSubscriptionStatusTransitionError,
    PaymentGatewayNotConfiguredError,
    SubscriptionReactivationNotAllowedError,
)
from app.domains.billing.models import Coupon, License, Plan, Subscription
from app.domains.billing.renewal_service import (
    PaymentResult,
    RenewalService,
    UnconfiguredPaymentGateway,
)
from app.domains.billing.service import (
    CouponService,
    LicenseService,
    SubscriptionService,
)
from app.domains.billing.validators import (
    compute_discount_amount,
    validate_discount_value,
)

# ============================================================================
# Shared helpers
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

    async def get_by_slug(self, slug: str) -> Plan | None:
        for plan in self.plans.values():
            if plan.slug == slug:
                return plan
        return None

    async def update_plan(self, plan: Plan, data: dict[str, object]) -> Plan:
        for key, value in data.items():
            setattr(plan, key, value)
        plan.version += 1
        return plan

    async def soft_delete_plan(self, plan: Plan) -> Plan:
        plan.is_deleted = True
        return plan

    async def list_plans(self, **kwargs: object):
        raise NotImplementedError

    async def create_plan_feature(self, **fields: object):
        raise NotImplementedError

    async def list_plan_features(self, plan_id: uuid.UUID) -> list:
        return []

    async def delete_plan_features(self, plan_id: uuid.UUID) -> None:
        return None


async def _make_plan(
    repository: FakePlanRepository,
    *,
    plan_type: str = PlanType.PROFESSIONAL.value,
    billing_cycle: str = BillingCycle.MONTHLY.value,
    base_price: Decimal = Decimal("49.99"),
    is_active: bool = True,
) -> Plan:
    return await repository.create_plan(
        name="Test Plan",
        slug=f"plan-{uuid.uuid4().hex[:8]}",
        plan_type=plan_type,
        description=None,
        billing_cycle=billing_cycle,
        base_price=base_price,
        currency="USD",
        is_active=is_active,
        is_public=True,
        created_by_user_id=None,
        sort_order=0,
    )


@dataclass
class FakeLicenseRepository:
    licenses: dict[uuid.UUID, License] = field(default_factory=dict)
    change_logs: dict[uuid.UUID, object] = field(default_factory=dict)

    async def create_license(self, **fields: object) -> License:
        license_ = License(**_base_fields(**fields))
        self.licenses[license_.id] = license_
        return license_

    async def get_by_id(
        self, license_id: uuid.UUID, *, include_deleted: bool = False
    ) -> License | None:
        return self.licenses.get(license_id)

    async def get_by_organization_id(
        self, organization_id: uuid.UUID
    ) -> License | None:
        for license_ in self.licenses.values():
            if license_.organization_id == organization_id:
                return license_
        return None

    async def update_license(
        self, license_: License, data: dict[str, object]
    ) -> License:
        for key, value in data.items():
            setattr(license_, key, value)
        license_.version += 1
        return license_

    async def create_change_log(self, **fields: object):
        entry = type("Entry", (), fields)()
        self.change_logs[uuid.uuid4()] = entry
        return entry

    async def list_change_logs(self, license_id: uuid.UUID) -> list:
        return []


@dataclass
class _FakeOrganization:
    id: uuid.UUID
    contact_email: str = "org@example.com"
    msp: bool = False

    def is_msp(self) -> bool:
        return self.msp


class FakeOrganizationComposer:
    """Satisfies ``OrganizationSyncProtocol`` (for ``LicenseService``) and
    ``OrganizationContactLookupProtocol`` (for ``RenewalService``) -- the
    real ``OrganizationService`` satisfies both too."""

    def __init__(
        self, organizations: dict[uuid.UUID, _FakeOrganization] | None = None
    ) -> None:
        self._organizations = organizations or {}
        self.sync_calls: list[tuple[uuid.UUID, str | None]] = []

    async def get_organization(
        self, organization_id: uuid.UUID, *, include_deleted: bool = False
    ) -> _FakeOrganization:
        if organization_id not in self._organizations:
            self._organizations[organization_id] = _FakeOrganization(id=organization_id)
        return self._organizations[organization_id]

    async def sync_subscription_tier(
        self, *, organization_id: uuid.UUID, subscription_tier: str | None
    ) -> None:
        self.sync_calls.append((organization_id, subscription_tier))


@dataclass
class FakeAuditWriter:
    entries: list[dict[str, object]] = field(default_factory=list)

    async def create_audit_log_entry(self, **fields: object) -> None:
        self.entries.append(fields)


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

    async def get_by_organization_id(
        self, organization_id: uuid.UUID
    ) -> Subscription | None:
        for subscription in self.subscriptions.values():
            if subscription.organization_id == organization_id:
                return subscription
        return None

    async def update_subscription(
        self, subscription: Subscription, data: dict[str, object]
    ) -> Subscription:
        for key, value in data.items():
            setattr(subscription, key, value)
        subscription.version += 1
        return subscription

    async def list_by_status(self, statuses: list[str]) -> list[Subscription]:
        return [s for s in self.subscriptions.values() if s.status in statuses]

    async def list_due_for_renewal(self, *, now: datetime) -> list[Subscription]:
        cyclic = {BillingCycle.MONTHLY.value, BillingCycle.YEARLY.value}
        renewable = {
            SubscriptionStatus.TRIALING.value,
            SubscriptionStatus.ACTIVE.value,
            SubscriptionStatus.PAST_DUE.value,
        }
        return [
            s
            for s in self.subscriptions.values()
            if s.auto_renew
            and s.billing_cycle in cyclic
            and s.status in renewable
            and s.current_period_end <= now
        ]


@dataclass
class FakeCouponRepository:
    coupons: dict[uuid.UUID, Coupon] = field(default_factory=dict)
    applicable_plans: dict[uuid.UUID, list[uuid.UUID]] = field(default_factory=dict)
    usages: list[dict[str, object]] = field(default_factory=list)
    increment_calls: list[uuid.UUID] = field(default_factory=list)

    async def create_coupon(self, **fields: object) -> Coupon:
        coupon = Coupon(**_base_fields(**fields))
        self.coupons[coupon.id] = coupon
        return coupon

    async def get_by_id(
        self, coupon_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Coupon | None:
        return self.coupons.get(coupon_id)

    async def get_by_code(self, code: str) -> Coupon | None:
        for coupon in self.coupons.values():
            if coupon.code == code:
                return coupon
        return None

    async def update_coupon(self, coupon: Coupon, data: dict[str, object]) -> Coupon:
        for key, value in data.items():
            setattr(coupon, key, value)
        coupon.version += 1
        return coupon

    async def soft_delete_coupon(self, coupon: Coupon) -> Coupon:
        coupon.is_deleted = True
        return coupon

    async def list_coupons(
        self,
        *,
        page: int,
        page_size: int,
        organization_id: uuid.UUID | None = None,
        is_active: bool | None = None,
    ) -> tuple[list[Coupon], PaginationMeta]:
        items = list(self.coupons.values())
        if organization_id is not None:
            items = [c for c in items if c.organization_id == organization_id]
        if is_active is not None:
            items = [c for c in items if c.is_active == is_active]
        params = PageParams(page=page, page_size=page_size)
        return items, PaginationMeta.from_total(params, len(items))

    async def set_applicable_plans(
        self, coupon_id: uuid.UUID, plan_ids: list[uuid.UUID]
    ) -> None:
        self.applicable_plans[coupon_id] = list(plan_ids)

    async def list_applicable_plan_ids(self, coupon_id: uuid.UUID) -> list[uuid.UUID]:
        return self.applicable_plans.get(coupon_id, [])

    async def increment_current_uses(self, coupon_id: uuid.UUID) -> Coupon:
        self.increment_calls.append(coupon_id)
        coupon = self.coupons[coupon_id]
        coupon.current_uses += 1
        return coupon

    async def create_coupon_usage(self, **fields: object) -> object:
        self.usages.append(fields)
        return type("Usage", (), fields)()


class FakePaymentGateway:
    """A controllable ``PaymentGatewayProtocol`` for exercising
    ``process_renewal``'s success/failure branches without depending on
    ``UnconfiguredPaymentGateway``'s own fixed behavior (that default is
    tested directly, separately, below)."""

    def __init__(self, *, results: list[PaymentResult] | None = None) -> None:
        self._results = list(results or [])
        self.calls: list[dict[str, object]] = []

    async def charge(
        self,
        *,
        organization_id: uuid.UUID,
        amount: Decimal,
        currency: str,
        subscription_id: uuid.UUID,
    ) -> PaymentResult:
        self.calls.append(
            {
                "organization_id": organization_id,
                "amount": amount,
                "currency": currency,
                "subscription_id": subscription_id,
            }
        )
        if self._results:
            return self._results.pop(0)
        return PaymentResult(success=True)


class FakeNotificationSender:
    """In-memory stand-in for ``RenewalService``'s own
    ``NotificationSenderProtocol``."""

    def __init__(self) -> None:
        self.enqueued: list[dict[str, object]] = []

    async def enqueue(self, **kwargs: object) -> None:
        self.enqueued.append(kwargs)


# ============================================================================
# Service fixtures
# ============================================================================


@dataclass
class LicenseFixture:
    license_repository: FakeLicenseRepository
    plan_repository: FakePlanRepository
    organization_composer: FakeOrganizationComposer
    service: LicenseService


def make_license_service() -> LicenseFixture:
    license_repository = FakeLicenseRepository()
    plan_repository = FakePlanRepository()
    organization_composer = FakeOrganizationComposer()
    service = LicenseService(
        license_repository, plan_repository, organization_sync=organization_composer
    )
    return LicenseFixture(
        license_repository, plan_repository, organization_composer, service
    )


@dataclass
class CouponFixture:
    repository: FakeCouponRepository
    audit_writer: FakeAuditWriter
    service: CouponService


def make_coupon_service() -> CouponFixture:
    repository = FakeCouponRepository()
    audit_writer = FakeAuditWriter()
    service = CouponService(repository, audit_writer=audit_writer)
    return CouponFixture(repository, audit_writer, service)


@dataclass
class SubscriptionFixture:
    subscription_repository: FakeSubscriptionRepository
    license_fixture: LicenseFixture
    coupon_fixture: CouponFixture
    service: SubscriptionService


def make_subscription_service(*, trial_period_days: int = 14) -> SubscriptionFixture:
    subscription_repository = FakeSubscriptionRepository()
    license_fixture = make_license_service()
    coupon_fixture = make_coupon_service()
    service = SubscriptionService(
        subscription_repository,
        license_fixture.plan_repository,
        license_fixture.service,
        coupon_service=coupon_fixture.service,
        trial_period_days=trial_period_days,
    )
    return SubscriptionFixture(
        subscription_repository, license_fixture, coupon_fixture, service
    )


@dataclass
class RenewalFixture:
    subscription_repository: FakeSubscriptionRepository
    plan_repository: FakePlanRepository
    license_fixture: LicenseFixture
    payment_gateway: FakePaymentGateway
    notification_service: FakeNotificationSender
    organization_composer: FakeOrganizationComposer
    service: RenewalService


def make_renewal_service(
    *,
    subscription_repository: FakeSubscriptionRepository | None = None,
    plan_repository: FakePlanRepository | None = None,
    license_fixture: LicenseFixture | None = None,
    payment_gateway: FakePaymentGateway | None = None,
    grace_period_days: int = 7,
    renewal_reminder_days_before: int = 3,
    expiry_reminder_days_before: int = 3,
) -> RenewalFixture:
    subscription_repository = subscription_repository or FakeSubscriptionRepository()
    license_fixture = license_fixture or make_license_service()
    plan_repository = plan_repository or license_fixture.plan_repository
    payment_gateway = payment_gateway or FakePaymentGateway()
    notification_service = FakeNotificationSender()
    organization_composer = license_fixture.organization_composer
    service = RenewalService(
        subscription_repository,
        plan_repository,
        license_service=license_fixture.service,
        organization_lookup=organization_composer,
        payment_gateway=payment_gateway,
        notification_service=notification_service,
        grace_period_days=grace_period_days,
        renewal_reminder_days_before=renewal_reminder_days_before,
        expiry_reminder_days_before=expiry_reminder_days_before,
    )
    return RenewalFixture(
        subscription_repository,
        plan_repository,
        license_fixture,
        payment_gateway,
        notification_service,
        organization_composer,
        service,
    )


async def _assign_and_activate_license(
    fixture: LicenseFixture, *, organization_id: uuid.UUID, plan_id: uuid.UUID
) -> License:
    license_ = await fixture.service.assign_license(
        actor_user_id=None, organization_id=organization_id, plan_id=plan_id
    )
    return await fixture.service.activate_license(
        actor_user_id=None, license_id=license_.id
    )


# ============================================================================
# Coupon discount computation
# ============================================================================


class TestDiscountComputation:
    def test_percentage_discount_computed_correctly(self) -> None:
        amount = compute_discount_amount(
            discount_type=DiscountType.PERCENTAGE,
            discount_value=Decimal("20"),
            base_amount=Decimal("100.00"),
        )
        assert amount == Decimal("20.00")

    def test_flat_discount_computed_correctly(self) -> None:
        amount = compute_discount_amount(
            discount_type=DiscountType.FLAT,
            discount_value=Decimal("15.00"),
            base_amount=Decimal("100.00"),
        )
        assert amount == Decimal("15.00")

    def test_flat_discount_never_exceeds_base_amount(self) -> None:
        """The real, important correctness detail: a flat discount larger
        than the charge itself must clamp to the charge, never go negative."""
        amount = compute_discount_amount(
            discount_type=DiscountType.FLAT,
            discount_value=Decimal("500.00"),
            base_amount=Decimal("49.99"),
        )
        assert amount == Decimal("49.99")

    def test_percentage_value_above_100_rejected(self) -> None:
        with pytest.raises(InvalidDiscountValueError):
            validate_discount_value(
                discount_type=DiscountType.PERCENTAGE, discount_value=Decimal("150")
            )

    def test_negative_discount_value_rejected(self) -> None:
        with pytest.raises(InvalidDiscountValueError):
            validate_discount_value(
                discount_type=DiscountType.FLAT, discount_value=Decimal("-5")
            )

    def test_flat_value_above_100_is_legal_at_creation_time(self) -> None:
        """A FLAT discount_value isn't bounded by 100 the way PERCENTAGE
        is -- only clamped at apply-time against whatever base_amount it
        is later used against."""
        validate_discount_value(
            discount_type=DiscountType.FLAT, discount_value=Decimal("500")
        )


# ============================================================================
# Coupon validation + application
# ============================================================================


class TestCouponValidation:
    async def _create_coupon(
        self,
        fx: CouponFixture,
        *,
        code: str = "SAVE20",
        discount_type: str = DiscountType.PERCENTAGE.value,
        discount_value: Decimal = Decimal("20"),
        organization_id: uuid.UUID | None = None,
        max_uses: int | None = None,
        valid_from: datetime | None = None,
        valid_until: datetime | None = None,
        is_active: bool = True,
        applicable_plan_ids: list[uuid.UUID] | None = None,
    ) -> Coupon:
        return await fx.service.create_coupon(
            actor_user_id=None,
            code=code,
            discount_type=discount_type,
            discount_value=discount_value,
            currency=None,
            organization_id=organization_id,
            max_uses=max_uses,
            valid_from=valid_from or (_now() - timedelta(days=1)),
            valid_until=valid_until,
            is_active=is_active,
            applicable_plan_ids=applicable_plan_ids or [],
        )

    async def test_valid_coupon_passes(self) -> None:
        fx = make_coupon_service()
        org_id = uuid.uuid4()
        plan_id = uuid.uuid4()
        await self._create_coupon(fx, code="VALID10")
        coupon = await fx.service.validate_coupon(
            code="valid10", organization_id=org_id, plan_id=plan_id
        )
        assert coupon.code == "VALID10"

    async def test_expired_coupon_rejected(self) -> None:
        fx = make_coupon_service()
        org_id = uuid.uuid4()
        plan_id = uuid.uuid4()
        await self._create_coupon(
            fx, code="OLD", valid_until=_now() - timedelta(days=1)
        )
        with pytest.raises(CouponExpiredError):
            await fx.service.validate_coupon(
                code="OLD", organization_id=org_id, plan_id=plan_id
            )

    async def test_exhausted_coupon_rejected(self) -> None:
        fx = make_coupon_service()
        org_id = uuid.uuid4()
        plan_id = uuid.uuid4()
        coupon = await self._create_coupon(fx, code="LIMITED", max_uses=1)
        coupon.current_uses = 1
        with pytest.raises(CouponExhaustedError):
            await fx.service.validate_coupon(
                code="LIMITED", organization_id=org_id, plan_id=plan_id
            )

    async def test_wrong_organization_coupon_rejected(self) -> None:
        fx = make_coupon_service()
        owning_org = uuid.uuid4()
        other_org = uuid.uuid4()
        plan_id = uuid.uuid4()
        await self._create_coupon(fx, code="ORGONLY", organization_id=owning_org)
        with pytest.raises(CouponNotApplicableToOrganizationError):
            await fx.service.validate_coupon(
                code="ORGONLY", organization_id=other_org, plan_id=plan_id
            )
        # The owning organization itself may use it.
        valid = await fx.service.validate_coupon(
            code="ORGONLY", organization_id=owning_org, plan_id=plan_id
        )
        assert valid.code == "ORGONLY"

    async def test_wrong_plan_coupon_rejected(self) -> None:
        fx = make_coupon_service()
        org_id = uuid.uuid4()
        allowed_plan = uuid.uuid4()
        other_plan = uuid.uuid4()
        await self._create_coupon(
            fx, code="PLANONLY", applicable_plan_ids=[allowed_plan]
        )
        with pytest.raises(CouponNotApplicableToPlanError):
            await fx.service.validate_coupon(
                code="PLANONLY", organization_id=org_id, plan_id=other_plan
            )
        valid = await fx.service.validate_coupon(
            code="PLANONLY", organization_id=org_id, plan_id=allowed_plan
        )
        assert valid.code == "PLANONLY"

    async def test_apply_coupon_records_usage_and_increments_atomically(self) -> None:
        fx = make_coupon_service()
        org_id = uuid.uuid4()
        plan_id = uuid.uuid4()
        subscription_id = uuid.uuid4()
        await self._create_coupon(fx, code="ATOMIC", discount_value=Decimal("10"))

        discount = await fx.service.apply_coupon(
            code="ATOMIC",
            organization_id=org_id,
            subscription_id=subscription_id,
            plan_id=plan_id,
            base_amount=Decimal("50.00"),
        )
        assert discount == Decimal("5.00")
        # The atomic-increment repository method was called -- not a
        # read-current_uses-then-write-in-Python race in the service layer.
        assert len(fx.repository.increment_calls) == 1
        assert len(fx.repository.usages) == 1
        usage = fx.repository.usages[0]
        assert usage["discount_amount_applied"] == Decimal("5.00")
        assert usage["subscription_id"] == subscription_id

        coupon = await fx.service.get_by_code("ATOMIC")
        assert coupon.current_uses == 1


# ============================================================================
# Subscription lifecycle
# ============================================================================


class TestSubscriptionCreation:
    async def test_create_subscription_without_coupon_goes_active(self) -> None:
        fx = make_subscription_service()
        plan = await _make_plan(fx.license_fixture.plan_repository)
        org_id = uuid.uuid4()

        subscription = await fx.service.create_subscription(
            actor_user_id=None, organization_id=org_id, plan_id=plan.id
        )
        assert subscription.status == SubscriptionStatus.ACTIVE.value
        assert subscription.plan_id == plan.id
        assert subscription.billing_cycle == plan.billing_cycle
        assert subscription.trial_end is None
        assert subscription.applied_coupon_id is None

        license_ = await fx.license_fixture.license_repository.get_by_organization_id(
            org_id
        )
        assert license_.status == LicenseStatus.ACTIVE.value

    async def test_create_subscription_for_free_trial_plan_is_trialing(self) -> None:
        fx = make_subscription_service(trial_period_days=14)
        plan = await _make_plan(
            fx.license_fixture.plan_repository,
            plan_type=PlanType.FREE_TRIAL.value,
            billing_cycle=BillingCycle.NONE.value,
            base_price=Decimal("0"),
        )
        org_id = uuid.uuid4()

        subscription = await fx.service.create_subscription(
            actor_user_id=None, organization_id=org_id, plan_id=plan.id
        )
        assert subscription.status == SubscriptionStatus.TRIALING.value
        assert subscription.trial_end is not None
        assert subscription.current_period_end == subscription.trial_end

    async def test_create_subscription_with_coupon_applies_and_records_usage(
        self,
    ) -> None:
        fx = make_subscription_service()
        plan = await _make_plan(
            fx.license_fixture.plan_repository, base_price=Decimal("100.00")
        )
        org_id = uuid.uuid4()
        await fx.coupon_fixture.service.create_coupon(
            actor_user_id=None,
            code="WELCOME50",
            discount_type=DiscountType.PERCENTAGE.value,
            discount_value=Decimal("50"),
            currency=None,
            organization_id=None,
            max_uses=None,
            valid_from=_now() - timedelta(days=1),
            valid_until=None,
            is_active=True,
            applicable_plan_ids=[],
        )

        subscription = await fx.service.create_subscription(
            actor_user_id=None,
            organization_id=org_id,
            plan_id=plan.id,
            coupon_code="welcome50",
        )
        assert subscription.applied_coupon_id is not None
        assert len(fx.coupon_fixture.repository.usages) == 1
        usage = fx.coupon_fixture.repository.usages[0]
        assert usage["discount_amount_applied"] == Decimal("50.00")
        assert usage["subscription_id"] == subscription.id

    async def test_duplicate_subscription_for_organization_rejected(self) -> None:
        fx = make_subscription_service()
        plan = await _make_plan(fx.license_fixture.plan_repository)
        org_id = uuid.uuid4()
        await fx.service.create_subscription(
            actor_user_id=None, organization_id=org_id, plan_id=plan.id
        )
        with pytest.raises(DuplicateSubscriptionError):
            await fx.service.create_subscription(
                actor_user_id=None, organization_id=org_id, plan_id=plan.id
            )


class TestSubscriptionCancellation:
    async def test_immediate_cancel_suspends_license_and_stops_auto_renew(
        self,
    ) -> None:
        fx = make_subscription_service()
        plan = await _make_plan(fx.license_fixture.plan_repository)
        org_id = uuid.uuid4()
        subscription = await fx.service.create_subscription(
            actor_user_id=None, organization_id=org_id, plan_id=plan.id
        )

        cancelled = await fx.service.cancel_subscription(
            actor_user_id=None, subscription_id=subscription.id, immediate=True
        )
        assert cancelled.status == SubscriptionStatus.CANCELLED.value
        assert cancelled.auto_renew is False
        assert cancelled.cancelled_at is not None

        license_ = await fx.license_fixture.license_repository.get_by_id(
            subscription.license_id
        )
        assert license_.status == LicenseStatus.SUSPENDED.value

    async def test_cancel_at_period_end_does_not_change_status_yet(self) -> None:
        fx = make_subscription_service()
        plan = await _make_plan(fx.license_fixture.plan_repository)
        org_id = uuid.uuid4()
        subscription = await fx.service.create_subscription(
            actor_user_id=None, organization_id=org_id, plan_id=plan.id
        )

        scheduled = await fx.service.cancel_subscription(
            actor_user_id=None, subscription_id=subscription.id, immediate=False
        )
        assert scheduled.status == SubscriptionStatus.ACTIVE.value
        assert scheduled.cancel_at_period_end is True

        license_ = await fx.license_fixture.license_repository.get_by_id(
            subscription.license_id
        )
        assert license_.status == LicenseStatus.ACTIVE.value


class TestSubscriptionPauseResumeReactivate:
    async def test_pause_then_resume_keeps_license_untouched(self) -> None:
        fx = make_subscription_service()
        plan = await _make_plan(fx.license_fixture.plan_repository)
        org_id = uuid.uuid4()
        subscription = await fx.service.create_subscription(
            actor_user_id=None, organization_id=org_id, plan_id=plan.id
        )

        paused = await fx.service.pause_subscription(
            actor_user_id=None, subscription_id=subscription.id
        )
        assert paused.status == SubscriptionStatus.PAUSED.value
        license_ = await fx.license_fixture.license_repository.get_by_id(
            subscription.license_id
        )
        assert license_.status == LicenseStatus.ACTIVE.value  # untouched by pause

        resumed = await fx.service.resume_subscription(
            actor_user_id=None, subscription_id=subscription.id
        )
        assert resumed.status == SubscriptionStatus.ACTIVE.value

    async def test_reactivate_from_cancelled_reverses_license_suspension(self) -> None:
        fx = make_subscription_service()
        plan = await _make_plan(fx.license_fixture.plan_repository)
        org_id = uuid.uuid4()
        subscription = await fx.service.create_subscription(
            actor_user_id=None, organization_id=org_id, plan_id=plan.id
        )
        await fx.service.cancel_subscription(
            actor_user_id=None, subscription_id=subscription.id, immediate=True
        )

        reactivated = await fx.service.reactivate_subscription(
            actor_user_id=None, subscription_id=subscription.id
        )
        assert reactivated.status == SubscriptionStatus.ACTIVE.value

        license_ = await fx.license_fixture.license_repository.get_by_id(
            subscription.license_id
        )
        assert license_.status == LicenseStatus.ACTIVE.value

    async def test_reactivate_rejected_once_license_has_expired(self) -> None:
        fx = make_subscription_service()
        plan = await _make_plan(fx.license_fixture.plan_repository)
        org_id = uuid.uuid4()
        subscription = await fx.service.create_subscription(
            actor_user_id=None, organization_id=org_id, plan_id=plan.id
        )
        await fx.service.cancel_subscription(
            actor_user_id=None, subscription_id=subscription.id, immediate=True
        )
        # Simulate the grace-period sweep having already hard-expired the
        # license (see RenewalService.expire_lapsed_subscriptions).
        license_ = await fx.license_fixture.license_repository.get_by_id(
            subscription.license_id
        )
        license_.status = LicenseStatus.EXPIRED.value

        with pytest.raises(SubscriptionReactivationNotAllowedError):
            await fx.service.reactivate_subscription(
                actor_user_id=None, subscription_id=subscription.id
            )

    async def test_pause_from_paused_is_illegal(self) -> None:
        fx = make_subscription_service()
        plan = await _make_plan(fx.license_fixture.plan_repository)
        org_id = uuid.uuid4()
        subscription = await fx.service.create_subscription(
            actor_user_id=None, organization_id=org_id, plan_id=plan.id
        )
        await fx.service.pause_subscription(
            actor_user_id=None, subscription_id=subscription.id
        )
        with pytest.raises(InvalidSubscriptionStatusTransitionError):
            await fx.service.pause_subscription(
                actor_user_id=None, subscription_id=subscription.id
            )


# ============================================================================
# PaymentGatewayProtocol seam
# ============================================================================


class TestPaymentGatewaySeam:
    async def test_unconfigured_gateway_auto_succeeds_for_zero_amount(self) -> None:
        gateway = UnconfiguredPaymentGateway()
        result = await gateway.charge(
            organization_id=uuid.uuid4(),
            amount=Decimal("0"),
            currency="USD",
            subscription_id=uuid.uuid4(),
        )
        assert result.success is True

    async def test_unconfigured_gateway_raises_for_real_charge(self) -> None:
        gateway = UnconfiguredPaymentGateway()
        with pytest.raises(PaymentGatewayNotConfiguredError):
            await gateway.charge(
                organization_id=uuid.uuid4(),
                amount=Decimal("49.99"),
                currency="USD",
                subscription_id=uuid.uuid4(),
            )

    async def test_process_renewal_calls_the_gateway_seam(self) -> None:
        fx = make_renewal_service()
        plan = await _make_plan(fx.plan_repository, base_price=Decimal("29.99"))
        org_id = uuid.uuid4()
        license_ = await _assign_and_activate_license(
            fx.license_fixture, organization_id=org_id, plan_id=plan.id
        )
        now = _now()
        subscription = await fx.subscription_repository.create_subscription(
            organization_id=org_id,
            license_id=license_.id,
            plan_id=plan.id,
            status=SubscriptionStatus.ACTIVE.value,
            billing_cycle=plan.billing_cycle,
            current_period_start=now - timedelta(days=30),
            current_period_end=now,
            trial_end=None,
            auto_renew=True,
            cancel_at_period_end=False,
            started_at=now - timedelta(days=30),
        )

        renewed = await fx.service.process_renewal(subscription.id)
        assert renewed.status == SubscriptionStatus.ACTIVE.value
        assert len(fx.payment_gateway.calls) == 1
        call = fx.payment_gateway.calls[0]
        assert call["amount"] == Decimal("29.99")
        assert call["organization_id"] == org_id
        # Period was extended by a real billing cycle, past the old boundary.
        assert renewed.current_period_end > now

    async def test_process_renewal_marks_past_due_when_gateway_not_configured(
        self,
    ) -> None:
        # No FakePaymentGateway override -- RenewalService's own default
        # (UnconfiguredPaymentGateway) is used, exercising the real seam
        # wiring end to end.
        fx = make_renewal_service(payment_gateway=UnconfiguredPaymentGateway())
        plan = await _make_plan(fx.plan_repository, base_price=Decimal("29.99"))
        org_id = uuid.uuid4()
        license_ = await _assign_and_activate_license(
            fx.license_fixture, organization_id=org_id, plan_id=plan.id
        )
        now = _now()
        subscription = await fx.subscription_repository.create_subscription(
            organization_id=org_id,
            license_id=license_.id,
            plan_id=plan.id,
            status=SubscriptionStatus.ACTIVE.value,
            billing_cycle=plan.billing_cycle,
            current_period_start=now - timedelta(days=30),
            current_period_end=now,
            trial_end=None,
            auto_renew=True,
            cancel_at_period_end=False,
            started_at=now - timedelta(days=30),
        )

        result = await fx.service.process_renewal(subscription.id)
        assert result.status == SubscriptionStatus.PAST_DUE.value
        assert result.past_due_at is not None
        # License is NOT touched at this point -- only after the grace
        # period lapses (see TestGracePeriodExpiry below).
        license_after = await fx.license_fixture.license_repository.get_by_id(
            license_.id
        )
        assert license_after.status == LicenseStatus.ACTIVE.value

    async def test_process_renewal_marks_past_due_on_declined_payment(self) -> None:
        gateway = FakePaymentGateway(
            results=[PaymentResult(success=False, failure_reason="card_declined")]
        )
        fx = make_renewal_service(payment_gateway=gateway)
        plan = await _make_plan(fx.plan_repository, base_price=Decimal("29.99"))
        org_id = uuid.uuid4()
        license_ = await _assign_and_activate_license(
            fx.license_fixture, organization_id=org_id, plan_id=plan.id
        )
        now = _now()
        subscription = await fx.subscription_repository.create_subscription(
            organization_id=org_id,
            license_id=license_.id,
            plan_id=plan.id,
            status=SubscriptionStatus.ACTIVE.value,
            billing_cycle=plan.billing_cycle,
            current_period_start=now - timedelta(days=30),
            current_period_end=now,
            trial_end=None,
            auto_renew=True,
            cancel_at_period_end=False,
            started_at=now - timedelta(days=30),
        )

        result = await fx.service.process_renewal(subscription.id)
        assert result.status == SubscriptionStatus.PAST_DUE.value

    async def test_process_renewal_recovers_past_due_subscription_on_retry(
        self,
    ) -> None:
        fx = make_renewal_service()
        plan = await _make_plan(fx.plan_repository, base_price=Decimal("10.00"))
        org_id = uuid.uuid4()
        license_ = await _assign_and_activate_license(
            fx.license_fixture, organization_id=org_id, plan_id=plan.id
        )
        now = _now()
        subscription = await fx.subscription_repository.create_subscription(
            organization_id=org_id,
            license_id=license_.id,
            plan_id=plan.id,
            status=SubscriptionStatus.PAST_DUE.value,
            billing_cycle=plan.billing_cycle,
            current_period_start=now - timedelta(days=30),
            current_period_end=now - timedelta(days=1),
            trial_end=None,
            auto_renew=True,
            cancel_at_period_end=False,
            started_at=now - timedelta(days=60),
            past_due_at=now - timedelta(days=1),
        )

        recovered = await fx.service.process_renewal(subscription.id)
        assert recovered.status == SubscriptionStatus.ACTIVE.value
        assert recovered.past_due_at is None

    async def test_process_renewal_rejects_paused_subscription(self) -> None:
        fx = make_renewal_service()
        plan = await _make_plan(fx.plan_repository)
        org_id = uuid.uuid4()
        license_ = await _assign_and_activate_license(
            fx.license_fixture, organization_id=org_id, plan_id=plan.id
        )
        now = _now()
        subscription = await fx.subscription_repository.create_subscription(
            organization_id=org_id,
            license_id=license_.id,
            plan_id=plan.id,
            status=SubscriptionStatus.PAUSED.value,
            billing_cycle=plan.billing_cycle,
            current_period_start=now - timedelta(days=30),
            current_period_end=now,
            trial_end=None,
            auto_renew=True,
            cancel_at_period_end=False,
            started_at=now - timedelta(days=30),
        )
        with pytest.raises(InvalidSubscriptionStatusForRenewalError):
            await fx.service.process_renewal(subscription.id)


# ============================================================================
# Renewal sweep: due-date detection + per-subscription failure isolation
# ============================================================================


class TestRenewalSweep:
    async def test_process_due_renewals_only_touches_due_subscriptions(self) -> None:
        fx = make_renewal_service()
        plan = await _make_plan(fx.plan_repository, base_price=Decimal("15.00"))
        now = _now()

        due_org = uuid.uuid4()
        due_license = await _assign_and_activate_license(
            fx.license_fixture, organization_id=due_org, plan_id=plan.id
        )
        due_subscription = await fx.subscription_repository.create_subscription(
            organization_id=due_org,
            license_id=due_license.id,
            plan_id=plan.id,
            status=SubscriptionStatus.ACTIVE.value,
            billing_cycle=plan.billing_cycle,
            current_period_start=now - timedelta(days=30),
            current_period_end=now - timedelta(hours=1),
            trial_end=None,
            auto_renew=True,
            cancel_at_period_end=False,
            started_at=now - timedelta(days=30),
        )

        not_due_org = uuid.uuid4()
        not_due_license = await _assign_and_activate_license(
            fx.license_fixture, organization_id=not_due_org, plan_id=plan.id
        )
        await fx.subscription_repository.create_subscription(
            organization_id=not_due_org,
            license_id=not_due_license.id,
            plan_id=plan.id,
            status=SubscriptionStatus.ACTIVE.value,
            billing_cycle=plan.billing_cycle,
            current_period_start=now,
            current_period_end=now + timedelta(days=20),
            trial_end=None,
            auto_renew=True,
            cancel_at_period_end=False,
            started_at=now,
        )

        result = await fx.service.process_due_renewals()
        assert result.subscriptions_checked == 1
        assert result.renewed == 1
        assert result.failed == []

        renewed = await fx.subscription_repository.get_by_id(due_subscription.id)
        assert renewed.current_period_end > now

    async def test_process_due_renewals_isolates_one_subscriptions_failure(
        self,
    ) -> None:
        fx = make_renewal_service()
        plan = await _make_plan(fx.plan_repository, base_price=Decimal("15.00"))
        now = _now()

        # A subscription whose plan will be deleted from the repository
        # before the sweep runs, forcing process_renewal to raise
        # PlanNotFoundError for it specifically.
        broken_org = uuid.uuid4()
        broken_license = await _assign_and_activate_license(
            fx.license_fixture, organization_id=broken_org, plan_id=plan.id
        )
        broken_subscription = await fx.subscription_repository.create_subscription(
            organization_id=broken_org,
            license_id=broken_license.id,
            plan_id=uuid.uuid4(),  # no such plan -- forces a failure
            status=SubscriptionStatus.ACTIVE.value,
            billing_cycle=plan.billing_cycle,
            current_period_start=now - timedelta(days=30),
            current_period_end=now - timedelta(hours=1),
            trial_end=None,
            auto_renew=True,
            cancel_at_period_end=False,
            started_at=now - timedelta(days=30),
        )

        healthy_org = uuid.uuid4()
        healthy_license = await _assign_and_activate_license(
            fx.license_fixture, organization_id=healthy_org, plan_id=plan.id
        )
        healthy_subscription = await fx.subscription_repository.create_subscription(
            organization_id=healthy_org,
            license_id=healthy_license.id,
            plan_id=plan.id,
            status=SubscriptionStatus.ACTIVE.value,
            billing_cycle=plan.billing_cycle,
            current_period_start=now - timedelta(days=30),
            current_period_end=now - timedelta(hours=1),
            trial_end=None,
            auto_renew=True,
            cancel_at_period_end=False,
            started_at=now - timedelta(days=30),
        )

        result = await fx.service.process_due_renewals()
        assert result.subscriptions_checked == 2
        assert result.renewed == 1
        assert len(result.failed) == 1
        assert result.failed[0][0] == broken_subscription.id

        # The healthy subscription still renewed despite its sibling's
        # failure -- the whole point of per-subscription isolation.
        healthy_after = await fx.subscription_repository.get_by_id(
            healthy_subscription.id
        )
        assert healthy_after.status == SubscriptionStatus.ACTIVE.value
        assert healthy_after.current_period_end > now


# ============================================================================
# Grace period -> license expiry (composes Part 1's expire_license)
# ============================================================================


class TestGracePeriodExpiry:
    async def test_expire_lapsed_subscriptions_calls_real_expire_license(self) -> None:
        fx = make_renewal_service(grace_period_days=7)
        plan = await _make_plan(fx.plan_repository)
        org_id = uuid.uuid4()
        license_ = await _assign_and_activate_license(
            fx.license_fixture, organization_id=org_id, plan_id=plan.id
        )
        now = _now()
        subscription = await fx.subscription_repository.create_subscription(
            organization_id=org_id,
            license_id=license_.id,
            plan_id=plan.id,
            status=SubscriptionStatus.PAST_DUE.value,
            billing_cycle=plan.billing_cycle,
            current_period_start=now - timedelta(days=40),
            current_period_end=now - timedelta(days=10),
            trial_end=None,
            auto_renew=True,
            cancel_at_period_end=False,
            started_at=now - timedelta(days=40),
            past_due_at=now - timedelta(days=8),  # grace period (7d) has lapsed
        )

        expired_ids = await fx.service.expire_lapsed_subscriptions()
        assert expired_ids == [subscription.id]

        # LicenseService.expire_license (Part 1, unmodified) was actually
        # called -- verified by its own real, unmodified state transition
        # (ACTIVE -> EXPIRED), not a reimplementation of that transition
        # here.
        license_after = await fx.license_fixture.license_repository.get_by_id(
            license_.id
        )
        assert license_after.status == LicenseStatus.EXPIRED.value

        subscription_after = await fx.subscription_repository.get_by_id(subscription.id)
        assert subscription_after.status == SubscriptionStatus.CANCELLED.value

    async def test_still_within_grace_period_is_not_expired(self) -> None:
        fx = make_renewal_service(grace_period_days=7)
        plan = await _make_plan(fx.plan_repository)
        org_id = uuid.uuid4()
        license_ = await _assign_and_activate_license(
            fx.license_fixture, organization_id=org_id, plan_id=plan.id
        )
        now = _now()
        await fx.subscription_repository.create_subscription(
            organization_id=org_id,
            license_id=license_.id,
            plan_id=plan.id,
            status=SubscriptionStatus.PAST_DUE.value,
            billing_cycle=plan.billing_cycle,
            current_period_start=now - timedelta(days=10),
            current_period_end=now - timedelta(days=2),
            trial_end=None,
            auto_renew=True,
            cancel_at_period_end=False,
            started_at=now - timedelta(days=10),
            past_due_at=now - timedelta(days=2),  # only 2 of 7 grace days elapsed
        )

        expired_ids = await fx.service.expire_lapsed_subscriptions()
        assert expired_ids == []
        license_after = await fx.license_fixture.license_repository.get_by_id(
            license_.id
        )
        assert license_after.status == LicenseStatus.ACTIVE.value


# ============================================================================
# Reminders
# ============================================================================


class TestReminders:
    async def test_renewal_reminder_sent_once_within_window(self) -> None:
        fx = make_renewal_service(renewal_reminder_days_before=3)
        plan = await _make_plan(fx.plan_repository)
        org_id = uuid.uuid4()
        license_ = await _assign_and_activate_license(
            fx.license_fixture, organization_id=org_id, plan_id=plan.id
        )
        now = _now()
        subscription = await fx.subscription_repository.create_subscription(
            organization_id=org_id,
            license_id=license_.id,
            plan_id=plan.id,
            status=SubscriptionStatus.ACTIVE.value,
            billing_cycle=plan.billing_cycle,
            current_period_start=now - timedelta(days=27),
            current_period_end=now + timedelta(days=2),  # within the 3-day window
            trial_end=None,
            auto_renew=True,
            cancel_at_period_end=False,
            started_at=now - timedelta(days=27),
        )

        sent_count = await fx.service.send_renewal_reminders()
        assert sent_count == 1
        assert len(fx.notification_service.enqueued) == 1
        assert fx.notification_service.enqueued[0]["recipient"] == "org@example.com"

        updated = await fx.subscription_repository.get_by_id(subscription.id)
        assert updated.last_renewal_reminder_sent_at is not None

        # A second sweep within the same billing period must not re-send.
        sent_again = await fx.service.send_renewal_reminders()
        assert sent_again == 0
        assert len(fx.notification_service.enqueued) == 1

    async def test_renewal_reminder_not_sent_outside_window(self) -> None:
        fx = make_renewal_service(renewal_reminder_days_before=3)
        plan = await _make_plan(fx.plan_repository)
        org_id = uuid.uuid4()
        license_ = await _assign_and_activate_license(
            fx.license_fixture, organization_id=org_id, plan_id=plan.id
        )
        now = _now()
        await fx.subscription_repository.create_subscription(
            organization_id=org_id,
            license_id=license_.id,
            plan_id=plan.id,
            status=SubscriptionStatus.ACTIVE.value,
            billing_cycle=plan.billing_cycle,
            current_period_start=now,
            current_period_end=now + timedelta(days=20),  # well outside the window
            trial_end=None,
            auto_renew=True,
            cancel_at_period_end=False,
            started_at=now,
        )
        sent_count = await fx.service.send_renewal_reminders()
        assert sent_count == 0

    async def test_expiry_reminder_sent_once_near_grace_deadline(self) -> None:
        fx = make_renewal_service(grace_period_days=7, expiry_reminder_days_before=3)
        plan = await _make_plan(fx.plan_repository)
        org_id = uuid.uuid4()
        license_ = await _assign_and_activate_license(
            fx.license_fixture, organization_id=org_id, plan_id=plan.id
        )
        now = _now()
        subscription = await fx.subscription_repository.create_subscription(
            organization_id=org_id,
            license_id=license_.id,
            plan_id=plan.id,
            status=SubscriptionStatus.PAST_DUE.value,
            billing_cycle=plan.billing_cycle,
            current_period_start=now - timedelta(days=20),
            current_period_end=now - timedelta(days=5),
            trial_end=None,
            auto_renew=True,
            cancel_at_period_end=False,
            started_at=now - timedelta(days=20),
            # grace deadline = past_due_at + 7d = now + 2d -- within the
            # 3-day expiry-reminder window.
            past_due_at=now - timedelta(days=5),
        )

        sent_count = await fx.service.send_expiry_reminders()
        assert sent_count == 1
        assert len(fx.notification_service.enqueued) == 1

        updated = await fx.subscription_repository.get_by_id(subscription.id)
        assert updated.last_expiry_reminder_sent_at is not None

        sent_again = await fx.service.send_expiry_reminders()
        assert sent_again == 0

    async def test_full_sweep_report_aggregates_every_phase(self) -> None:
        fx = make_renewal_service(grace_period_days=7)
        plan = await _make_plan(fx.plan_repository, base_price=Decimal("10.00"))
        org_id = uuid.uuid4()
        license_ = await _assign_and_activate_license(
            fx.license_fixture, organization_id=org_id, plan_id=plan.id
        )
        now = _now()
        await fx.subscription_repository.create_subscription(
            organization_id=org_id,
            license_id=license_.id,
            plan_id=plan.id,
            status=SubscriptionStatus.ACTIVE.value,
            billing_cycle=plan.billing_cycle,
            current_period_start=now - timedelta(days=30),
            current_period_end=now - timedelta(hours=1),
            trial_end=None,
            auto_renew=True,
            cancel_at_period_end=False,
            started_at=now - timedelta(days=30),
        )

        report = await fx.service.run_renewal_sweep()
        assert report.renewal.subscriptions_checked == 1
        assert report.renewal.renewed == 1
        assert report.expired_subscription_ids == []
        assert isinstance(report.renewal_reminders_sent, int)
        assert isinstance(report.expiry_reminders_sent, int)
