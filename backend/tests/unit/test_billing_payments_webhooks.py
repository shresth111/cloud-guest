"""Unit tests for BE-013 Part 3 (Billing: Payment Service + real Stripe/
Razorpay Integration + Webhooks): real idempotency-key enforcement (same
key twice -> same ``Payment`` row, including the real DB-unique-constraint-
shaped race backstop), both gateways' not-configured guard (before any
network attempt), refund (full/partial), retry (per-provider idempotency-
key strategy), real Stripe/Razorpay webhook signature verification (valid,
tampered, wrong secret, expired timestamp) against real HMAC fixtures this
file computes the same way each provider actually does it, webhook event-id
dedup, the webhook-confirms-a-renewal composition path (verified via a real
``RenewalService`` -- proving ``_mark_renewed``/``_mark_past_due`` are
reused, never reimplemented), and tenant isolation.

Follows this project's plain-``assert``/native-``async def`` style (see
``test_billing_subscriptions_renewals_coupons.py``'s own module docstring,
the Part 2 template this file mirrors); ``asyncio_mode = "auto"`` runs async
tests directly. Every service under test is exercised against small,
hand-rolled in-memory fakes satisfying this module's own narrow ``Protocol``
shapes -- no live Postgres/Redis/Stripe/Razorpay anywhere in this suite.
``StripePaymentGateway``/``RazorpayPaymentGateway`` are exercised for real
for their **not-configured** guard (a genuinely unconfigured
``Settings()`` -- the honest, permanent state of this sandbox) and their
**pure validator** helpers; anything that would require an actual network
call is never reached in any of these tests, by construction.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from app.core.config import Settings
from app.database.exceptions import DuplicateRecordError
from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.billing.constants import (
    BillingCycle,
    PaymentStatus,
    PlanType,
    SubscriptionStatus,
)
from app.domains.billing.exceptions import (
    NoDefaultPaymentMethodError,
    PaymentGatewayNotConfiguredError,
    PaymentNotFoundError,
    PaymentNotRefundableError,
    PaymentNotRetryableError,
    RefundExceedsRefundableAmountError,
    UnsupportedPaymentProviderError,
    WebhookSignatureInvalidError,
)
from app.domains.billing.models import Payment, PaymentMethod, Plan, Subscription
from app.domains.billing.payment_gateways import (
    RazorpayPaymentGateway,
    StripePaymentGateway,
)
from app.domains.billing.renewal_service import RenewalService
from app.domains.billing.service import PaymentMethodService, PaymentService
from app.domains.billing.validators import derive_retry_idempotency_key, to_minor_units
from app.domains.billing.webhooks import (
    RedisWebhookEventDedup,
    process_razorpay_event,
    process_stripe_event,
    verify_razorpay_signature,
    verify_stripe_event,
)

# ============================================================================
# Shared helpers (mirrors test_billing_subscriptions_renewals_coupons.py's
# own identical helpers)
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
class FakePaymentRepository:
    """Mirrors ``app.database.repositories.generic.GenericRepository``'s
    real unique-constraint-shaped behavior for ``idempotency_key``:
    ``create_payment`` raises the exact same ``DuplicateRecordError`` a real
    Postgres unique-constraint violation would be translated into (see
    ``GenericRepository._flush_or_raise``), never silently overwriting or
    ignoring a duplicate."""

    payments: dict[uuid.UUID, Payment] = field(default_factory=dict)
    create_calls: int = 0

    async def create_payment(self, **fields: object) -> Payment:
        idempotency_key = fields.get("idempotency_key")
        for existing in self.payments.values():
            if existing.idempotency_key == idempotency_key:
                raise DuplicateRecordError("Payment", "idempotency_key")
        payment = Payment(**_base_fields(**fields))
        self.payments[payment.id] = payment
        self.create_calls += 1
        return payment

    async def get_by_id(
        self, payment_id: uuid.UUID, *, include_deleted: bool = False
    ) -> Payment | None:
        return self.payments.get(payment_id)

    async def get_by_idempotency_key(self, idempotency_key: str) -> Payment | None:
        for payment in self.payments.values():
            if payment.idempotency_key == idempotency_key:
                return payment
        return None

    async def get_by_provider_payment_id(
        self, provider_payment_id: str
    ) -> Payment | None:
        for payment in self.payments.values():
            if payment.provider_payment_id == provider_payment_id:
                return payment
        return None

    async def update_payment(
        self, payment: Payment, data: dict[str, object]
    ) -> Payment:
        for key, value in data.items():
            setattr(payment, key, value)
        payment.version += 1
        return payment

    async def list_payments(
        self,
        *,
        page: int,
        page_size: int,
        organization_id: uuid.UUID | None = None,
        status: str | None = None,
        provider: str | None = None,
    ) -> tuple[list[Payment], PaginationMeta]:
        items = list(self.payments.values())
        if organization_id is not None:
            items = [p for p in items if p.organization_id == organization_id]
        if status is not None:
            items = [p for p in items if p.status == status]
        if provider is not None:
            items = [p for p in items if p.provider == provider]
        params = PageParams(page=page, page_size=page_size)
        return items, PaginationMeta.from_total(params, len(items))

    async def list_failed_payments(
        self, organization_id: uuid.UUID | None = None
    ) -> list[Payment]:
        items = [
            p for p in self.payments.values() if p.status == PaymentStatus.FAILED.value
        ]
        if organization_id is not None:
            items = [p for p in items if p.organization_id == organization_id]
        return items


@dataclass
class FakeRacyPaymentRepository(FakePaymentRepository):
    """A ``FakePaymentRepository`` variant that simulates the real
    concurrent-race window ``PaymentService.initiate_payment``'s own
    docstring describes: the *first* ``get_by_idempotency_key`` lookup
    (the fast-path pre-check) reports "not found" even though a row already
    exists, exactly as if a concurrent request's own ``INSERT`` had not yet
    committed at the instant this request's pre-check ran. Every subsequent
    lookup behaves normally. Combined with the base class's real
    duplicate-detecting ``create_payment``, this reproduces the exact
    "pre-check said no, INSERT says yes" race the DB unique constraint is
    the real backstop against."""

    _lookup_calls: int = 0

    async def get_by_idempotency_key(self, idempotency_key: str) -> Payment | None:
        self._lookup_calls += 1
        if self._lookup_calls == 1:
            return None
        return await super().get_by_idempotency_key(idempotency_key)


@dataclass
class FakePaymentMethodRepository:
    methods: dict[uuid.UUID, PaymentMethod] = field(default_factory=dict)

    async def create_payment_method(self, **fields: object) -> PaymentMethod:
        payment_method = PaymentMethod(**_base_fields(**fields))
        self.methods[payment_method.id] = payment_method
        return payment_method

    async def get_by_id(
        self, payment_method_id: uuid.UUID, *, include_deleted: bool = False
    ) -> PaymentMethod | None:
        return self.methods.get(payment_method_id)

    async def list_for_organization(
        self, organization_id: uuid.UUID, *, active_only: bool = True
    ) -> list[PaymentMethod]:
        items = [
            m for m in self.methods.values() if m.organization_id == organization_id
        ]
        if active_only:
            items = [m for m in items if m.is_active]
        return items

    async def get_default_for_organization(
        self, organization_id: uuid.UUID
    ) -> PaymentMethod | None:
        for method in self.methods.values():
            if (
                method.organization_id == organization_id
                and method.is_default
                and method.is_active
            ):
                return method
        return None

    async def update_payment_method(
        self, payment_method: PaymentMethod, data: dict[str, object]
    ) -> PaymentMethod:
        for key, value in data.items():
            setattr(payment_method, key, value)
        payment_method.version += 1
        return payment_method

    async def soft_delete_payment_method(
        self, payment_method: PaymentMethod
    ) -> PaymentMethod:
        payment_method.is_deleted = True
        return payment_method

    async def set_as_default(self, payment_method: PaymentMethod) -> PaymentMethod:
        for method in self.methods.values():
            if (
                method.organization_id == payment_method.organization_id
                and method.id != payment_method.id
            ):
                method.is_default = False
        payment_method.is_default = True
        return payment_method


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


class _StubLicenseService:
    """Satisfies ``LicenseLifecycleProtocol`` -- never actually called by
    ``RenewalService.confirm_renewal_payment_succeeded``/
    ``confirm_renewal_payment_failed`` (see those methods' own docstrings:
    they only call ``_mark_renewed``/``_mark_past_due``), so every method
    here is a defensive stub that fails loudly if that assumption is ever
    wrong."""

    async def assign_license(self, **kwargs: object) -> object:
        raise NotImplementedError

    async def activate_license(self, **kwargs: object) -> object:
        raise NotImplementedError

    async def suspend_license(self, **kwargs: object) -> object:
        raise NotImplementedError

    async def get_license(self, license_id: uuid.UUID) -> object:
        raise NotImplementedError

    async def expire_license(self, *, license_id: uuid.UUID) -> object:
        raise NotImplementedError


class _StubOrganizationLookup:
    async def get_organization(
        self, organization_id: uuid.UUID, *, include_deleted: bool = False
    ) -> object:
        raise NotImplementedError


class FakeGateway:
    """A controllable ``PaymentGatewayAdminProtocol`` for exercising
    ``PaymentService``'s own orchestration (idempotency, audit, event
    dispatch) without depending on either real gateway's not-configured
    guard (that is tested directly and separately below)."""

    def __init__(
        self,
        *,
        charge_status: str = PaymentStatus.SUCCEEDED.value,
        failure_reason: str | None = None,
    ) -> None:
        self.charge_status = charge_status
        self.failure_reason = failure_reason
        self.charge_calls: list[uuid.UUID] = []
        self.refund_calls: list[tuple[uuid.UUID, Decimal | None]] = []
        self.retry_calls: list[uuid.UUID] = []

    async def charge_via_provider(self, payment: Payment) -> Payment:
        self.charge_calls.append(payment.id)
        payment.status = self.charge_status
        if self.charge_status == PaymentStatus.SUCCEEDED.value:
            payment.provider_payment_id = f"ext_{payment.id.hex[:8]}"
            payment.failure_reason = None
        else:
            payment.failure_reason = self.failure_reason or "declined"
        return payment

    async def refund(self, payment: Payment, amount: Decimal | None) -> Payment:
        self.refund_calls.append((payment.id, amount))
        refund_amount = (
            amount if amount is not None else (payment.amount - payment.refunded_amount)
        )
        payment.refunded_amount = payment.refunded_amount + refund_amount
        payment.status = (
            PaymentStatus.REFUNDED.value
            if payment.refunded_amount >= payment.amount
            else PaymentStatus.PARTIALLY_REFUNDED.value
        )
        return payment

    async def retry(self, payment: Payment) -> Payment:
        self.retry_calls.append(payment.id)
        payment.status = PaymentStatus.SUCCEEDED.value
        payment.provider_payment_id = (
            payment.provider_payment_id or f"ext_retry_{payment.id.hex[:8]}"
        )
        payment.failure_reason = None
        return payment


class FakeInMemoryDedup:
    """Satisfies ``webhooks.WebhookEventDedupProtocol`` with a plain
    in-memory set -- the same atomic "first call true, every subsequent
    call for the same pair false" contract ``RedisWebhookEventDedup``
    provides for real (tested directly, separately, below)."""

    def __init__(self) -> None:
        self.seen: set[tuple[str, str]] = set()

    async def mark_processed_if_new(self, provider: str, event_id: str) -> bool:
        key = (provider, event_id)
        if key in self.seen:
            return False
        self.seen.add(key)
        return True


class FakeRedisForDedup:
    """A minimal stand-in for ``redis.asyncio.Redis`` -- only implements
    the one real command ``RedisWebhookEventDedup`` calls
    (``SET key value NX EX ttl``), with the exact same real semantics
    ``redis-py`` itself has: ``nx=True`` against an existing key returns
    ``None`` (no-op), never overwriting."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    async def set(
        self, key: str, value: str, *, nx: bool = False, ex: int | None = None
    ) -> bool | None:
        if nx and key in self.store:
            return None
        self.store[key] = value
        return True


# ============================================================================
# Real HMAC fixtures -- computed the same way each provider actually does it
# (see webhooks.py's own module docstring for the exact schemes, verified
# directly against each installed SDK's source while writing this module).
# ============================================================================


def _build_stripe_event_json(event_id: str, event_type: str, obj: dict) -> bytes:
    payload = {
        "id": event_id,
        "object": "event",
        "type": event_type,
        "data": {"object": obj},
    }
    return json.dumps(payload).encode("utf-8")


def _stripe_signature_header(payload: bytes, secret: str, *, timestamp: int) -> str:
    """The real Stripe scheme: signed_payload = f"{timestamp}.{payload}";
    HMAC-SHA256 hex digest; header = "t=<ts>,v1=<sig>"."""
    signed_payload = f"{timestamp}.".encode() + payload
    signature = hmac.new(
        secret.encode("utf-8"), signed_payload, hashlib.sha256
    ).hexdigest()
    return f"t={timestamp},v1={signature}"


def _razorpay_signature_header(payload: bytes, secret: str) -> str:
    """The real Razorpay scheme: HMAC-SHA256 hex digest of the raw body,
    no timestamp component at all."""
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


# ============================================================================
# Idempotency enforcement
# ============================================================================


class TestPaymentIdempotency:
    async def test_same_idempotency_key_returns_same_payment_row(self) -> None:
        payment_repository = FakePaymentRepository()
        payment_method_repository = FakePaymentMethodRepository()
        gateway = FakeGateway()
        service = PaymentService(
            payment_repository,
            payment_method_repository,
            gateways={"stripe": gateway},
        )
        org_id = uuid.uuid4()

        first = await service.initiate_payment(
            actor_user_id=None,
            organization_id=org_id,
            subscription_id=None,
            amount=Decimal("49.99"),
            currency="USD",
            provider="stripe",
            idempotency_key="checkout-abc-123",
        )
        second = await service.initiate_payment(
            actor_user_id=None,
            organization_id=org_id,
            subscription_id=None,
            amount=Decimal("49.99"),
            currency="USD",
            provider="stripe",
            idempotency_key="checkout-abc-123",
        )

        assert first.id == second.id
        assert payment_repository.create_calls == 1
        # The gateway (i.e. the real provider) was only ever actually
        # charged once -- the second call never double-charges.
        assert len(gateway.charge_calls) == 1

    async def test_concurrent_race_is_resolved_by_the_real_db_constraint(
        self,
    ) -> None:
        """Simulates two requests racing on the same idempotency_key: the
        pre-check (get_by_idempotency_key) reports "not found" for both,
        but the real (here, simulated) unique constraint on the second
        INSERT raises DuplicateRecordError -- PaymentService must recover
        by returning the winner's row, never by attempting a second
        charge."""
        payment_repository = FakeRacyPaymentRepository()
        payment_method_repository = FakePaymentMethodRepository()
        gateway = FakeGateway()
        service = PaymentService(
            payment_repository,
            payment_method_repository,
            gateways={"stripe": gateway},
        )
        org_id = uuid.uuid4()

        # The "winning" concurrent request's row already exists before this
        # request's own pre-check runs (which, per FakeRacyPaymentRepository,
        # will still report "not found" on its first call).
        winner = await payment_repository.create_payment(
            organization_id=org_id,
            subscription_id=None,
            amount=Decimal("49.99"),
            currency="USD",
            status=PaymentStatus.SUCCEEDED.value,
            provider="stripe",
            provider_payment_id="pi_winner",
            idempotency_key="race-key",
            refunded_amount=Decimal("0"),
        )

        result = await service.initiate_payment(
            actor_user_id=None,
            organization_id=org_id,
            subscription_id=None,
            amount=Decimal("49.99"),
            currency="USD",
            provider="stripe",
            idempotency_key="race-key",
        )

        assert result.id == winner.id
        assert result.status == PaymentStatus.SUCCEEDED.value
        # The gateway was never called for the losing request -- no double
        # charge occurred.
        assert gateway.charge_calls == []

    async def test_unsupported_provider_rejected(self) -> None:
        payment_repository = FakePaymentRepository()
        payment_method_repository = FakePaymentMethodRepository()
        service = PaymentService(
            payment_repository, payment_method_repository, gateways={}
        )
        with pytest.raises(UnsupportedPaymentProviderError):
            await service.initiate_payment(
                actor_user_id=None,
                organization_id=uuid.uuid4(),
                subscription_id=None,
                amount=Decimal("10.00"),
                currency="USD",
                provider="unknown_provider",
                idempotency_key="key-x",
            )


# ============================================================================
# Both gateways' not-configured guard -- real classes, genuinely unconfigured
# Settings (the honest, permanent state of this sandbox), no network attempt.
# ============================================================================


class TestGatewayNotConfigured:
    async def test_stripe_charge_raises_before_creating_any_row(self) -> None:
        settings = Settings()
        payment_repository = FakePaymentRepository()
        payment_method_repository = FakePaymentMethodRepository()
        gateway = StripePaymentGateway(
            settings=settings,
            payment_repository=payment_repository,
            payment_method_repository=payment_method_repository,
        )
        with pytest.raises(PaymentGatewayNotConfiguredError):
            await gateway.charge(
                organization_id=uuid.uuid4(),
                amount=Decimal("10.00"),
                currency="USD",
                subscription_id=uuid.uuid4(),
            )
        assert payment_repository.payments == {}

    async def test_razorpay_charge_raises_before_creating_any_row(self) -> None:
        settings = Settings()
        payment_repository = FakePaymentRepository()
        payment_method_repository = FakePaymentMethodRepository()
        gateway = RazorpayPaymentGateway(
            settings=settings,
            payment_repository=payment_repository,
            payment_method_repository=payment_method_repository,
        )
        with pytest.raises(PaymentGatewayNotConfiguredError):
            await gateway.charge(
                organization_id=uuid.uuid4(),
                amount=Decimal("10.00"),
                currency="USD",
                subscription_id=uuid.uuid4(),
            )
        assert payment_repository.payments == {}

    async def test_zero_amount_charge_auto_succeeds_even_when_not_configured(
        self,
    ) -> None:
        """Preserves UnconfiguredPaymentGateway's own Part 2 behavior byte-
        for-byte in both real gateways -- a genuinely free renewal must
        never start failing just because a real (still-unconfigured)
        gateway replaced the honest placeholder."""
        settings = Settings()
        payment_repository = FakePaymentRepository()
        payment_method_repository = FakePaymentMethodRepository()
        for gateway_cls in (StripePaymentGateway, RazorpayPaymentGateway):
            gateway = gateway_cls(
                settings=settings,
                payment_repository=payment_repository,
                payment_method_repository=payment_method_repository,
            )
            result = await gateway.charge(
                organization_id=uuid.uuid4(),
                amount=Decimal("0"),
                currency="USD",
                subscription_id=uuid.uuid4(),
            )
            assert result.success is True
        assert payment_repository.payments == {}

    async def test_charge_via_provider_marks_existing_payment_failed(self) -> None:
        settings = Settings()
        payment_repository = FakePaymentRepository()
        payment_method_repository = FakePaymentMethodRepository()
        gateway = StripePaymentGateway(
            settings=settings,
            payment_repository=payment_repository,
            payment_method_repository=payment_method_repository,
        )
        payment = await payment_repository.create_payment(
            organization_id=uuid.uuid4(),
            subscription_id=None,
            amount=Decimal("10.00"),
            currency="USD",
            status=PaymentStatus.PENDING.value,
            provider="stripe",
            provider_payment_id=None,
            idempotency_key="key-not-configured",
            refunded_amount=Decimal("0"),
        )

        with pytest.raises(PaymentGatewayNotConfiguredError):
            await gateway.charge_via_provider(payment)

        updated = await payment_repository.get_by_id(payment.id)
        assert updated.status == PaymentStatus.FAILED.value
        assert updated.failure_reason == "payment_gateway_not_configured"

    async def test_refund_raises_without_mutating_the_payment(self) -> None:
        settings = Settings()
        payment_repository = FakePaymentRepository()
        payment_method_repository = FakePaymentMethodRepository()
        gateway = StripePaymentGateway(
            settings=settings,
            payment_repository=payment_repository,
            payment_method_repository=payment_method_repository,
        )
        payment = await payment_repository.create_payment(
            organization_id=uuid.uuid4(),
            subscription_id=None,
            amount=Decimal("10.00"),
            currency="USD",
            status=PaymentStatus.SUCCEEDED.value,
            provider="stripe",
            provider_payment_id="pi_1",
            idempotency_key="key-refund",
            refunded_amount=Decimal("0"),
        )

        with pytest.raises(PaymentGatewayNotConfiguredError):
            await gateway.refund(payment, None)

        updated = await payment_repository.get_by_id(payment.id)
        assert updated.status == PaymentStatus.SUCCEEDED.value
        assert updated.refunded_amount == Decimal("0")

    async def test_retry_raises_without_mutating_the_payment(self) -> None:
        settings = Settings()
        payment_repository = FakePaymentRepository()
        payment_method_repository = FakePaymentMethodRepository()
        gateway = RazorpayPaymentGateway(
            settings=settings,
            payment_repository=payment_repository,
            payment_method_repository=payment_method_repository,
        )
        payment = await payment_repository.create_payment(
            organization_id=uuid.uuid4(),
            subscription_id=None,
            amount=Decimal("10.00"),
            currency="USD",
            status=PaymentStatus.FAILED.value,
            provider="razorpay",
            provider_payment_id=None,
            idempotency_key="key-retry",
            refunded_amount=Decimal("0"),
        )

        with pytest.raises(PaymentGatewayNotConfiguredError):
            await gateway.retry(payment)

        updated = await payment_repository.get_by_id(payment.id)
        assert updated.status == PaymentStatus.FAILED.value

    async def test_no_default_payment_method_is_a_distinct_error_when_configured(
        self,
    ) -> None:
        """Configured (a real key is present) but no saved payment method
        on file -- a real, organization-specific data gap, distinct from
        "gateway not configured"."""
        settings = Settings(stripe_secret_key="sk_test_fake_never_used_over_network")
        payment_repository = FakePaymentRepository()
        payment_method_repository = FakePaymentMethodRepository()  # empty
        gateway = StripePaymentGateway(
            settings=settings,
            payment_repository=payment_repository,
            payment_method_repository=payment_method_repository,
        )
        payment = await payment_repository.create_payment(
            organization_id=uuid.uuid4(),
            subscription_id=None,
            amount=Decimal("10.00"),
            currency="USD",
            status=PaymentStatus.PENDING.value,
            provider="stripe",
            provider_payment_id=None,
            idempotency_key="key-no-method",
            refunded_amount=Decimal("0"),
        )

        with pytest.raises(NoDefaultPaymentMethodError):
            await gateway.charge_via_provider(payment)

        updated = await payment_repository.get_by_id(payment.id)
        assert updated.status == PaymentStatus.FAILED.value


# ============================================================================
# Refund
# ============================================================================


class TestRefund:
    async def _make_succeeded_payment(
        self, payment_repository: FakePaymentRepository, *, amount: Decimal
    ) -> Payment:
        return await payment_repository.create_payment(
            organization_id=uuid.uuid4(),
            subscription_id=None,
            amount=amount,
            currency="USD",
            status=PaymentStatus.SUCCEEDED.value,
            provider="stripe",
            provider_payment_id="pi_refund_test",
            idempotency_key=f"key-{uuid.uuid4().hex[:8]}",
            refunded_amount=Decimal("0"),
        )

    async def test_full_refund_sets_status_refunded(self) -> None:
        payment_repository = FakePaymentRepository()
        gateway = FakeGateway()
        service = PaymentService(
            payment_repository,
            FakePaymentMethodRepository(),
            gateways={"stripe": gateway},
        )
        payment = await self._make_succeeded_payment(
            payment_repository, amount=Decimal("100.00")
        )

        refunded = await service.refund_payment(
            actor_user_id=None, payment_id=payment.id
        )
        assert refunded.status == PaymentStatus.REFUNDED.value
        assert refunded.refunded_amount == Decimal("100.00")
        # PaymentService.refund_payment resolves "amount=None" (a full
        # refund) into the concrete remaining chargeable amount *before*
        # calling the gateway -- the gateway itself never has to guess.
        assert gateway.refund_calls == [(payment.id, Decimal("100.00"))]

    async def test_partial_refund_sets_status_partially_refunded(self) -> None:
        payment_repository = FakePaymentRepository()
        gateway = FakeGateway()
        service = PaymentService(
            payment_repository,
            FakePaymentMethodRepository(),
            gateways={"stripe": gateway},
        )
        payment = await self._make_succeeded_payment(
            payment_repository, amount=Decimal("100.00")
        )

        refunded = await service.refund_payment(
            actor_user_id=None, payment_id=payment.id, amount=Decimal("30.00")
        )
        assert refunded.status == PaymentStatus.PARTIALLY_REFUNDED.value
        assert refunded.refunded_amount == Decimal("30.00")

        # A second partial refund of the remainder completes it.
        refunded_again = await service.refund_payment(
            actor_user_id=None, payment_id=payment.id, amount=Decimal("70.00")
        )
        assert refunded_again.status == PaymentStatus.REFUNDED.value
        assert refunded_again.refunded_amount == Decimal("100.00")

    async def test_refund_exceeding_remaining_amount_rejected(self) -> None:
        payment_repository = FakePaymentRepository()
        service = PaymentService(
            payment_repository,
            FakePaymentMethodRepository(),
            gateways={"stripe": FakeGateway()},
        )
        payment = await self._make_succeeded_payment(
            payment_repository, amount=Decimal("50.00")
        )
        with pytest.raises(RefundExceedsRefundableAmountError):
            await service.refund_payment(
                actor_user_id=None, payment_id=payment.id, amount=Decimal("500.00")
            )

    async def test_refund_of_non_refundable_status_rejected(self) -> None:
        payment_repository = FakePaymentRepository()
        service = PaymentService(
            payment_repository,
            FakePaymentMethodRepository(),
            gateways={"stripe": FakeGateway()},
        )
        payment = await payment_repository.create_payment(
            organization_id=uuid.uuid4(),
            subscription_id=None,
            amount=Decimal("10.00"),
            currency="USD",
            status=PaymentStatus.PENDING.value,
            provider="stripe",
            provider_payment_id=None,
            idempotency_key="key-pending",
            refunded_amount=Decimal("0"),
        )
        with pytest.raises(PaymentNotRefundableError):
            await service.refund_payment(actor_user_id=None, payment_id=payment.id)


# ============================================================================
# Retry -- idempotency-key strategy
# ============================================================================


class TestRetry:
    async def test_derive_retry_idempotency_key_is_fresh_but_related(self) -> None:
        original = "checkout-abc-123"
        first_retry = derive_retry_idempotency_key(original)
        second_retry = derive_retry_idempotency_key(original)
        assert first_retry.startswith(f"{original}:retry:")
        assert second_retry.startswith(f"{original}:retry:")
        # Every retry gets its own fresh value -- never a reuse (see
        # payment_gateways.py's own module docstring for why Stripe
        # specifically requires this).
        assert first_retry != second_retry
        assert first_retry != original

    async def test_retry_reuses_the_same_payment_row_and_idempotency_key(self) -> None:
        payment_repository = FakePaymentRepository()
        gateway = FakeGateway()
        service = PaymentService(
            payment_repository,
            FakePaymentMethodRepository(),
            gateways={"stripe": gateway},
        )
        payment = await payment_repository.create_payment(
            organization_id=uuid.uuid4(),
            subscription_id=None,
            amount=Decimal("10.00"),
            currency="USD",
            status=PaymentStatus.FAILED.value,
            provider="stripe",
            provider_payment_id=None,
            idempotency_key="key-retry-1",
            refunded_amount=Decimal("0"),
        )
        original_id = payment.id
        original_key = payment.idempotency_key

        retried = await service.retry_failed_payment(
            actor_user_id=None, payment_id=payment.id
        )

        assert retried.id == original_id
        # This module's own "Payment doubles as history" decision -- a
        # retry mutates the SAME row in place, never creates a second one.
        assert payment_repository.create_calls == 1
        # The row's own idempotency_key column is this Payment's permanent
        # identity -- unchanged by a retry (see validators
        # .derive_retry_idempotency_key's own docstring for the contrast
        # with the *wire-level* key a gateway sends to Stripe).
        assert retried.idempotency_key == original_key
        assert retried.status == PaymentStatus.SUCCEEDED.value
        assert gateway.retry_calls == [original_id]

    async def test_retry_of_non_failed_payment_rejected(self) -> None:
        payment_repository = FakePaymentRepository()
        service = PaymentService(
            payment_repository,
            FakePaymentMethodRepository(),
            gateways={"stripe": FakeGateway()},
        )
        payment = await payment_repository.create_payment(
            organization_id=uuid.uuid4(),
            subscription_id=None,
            amount=Decimal("10.00"),
            currency="USD",
            status=PaymentStatus.SUCCEEDED.value,
            provider="stripe",
            provider_payment_id="pi_1",
            idempotency_key="key-succeeded",
            refunded_amount=Decimal("0"),
        )
        with pytest.raises(PaymentNotRetryableError):
            await service.retry_failed_payment(
                actor_user_id=None, payment_id=payment.id
            )


# ============================================================================
# Tenant isolation
# ============================================================================


class TestTenantIsolation:
    async def test_get_payment_enforces_organization_id_filter(self) -> None:
        payment_repository = FakePaymentRepository()
        service = PaymentService(
            payment_repository,
            FakePaymentMethodRepository(),
            gateways={"stripe": FakeGateway()},
        )
        owner_org = uuid.uuid4()
        other_org = uuid.uuid4()
        payment = await payment_repository.create_payment(
            organization_id=owner_org,
            subscription_id=None,
            amount=Decimal("10.00"),
            currency="USD",
            status=PaymentStatus.SUCCEEDED.value,
            provider="stripe",
            provider_payment_id="pi_1",
            idempotency_key="key-tenant",
            refunded_amount=Decimal("0"),
        )

        # The owning organization can read it.
        fetched = await service.get_payment(payment.id, organization_id=owner_org)
        assert fetched.id == payment.id

        # A different organization gets a real not-found, never a leak of
        # the payment's existence.
        with pytest.raises(PaymentNotFoundError):
            await service.get_payment(payment.id, organization_id=other_org)

    async def test_list_payments_filters_by_organization(self) -> None:
        payment_repository = FakePaymentRepository()
        service = PaymentService(
            payment_repository,
            FakePaymentMethodRepository(),
            gateways={"stripe": FakeGateway()},
        )
        org_a = uuid.uuid4()
        org_b = uuid.uuid4()
        await payment_repository.create_payment(
            organization_id=org_a,
            subscription_id=None,
            amount=Decimal("10.00"),
            currency="USD",
            status=PaymentStatus.SUCCEEDED.value,
            provider="stripe",
            provider_payment_id="pi_a",
            idempotency_key="key-a",
            refunded_amount=Decimal("0"),
        )
        await payment_repository.create_payment(
            organization_id=org_b,
            subscription_id=None,
            amount=Decimal("20.00"),
            currency="USD",
            status=PaymentStatus.SUCCEEDED.value,
            provider="stripe",
            provider_payment_id="pi_b",
            idempotency_key="key-b",
            refunded_amount=Decimal("0"),
        )

        items, meta = await service.list_payments(organization_id=org_a)
        assert len(items) == 1
        assert items[0].organization_id == org_a
        assert meta.total_items == 1


# ============================================================================
# PaymentMethod: token-only storage + at-most-one-default enforcement
# ============================================================================


class TestPaymentMethodService:
    async def test_register_and_only_one_default_per_organization(self) -> None:
        repository = FakePaymentMethodRepository()
        service = PaymentMethodService(repository)
        org_id = uuid.uuid4()

        first = await service.register_payment_method(
            actor_user_id=None,
            organization_id=org_id,
            provider="stripe",
            provider_payment_method_id="pm_1NExampleToken",
            method_type="card",
            last4="4242",
            is_default=True,
        )
        assert first.is_default is True

        second = await service.register_payment_method(
            actor_user_id=None,
            organization_id=org_id,
            provider="stripe",
            provider_payment_method_id="pm_2NExampleToken",
            method_type="card",
            last4="1111",
            is_default=True,
        )
        refreshed_first = await repository.get_by_id(first.id)
        assert refreshed_first.is_default is False
        assert second.is_default is True

    async def test_remove_payment_method_deactivates(self) -> None:
        repository = FakePaymentMethodRepository()
        service = PaymentMethodService(repository)
        org_id = uuid.uuid4()
        payment_method = await service.register_payment_method(
            actor_user_id=None,
            organization_id=org_id,
            provider="stripe",
            provider_payment_method_id="pm_1NExampleToken",
            method_type="card",
            last4="4242",
            is_default=True,
        )

        removed = await service.remove_payment_method(
            actor_user_id=None, payment_method_id=payment_method.id
        )
        assert removed.is_active is False
        assert removed.is_default is False


# ============================================================================
# Stripe webhook signature verification -- real HMAC-SHA256, real scheme.
# ============================================================================


class TestStripeWebhookSignature:
    def _payload(self) -> bytes:
        return _build_stripe_event_json(
            "evt_test_1",
            "payment_intent.succeeded",
            {"id": "pi_test_1", "object": "payment_intent"},
        )

    def test_valid_signature_accepted(self) -> None:
        secret = "whsec_test_secret"
        payload = self._payload()
        header = _stripe_signature_header(payload, secret, timestamp=int(time.time()))

        event = verify_stripe_event(
            payload, signature_header=header, secret=secret, tolerance_seconds=300
        )
        assert event.id == "evt_test_1"
        assert event.type == "payment_intent.succeeded"

    def test_tampered_payload_rejected(self) -> None:
        secret = "whsec_test_secret"
        payload = self._payload()
        header = _stripe_signature_header(payload, secret, timestamp=int(time.time()))
        tampered = payload.replace(b"pi_test_1", b"pi_tampered")

        with pytest.raises(WebhookSignatureInvalidError):
            verify_stripe_event(
                tampered, signature_header=header, secret=secret, tolerance_seconds=300
            )

    def test_garbage_signature_rejected(self) -> None:
        secret = "whsec_test_secret"
        payload = self._payload()
        header = f"t={int(time.time())},v1=0000deadbeef0000"

        with pytest.raises(WebhookSignatureInvalidError):
            verify_stripe_event(
                payload, signature_header=header, secret=secret, tolerance_seconds=300
            )

    def test_wrong_secret_rejected(self) -> None:
        payload = self._payload()
        ts = int(time.time())
        header = _stripe_signature_header(payload, "whsec_correct", timestamp=ts)

        with pytest.raises(WebhookSignatureInvalidError):
            verify_stripe_event(
                payload,
                signature_header=header,
                secret="whsec_wrong",
                tolerance_seconds=300,
            )

    def test_expired_timestamp_rejected(self) -> None:
        secret = "whsec_test_secret"
        payload = self._payload()
        old_timestamp = int(time.time()) - 1000  # outside the 300s tolerance
        header = _stripe_signature_header(payload, secret, timestamp=old_timestamp)

        with pytest.raises(WebhookSignatureInvalidError):
            verify_stripe_event(
                payload, signature_header=header, secret=secret, tolerance_seconds=300
            )


# ============================================================================
# Razorpay webhook signature verification -- real HMAC-SHA256, real scheme.
# ============================================================================


class TestRazorpayWebhookSignature:
    def _payload(self) -> bytes:
        return json.dumps(
            {
                "event": "payment.captured",
                "payload": {"payment": {"entity": {"id": "pay_test_1"}}},
            }
        ).encode("utf-8")

    def test_valid_signature_accepted(self) -> None:
        secret = "razorpay_webhook_secret"
        payload = self._payload()
        signature = _razorpay_signature_header(payload, secret)

        # Raises nothing on success.
        verify_razorpay_signature(payload, signature=signature, secret=secret)

    def test_tampered_payload_rejected(self) -> None:
        secret = "razorpay_webhook_secret"
        payload = self._payload()
        signature = _razorpay_signature_header(payload, secret)
        tampered = payload.replace(b"pay_test_1", b"pay_tampered")

        with pytest.raises(WebhookSignatureInvalidError):
            verify_razorpay_signature(tampered, signature=signature, secret=secret)

    def test_garbage_signature_rejected(self) -> None:
        secret = "razorpay_webhook_secret"
        payload = self._payload()

        with pytest.raises(WebhookSignatureInvalidError):
            verify_razorpay_signature(
                payload, signature="0000deadbeef0000", secret=secret
            )

    def test_wrong_secret_rejected(self) -> None:
        payload = self._payload()
        signature = _razorpay_signature_header(payload, "secret_correct")

        with pytest.raises(WebhookSignatureInvalidError):
            verify_razorpay_signature(
                payload, signature=signature, secret="secret_wrong"
            )


# ============================================================================
# Webhook event-id dedup
# ============================================================================


class TestWebhookEventDedup:
    async def test_redis_backed_dedup_marks_first_new_second_duplicate(self) -> None:
        redis = FakeRedisForDedup()
        dedup = RedisWebhookEventDedup(redis, ttl_seconds=3600)

        first = await dedup.mark_processed_if_new("stripe", "evt_dedup_1")
        second = await dedup.mark_processed_if_new("stripe", "evt_dedup_1")

        assert first is True
        assert second is False

    async def test_different_event_ids_are_independent(self) -> None:
        redis = FakeRedisForDedup()
        dedup = RedisWebhookEventDedup(redis, ttl_seconds=3600)

        assert await dedup.mark_processed_if_new("stripe", "evt_a") is True
        assert await dedup.mark_processed_if_new("stripe", "evt_b") is True

    async def test_different_providers_with_same_event_id_are_independent(
        self,
    ) -> None:
        redis = FakeRedisForDedup()
        dedup = RedisWebhookEventDedup(redis, ttl_seconds=3600)

        assert await dedup.mark_processed_if_new("stripe", "evt_shared") is True
        assert await dedup.mark_processed_if_new("razorpay", "evt_shared") is True


# ============================================================================
# Webhook processing -> real subscription-renewal composition (never
# reimplemented -- verified via the real RenewalService, whose
# _mark_renewed/_mark_past_due are the exact same transitions
# process_renewal's own synchronous path already uses).
# ============================================================================


class TestWebhookRenewalComposition:
    def _make_renewal_service(
        self,
    ) -> tuple[FakeSubscriptionRepository, FakePlanRepository, RenewalService]:
        subscription_repository = FakeSubscriptionRepository()
        plan_repository = FakePlanRepository()
        service = RenewalService(
            subscription_repository,
            plan_repository,
            license_service=_StubLicenseService(),
            organization_lookup=_StubOrganizationLookup(),
        )
        return subscription_repository, plan_repository, service

    async def _make_past_due_subscription(
        self,
        subscription_repository: FakeSubscriptionRepository,
        plan_repository: FakePlanRepository,
        *,
        org_id: uuid.UUID,
    ) -> tuple[Plan, Subscription]:
        plan = await plan_repository.create_plan(
            name="Professional",
            slug=f"plan-{uuid.uuid4().hex[:8]}",
            plan_type=PlanType.PROFESSIONAL.value,
            description=None,
            billing_cycle=BillingCycle.MONTHLY.value,
            base_price=Decimal("29.99"),
            currency="USD",
            is_active=True,
            is_public=True,
            created_by_user_id=None,
            sort_order=0,
        )
        now = _now()
        subscription = await subscription_repository.create_subscription(
            organization_id=org_id,
            license_id=uuid.uuid4(),
            plan_id=plan.id,
            status=SubscriptionStatus.PAST_DUE.value,
            billing_cycle=plan.billing_cycle,
            current_period_start=now - timedelta(days=30),
            current_period_end=now - timedelta(days=1),
            trial_end=None,
            auto_renew=True,
            cancel_at_period_end=False,
            started_at=now - timedelta(days=30),
            past_due_at=now - timedelta(days=1),
        )
        return plan, subscription

    async def test_stripe_payment_intent_succeeded_confirms_renewal(self) -> None:
        (
            subscription_repository,
            plan_repository,
            renewal_service,
        ) = self._make_renewal_service()
        org_id = uuid.uuid4()
        _plan, subscription = await self._make_past_due_subscription(
            subscription_repository, plan_repository, org_id=org_id
        )

        payment_repository = FakePaymentRepository()
        payment = await payment_repository.create_payment(
            organization_id=org_id,
            subscription_id=subscription.id,
            amount=Decimal("29.99"),
            currency="USD",
            status=PaymentStatus.PENDING.value,
            provider="stripe",
            provider_payment_id="pi_confirmed_success",
            idempotency_key="renewal-key-succeeded",
            refunded_amount=Decimal("0"),
        )

        event_payload = _build_stripe_event_json(
            "evt_renewal_success",
            "payment_intent.succeeded",
            {"id": "pi_confirmed_success", "object": "payment_intent"},
        )
        secret = "whsec_renewal_test"
        header = _stripe_signature_header(
            event_payload, secret, timestamp=int(time.time())
        )
        event = verify_stripe_event(
            event_payload, signature_header=header, secret=secret, tolerance_seconds=300
        )

        # Captured before processing -- FakeSubscriptionRepository mutates
        # the Subscription object in place (no real DB round-trip), so
        # ``subscription`` and ``updated_subscription`` end up being the
        # exact same Python object; the *value* must be snapshotted first.
        original_period_end = subscription.current_period_end

        dedup = FakeInMemoryDedup()
        applied = await process_stripe_event(
            event,
            payment_repository=payment_repository,
            renewal_service=renewal_service,
            dedup=dedup,
        )
        assert applied is True

        updated_subscription = await subscription_repository.get_by_id(subscription.id)
        # Proves _mark_renewed (RenewalService's own existing, already-
        # tested transition) actually ran -- never reimplemented here.
        assert updated_subscription.status == SubscriptionStatus.ACTIVE.value
        assert updated_subscription.past_due_at is None
        assert updated_subscription.current_period_end > original_period_end

        updated_payment = await payment_repository.get_by_id(payment.id)
        assert updated_payment.status == PaymentStatus.SUCCEEDED.value

        # A real redelivery of the exact same event id must be a no-op.
        applied_again = await process_stripe_event(
            event,
            payment_repository=payment_repository,
            renewal_service=renewal_service,
            dedup=dedup,
        )
        assert applied_again is False

    async def test_stripe_payment_intent_payment_failed_confirms_renewal_failure(
        self,
    ) -> None:
        (
            subscription_repository,
            plan_repository,
            renewal_service,
        ) = self._make_renewal_service()
        org_id = uuid.uuid4()
        _plan, subscription = await self._make_past_due_subscription(
            subscription_repository, plan_repository, org_id=org_id
        )
        # Clear past_due_at to prove _mark_past_due (not a no-op) actually
        # set it again.
        subscription.past_due_at = None

        payment_repository = FakePaymentRepository()
        await payment_repository.create_payment(
            organization_id=org_id,
            subscription_id=subscription.id,
            amount=Decimal("29.99"),
            currency="USD",
            status=PaymentStatus.PENDING.value,
            provider="stripe",
            provider_payment_id="pi_confirmed_failure",
            idempotency_key="renewal-key-failed",
            refunded_amount=Decimal("0"),
        )

        event_payload = _build_stripe_event_json(
            "evt_renewal_failure",
            "payment_intent.payment_failed",
            {
                "id": "pi_confirmed_failure",
                "object": "payment_intent",
                "last_payment_error": {"message": "Your card was declined."},
            },
        )
        secret = "whsec_renewal_test"
        header = _stripe_signature_header(
            event_payload, secret, timestamp=int(time.time())
        )
        event = verify_stripe_event(
            event_payload, signature_header=header, secret=secret, tolerance_seconds=300
        )

        dedup = FakeInMemoryDedup()
        applied = await process_stripe_event(
            event,
            payment_repository=payment_repository,
            renewal_service=renewal_service,
            dedup=dedup,
        )
        assert applied is True

        updated_subscription = await subscription_repository.get_by_id(subscription.id)
        assert updated_subscription.status == SubscriptionStatus.PAST_DUE.value
        assert updated_subscription.past_due_at is not None

    async def test_razorpay_payment_captured_confirms_renewal(self) -> None:
        (
            subscription_repository,
            plan_repository,
            renewal_service,
        ) = self._make_renewal_service()
        org_id = uuid.uuid4()
        _plan, subscription = await self._make_past_due_subscription(
            subscription_repository, plan_repository, org_id=org_id
        )

        payment_repository = FakePaymentRepository()
        await payment_repository.create_payment(
            organization_id=org_id,
            subscription_id=subscription.id,
            amount=Decimal("29.99"),
            currency="USD",
            status=PaymentStatus.PENDING.value,
            provider="razorpay",
            provider_payment_id="pay_confirmed_success",
            idempotency_key="renewal-key-razorpay",
            refunded_amount=Decimal("0"),
        )

        payload = {
            "event": "payment.captured",
            "payload": {"payment": {"entity": {"id": "pay_confirmed_success"}}},
            "_event_id": "evt_razorpay_success",
        }

        dedup = FakeInMemoryDedup()
        applied = await process_razorpay_event(
            payload,
            payment_repository=payment_repository,
            renewal_service=renewal_service,
            dedup=dedup,
        )
        assert applied is True

        updated_subscription = await subscription_repository.get_by_id(subscription.id)
        assert updated_subscription.status == SubscriptionStatus.ACTIVE.value

        # A redelivery of the same Razorpay event id is a no-op.
        applied_again = await process_razorpay_event(
            payload,
            payment_repository=payment_repository,
            renewal_service=renewal_service,
            dedup=dedup,
        )
        assert applied_again is False

    async def test_webhook_for_untracked_payment_is_a_safe_no_op(self) -> None:
        """A webhook for a provider_payment_id this platform never created a
        Payment row for -- real webhook-handling best practice is to
        acknowledge and ignore, never error the delivery."""
        (
            subscription_repository,
            plan_repository,
            renewal_service,
        ) = self._make_renewal_service()
        payment_repository = FakePaymentRepository()

        event_payload = _build_stripe_event_json(
            "evt_untracked",
            "payment_intent.succeeded",
            {"id": "pi_never_tracked", "object": "payment_intent"},
        )
        secret = "whsec_renewal_test"
        header = _stripe_signature_header(
            event_payload, secret, timestamp=int(time.time())
        )
        event = verify_stripe_event(
            event_payload, signature_header=header, secret=secret, tolerance_seconds=300
        )

        dedup = FakeInMemoryDedup()
        applied = await process_stripe_event(
            event,
            payment_repository=payment_repository,
            renewal_service=renewal_service,
            dedup=dedup,
        )
        # The event was still genuinely processed (not a dedup no-op) --
        # it simply found nothing to update.
        assert applied is True
        assert payment_repository.payments == {}


# ============================================================================
# Minor-units / zero-decimal-currency validator
# ============================================================================


class TestToMinorUnits:
    def test_standard_currency_multiplies_by_100(self) -> None:
        assert to_minor_units(Decimal("12.34"), "USD") == 1234
        assert to_minor_units(Decimal("0.99"), "usd") == 99

    def test_zero_decimal_currency_is_not_multiplied(self) -> None:
        assert to_minor_units(Decimal("1234"), "JPY") == 1234
        assert to_minor_units(Decimal("1234"), "jpy") == 1234
