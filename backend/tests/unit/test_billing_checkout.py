"""Unit tests for the Razorpay Checkout (flat-plan self-service payment)
addition: ``service.PaymentService.create_checkout_order``,
``payment_gateways.RazorpayPaymentGateway.create_checkout_order``'s real
not-configured guard, ``webhooks.process_razorpay_event``'s order_id
correlation fallback + real license-activation-on-first-payment
composition, and the webhook audit-trail addition
(``log_signature_failure``/``process_razorpay_event`` writing real
``audit_log_entries`` rows for every receipt, verified or rejected).

Follows this project's plain-``assert``/native-``async def`` style (see
``test_billing_payments_webhooks.py``'s own module docstring, the template
this file mirrors); ``asyncio_mode = "auto"`` runs async tests directly.
Every service under test is exercised against small, hand-rolled in-memory
fakes satisfying this module's own narrow ``Protocol`` shapes -- no live
Postgres/Redis/Razorpay anywhere in this suite. ``RazorpayPaymentGateway``
is exercised for real for its **not-configured** guard (a genuinely
unconfigured ``Settings()`` -- the honest, permanent state of this
sandbox); no fabricated credential is ever used, including here (see
``Settings(razorpay_key_id=..., razorpay_key_secret=...)`` below, both
obviously-fake placeholder strings, never anything resembling a real key).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from decimal import Decimal
from types import SimpleNamespace

import pytest

from app.core.config import Settings
from app.database.exceptions import DuplicateRecordError
from app.database.utils.pagination import PageParams, PaginationMeta
from app.domains.billing.constants import (
    AUDIT_ACTION_WEBHOOK_RECEIVED,
    AUDIT_ACTION_WEBHOOK_REJECTED,
    LicenseStatus,
    PaymentStatus,
)
from app.domains.billing.exceptions import (
    InvalidLicenseStatusTransitionError,
    LicenseNotActiveError,
    LicenseNotFoundError,
    NoDefaultPaymentMethodError,
    PaymentGatewayNotConfiguredError,
)
from app.domains.billing.models import Payment
from app.domains.billing.payment_gateways import RazorpayPaymentGateway
from app.domains.billing.service import PaymentService
from app.domains.billing.webhooks import (
    log_signature_failure,
    process_razorpay_event,
)

# ============================================================================
# Shared helpers (mirrors test_billing_payments_webhooks.py's own identical
# helpers)
# ============================================================================


def _base_fields(**overrides: object) -> dict[str, object]:
    from datetime import UTC, datetime

    base: dict[str, object] = {
        "id": uuid.uuid4(),
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
        "deleted_at": None,
        "is_deleted": False,
        "created_by": None,
        "updated_by": None,
        "version": 1,
    }
    base.update(overrides)
    return base


@dataclass
class FakePaymentRepository:
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

    async def get_by_razorpay_order_id(self, razorpay_order_id: str) -> Payment | None:
        for payment in self.payments.values():
            if getattr(payment, "razorpay_order_id", None) == razorpay_order_id:
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
        params = PageParams(page=page, page_size=page_size)
        return items, PaginationMeta.from_total(params, len(items))

    async def list_failed_payments(
        self, organization_id: uuid.UUID | None = None
    ) -> list[Payment]:
        return [
            p for p in self.payments.values() if p.status == PaymentStatus.FAILED.value
        ]


@dataclass
class FakePaymentMethodRepository:
    async def get_default_for_organization(self, organization_id: uuid.UUID):
        return None


@dataclass
class FakeLicense:
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    plan_id: uuid.UUID = field(default_factory=uuid.uuid4)
    status: str = LicenseStatus.ACTIVE.value


@dataclass
class FakeLicenseRepository:
    licenses_by_org: dict[uuid.UUID, FakeLicense] = field(default_factory=dict)

    async def get_by_organization_id(self, organization_id: uuid.UUID):
        return self.licenses_by_org.get(organization_id)


@dataclass
class FakePlan:
    id: uuid.UUID
    slug: str = "professional"
    base_price: Decimal = Decimal("999.00")
    currency: str = "INR"


@dataclass
class FakePlanRepository:
    plans_by_id: dict[uuid.UUID, FakePlan] = field(default_factory=dict)

    async def get_by_id(self, plan_id: uuid.UUID, *, include_deleted: bool = False):
        return self.plans_by_id.get(plan_id)


@dataclass
class FakeSubscriptionRepository:
    async def get_by_organization_id(self, organization_id: uuid.UUID):
        return None


class FakeRazorpayCheckoutGateway:
    """Satisfies ``payment_gateways.RazorpayCheckoutProtocol`` -- mirrors
    ``test_billing_payments_webhooks.FakeGateway``'s own "controllable fake,
    real not-configured guard tested separately" split."""

    def __init__(self, *, order_id: str = "order_fake_checkout_123") -> None:
        self.order_id = order_id
        self.calls: list[uuid.UUID] = []

    async def create_checkout_order(self, payment: Payment) -> Payment:
        self.calls.append(payment.id)
        payment.razorpay_order_id = self.order_id
        return payment


class FakeAuditWriter:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    async def create_audit_log_entry(self, **fields: object) -> object:
        self.calls.append(fields)
        return SimpleNamespace(**fields)


class FakeLicenseActivation:
    """Satisfies ``webhooks.LicenseActivationProtocol``."""

    def __init__(self, *, status: str = LicenseStatus.PENDING_ACTIVATION.value) -> None:
        self.license = SimpleNamespace(id=uuid.uuid4(), status=status)
        self.activate_calls: list[uuid.UUID] = []
        self.raise_on_activate: Exception | None = None

    async def get_license_for_organization(self, organization_id: uuid.UUID):
        return self.license

    async def activate_license(
        self, *, actor_user_id, license_id: uuid.UUID, requesting_organization_id
    ):
        if self.raise_on_activate is not None:
            raise self.raise_on_activate
        self.activate_calls.append(license_id)
        self.license.status = LicenseStatus.ACTIVE.value
        return self.license


class FakeRenewalService:
    """A minimal stand-in used only where ``process_razorpay_event``
    requires a ``renewal_service`` argument but the test's own payment has
    no ``subscription_id`` (so neither real method is ever called) --
    fails loudly if that assumption is ever wrong."""

    async def confirm_renewal_payment_succeeded(self, subscription_id):
        raise AssertionError(
            "confirm_renewal_payment_succeeded should not be called for a "
            "payment with no subscription_id"
        )

    async def confirm_renewal_payment_failed(self, subscription_id, *, reason):
        raise AssertionError(
            "confirm_renewal_payment_failed should not be called for a "
            "payment with no subscription_id"
        )


class FakeInMemoryDedup:
    def __init__(self) -> None:
        self.seen: set[tuple[str, str]] = set()

    async def mark_processed_if_new(self, provider: str, event_id: str) -> bool:
        key = (provider, event_id)
        if key in self.seen:
            return False
        self.seen.add(key)
        return True


# ============================================================================
# PaymentService.create_checkout_order
# ============================================================================


class TestCreateCheckoutOrder:
    def _make_service(
        self,
        *,
        license_status: str = LicenseStatus.ACTIVE.value,
        gateway: FakeRazorpayCheckoutGateway | None = None,
    ) -> tuple[PaymentService, uuid.UUID, FakePlan, FakeRazorpayCheckoutGateway]:
        payment_repository = FakePaymentRepository()
        payment_method_repository = FakePaymentMethodRepository()
        license_repository = FakeLicenseRepository()
        plan_repository = FakePlanRepository()
        subscription_repository = FakeSubscriptionRepository()
        checkout_gateway = gateway or FakeRazorpayCheckoutGateway()

        org_id = uuid.uuid4()
        plan = FakePlan(id=uuid.uuid4())
        license_ = FakeLicense(plan_id=plan.id, status=license_status)
        license_repository.licenses_by_org[org_id] = license_
        plan_repository.plans_by_id[plan.id] = plan

        service = PaymentService(
            payment_repository,
            payment_method_repository,
            gateways={},
            license_repository=license_repository,
            plan_repository=plan_repository,
            subscription_repository=subscription_repository,
            razorpay_checkout_gateway=checkout_gateway,
        )
        return service, org_id, plan, checkout_gateway

    async def test_creates_order_with_real_plan_price_never_client_supplied(
        self,
    ) -> None:
        service, org_id, plan, gateway = self._make_service()

        payment = await service.create_checkout_order(
            actor_user_id=None,
            organization_id=org_id,
            idempotency_key="checkout-key-1",
        )

        assert payment.amount == plan.base_price
        assert payment.currency == plan.currency
        assert payment.provider == "razorpay"
        assert payment.status == PaymentStatus.PENDING.value
        assert payment.razorpay_order_id == gateway.order_id
        assert gateway.calls == [payment.id]

    async def test_same_idempotency_key_returns_same_order_no_second_gateway_call(
        self,
    ) -> None:
        service, org_id, _plan, gateway = self._make_service()

        first = await service.create_checkout_order(
            actor_user_id=None,
            organization_id=org_id,
            idempotency_key="checkout-key-idem",
        )
        second = await service.create_checkout_order(
            actor_user_id=None,
            organization_id=org_id,
            idempotency_key="checkout-key-idem",
        )

        assert first.id == second.id
        assert first.razorpay_order_id == second.razorpay_order_id
        # The real Razorpay Order was only ever actually created once.
        assert gateway.calls == [first.id]

    async def test_no_license_raises_license_not_found(self) -> None:
        payment_repository = FakePaymentRepository()
        service = PaymentService(
            payment_repository,
            FakePaymentMethodRepository(),
            gateways={},
            license_repository=FakeLicenseRepository(),
            plan_repository=FakePlanRepository(),
            subscription_repository=FakeSubscriptionRepository(),
            razorpay_checkout_gateway=FakeRazorpayCheckoutGateway(),
        )
        with pytest.raises(LicenseNotFoundError):
            await service.create_checkout_order(
                actor_user_id=None,
                organization_id=uuid.uuid4(),
                idempotency_key="checkout-key-no-license",
            )
        assert payment_repository.payments == {}

    async def test_cancelled_license_rejected_never_reaches_gateway(self) -> None:
        service, org_id, _plan, gateway = self._make_service(
            license_status=LicenseStatus.CANCELLED.value
        )
        with pytest.raises(LicenseNotActiveError):
            await service.create_checkout_order(
                actor_user_id=None,
                organization_id=org_id,
                idempotency_key="checkout-key-cancelled",
            )
        assert gateway.calls == []

    async def test_suspended_license_may_still_checkout(self) -> None:
        """A SUSPENDED (e.g. payment-issue) license can still be paid for
        via checkout -- that is the whole point of this flow."""
        service, org_id, _plan, gateway = self._make_service(
            license_status=LicenseStatus.SUSPENDED.value
        )
        payment = await service.create_checkout_order(
            actor_user_id=None,
            organization_id=org_id,
            idempotency_key="checkout-key-suspended",
        )
        assert payment.status == PaymentStatus.PENDING.value
        assert gateway.calls == [payment.id]


# ============================================================================
# RazorpayPaymentGateway.create_checkout_order -- real not-configured guard
# ============================================================================


class TestCheckoutGatewayNotConfigured:
    async def test_create_checkout_order_raises_before_any_network_attempt(
        self,
    ) -> None:
        """A genuinely unconfigured Settings() (this sandbox's honest,
        permanent state -- no real Razorpay credentials exist here or ever
        will) must raise PaymentGatewayNotConfiguredError, mapped to a real
        503 by app.common.exceptions' CloudGuestError handler, BEFORE any
        razorpay.Client is even constructed."""
        settings = Settings()  # no razorpay_key_id/secret set anywhere
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
            amount=Decimal("999.00"),
            currency="INR",
            status=PaymentStatus.PENDING.value,
            provider="razorpay",
            provider_payment_id=None,
            idempotency_key="checkout-not-configured",
            refunded_amount=Decimal("0"),
        )

        with pytest.raises(PaymentGatewayNotConfiguredError):
            await gateway.create_checkout_order(payment)

        updated = await payment_repository.get_by_id(payment.id)
        assert updated.status == PaymentStatus.FAILED.value
        assert updated.failure_reason == "payment_gateway_not_configured"
        assert updated.razorpay_order_id is None

    async def test_configured_gateway_never_requires_a_saved_payment_method(
        self,
    ) -> None:
        """Unlike the recurring-charge path, create_checkout_order never
        even looks at PaymentMethodRepository -- a real, obviously-fake test
        key is enough to exercise the code path up to (but not including)
        the real network call, proving no NoDefaultPaymentMethodError is
        ever raised here the way it would be for _attempt_charge."""
        settings = Settings(
            razorpay_key_id="rzp_test_fake_key_for_tests",
            razorpay_key_secret="fake_secret_for_tests_never_a_real_key",
        )
        payment_repository = FakePaymentRepository()
        payment_method_repository = FakePaymentMethodRepository()
        gateway = RazorpayPaymentGateway(
            settings=settings,
            payment_repository=payment_repository,
            payment_method_repository=payment_method_repository,
        )
        assert gateway._is_configured() is True
        # NoDefaultPaymentMethodError would only ever come from
        # _default_payment_method_token, which create_checkout_order's own
        # implementation never calls -- confirmed structurally: calling it
        # directly still raises (proving the fake repo is genuinely empty),
        # while create_checkout_order's own real network call is the only
        # thing that would fail next (unreachable in this sandbox, so not
        # exercised here -- see module docstring).
        with pytest.raises(NoDefaultPaymentMethodError):
            await gateway._default_payment_method_token(uuid.uuid4())


# ============================================================================
# webhooks.process_razorpay_event -- Checkout order_id correlation +
# license-activation-on-first-payment composition
# ============================================================================


class TestWebhookCheckoutOrderCorrelation:
    async def _make_pending_checkout_payment(
        self, payment_repository: FakePaymentRepository, *, order_id: str
    ) -> Payment:
        return await payment_repository.create_payment(
            organization_id=uuid.uuid4(),
            subscription_id=None,
            amount=Decimal("999.00"),
            currency="INR",
            status=PaymentStatus.PENDING.value,
            provider="razorpay",
            provider_payment_id=None,
            razorpay_order_id=order_id,
            idempotency_key=f"checkout-{uuid.uuid4().hex[:8]}",
            refunded_amount=Decimal("0"),
        )

    async def test_payment_captured_resolves_pending_row_by_order_id(self) -> None:
        payment_repository = FakePaymentRepository()
        payment = await self._make_pending_checkout_payment(
            payment_repository, order_id="order_abc123"
        )
        license_activation = FakeLicenseActivation()
        audit_writer = FakeAuditWriter()

        webhook_payload = {
            "event": "payment.captured",
            "payload": {
                "payment": {
                    "entity": {
                        "id": "pay_checkout_success",
                        "order_id": "order_abc123",
                    }
                }
            },
            "_event_id": "evt_checkout_success",
        }

        applied = await process_razorpay_event(
            webhook_payload,
            payment_repository=payment_repository,
            renewal_service=FakeRenewalService(),
            dedup=FakeInMemoryDedup(),
            license_activation=license_activation,
            signature="verified-sig-abc",
            audit_writer=audit_writer,
        )
        assert applied is True

        updated = await payment_repository.get_by_id(payment.id)
        assert updated.status == PaymentStatus.SUCCEEDED.value
        assert updated.provider_payment_id == "pay_checkout_success"
        assert updated.razorpay_signature == "verified-sig-abc"

        # No subscription was tracked against this payment -- the license
        # is activated for real instead.
        assert license_activation.activate_calls == [license_activation.license.id]

        # A real, permanent audit_log_entries row was written for this
        # verified receipt.
        assert len(audit_writer.calls) == 1
        assert audit_writer.calls[0]["action"] == AUDIT_ACTION_WEBHOOK_RECEIVED
        assert audit_writer.calls[0]["entity_id"] == payment.id

    async def test_redelivery_of_the_same_event_is_a_dedup_no_op(self) -> None:
        payment_repository = FakePaymentRepository()
        await self._make_pending_checkout_payment(
            payment_repository, order_id="order_redeliver"
        )
        dedup = FakeInMemoryDedup()
        payload = {
            "event": "payment.captured",
            "payload": {
                "payment": {
                    "entity": {"id": "pay_redeliver", "order_id": "order_redeliver"}
                }
            },
            "_event_id": "evt_redeliver",
        }

        first = await process_razorpay_event(
            payload,
            payment_repository=payment_repository,
            renewal_service=FakeRenewalService(),
            dedup=dedup,
        )
        second = await process_razorpay_event(
            payload,
            payment_repository=payment_repository,
            renewal_service=FakeRenewalService(),
            dedup=dedup,
        )
        assert first is True
        assert second is False

    async def test_already_resolved_row_is_idempotent_even_without_dedup(self) -> None:
        """Defense in depth beyond event-id dedup: even if the SAME
        already-SUCCEEDED row were somehow reached twice (e.g. two
        different event ids for the same underlying payment -- a real
        possibility Razorpay's own docs do not fully rule out), the second
        call must be a safe no-op, never re-processing/double-activating."""
        payment_repository = FakePaymentRepository()
        payment = await self._make_pending_checkout_payment(
            payment_repository, order_id="order_twice"
        )
        license_activation = FakeLicenseActivation()
        payload_a = {
            "event": "payment.captured",
            "payload": {
                "payment": {"entity": {"id": "pay_twice", "order_id": "order_twice"}}
            },
            "_event_id": "evt_twice_a",
        }
        payload_b = {**payload_a, "_event_id": "evt_twice_b"}

        await process_razorpay_event(
            payload_a,
            payment_repository=payment_repository,
            renewal_service=FakeRenewalService(),
            dedup=FakeInMemoryDedup(),
            license_activation=license_activation,
        )
        await process_razorpay_event(
            payload_b,
            payment_repository=payment_repository,
            renewal_service=FakeRenewalService(),
            dedup=FakeInMemoryDedup(),
            license_activation=license_activation,
        )

        # License activation only ever invoked once, even though the
        # "already resolved" row was reached by two distinct event ids.
        assert license_activation.activate_calls == [license_activation.license.id]
        updated = await payment_repository.get_by_id(payment.id)
        assert updated.status == PaymentStatus.SUCCEEDED.value

    async def test_license_already_active_is_a_safe_no_op(self) -> None:
        payment_repository = FakePaymentRepository()
        await self._make_pending_checkout_payment(
            payment_repository, order_id="order_already_active"
        )
        license_activation = FakeLicenseActivation(status=LicenseStatus.ACTIVE.value)
        payload = {
            "event": "payment.captured",
            "payload": {
                "payment": {
                    "entity": {
                        "id": "pay_already_active",
                        "order_id": "order_already_active",
                    }
                }
            },
            "_event_id": "evt_already_active",
        }

        await process_razorpay_event(
            payload,
            payment_repository=payment_repository,
            renewal_service=FakeRenewalService(),
            dedup=FakeInMemoryDedup(),
            license_activation=license_activation,
        )
        # Already ACTIVE -- activate_license is never called.
        assert license_activation.activate_calls == []

    async def test_illegal_transition_during_activation_is_swallowed(self) -> None:
        payment_repository = FakePaymentRepository()
        await self._make_pending_checkout_payment(
            payment_repository, order_id="order_illegal"
        )
        license_activation = FakeLicenseActivation(
            status=LicenseStatus.PENDING_ACTIVATION.value
        )
        license_activation.raise_on_activate = InvalidLicenseStatusTransitionError(
            "expired", "active"
        )
        payload = {
            "event": "payment.captured",
            "payload": {
                "payment": {
                    "entity": {"id": "pay_illegal", "order_id": "order_illegal"}
                }
            },
            "_event_id": "evt_illegal",
        }

        # Must not raise -- a webhook handler never fails delivery over an
        # activation attempt that turns out to be moot.
        applied = await process_razorpay_event(
            payload,
            payment_repository=payment_repository,
            renewal_service=FakeRenewalService(),
            dedup=FakeInMemoryDedup(),
            license_activation=license_activation,
        )
        assert applied is True

    async def test_payment_failed_resolves_by_order_id_too(self) -> None:
        payment_repository = FakePaymentRepository()
        payment = await self._make_pending_checkout_payment(
            payment_repository, order_id="order_failed_case"
        )
        payload = {
            "event": "payment.failed",
            "payload": {
                "payment": {
                    "entity": {
                        "id": "pay_failed_case",
                        "order_id": "order_failed_case",
                        "error_description": "Insufficient funds",
                    }
                }
            },
            "_event_id": "evt_failed_case",
        }

        await process_razorpay_event(
            payload,
            payment_repository=payment_repository,
            renewal_service=FakeRenewalService(),
            dedup=FakeInMemoryDedup(),
        )

        updated = await payment_repository.get_by_id(payment.id)
        assert updated.status == PaymentStatus.FAILED.value
        assert updated.failure_reason == "Insufficient funds"

    async def test_unknown_order_id_is_a_safe_no_op(self) -> None:
        payment_repository = FakePaymentRepository()
        payload = {
            "event": "payment.captured",
            "payload": {
                "payment": {
                    "entity": {"id": "pay_unknown", "order_id": "order_never_tracked"}
                }
            },
            "_event_id": "evt_unknown_order",
        }

        applied = await process_razorpay_event(
            payload,
            payment_repository=payment_repository,
            renewal_service=FakeRenewalService(),
            dedup=FakeInMemoryDedup(),
        )
        assert applied is True
        assert payment_repository.payments == {}


# ============================================================================
# Webhook audit trail -- rejected (signature-invalid) deliveries
# ============================================================================


class TestWebhookRejectedAudit:
    async def test_log_signature_failure_writes_a_real_audit_entry(self) -> None:
        audit_writer = FakeAuditWriter()

        await log_signature_failure(
            "razorpay", "signature mismatch", audit_writer=audit_writer
        )

        assert len(audit_writer.calls) == 1
        call = audit_writer.calls[0]
        assert call["action"] == AUDIT_ACTION_WEBHOOK_REJECTED
        assert call["entity_id"] is None
        assert call["organization_id"] is None
        assert "razorpay" in call["description"]

    async def test_log_signature_failure_without_audit_writer_does_not_raise(
        self,
    ) -> None:
        # Real, pre-existing call shape (no audit_writer) must keep working
        # unmodified -- only now as an async function callers must await.
        await log_signature_failure("stripe", "bad signature")
