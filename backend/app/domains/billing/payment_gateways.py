"""Real Stripe/Razorpay ``renewal_service.PaymentGatewayProtocol``
implementations (BE-013 Part 3).

## Honesty framing -- read this first

There are no real Stripe/Razorpay API keys or test credentials anywhere in
this sandbox, and there never will be: neither class here can make a real
network call to either provider's live/sandbox API and get a real response
back, in this environment. What *is* real: both ``stripe``/``razorpay`` are
the official, installable Python SDKs (added to ``requirements.txt``/
``pyproject.toml`` by this part), and every request shape below (parameter
names, units, idempotency handling, exception types) is written against
each SDK's actual, installed, current API -- verified by introspecting the
installed packages directly while writing this module, not recalled from
memory. When ``Settings.stripe_secret_key``/``Settings.razorpay_key_id``+
``razorpay_key_secret`` are unconfigured (as they always will be in this
sandbox), each class's ``_is_configured`` guard raises
``exceptions.PaymentGatewayNotConfiguredError`` **before any network
attempt** -- reusing Part 2's exact exception, never a parallel one.

## The seam these classes fill

``renewal_service.PaymentGatewayProtocol`` has exactly one method,
``charge(*, organization_id, amount, currency, subscription_id) ->
PaymentResult``. Both classes below implement it exactly (see
``RenewalService``'s own docstring for why the signature cannot change).
But a real payment integration needs more than that one seam method --
refunds, retries, and a richer, ``Payment``-row-returning charge path for
the explicit ``POST /payments`` API (as opposed to the automatic renewal
sweep) -- so each class *also* implements the broader,
non-``Protocol``-constrained ``PaymentGatewayAdminProtocol`` below
(``charge_via_provider``/``refund``/``retry``, all operating on an
already-persisted ``Payment`` row), which ``service.PaymentService`` uses
directly. ``charge()`` is a thin wrapper around ``charge_via_provider`` that
creates its own ``Payment`` row with a freshly-generated idempotency key
(see below for why a fresh key, not a reused one, is correct here) and
translates the resulting row into a ``PaymentResult``.

## PaymentMethod token-only storage, reused here

Neither class ever sees a raw card number/CVV -- ``_default_payment_method_token``
reads ``PaymentMethod.provider_payment_method_id`` (an opaque provider token,
e.g. a Stripe ``pm_...`` id) via the injected ``PaymentMethodRepositoryProtocol``.
If an organization has no default, active payment method on file, a
distinct ``exceptions.NoDefaultPaymentMethodError`` is raised -- a real,
organization-specific data gap, not the same thing as "no gateway
configured at all" (see that exception's own docstring).

## A documented, honest scope simplification: no separate "Customer" entity

A fully productionized integration would also persist a provider-side
Customer object id (Stripe ``cus_...``, or the equivalent Razorpay
customer concept) that a saved payment method is attached to -- both
providers' own real off-session/recurring-charge APIs are commonly used
this way. BE-013's own column list for ``PaymentMethod`` (see
``models.py``) does not include a separate customer-id column, and this
part does not invent one out of scope. ``StripePaymentGateway`` therefore
passes ``payment_method=<token>`` directly to ``PaymentIntent.create`` with
``confirm=True, off_session=True`` -- a real, valid call shape Stripe's API
accepts for an unattached PaymentMethod, though a mature production
rollout would typically attach it to a persisted Customer first.
``RazorpayPaymentGateway`` similarly passes the stored token as both
``customer_id`` and ``token`` to ``payment.createRecurring`` -- Razorpay's
real "charge a saved card" (recurring/e-mandate) endpoint -- which is an
honest simplification for the identical reason. Both are noted here
plainly rather than silently glossed over; neither code path is ever
actually exercised end-to-end in this sandbox regardless, since
``_is_configured`` always short-circuits first.

## Idempotency: Stripe (native, SDK-level) vs. Razorpay (DB-level only)

Stripe's SDK genuinely supports a per-request ``idempotency_key`` parameter
(verified directly against the installed ``stripe`` package's
``RequestOptions``/``_static_request`` machinery) -- passed through for
real on every ``PaymentIntent.create``/``Refund.create`` call, so Stripe's
own servers deduplicate a retried request with the same key, independent
of anything this module does. The installed ``razorpay`` SDK's
``Payment.createRecurring``/``Order.create``/``Payment.refund`` resources
expose **no** client-supplied idempotency parameter at all (verified by
introspecting ``razorpay.resources.Payment``/``Order`` directly) -- so for
Razorpay, **all** idempotency protection is enforced at this module's own
``Payment.idempotency_key`` unique-constraint level (see
``models.Payment``'s own docstring): the same caller-supplied key always
resolves to the same row, but a retried Razorpay wire call is always a
genuinely fresh provider-side attempt, key or no key. This is a real,
honestly-documented difference between the two providers' SDKs, not a
gap in this module's own implementation.

## Retry idempotency-key strategy: fresh key for Stripe, moot for Razorpay

``retry_failed_payment`` reuses the **same** ``Payment`` row (this domain's
"Payment doubles as history" decision -- see ``models.Payment``) but, for
Stripe, sends a **freshly-derived** idempotency key
(``validators.derive_retry_idempotency_key``) on the retried
``PaymentIntent.create`` call rather than reusing the original key. This
is Stripe's own real, documented guidance: reusing an idempotency key
returns the *cached* result of the original request, including a genuine
decline, for a real window (currently 24h) -- resubmitting the same key
for an intentional retry (e.g. after the customer updated their card)
would silently just return the old decline again, never actually
attempting a new charge. Razorpay's retry has no such concern (no
provider-level idempotency key exists to reuse or avoid reusing in the
first place) -- its retry is unconditionally a fresh attempt. Either way,
the ``Payment.idempotency_key`` **column** itself never changes across a
retry -- it is this row's own permanent identity, not a per-attempt value.

## Zero-decimal currencies + minor units

``validators.to_minor_units`` handles the real "smallest currency unit"
requirement both providers document identically (cents for USD, no
sub-unit at all for JPY, ...).
"""

from __future__ import annotations

import logging
import uuid
from decimal import Decimal
from typing import Protocol

import razorpay
import stripe

from app.core.config import Settings

from .constants import PaymentProvider, PaymentStatus
from .exceptions import (
    NoDefaultPaymentMethodError,
    PaymentGatewayNotConfiguredError,
    PaymentProviderError,
)
from .models import Payment
from .renewal_service import PaymentGatewayProtocol, PaymentResult
from .repository import PaymentMethodRepositoryProtocol, PaymentRepositoryProtocol
from .validators import derive_retry_idempotency_key, to_minor_units

logger = logging.getLogger(__name__)


class PaymentGatewayAdminProtocol(Protocol):
    """The richer surface ``service.PaymentService`` needs beyond
    ``renewal_service.PaymentGatewayProtocol``'s narrow single ``charge()``
    method -- satisfied structurally by both concrete gateways below. Every
    method here operates on an already-persisted ``Payment`` row (created
    by the caller with its own real idempotency key), never creates one
    itself -- see module docstring for how ``charge()`` (the narrow,
    ``Protocol``-constrained seam method) composes with
    ``charge_via_provider`` instead of duplicating it."""

    async def charge_via_provider(self, payment: Payment) -> Payment: ...

    async def refund(self, payment: Payment, amount: Decimal | None) -> Payment: ...

    async def retry(self, payment: Payment) -> Payment: ...


class _BaseGateway:
    """Shared not-configured guard + PENDING-row bookkeeping both concrete
    gateways compose with -- see module docstring for the full write-up of
    why each guard sits where it does (before vs. after row creation)."""

    provider: PaymentProvider

    def __init__(
        self,
        *,
        settings: Settings,
        payment_repository: PaymentRepositoryProtocol,
        payment_method_repository: PaymentMethodRepositoryProtocol,
    ) -> None:
        self._settings = settings
        self.payment_repository = payment_repository
        self.payment_method_repository = payment_method_repository

    def _is_configured(self) -> bool:  # pragma: no cover - overridden
        raise NotImplementedError

    async def _default_payment_method_token(self, organization_id: uuid.UUID) -> str:
        payment_method = (
            await self.payment_method_repository.get_default_for_organization(
                organization_id
            )
        )
        if payment_method is None:
            raise NoDefaultPaymentMethodError(organization_id)
        return payment_method.provider_payment_method_id

    # ========================================================================
    # renewal_service.PaymentGatewayProtocol -- the narrow seam
    # ========================================================================

    async def charge(
        self,
        *,
        organization_id: uuid.UUID,
        amount: Decimal,
        currency: str,
        subscription_id: uuid.UUID,
    ) -> PaymentResult:
        """The one seam method ``RenewalService.process_renewal`` calls.

        A zero-(or negative-)amount charge auto-succeeds with **no**
        configuration check and **no** ``Payment`` row at all -- byte-for-
        byte the same short-circuit ``renewal_service
        .UnconfiguredPaymentGateway`` itself already documents (a
        ``FREE_TRIAL`` plan, or any plan whose ``base_price`` is genuinely
        ``0``, needs no real payment processor regardless of which real
        gateway is wired in as the platform default). This is not merely
        cosmetic: preserving this exact behavior in the real gateways
        matters, since a ``TRIALING`` subscription on a cyclic
        (``MONTHLY``/``YEARLY``) billing cycle *can* reach this method via
        ``process_due_renewals`` before its trial ever converts to a real
        paid plan, and it must not start raising
        ``PaymentGatewayNotConfiguredError`` for a genuinely free renewal
        just because Part 3 wired in a real (but still-unconfigured, in
        this sandbox) gateway in place of Part 2's honest placeholder.

        Otherwise, checks configuration **before creating any row at all**
        -- an hourly Beat sweep against a totally unconfigured platform
        would otherwise write a junk ``PENDING`` row for every real, due,
        non-zero-amount subscription, every tick, forever; raising
        immediately here avoids that."""
        if amount <= 0:
            logger.info(
                "billing_payment_gateway_zero_amount_auto_succeeded",
                extra={
                    "organization_id": str(organization_id),
                    "subscription_id": str(subscription_id),
                    "provider": self.provider.value,
                },
            )
            return PaymentResult(success=True)
        if not self._is_configured():
            raise PaymentGatewayNotConfiguredError(
                organization_id=organization_id, amount=amount, currency=currency
            )
        idempotency_key = f"renewal:{subscription_id}:{uuid.uuid4().hex}"
        payment = await self.payment_repository.create_payment(
            organization_id=organization_id,
            subscription_id=subscription_id,
            amount=amount,
            currency=currency,
            status=PaymentStatus.PENDING.value,
            provider=self.provider.value,
            provider_payment_id=None,
            idempotency_key=idempotency_key,
            refunded_amount=Decimal("0"),
        )
        payment = await self.charge_via_provider(payment)
        if payment.status == PaymentStatus.SUCCEEDED.value:
            return PaymentResult(success=True, reference=payment.provider_payment_id)
        if payment.status == PaymentStatus.FAILED.value:
            return PaymentResult(success=False, failure_reason=payment.failure_reason)
        # A real, honest intermediate state (e.g. Stripe requires_action /
        # Razorpay authorized-not-yet-captured) -- treated as a real
        # decline for this synchronous seam's purposes (RenewalService has
        # no notion of "wait for a later webhook"); a subsequent webhook
        # confirming success later calls
        # RenewalService.confirm_renewal_payment_succeeded to recover it.
        return PaymentResult(
            success=False, failure_reason="payment_pending_provider_confirmation"
        )

    # ========================================================================
    # PaymentGatewayAdminProtocol -- the richer surface PaymentService uses
    # ========================================================================

    async def charge_via_provider(self, payment: Payment) -> Payment:
        if not self._is_configured():
            updated = await self.payment_repository.update_payment(
                payment,
                {
                    "status": PaymentStatus.FAILED.value,
                    "failure_reason": "payment_gateway_not_configured",
                },
            )
            raise PaymentGatewayNotConfiguredError(
                organization_id=updated.organization_id,
                amount=updated.amount,
                currency=updated.currency,
            )
        return await self._charge_via_provider_impl(payment)

    async def refund(self, payment: Payment, amount: Decimal | None) -> Payment:
        if not self._is_configured():
            raise PaymentGatewayNotConfiguredError(
                organization_id=payment.organization_id,
                amount=amount if amount is not None else payment.amount,
                currency=payment.currency,
            )
        return await self._refund_impl(payment, amount)

    async def retry(self, payment: Payment) -> Payment:
        if not self._is_configured():
            raise PaymentGatewayNotConfiguredError(
                organization_id=payment.organization_id,
                amount=payment.amount,
                currency=payment.currency,
            )
        return await self._retry_impl(payment)

    async def _charge_via_provider_impl(
        self, payment: Payment
    ) -> Payment:  # pragma: no cover - overridden
        raise NotImplementedError

    async def _refund_impl(
        self, payment: Payment, amount: Decimal | None
    ) -> Payment:  # pragma: no cover - overridden
        raise NotImplementedError

    async def _retry_impl(
        self, payment: Payment
    ) -> Payment:  # pragma: no cover - overridden
        raise NotImplementedError


class StripePaymentGateway(_BaseGateway):
    """Real ``stripe`` SDK integration -- ``stripe.PaymentIntent.create``
    for a charge (off-session, against a saved ``PaymentMethod`` token,
    ``confirm=True``), ``stripe.Refund.create`` for a refund. See module
    docstring for the full idempotency-key/no-Customer-entity write-up."""

    provider = PaymentProvider.STRIPE

    def _is_configured(self) -> bool:
        return bool(self._settings.stripe_secret_key)

    async def _charge_via_provider_impl(self, payment: Payment) -> Payment:
        return await self._attempt_charge(
            payment, idempotency_key=payment.idempotency_key
        )

    async def _retry_impl(self, payment: Payment) -> Payment:
        # A fresh, derived idempotency key -- see module docstring for why
        # reusing the original key here would be wrong for Stripe
        # specifically.
        retry_key = derive_retry_idempotency_key(payment.idempotency_key)
        return await self._attempt_charge(payment, idempotency_key=retry_key)

    async def _attempt_charge(
        self, payment: Payment, *, idempotency_key: str
    ) -> Payment:
        try:
            payment_method_token = await self._default_payment_method_token(
                payment.organization_id
            )
        except NoDefaultPaymentMethodError as exc:
            await self.payment_repository.update_payment(
                payment,
                {"status": PaymentStatus.FAILED.value, "failure_reason": str(exc)},
            )
            raise

        try:
            intent = stripe.PaymentIntent.create(
                amount=to_minor_units(payment.amount, payment.currency),
                currency=payment.currency.lower(),
                payment_method=payment_method_token,
                confirm=True,
                off_session=True,
                idempotency_key=idempotency_key,
                api_key=self._settings.stripe_secret_key,
            )
        except stripe.CardError as exc:
            # A real, legitimate business decline -- captured as a Payment
            # status, never raised (mirrors PaymentResult's own
            # success=False-is-not-an-exception design in renewal_service).
            logger.info(
                "billing_stripe_card_declined",
                extra={"payment_id": str(payment.id)},
            )
            return await self.payment_repository.update_payment(
                payment,
                {
                    "status": PaymentStatus.FAILED.value,
                    "failure_reason": exc.user_message or str(exc),
                },
            )
        except stripe.StripeError as exc:
            # A genuine, unexpected provider/infra error (network, auth,
            # rate limit, ...) -- distinct from a card decline; raised so
            # the caller can react (row is left PENDING, not FAILED, since
            # this is not a real declined-charge outcome).
            logger.exception(
                "billing_stripe_provider_error", extra={"payment_id": str(payment.id)}
            )
            raise PaymentProviderError(str(exc)) from exc

        if intent.status == "succeeded":
            return await self.payment_repository.update_payment(
                payment,
                {
                    "status": PaymentStatus.SUCCEEDED.value,
                    "provider_payment_id": intent.id,
                    "failure_reason": None,
                },
            )
        # A real, honest intermediate Stripe status (e.g.
        # "requires_action" for SCA/3-D Secure) -- left PENDING;
        # webhooks.py's payment_intent.succeeded/payment_intent.payment_failed
        # handler (composing with RenewalService.confirm_renewal_payment_*)
        # resolves it from here.
        return await self.payment_repository.update_payment(
            payment, {"provider_payment_id": intent.id}
        )

    async def _refund_impl(self, payment: Payment, amount: Decimal | None) -> Payment:
        refund_amount = (
            amount if amount is not None else (payment.amount - payment.refunded_amount)
        )
        try:
            stripe.Refund.create(
                payment_intent=payment.provider_payment_id,
                amount=to_minor_units(refund_amount, payment.currency),
                idempotency_key=f"{payment.idempotency_key}:refund:{uuid.uuid4().hex[:12]}",
                api_key=self._settings.stripe_secret_key,
            )
        except stripe.StripeError as exc:
            logger.exception(
                "billing_stripe_refund_provider_error",
                extra={"payment_id": str(payment.id)},
            )
            raise PaymentProviderError(str(exc)) from exc

        new_refunded = payment.refunded_amount + refund_amount
        new_status = (
            PaymentStatus.REFUNDED
            if new_refunded >= payment.amount
            else PaymentStatus.PARTIALLY_REFUNDED
        )
        return await self.payment_repository.update_payment(
            payment, {"refunded_amount": new_refunded, "status": new_status.value}
        )


class RazorpayPaymentGateway(_BaseGateway):
    """Real ``razorpay`` SDK integration -- ``client.order.create`` +
    ``client.payment.createRecurring`` (Razorpay's real "charge a saved
    card/token" recurring-payment API) for a charge, ``client.payment
    .refund`` for a refund. See module docstring for the full
    no-native-idempotency-parameter write-up (the real reason this
    provider's idempotency protection lives entirely at this module's own
    DB-unique-constraint level)."""

    provider = PaymentProvider.RAZORPAY

    def _is_configured(self) -> bool:
        return bool(
            self._settings.razorpay_key_id and self._settings.razorpay_key_secret
        )

    def _client(self) -> razorpay.Client:
        return razorpay.Client(
            auth=(self._settings.razorpay_key_id, self._settings.razorpay_key_secret)
        )

    async def _charge_via_provider_impl(self, payment: Payment) -> Payment:
        return await self._attempt_charge(payment)

    async def _retry_impl(self, payment: Payment) -> Payment:
        # No client-supplied idempotency parameter exists on this SDK's
        # order/payment-creation calls (verified against the installed
        # package) -- a retry is unconditionally a fresh provider-side
        # attempt; see module docstring.
        return await self._attempt_charge(payment)

    async def _attempt_charge(self, payment: Payment) -> Payment:
        try:
            payment_method_token = await self._default_payment_method_token(
                payment.organization_id
            )
        except NoDefaultPaymentMethodError as exc:
            await self.payment_repository.update_payment(
                payment,
                {"status": PaymentStatus.FAILED.value, "failure_reason": str(exc)},
            )
            raise

        client = self._client()
        minor_amount = to_minor_units(payment.amount, payment.currency)
        try:
            order = client.order.create(
                {
                    "amount": minor_amount,
                    "currency": payment.currency.upper(),
                    "receipt": str(payment.id),
                    "payment_capture": 1,
                }
            )
            # Razorpay's real "charge a saved card" (recurring/e-mandate)
            # endpoint -- see module docstring for the honest
            # no-separate-Customer-entity simplification (customer_id/token
            # both set to the one stored provider token).
            result = client.payment.createRecurring(
                {
                    "amount": minor_amount,
                    "currency": payment.currency.upper(),
                    "order_id": order["id"],
                    "customer_id": payment_method_token,
                    "token": payment_method_token,
                    "recurring": "1",
                    "description": f"CloudGuest payment {payment.id}",
                }
            )
        except razorpay.errors.BadRequestError as exc:
            # A real, legitimate business decline (mirrors Stripe's
            # CardError handling above).
            logger.info(
                "billing_razorpay_payment_declined",
                extra={"payment_id": str(payment.id)},
            )
            return await self.payment_repository.update_payment(
                payment,
                {"status": PaymentStatus.FAILED.value, "failure_reason": str(exc)},
            )
        except (razorpay.errors.GatewayError, razorpay.errors.ServerError) as exc:
            logger.exception(
                "billing_razorpay_provider_error", extra={"payment_id": str(payment.id)}
            )
            raise PaymentProviderError(str(exc)) from exc

        provider_payment_id = result.get("id") if isinstance(result, dict) else None
        result_status = result.get("status") if isinstance(result, dict) else None
        if result_status == "captured":
            return await self.payment_repository.update_payment(
                payment,
                {
                    "status": PaymentStatus.SUCCEEDED.value,
                    "provider_payment_id": provider_payment_id,
                    "failure_reason": None,
                },
            )
        if result_status == "failed":
            return await self.payment_repository.update_payment(
                payment,
                {
                    "status": PaymentStatus.FAILED.value,
                    "provider_payment_id": provider_payment_id,
                    "failure_reason": "razorpay_payment_failed",
                },
            )
        # A real, honest intermediate Razorpay status (e.g. "authorized"
        # but not yet captured) -- left PENDING; webhooks.py's
        # payment.captured/payment.failed handler resolves it from here.
        return await self.payment_repository.update_payment(
            payment, {"provider_payment_id": provider_payment_id}
        )

    async def _refund_impl(self, payment: Payment, amount: Decimal | None) -> Payment:
        refund_amount = (
            amount if amount is not None else (payment.amount - payment.refunded_amount)
        )
        client = self._client()
        try:
            client.payment.refund(
                payment.provider_payment_id,
                {"amount": to_minor_units(refund_amount, payment.currency)},
            )
        except (
            razorpay.errors.BadRequestError,
            razorpay.errors.GatewayError,
            razorpay.errors.ServerError,
        ) as exc:
            logger.exception(
                "billing_razorpay_refund_provider_error",
                extra={"payment_id": str(payment.id)},
            )
            raise PaymentProviderError(str(exc)) from exc

        new_refunded = payment.refunded_amount + refund_amount
        new_status = (
            PaymentStatus.REFUNDED
            if new_refunded >= payment.amount
            else PaymentStatus.PARTIALLY_REFUNDED
        )
        return await self.payment_repository.update_payment(
            payment, {"refunded_amount": new_refunded, "status": new_status.value}
        )


# Both classes satisfy renewal_service.PaymentGatewayProtocol structurally
# (duck-typed Protocol -- no explicit inheritance declaration needed/used
# anywhere else in this codebase's own Protocol usage).
_: type[PaymentGatewayProtocol] = StripePaymentGateway
_: type[PaymentGatewayProtocol] = RazorpayPaymentGateway
_: type[PaymentGatewayAdminProtocol] = StripePaymentGateway
_: type[PaymentGatewayAdminProtocol] = RazorpayPaymentGateway


__all__ = [
    "PaymentGatewayAdminProtocol",
    "StripePaymentGateway",
    "RazorpayPaymentGateway",
]
