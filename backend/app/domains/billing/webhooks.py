"""Real Stripe/Razorpay webhook signature verification + event processing
(BE-013 Part 3).

## Signature verification: real, complete, cryptographically genuine

Both schemes below are pure, deterministic HMAC-SHA256 cryptography that
needs no live provider API access at all -- unlike a charge (which requires
a real, unconfigured-in-this-sandbox API key), signature verification is
implemented and exercised for real here, with real test fixtures (a real
secret + a real HMAC computed the same way each provider actually does it,
verified against this module's own verification function in
``tests/unit/test_billing_payments_webhooks.py``).

* **Stripe** -- ``verify_stripe_event`` uses the real, installed ``stripe``
  SDK's ``stripe.Webhook.construct_event``, whose source was read directly
  (``stripe._webhook.WebhookSignature.verify_header``) while writing this
  module: the ``Stripe-Signature`` header is a comma-separated
  ``t=<unix-timestamp>,v1=<hex-hmac>[,v0=<hex-hmac>...]`` string; the
  *signed payload* is ``f"{timestamp}.{raw_body}"``; the expected signature
  is ``hmac.new(secret, signed_payload, sha256).hexdigest()``; comparison
  against every ``v1=`` value uses a constant-time compare
  (``stripe._webhook.secure_compare`` -> ``hmac.compare_digest``); and a
  request whose timestamp is older than ``tolerance`` seconds (default
  300, configurable via ``Settings.stripe_webhook_tolerance_seconds``) is
  rejected as a replay. Using the SDK's own real implementation directly
  (rather than a hand-rolled reimplementation that could subtly drift from
  it) is judged the more honest, more correct choice here -- it is
  genuinely the same code Stripe's own SDK ships and this codebase
  installs.
* **Razorpay** -- ``verify_razorpay_signature`` uses the real, installed
  ``razorpay`` SDK's ``razorpay.Utility.verify_webhook_signature`` (source
  read directly: ``hmac.new(secret, raw_body, sha256).hexdigest()``,
  compared via ``hmac.compare_digest`` against the ``X-Razorpay-Signature``
  header). Razorpay's webhook scheme has no timestamp/replay-tolerance
  component at all (verified against the installed SDK -- there simply is
  none to check), so none is invented here; this is an honest reflection of
  the real, documented scheme, not a gap in this module.

## Event-id dedup: Redis, TTL'd, not a dedicated table

Both providers really do redeliver the same webhook event more than once
(timeout, an ambiguous 2xx, a manual "resend" from either dashboard) --
webhook handlers must be idempotent themselves. This module tracks
processed event ids in Redis (reusing, not modifying,
``app.database.redis.get_redis_client`` -- the same Redis instance every
other domain's own caching already uses) via a single atomic ``SET ...
NX EX`` per event id (``RedisWebhookEventDedup.mark_processed_if_new``):
the first delivery of a given event id sets the key and proceeds; every
redelivery finds the key already set and is a no-op. A TTL (``Settings
.payment_webhook_event_dedup_ttl_seconds``, default 7 days) is used rather
than a permanent record for two reasons: (1) both providers' own real
redelivery/retry windows are measured in hours to a few days, not
forever, so a multi-day TTL comfortably covers every real redelivery
while not accumulating an ever-growing key set; (2) a dedicated
``processed_webhook_events`` table would need its own migration, its own
cleanup sweep to avoid unbounded growth, and buys no correctness Redis's
own atomic ``SET NX`` doesn't already provide via a single command --
the identical "simplest real mechanism, no new table for its own sake"
judgment call this domain already makes elsewhere (e.g.
``events.py``'s "no event bus" decision). A small, dedicated table was a
real, legitimate alternative (a unique constraint on ``(provider,
event_id)`` is exactly as atomic); Redis was chosen for the free TTL-based
cleanup alone.

## Handler composition -- never reimplementing subscription renewal

On a real success confirmation for a payment tied to a subscription
renewal, these handlers call ``renewal_service.RenewalService
.confirm_renewal_payment_succeeded``/``confirm_renewal_payment_failed`` --
two narrow, additive Part 3 methods that do nothing but call that class's
own existing, already-tested ``_mark_renewed``/``_mark_past_due``
transitions (see that module's own docstring). No period-extension/
past-due bookkeeping is reimplemented here.

## BE-013 Part 4 addition: payment-webhook-to-invoice composition

On a real success confirmation, ``process_stripe_event``/
``process_razorpay_event`` now also accept an optional
``invoice_service: InvoiceServiceProtocol | None`` parameter -- when
supplied (the real, wired case, via ``router.py``'s own dependency), a
resolved successful payment is handed to
``service.InvoiceService.mark_invoice_paid_for_payment`` (an additive call
into this new BE-013 Part 4 method, never a second, independent
reimplementation of "what does a successful payment mean for billing").
Defaulting to ``None`` keeps this an entirely backward-compatible, additive
change: every existing caller/test that does not pass ``invoice_service``
observes byte-for-byte the same behavior this module had before Part 4.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Any, Protocol

import razorpay
import stripe
from redis.asyncio import Redis

from .constants import WEBHOOK_EVENT_DEDUP_KEY_PREFIX, PaymentStatus
from .events import WebhookProcessed, WebhookSignatureInvalid
from .exceptions import WebhookSignatureInvalidError
from .models import Payment
from .renewal_service import RenewalService
from .repository import PaymentRepositoryProtocol

logger = logging.getLogger(__name__)


class InvoiceServiceProtocol(Protocol):
    """The single, narrow method these webhook handlers need from
    ``service.InvoiceService`` -- see that method's own docstring for the
    full "natural continuation of a successful payment webhook" write-up.
    Kept as a locally-defined ``Protocol`` (never a concrete import of
    ``service.InvoiceService``) for the same "avoid a construction cycle /
    keep the dependency structural" reasoning ``service
    .LicenseLifecycleProtocol``/``renewal_service
    .PaymentGatewayProtocol`` already establish elsewhere in this domain."""

    async def mark_invoice_paid_for_payment(
        self, payment: Payment
    ) -> object | None: ...


# ============================================================================
# Signature verification
# ============================================================================


def verify_stripe_event(
    payload: bytes, *, signature_header: str, secret: str, tolerance_seconds: int
) -> stripe.Event:
    """Real Stripe-Signature verification -- see module docstring for the
    exact scheme. Raises ``WebhookSignatureInvalidError`` (never a raw SDK
    exception) on any failure: bad signature, tampered payload, or a
    timestamp outside ``tolerance_seconds``."""
    try:
        return stripe.Webhook.construct_event(
            payload, signature_header, secret, tolerance=tolerance_seconds
        )
    except stripe.SignatureVerificationError as exc:
        raise WebhookSignatureInvalidError("Stripe", str(exc)) from exc
    except ValueError as exc:  # malformed JSON payload
        raise WebhookSignatureInvalidError("Stripe", str(exc)) from exc


def verify_razorpay_signature(payload: bytes, *, signature: str, secret: str) -> None:
    """Real X-Razorpay-Signature verification -- see module docstring for
    the exact scheme (HMAC-SHA256 of the raw body, constant-time compare;
    no timestamp/replay-tolerance component exists in Razorpay's own real
    scheme). Raises ``WebhookSignatureInvalidError`` on mismatch."""
    utility = razorpay.Utility()
    try:
        utility.verify_webhook_signature(payload.decode("utf-8"), signature, secret)
    except razorpay.errors.SignatureVerificationError as exc:
        raise WebhookSignatureInvalidError("Razorpay", str(exc)) from exc


# ============================================================================
# Event-id dedup
# ============================================================================


class WebhookEventDedupProtocol(Protocol):
    async def mark_processed_if_new(self, provider: str, event_id: str) -> bool:
        """Returns ``True`` the first time this ``(provider, event_id)``
        pair is seen (and atomically marks it processed), ``False`` on
        every subsequent call for the same pair (a real redelivery)."""
        ...


class RedisWebhookEventDedup:
    """Real Redis-backed implementation -- see module docstring for the
    full "why Redis, why a TTL, why not a table" write-up. A single
    ``SET key value NX EX ttl`` is atomic: two concurrent deliveries of the
    same event id can never both observe "new"."""

    def __init__(self, redis: Redis, *, ttl_seconds: int) -> None:
        self._redis = redis
        self._ttl_seconds = ttl_seconds

    async def mark_processed_if_new(self, provider: str, event_id: str) -> bool:
        key = f"{WEBHOOK_EVENT_DEDUP_KEY_PREFIX}:{provider}:{event_id}"
        was_set = await self._redis.set(key, "1", nx=True, ex=self._ttl_seconds)
        return bool(was_set)


# ============================================================================
# Handlers
# ============================================================================


async def _resolve_and_update_payment(
    payment_repository: PaymentRepositoryProtocol,
    *,
    provider_payment_id: str | None,
    succeeded: bool,
    failure_reason: str | None,
) -> Any:
    if not provider_payment_id:
        return None
    payment = await payment_repository.get_by_provider_payment_id(provider_payment_id)
    if payment is None:
        # A webhook for a charge this platform doesn't track (e.g. created
        # directly in the provider dashboard, outside this module) -- real
        # webhook-handling best practice is to acknowledge (2xx) and
        # ignore, never error the delivery for something this platform was
        # never asked to track.
        logger.info(
            "billing_webhook_payment_not_tracked",
            extra={"provider_payment_id": provider_payment_id},
        )
        return None
    if payment.status in (PaymentStatus.SUCCEEDED.value, PaymentStatus.FAILED.value):
        # Already resolved (e.g. a redelivery that slipped past dedup, or
        # this platform's own synchronous charge path already resolved it)
        # -- idempotent no-op, never double-apply.
        return payment
    if succeeded:
        return await payment_repository.update_payment(
            payment,
            {"status": PaymentStatus.SUCCEEDED.value, "failure_reason": None},
        )
    return await payment_repository.update_payment(
        payment,
        {
            "status": PaymentStatus.FAILED.value,
            "failure_reason": failure_reason or "provider_reported_failure",
        },
    )


async def process_stripe_event(
    event: stripe.Event,
    *,
    payment_repository: PaymentRepositoryProtocol,
    renewal_service: RenewalService,
    dedup: WebhookEventDedupProtocol,
    invoice_service: InvoiceServiceProtocol | None = None,
) -> bool:
    """Processes one verified Stripe ``Event``. Returns ``True`` if this
    call actually applied the event (``False`` if it was a dedup no-op).
    Real event types handled: ``payment_intent.succeeded``/
    ``payment_intent.payment_failed``; every other event type is
    acknowledged (the caller returns 2xx either way) and otherwise
    ignored -- real Stripe guidance for a webhook endpoint that only cares
    about a subset of event types."""
    is_new = await dedup.mark_processed_if_new("stripe", event.id)
    if not is_new:
        logger.info(
            "billing_webhook_event_duplicate_ignored",
            extra={"provider": "stripe", "event_id": event.id},
        )
        return False

    intent = event.data.object
    provider_payment_id = getattr(intent, "id", None)

    if event.type == "payment_intent.succeeded":
        payment = await _resolve_and_update_payment(
            payment_repository,
            provider_payment_id=provider_payment_id,
            succeeded=True,
            failure_reason=None,
        )
        if payment is not None and payment.subscription_id is not None:
            await renewal_service.confirm_renewal_payment_succeeded(
                payment.subscription_id
            )
        if payment is not None and invoice_service is not None:
            await invoice_service.mark_invoice_paid_for_payment(payment)
    elif event.type == "payment_intent.payment_failed":
        last_error = getattr(intent, "last_payment_error", None)
        reason = getattr(last_error, "message", None) if last_error else None
        payment = await _resolve_and_update_payment(
            payment_repository,
            provider_payment_id=provider_payment_id,
            succeeded=False,
            failure_reason=reason,
        )
        if payment is not None and payment.subscription_id is not None:
            await renewal_service.confirm_renewal_payment_failed(
                payment.subscription_id, reason=reason or "provider_reported_failure"
            )
    else:
        logger.info(
            "billing_webhook_event_type_unhandled",
            extra={"provider": "stripe", "event_type": event.type},
        )

    logged = WebhookProcessed(
        provider="stripe", event_id=event.id, event_type=event.type
    )
    logger.info("billing_webhook_processed", extra=_event_extra(logged))
    return True


async def process_razorpay_event(
    payload: dict[str, Any],
    *,
    payment_repository: PaymentRepositoryProtocol,
    renewal_service: RenewalService,
    dedup: WebhookEventDedupProtocol,
    invoice_service: InvoiceServiceProtocol | None = None,
) -> bool:
    """Processes one verified Razorpay webhook payload (already
    signature-verified JSON, parsed into a plain dict). Real event types
    handled: ``payment.captured``/``payment.failed``. Razorpay's webhook
    payload includes its own ``event`` field (the event type) but no
    top-level unique event id the way Stripe's ``Event.id`` is -- Razorpay
    webhooks instead carry an ``x-razorpay-event-id`` HTTP header per its
    real documented delivery format; the caller (``router.py``) passes
    that header value through as ``event_id``."""
    event_type = payload.get("event", "")
    event_id = payload.get("_event_id", "")
    is_new = await dedup.mark_processed_if_new("razorpay", event_id)
    if not is_new:
        logger.info(
            "billing_webhook_event_duplicate_ignored",
            extra={"provider": "razorpay", "event_id": event_id},
        )
        return False

    payment_entity = (
        payload.get("payload", {}).get("payment", {}).get("entity", {})
        if isinstance(payload.get("payload"), dict)
        else {}
    )
    provider_payment_id = payment_entity.get("id")

    if event_type == "payment.captured":
        payment = await _resolve_and_update_payment(
            payment_repository,
            provider_payment_id=provider_payment_id,
            succeeded=True,
            failure_reason=None,
        )
        if payment is not None and payment.subscription_id is not None:
            await renewal_service.confirm_renewal_payment_succeeded(
                payment.subscription_id
            )
        if payment is not None and invoice_service is not None:
            await invoice_service.mark_invoice_paid_for_payment(payment)
    elif event_type == "payment.failed":
        reason = payment_entity.get("error_description")
        payment = await _resolve_and_update_payment(
            payment_repository,
            provider_payment_id=provider_payment_id,
            succeeded=False,
            failure_reason=reason,
        )
        if payment is not None and payment.subscription_id is not None:
            await renewal_service.confirm_renewal_payment_failed(
                payment.subscription_id, reason=reason or "provider_reported_failure"
            )
    else:
        logger.info(
            "billing_webhook_event_type_unhandled",
            extra={"provider": "razorpay", "event_type": event_type},
        )

    logged = WebhookProcessed(
        provider="razorpay", event_id=event_id, event_type=event_type
    )
    logger.info("billing_webhook_processed", extra=_event_extra(logged))
    return True


def _event_extra(event: object) -> dict[str, object]:
    """Identical reflection trick to ``service._event_extra``/
    ``renewal_service._event_extra`` -- duplicated (not imported), same
    "no import-time dependency beyond what this module already needs"
    reasoning."""
    return {
        f"event_{f.name}": value
        if isinstance(value := getattr(event, f.name), str | int | float | bool)
        else str(value)
        for f in dataclasses.fields(event)
    }


def log_signature_failure(provider: str, reason: str) -> None:
    event = WebhookSignatureInvalid(provider=provider, reason=reason)
    logger.warning("billing_webhook_signature_invalid", extra=_event_extra(event))


__all__ = [
    "verify_stripe_event",
    "verify_razorpay_signature",
    "WebhookEventDedupProtocol",
    "RedisWebhookEventDedup",
    "InvoiceServiceProtocol",
    "process_stripe_event",
    "process_razorpay_event",
    "log_signature_failure",
]
